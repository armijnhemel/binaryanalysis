#!/usr/bin/python

import sys, os, os.path, re
import fnmatch
import psycopg2
import ConfigParser
from optparse import OptionParser

## Binary Analysis Tool
## Copyright 2012-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script verifies that the tables in a database are in sync, which means: all of the files in the tables "extracted_string" and "extracted_function" can also be found in "processed_file"
'''

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")

	(options, args) = parser.parse_args()
	if options.cfg == None:
		parser.error("Need path to configuration file")

	try:
		configfile = open(options.cfg, 'r')
	except:
		parser.error("Configuration file not readable")
	config.readfp(configfile)
	configfile.close()

	section = 'extractconfig'

	try:
		postgresql_user = config.get(section, 'postgresql_user')
		postgresql_password = config.get(section, 'postgresql_password')
		postgresql_db = config.get(section, 'postgresql_db')

		## check to see if a host (IP-address) was supplied either
		## as host or hostaddr. hostaddr is not supported on older
		## versions of psycopg2, for example CentOS 6.6, so it is not
		## used at the moment.
		try:
			postgresql_host = config.get(section, 'postgresql_host')
		except:
			postgresql_host = None
		try:
			postgresql_hostaddr = config.get(section, 'postgresql_hostaddr')
		except:
			postgresql_hostaddr = None
		## check to see if a port was specified. If not, default to 'None'
		try:
			postgresql_port = config.get(section, 'postgresql_port')
		except Exception, e:
			postgresql_port = None
	except:
		print >>sys.stderr, "Database connection not defined in configuration file. Exiting..."
		sys.stderr.flush()
		sys.exit(1)

	try:
		conn = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password, host=postgresql_host, port=postgresql_port)

		cursor = conn.cursor()
	except:
		print >>sys.stderr, "Can't open database"
		sys.exit(1)

	print "checking processed"
	sys.stdout.flush()
	cursor.execute("select distinct checksum from processed")
	res = cursor.fetchall()
	conn.commit()
	for r in res:
		cursor.execute('select checksum from processed where checksum=%s', r)
		processed_results = cursor.fetchall()
		conn.commit()
		if len(processed_results) != 1:
			cursor.execute('select * from processed where checksum=%s', r)
			processed_results = cursor.fetchall()
			conn.commit()
			print "identical:", map(lambda x: "%s %s" % (x[0], x[1]), processed_results)
			sys.stdout.flush()

	## create a new cursor
	ncursor = conn.cursor()

	cursor.execute("select package,version from processed_file")
	res = cursor.fetchmany(40000)
	conn.commit()

	totals = 0
	print "checking processed_file"
	sys.stdout.flush()
	while res != []:
		totals += len(res)
		#print "processing", totals
		for r in res:
			(package,version) = r
			ncursor.execute('select checksum from processed where package=%s and version=%s LIMIT 1', r)
			pres = ncursor.fetchall()
			conn.commit()
			if pres == []:
				print "database not in sync", r
				sys.stdout.flush()
		res = cursor.fetchmany(40000)
		conn.commit()

	for i in ["extracted_string", "extracted_function"]:
		cursor.execute("select distinct(checksum) from %s" % i)
		res = cursor.fetchmany(40000)
		conn.commit()
		totals = 0
		while res != []:
			totals += len(res)
			print "processing %s" % i, totals
			sys.stdout.flush()
			for r in res:
				ncursor.execute('select checksum from processed_file where checksum=%s LIMIT 1', r)
				pres = ncursor.fetchall()
				conn.commit()
				if pres == []:
					print "database %s not in sync" % i, r[0]
					sys.stdout.flush()
			res = cursor.fetchmany(40000)
			conn.commit()

if __name__ == "__main__":
	main(sys.argv)
