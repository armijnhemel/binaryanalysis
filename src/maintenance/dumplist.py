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
This script can be used to regenerate a LIST file from a database. This
can be useful in situations like a diskcrash (and only the 'processed' table
could be recovered), or in case of errors in the extraction scripts where parts
of the database have to be regenerated.

By default the script writes data for files from all origins, unless 'origin'
is specified.

This script needs the same configuration file as the database creation script.
'''

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--configuration", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-l", "--listfile", action="store", dest="listfile", help="path to LIST file (output)", metavar="FILE")
	parser.add_option("-o", "--origin", action="store", dest="origin", help="optional origin filter")

	(options, args) = parser.parse_args()
	if options.listfile == None:
		parser.error("Need path to LIST file")
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

	## TODO: add some sanity checks for 'origin' first
	if options.origin != None:
		cursor.execute("select package, version, filename, origin from processed where origin=%s", (options.origin,))
	else:
		cursor.execute("select package, version, filename, origin from processed")
	res = cursor.fetchall()
	cursor.close()
	conn.close()

	if res != []:
		listfile = open(options.listfile, 'w')
		for i in res:
			(package, version, filename, origin) = i
			listfile.write("%s\t%s\t%s\t%s\n" % (package, version, filename, origin))
		listfile.flush()
		listfile.close()

if __name__ == "__main__":
	main(sys.argv)
