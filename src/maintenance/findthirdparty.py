#! /usr/bin/python

## Binary Analysis Tool
## Copyright 2015-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script finds clones in packages that are very specifically indicated in
the source code tree of a package as "third party" by looking if certain
patterns occur in path names.
'''

import sys, os, psycopg2, multiprocessing
from optparse import OptionParser
import ConfigParser

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-t", "--test", action="store_true", dest="dryrun", help="do a test run, only report", metavar="TEST")
	(options, args) = parser.parse_args()

	if options.cfg == None:
		parser.error("No configuration file found")

	if not os.path.exists(options.cfg):
		parser.error("Configuration file does not exist")
	try:
		configfile = open(options.cfg, 'r')
	except:
		parser.error("Configuration file not readable")
	config.readfp(configfile)
	configfile.close()

	if not options.dryrun:
		options.dryrun = False

	## search configuration to see if it is correct and/or not malformed
	## first search for a section called 'extractconfig' with configtype = global
	for section in config.sections():
		if section == "extractconfig":
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
		packagecursor = conn.cursor()
	except:
		print >>sys.stderr, "Database not running or misconfigured"
		sys.exit(1)

	packages = cursor.execute("select package, version, origin from processed")
	packages = cursor.fetchall()
	conn.commit()

	ignorepackages = ['linux', 'busybox']

	packages = map(lambda x: x[:2], packages)

	packages.sort()

	thirdparty = set(['thirdparty', 'third_party', '3rdparty', '3rdpart'])

	seensha256 = set()
	for i in packages:
		packagecursor.execute("select distinct checksum,thirdparty from processed_file where package=%s and version=%s", i)
		while True:
			res = packagecursor.fetchmany(50000)
			conn.commit()
			if len(res) == 0:
				break
			for s in res:
				if s[0] in seensha256:
					continue
				if s[1] != None:
					continue
				checksum = s[0]
				cursor.execute("select distinct package,pathname,thirdparty from processed_file where checksum=%s", (checksum,))
				packageres = cursor.fetchall()
				conn.commit()
				packageres = filter(lambda x: x[0] != i[0], packageres)
				for p in packageres:
					if p[0] in ignorepackages:
						continue
					if p[2] != None:
						continue
					## check if specific markers are in the path
					if i[0] in os.path.dirname(p[1]):
						marked = False
						for t in thirdparty:
							if t in os.path.dirname(p[1]):
								if options.dryrun:
									print i[0], i[1], checksum, p[:-1]
								else:
									cursor.execute("update processed_file set thirdparty=%s where package=%s and pathname=%s and checksum=%s", (True, p[0], p[1], checksum))
								marked = True
								break
						if 'external' in os.path.dirname(p[1]) and not marked:
							if options.dryrun:
								print i[0], i[1], checksum, p[:-1]
							else:
								cursor.execute("update processed_file set thirdparty=%s where package=%s and pathname=%s and checksum=%s", (True, p[0], p[1], checksum))
						else:
							if options.dryrun:
								pass
								#print i[0], i[1], checksum, p[:-1]
							else:
								pass
				conn.commit()
				seensha256.add(s[0])
	conn.commit()
	packagecursor.close()
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main(sys.argv)
