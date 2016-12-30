#/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script mines data from Debian package databases (available on any Debian mirror as Contents-$ARCH.gz) and puts it in another database.
'''

import os, os.path, sys, psycopg2, gzip, ConfigParser
from optparse import OptionParser

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-f", "--file", action="store", dest="contentsfile", help="path to file containing contents of Debian packages", metavar="FILE")

	(options, args) = parser.parse_args()
	if options.contentsfile == None:
		parser.error("Need path to Debian packages file")

	if not os.path.exists(options.contentsfile):
		print >>sys.stderr, "Debian packages file does not exist"
		sys.stderr.flush()
		sys.exit(1)

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

	contents = gzip.open(options.contentsfile)
	seenstart = False
	for i in contents:
		if not seenstart:
			if i.startswith('FILE'):
				seenstart = True
				continue
			else:
				continue
		packageversion=''
		(filepath, categorypackage) = i.strip().rsplit(' ', 1)
		package = categorypackage.rsplit('/')[1].strip()
		
		cursor.execute("insert into file values (%s,%s,%s,%s, 'Debian', %s)", (os.path.basename(filepath.strip()), os.path.dirname(filepath.strip()), package, packageversion, ''))

	contents.close()
	conn.commit()
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main(sys.argv)
