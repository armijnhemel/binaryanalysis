#/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script mines data from Fedora package databases (available on any Fedora mirror under os/repodata) and puts it in another database.

The names of the files that are needed end in "filelists.sqlite.bz2" (file list database) and "primary.sqlite.bz2" (package database)

Example: linux/releases/24/Everything/x86_64/os/repodata/

The files need to be decompressed first
'''

import os, os.path, sys, sqlite3, psycopg2
from optparse import OptionParser
import ConfigParser

# select version,name,pkgKey from packages;
# store in {pkgKey: {'name': name, 'version': version}}
# from other database:
# select version,name,pkgKey from packages;
# process all files (not directories)
# store in database

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-f", "--filelistdatabase", action="store", dest="filelistdatabase", help="path to database containing file info (filelists.sqlite)", metavar="FILE")
	parser.add_option("-p", "--packagedatabase", action="store", dest="packagedatabase", help="path to database containing package info (primary.sqlite)", metavar="FILE")
	parser.add_option("-s", "--fedoraversion", action="store", dest="fedoraversion", help="Fedora version", metavar="VERSION")

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

	if options.filelistdatabase == None or options.packagedatabase == None:
		parser.error("Provide paths to Fedora databases")
	if options.fedoraversion == None:
		parser.error("Provide version of Fedora")

	filelistconn = sqlite3.connect(options.filelistdatabase)
	filelistcursor = filelistconn.cursor()

	packageconn = sqlite3.connect(options.packagedatabase)
	packagecursor = packageconn.cursor()

	pkgnameversion = {}
	packagecursor.execute("select pkgKey, name, version from packages")
	res = packagecursor.fetchall()
	packageconn.commit()
	for i in res:
		pkgnameversion[i[0]] = {'name': i[1], 'version': i[2]}
	packagecursor.close()
	packageconn.close()

	for pkg in pkgnameversion.keys():
		filelistcursor.execute("select pkgKey, dirname, filenames, filetypes from filelist where pkgKey=%d" % pkg)
		res = filelistcursor.fetchall()
		distroversion=''
		for r in res:
			(pkgKey, dirname, filenames, filetypes) = r
			files = filenames.split('/')
			## very crude filter to take care of '/' in filenames, which split will
			## turn into ['', '']
			if '' in files:
				newfiles = []
				for i in range(0,len(files)):
					empty = False
					if files[i] == '':
						if not empty:
							empty = True
							continue
						else:
							newfiles.append('/')
							empty = False
					else:
						newfiles.append(files[i])
						empty = False
				files = newfiles
			for i in range(0,len(files)):
				if files[i] == '':
					continue
				if filetypes[i] == 'd':
					continue
				cursor.execute("insert into file values (%s,%s,%s,%s, 'Fedora', %s)", (files[i], dirname, pkgnameversion[pkg]['name'], pkgnameversion[pkg]['version'], options.fedoraversion))
				#print dirname, files[i], pkgnameversion[pkg]
	filelistcursor.close()
	filelistconn.close()
	conn.commit()
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main(sys.argv)
