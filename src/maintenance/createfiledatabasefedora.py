#/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script mines data from Fedora package databases (available on any Fedora mirror under os/repodata) and puts it in another database.

The names of the files that are needed end in "filelists.sqlite.bz2" (file list database) and "primary.sqlite.bz2" (package database)
'''

import os, os.path, sys, sqlite3
from optparse import OptionParser

# select version,name,pkgKey from packages;
# store in {pkgKey: {'name': name, 'version': version}}
# from other database:
# select version,name,pkgKey from packages;
# process all files (not directories)
# store in database

def processPackages(destinationcursor, filelistcursor, packagecursor):
	pkgnameversion = {}
	packagecursor.execute("select pkgKey, name, version from packages")
	res = packagecursor.fetchall()
	for i in res:
		pkgnameversion[i[0]] = {'name': i[1], 'version': i[2]}

	for pkg in pkgnameversion.keys():
		filelistcursor.execute("select pkgKey, dirname, filenames, filetypes from filelist where pkgKey=%d" % pkg)
		res = filelistcursor.fetchall()
		for r in res:
			(pkgKey, dirname, filenames, filetypes) = r
			files = filenames.split('/')
			for i in range(0,len(files)):
				if files[i] == '':
					continue
				if filetypes[i] == 'd':
					continue
				destinationcursor.execute("insert into file values (?,?,?,?, 'fedora')", (files[i], dirname, pkgnameversion[pkg]['name'], pkgnameversion[pkg]['version']))
				#print dirname, files[i], pkgnameversion[pkg]
	return

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--destination", action="store", dest="destination", help="path to destination database", metavar="FILE")
	parser.add_option("-f", "--filelistdatabase", action="store", dest="filelistdatabase", help="path to database containing file info", metavar="FILE")
	parser.add_option("-p", "--packagedatabase", action="store", dest="packagedatabase", help="path to database containing package info", metavar="FILE")

	(options, args) = parser.parse_args()
	if options.destination == None or options.filelistdatabase == None or options.packagedatabase == None:
		print >>sys.stderr, "Provide all databases"
		sys.exit(1)

	destinationconn = sqlite3.connect(options.destination)
	destinationcursor = destinationconn.cursor()

	filelistconn = sqlite3.connect(options.filelistdatabase)
	filelistcursor = filelistconn.cursor()

	packageconn = sqlite3.connect(options.packagedatabase)
	packagecursor = packageconn.cursor()

	try:
		destinationcursor.execute("create table if not exists file(filename text, directory text, package text, version text, source text)")
        	destinationcursor.execute("create index if not exists file_index on file(filename, directory)")
	except:
		print >>sys.stderr, "Can't create tables in destination database"
		sys.exit(1)
	processPackages(destinationcursor, filelistcursor, packagecursor)
	destinationconn.commit()

if __name__ == "__main__":
	main(sys.argv)
