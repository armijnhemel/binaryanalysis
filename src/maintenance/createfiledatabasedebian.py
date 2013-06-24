#/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script mines data from Debian package databases (available on any Debian mirror as Contents-$ARCH.gz) and puts it in another database.

It requires that the file is decompressed first.
'''


import os, os.path, sys, sqlite3, gzip
from optparse import OptionParser

def processPackages(destinationcursor, destinationconn, contentsfile):
	#contents = gzip.open(contentsfile)
	contents = open(contentsfile)
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
		
		destinationcursor.execute("insert into file values (?,?,?,?, 'Debian', ?)", (os.path.basename(filepath.strip()), os.path.dirname(filepath.strip()), package, packageversion, ''))
		#destinationconn.commit()
	return

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--destination", action="store", dest="destination", help="path to destination database", metavar="FILE")
	parser.add_option("-c", "--contentsfile", action="store", dest="contentsfile", help="path to file containing contents of Debian packages", metavar="FILE")

	(options, args) = parser.parse_args()
	if options.destination == None or options.contentsfile == None:
		print >>sys.stderr, "Provide all databases"
		sys.exit(1)

	## first build the new database in memory, since it's faster
	#destinationconn = sqlite3.connect(options.destination)
	destinationconn = sqlite3.connect(':memory:')
	destinationconn.text_factory = str
	destinationcursor = destinationconn.cursor()
	destinationcursor.execute("attach '%s' as disk" % (options.destination))

	try:
		destinationcursor.execute("create table if not exists file(filename text, directory text, package text, packageversion text, source text, distroversion text)")
        	destinationcursor.execute("create index if not exists file_index on file(filename, directory)")
		destinationcursor.execute("create table if not exists disk.file(filename text, directory text, package text, packageversion text, source text, distroversion text)")
        	destinationcursor.execute("create index if not exists disk.file_index on file(filename, directory)")
		destinationconn.commit()
	except:
		print >>sys.stderr, "Can't create tables in destination database"
		sys.exit(1)
	processPackages(destinationcursor, destinationconn, options.contentsfile)
	destinationconn.commit()
	destinationcursor.execute("insert into disk.file select * from file")
	destinationconn.commit()

if __name__ == "__main__":
	main(sys.argv)
