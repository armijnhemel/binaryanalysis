#!/usr/bin/python

import sys, os, os.path, re
import fnmatch
import sqlite3
import ConfigParser
from optparse import OptionParser

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script can be used to regenerate a LIST file from a database. This
can be useful in situations like a diskcrash (and only the 'processed' table
could be recovered), or in case of errors in the extraction scripts where parts
of the database have to be regenerated.

By default the script writes data for files from all origins, unless 'origin'
is specified.
'''

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="master", help="path to database", metavar="FILE")
	parser.add_option("-l", "--listfile", action="store", dest="listfile", help="path to LIST file (output)", metavar="FILE")
	parser.add_option("-o", "--origin", action="store", dest="origin", help="optional origin filter")

	(options, args) = parser.parse_args()
	if options.listfile == None:
		parser.error("Need path to LIST file")
	if options.master == None:
		parser.error("Need path to database")
	if not os.path.exists(options.master):
		parser.error("Need path to database")
	try:
		conn = sqlite3.connect(options.master)
	except:
		print >>sys.stderr, "Can't open database"
		sys.exit(1)
	cursor = conn.cursor()

	## TODO: add some sanity checks for 'origin' first
	if options.origin != None:
		cursor.execute("select package, version, filename, origin from processed where origin=?", (options.origin,))
	else:
		cursor.execute("select package, version, filename, origin from processed")
	res = cursor.fetchall()
	cursor.close()

	if res != []:
		listfile = open(options.listfile, 'w')
		for i in res:
			(package, version, filename, origin) = i
			listfile.write("%s\t%s\t%s\t%s\n" % (package, version, filename, origin))
		listfile.flush()
		listfile.close()

if __name__ == "__main__":
	main(sys.argv)
