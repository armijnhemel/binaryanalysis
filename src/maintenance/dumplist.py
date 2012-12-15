#!/usr/bin/python

import sys, os, os.path, re
import fnmatch
import sqlite3
import ConfigParser
from optparse import OptionParser

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
'''

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="master", help="path to database", metavar="FILE")
	parser.add_option("-l", "--listfile", action="store", dest="listfile", help="path to LIST file (output)", metavar="FILE")

	(options, args) = parser.parse_args()
	if options.listfile == None:
		parser.error("Need path to LIST file")
	if options.master == None:
		parser.error("Need path to database")
	try:
		conn = sqlite3.connect(options.master)
	except:
		print "Can't open database"
		sys.exit(1)
	cursor = conn.cursor()

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
