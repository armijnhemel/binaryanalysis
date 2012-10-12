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
This script verifies that the tables in a database are in sync, which means: all of the files in the tables "extracted_file", "licenses" and "extracted_function" can also be found in "processed_file"

Usage:

python verifydb.py --database=/path/to/database
'''

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="master", help="path to database", metavar="FILE")

	(options, args) = parser.parse_args()
	if options.master == None:
		print >>sys.stderr, "Need path to database"
		sys.exit(1)
	try:
		conn = sqlite3.connect(options.master)
	except:
		print "Can't open database"
		sys.exit(1)
	cursor = conn.cursor()

	## first get all the unique checksums in processed_file. This could already eat quite some memory.
	cursor.execute("select distinct(sha256) from processed_file")
	res = cursor.fetchall()
	cursor.close()

	## change the results from tuples to single values, put it in a set,
	## for determining differences and intersections.
	if res != []:
		processed_file_sha256 = set(map(lambda x: x[0], res))
	else:
		processed_file_sha256 = set([])
	print "processed files: %d" % len(processed_file_sha256)

	for i in ["extracted_file", "licenses", "extracted_function"]:
		cursor = conn.cursor()
		print "processing %s" % i
		cursor.execute("select distinct(sha256) from %s" % i)
		res = cursor.fetchall()
		cursor.close()
		if res != []:
			sha256s = set(map(lambda x: x[0], res))
			res = []
		else:
			sha256s = set([])

		intersect = processed_file_sha256.intersection(sha256s)
		if not len(intersect) == len(sha256s):
			## something is wrong: there are values in table i that should not be in there
			print "database %s not in sync" % i
			for j in list(sha256s.difference(intersect)):
				print j
			sys.exit(1)

if __name__ == "__main__":
	main(sys.argv)
