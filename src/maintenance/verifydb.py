#!/usr/bin/python

import sys, os, os.path, re
import fnmatch
import sqlite3
import ConfigParser
from optparse import OptionParser
from multiprocessing import Pool

## Binary Analysis Tool
## Copyright 2012-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script verifies that the tables in a database are in sync, which means: all of the files in the tables "extracted_string", "licenses" and "extracted_function" can also be found in "processed_file"

Usage:

python verifydb.py --database=/path/to/database
'''

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="master", help="path to database", metavar="FILE")

	(options, args) = parser.parse_args()
	if options.master == None:
		parser.error("Need path to database")
	if not os.path.exists(options.master):
		parser.error("Need path to database")
	try:
		conn = sqlite3.connect(options.master)
	except:
		print "Can't open database"
		sys.exit(1)

	cursor = conn.cursor()

	print "checking processed"
	cursor.execute("select distinct checksum from processed")
	res = cursor.fetchall()
	for r in res:
		cursor.execute('select checksum from processed where checksum=?', r)
		processed_results = cursor.fetchall()
		if len(processed_results) != 1:
			cursor.execute('select * from processed where checksum=?', r)
			processed_results = cursor.fetchall()
			print "identical:", map(lambda x: "%s %s" % (x[0], x[1]), processed_results)

	cursor.execute("select package,version from processed_file")
	res = cursor.fetchmany(40000)
	ncursor = conn.cursor()
	totals = 0
	print "checking processed_file"
	while res != []:
		totals += len(res)
		#print "processing", totals
		for r in res:
			(package,version) = r
			ncursor.execute('select checksum from processed where package=? and version=? LIMIT 1', r)
			pres = ncursor.fetchall()
			if pres == []:
				print "database not in sync", r
		res = cursor.fetchmany(40000)
	cursor.close()

	for i in ["extracted_string", "extracted_function"]:
		cursor = conn.cursor()
		cursor.execute("select distinct(checksum) from %s" % i)
		res = cursor.fetchmany(40000)
		ncursor = conn.cursor()
		totals = 0
		while res != []:
			totals += len(res)
			print "processing %s" % i, totals
			for r in res:
				ncursor.execute('select checksum from processed_file where checksum=? LIMIT 1', r)
				pres = ncursor.fetchall()
				if pres == []:
					print "database %s not in sync" % i, r[0]
			res = cursor.fetchmany(40000)

if __name__ == "__main__":
	main(sys.argv)
