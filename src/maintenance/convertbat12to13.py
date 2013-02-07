#!/usr/bin/python

import sys, os, os.path
import sqlite3
from optparse import OptionParser

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script is to merge avgstringscache into the normal stringscache. BAT 12 and earlier used two separate caches, BAT 13 and later use a single stringscache.
'''

def main(argv):
	parser = OptionParser()
	parser.add_option("-a", "--avgs", action="store", dest="avgs", help="path to averages cache", metavar="FILE")
	parser.add_option("-s", "--stringscache", action="store", dest="stringscache", help="path to stringscache", metavar="FILE")

	(options, args) = parser.parse_args()
	if options.avgs == None:
		parser.error("Need path to averages cache")
	if options.stringscache == None:
		parser.error("Need path to stringscache")
	try:
		conn = sqlite3.connect(options.stringscache)
	except:
		print "Can't open database"
		sys.exit(1)
	cursor = conn.cursor()

	cursor.execute("create table if not exists avgstringscache (package text, avgstrings real, primary key (package))")
	cursor.execute("create index if not exists package_index on avgstringscache(package)")

	cursor.execute("attach ? as avg", (options.avgs,))

	cursor.execute("insert into avgstringscache select * from avg.avgstringscache")
	conn.commit()

	## first create

if __name__ == "__main__":
	main(sys.argv)
