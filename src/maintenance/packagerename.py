#! /usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script mass renames files in the database. It uses a file with names and
versions of packages, plus the new name and version the package should be
given. Per package one line is used. Each line has four fields, separated by |

oldname|oldversion|newname|newversion
'''

import sys, os, sqlite3
from optparse import OptionParser

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="db", help="path to database file", metavar="FILE")
	parser.add_option("-r", "--rename", action="store", dest="removal", help="path to file listing package/version that need to be renamed", metavar="FILE")
	(options, args) = parser.parse_args()

	if options.db == None:
		print >>sys.stderr, "No database found"
		sys.exit(1)

	if options.removal == None:
		print >>sys.stderr, "No rename file found"
		sys.exit(1)

	rename = open(options.removal).readlines()
	renamefiles = []
	for i in rename:
		(oldpackage, oldversion, newpackage, newversion) = i.strip().split('|')
		renamefiles.append((oldpackage, oldversion, newpackage, newversion))
	conn = sqlite3.connect(options.db)
	cursor = conn.cursor()
	for r in renamefiles:
		renamesha256 = []
		removesha256 = []
		cursor.execute('select sha256 from processed_file where package=? and version=?', ((r[0], r[1])))
		sha256s = cursor.fetchall()
		for sha256 in sha256s:
			cursor.execute('select distinct package, version from processed_file where sha256=?', sha256)
			res = cursor.fetchall()
			if (r[0], r[1]) in res:
				if (r[2], r[3]) in res:
					removesha256.append(sha256)
					continue
				else:
					renamesha256.append(sha256)
		for s in renamesha256:
			cursor.execute("update processed_file set package=?, version=? where sha256=? and package=? and version=?", (r[2], r[3], s[0], r[0], r[1]))
		for s in removesha256:
			cursor.execute("delete from processed_file where sha256=? and package=? and version=?", (s[0], r[0], r[1]))
		conn.commit()
		cursor.execute("select * from processed where package=? and version=?", (r[2], r[3]))
		res = cursor.fetchall()
		## only when doesn't exist in processed yet
		if res == []:
			cursor.execute("update processed set package=?, version=? where package=? and version=?", (r[2], r[3], r[0], r[1]))
		else:
			cursor.execute("delete from processed where package=? and version=?", (r[0], r[1]))
		conn.commit()
	conn.close()

if __name__ == "__main__":
	main(sys.argv)
