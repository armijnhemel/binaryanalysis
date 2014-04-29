#! /usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script mass renames files in the database. It uses a file with names and
versions of packages, plus the new name and version the package should be
given. Per package one line is used. Each line has four fields, separated by |

oldname|oldversion|newname|newversion

Optionally takes extra argument to dump data. This is useful to update the caches
without having to regenerate the complete cache (which can take a looong time).
'''

import sys, os, sqlite3, cPickle
from optparse import OptionParser

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="db", help="path to database file", metavar="FILE")
	parser.add_option("-r", "--rename", action="store", dest="removal", help="path to file listing package/version that need to be renamed", metavar="FILE")
	parser.add_option("-p", "--dump", action="store", dest="pickle", help="path to dump file", metavar="FILE")
	(options, args) = parser.parse_args()

	if options.db == None:
		parser.error("No database found")

	if options.removal == None:
		parser.error("No rename file found")

	dump = False
	if options.pickle != None:
		dump = True
		#parser.error("No dump file found")

	## store in pickle:
	## * package
	## * function names
	## * strings
	## * variable names
	pickledumps = []

	rename = open(options.removal).readlines()
	renamefiles = []
	for i in rename:
		(oldpackage, oldversion, newpackage, newversion) = i.strip().split('|')
		renamefiles.append((oldpackage, oldversion, newpackage, newversion))
	conn = sqlite3.connect(options.db)
	cursor = conn.cursor()
	for r in renamefiles:
		(oldpackage, oldversion, newpackage, newversion) = r
		renamesha256 = set()
		removesha256 = set()
		cursor.execute('select sha256 from processed_file where package=? and version=?', ((oldpackage, oldversion)))
		sha256s = cursor.fetchall()
		## now check for each SHA256 if it already exists with the new version (and the
		## old entry only needs to be removed) or if it actually needs to be renamed.
		for sha256 in sha256s:
			cursor.execute('select distinct package, version from processed_file where sha256=?', sha256)
			res = cursor.fetchall()
			if (newpackage, newversion) in res:
				removesha256.add(sha256)
				continue
			else:
				renamesha256.add(sha256)
		if dump:
			## first dump all data
			programstrings = []
			functionnames = []
			varnames = []
			allsha256 = set()
			#allsha256 = removesha256 + renamesha256
			allsha256.update(removesha256)
			allsha256.update(renamesha256)
			for s in allsha256:
				res = cursor.execute("select programstring,language from extracted_file where sha256=?", (s[0],))
				if res != None:
					programstrings += res
				res = cursor.execute("select functionname,language from extracted_function where sha256=?", (s[0],))
				if res != None:
					functionnames += res
				res = cursor.execute("select name,language,type from extracted_name where sha256=?", (s[0],))
				if res != None:
					varnames += res
			pickledumps.append({'package': oldpackage, 'programstrings': programstrings, 'functionnames': functionnames, 'varnames': varnames})

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

	if dump:
		dumpfile = open(options.pickle, 'wb')
		cPickle.dump(pickledumps, dumpfile)
		dumpfile.close()

if __name__ == "__main__":
	main(sys.argv)
