#! /usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script finds clones in packages that are very specifically indicated in
the source code tree of a package as "third party" by looking if certain
patterns occur in path names.
'''

import sys, os, sqlite3, multiprocessing
from optparse import OptionParser

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="db", help="path to database file", metavar="FILE")
	parser.add_option("-t", "--test", action="store_true", dest="dryrun", help="do a test run, only report", metavar="TEST")
	(options, args) = parser.parse_args()

	if options.db == None:
		parser.error("No database found")

	if not options.dryrun:
		options.dryrun = False

	conn = sqlite3.connect(options.db)
	cursor = conn.cursor()
	packages = cursor.execute("select package, version, origin from processed").fetchall()

	ignorepackages = ['linux', 'busybox']

	packages = map(lambda x: x[:2], filter(lambda x: x[2] == 'qt', packages))

	packages.sort()

	thirdparty = ['thirdparty', 'third_party', '3rdparty', '3rdpart']

	seensha256 = set()
	for i in packages:
		cursor.execute("select distinct checksum,thirdparty from processed_file where package=? and version=?", i)
		res = cursor.fetchall()
		for s in res:
			if s[0] in seensha256:
				continue
			if s[1] != None:
				continue
			checksum = s[0]
			cursor.execute("select distinct package,pathname,thirdparty from processed_file where checksum=?", (checksum,))
			packageres = cursor.fetchall()
			packageres = filter(lambda x: x[0] != i[0], packageres)
			for p in packageres:
				if p[0] in ignorepackages:
					continue
				if p[2] != None:
					continue
				## check if specific markers are in in the path
				for t in thirdparty:
					if t in os.path.dirname(p[1]):
						if options.dryrun:
							print s, p
						else:
							cursor.execute("update processed_file set thirdparty=? where package=? and pathname=? and checksum=?", (True, p[0], p[1], checksum))
				if 'external' in os.path.dirname(p[1]):
					if options.dryrun:
						print s, p
					else:
						cursor.execute("update processed_file set thirdparty=? where package=? and pathname=? and checksum=?", (True, p[0], p[1], checksum))
				else:
					if i[0] in os.path.dirname(p[1]):
						if options.dryrun:
							print s, p
						else:
							pass
			conn.commit()
			seensha256.add(s[0])
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main(sys.argv)
