#! /usr/bin/python

## Binary Analysis Tool
## Copyright 2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a barebones script to print information about cloning inside
the BAT database. Two types of clones are stored:

* identical clones: all files of the package are the same. This could be
because the packages are identical, or because the number of files that BAT
would process is actually really really small. This happens for example with
wrappers around libraries to provide language bindings

* embedding: a package is completely copied into another package.

Results are output on stdout
'''

import sys, os, sqlite3, multiprocessing
from optparse import OptionParser

## process packages by querying the database.
## This method takes three parameters:
## * db -- location of the database
## * package -- tuple (packagename, version)
## * packageclones -- boolean to indicate whether or not clones
## between different versions of the same package should also be
## considered. Default False.
def clonedetect((db, package, packageclones)):
	print >>sys.stderr, "processing %s, %s" % package
	conn = sqlite3.connect(db)
	cursor = conn.cursor()
	possibleclones = {}
	sha256perpackage = {}
	cursor.execute("select distinct sha256 from processed_file where package=? and version=?", package)
	sha256 = cursor.fetchall()
	sha256perpackage[package] = len(sha256)
	if len(sha256) != 0:
		unique = False
		clonep = {}
		for s in sha256:
			cursor.execute('select distinct package, version from processed_file where sha256=?', s)
			clonesha256 = cursor.fetchall()
			## one file is unique to this package, so there are no complete clones
			if len(clonesha256) == 1:
				unique = True
				break
			else:
				#clonep = clonep + clonesha256
				for p in clonesha256:
					if not packageclones:
						if p[0] == package[0]:
							continue
					else:
						if p[1] == package[1]:
							continue
					if clonep.has_key(p):
						clonep[p] += 1
					else:
						clonep[p] = 1
				
		if not unique:
			possibleclones[package] = clonep
	cursor.close()
	conn.close()
	return (possibleclones, sha256perpackage)

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="db", help="path to database file", metavar="FILE")
	(options, args) = parser.parse_args()

	if options.db == None:
		parser.error("No database found")

	conn = sqlite3.connect(options.db)
	cursor = conn.cursor()
	packages = cursor.execute("select package, version from processed").fetchall()
	cursor.close()
	conn.close()

	packages.sort()
	pool = multiprocessing.Pool()
	packageclones = False
	scantasks = map(lambda x: (options.db, x, packageclones), packages)
	cloneresults = pool.map(clonedetect, scantasks, 1)
	pool.terminate()
	clonedb = {}
	sha256perpackage = {}
	for i in cloneresults:
		if i != None:
			(clones, lensha256) = i
			if len(clones) == 0:
				continue
			if len(clones) != 1:
				## this should not happen
				continue
			else:
				clonedb[clones.keys()[0]] = clones.values()
			sha256perpackage.update(lensha256)

	for i in clonedb:
		for j in clonedb[i]:
			for v in j.keys():
				if clonedb.has_key(v):
					if i in clonedb[v][0].keys():
						if clonedb[v][0][i] == sha256perpackage[i]:
							if clonedb[v][0][i] == sha256perpackage[v]:
								args = i + v + (clonedb[v][0][i],)
								print "identical:\t%s, %s == %s, %s -- %d" % args
							else:
								args = i + v + (clonedb[v][0][i], sha256perpackage[v])
								print "partial:\t%s, %s << %s, %s -- %d %d" % args

if __name__ == "__main__":
	main(sys.argv)
