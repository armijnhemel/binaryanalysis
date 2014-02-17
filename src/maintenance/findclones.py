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


def counthashes((db, packageversion, packageclones, ignorepackages)):
	(package, version) = packageversion
	if package in ignorepackages:
		return
	print >>sys.stderr, "hashing %s, %s" % packageversion
	conn = sqlite3.connect(db)
	cursor = conn.cursor()
	cursor.execute("select distinct sha256 from processed_file where package=? and version=?", packageversion)
	sha256 = cursor.fetchall()
	cursor.close()
	conn.close()
	return (packageversion, len(sha256))

## process packages by querying the database.
## This method takes three parameters:
## * db -- location of the database
## * packageversion -- tuple (packagename, version)
## * packageclones -- boolean to indicate whether or not clones
## between different versions of the same package should also be
## considered.
## * ignorepackages -- list of packages that should be ignored
def clonedetect((db, packageversion, packageclones, ignorepackages)):
	(package, version) = packageversion
	print >>sys.stderr, "processing %s, %s" % packageversion
	conn = sqlite3.connect(db)
	cursor = conn.cursor()
	possibleclones = {}
	if package in ignorepackages:
		return (packageversion, possibleclones)
	cursor.execute("select distinct sha256 from processed_file where package=? and version=?", packageversion)
	sha256 = cursor.fetchall()
	if len(sha256) != 0:
		clonep = {}
		for s in sha256:
			cursor.execute('select distinct package, version from processed_file where sha256=?', s)
			clonesha256 = cursor.fetchall()
			## one file is unique to this package, so there are no complete clones
			if len(clonesha256) == 1:
				clonep = {}
				break
			if not packageclones:
				if len(set(map(lambda x: x[0], clonesha256))) == 1:
					continue
			for p in clonesha256:
				if not packageclones:
					if p[0] == package:
						continue
				else:
					if p[1] == version:
						continue
				if clonep.has_key(p):
					clonep[p] += 1
				else:
					clonep[p] = 1

	clonep_final = {}
	for p in clonep:
		## only consider results that contain the package completely
		if clonep[p] >= len(sha256):
			clonep_final[p] = clonep[p]
	
	cursor.close()
	conn.close()
	return (packageversion, clonep_final)

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

	#ignorepackages = ['linux']
	ignorepackages = []

	packages.sort()
	pool = multiprocessing.Pool()
	packageclones = False
	sha256perpackage = {}
	scantasks = map(lambda x: (options.db, x, packageclones, ignorepackages), packages)
	hashes = pool.map(counthashes, scantasks, 1)

	for i in hashes:
		if i != None:
			(package, lensha256) = i
			sha256perpackage[package] = lensha256

	cloneresults = pool.map(clonedetect, scantasks, 1)
	pool.terminate()

	clonedb = {}
	for i in cloneresults:
		if i != None:
			(package, clones) = i
			clonedb[package] = clones

	for i in clonedb:
		for j in clonedb[i]:
			if sha256perpackage.has_key(j):
				if sha256perpackage[i] == sha256perpackage[j]:
					args = i + j + (sha256perpackage[i],)
					print "identical:\t%s, %s == %s, %s -- %d" % args
				else:
					args = i + j + (sha256perpackage[i], sha256perpackage[j])
					print "partial:\t%s, %s << %s, %s -- %d %d" % args

if __name__ == "__main__":
	main(sys.argv)
