#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script is to update the SHA256SUM file in a directory that contains sha256 checksums 
for each file, that speeds up database creation.
'''

import os, os.path, sys, hashlib, multiprocessing
from optparse import OptionParser

def computehash((filedir, filename)):
	resolved_path = os.path.join(filedir, filename)
	scanfile = open(resolved_path, 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	filehash = h.hexdigest()
        return (filename, filehash)

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory with files", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.filedir == None:
		parser.error("No directory defined")
	if not os.path.exists(options.filedir):
		parser.error("No directory found")
	dirlist = os.listdir(options.filedir)
	dirlist = filter(lambda x: x != 'LIST' and x != 'SHA256SUM', dirlist)
	dirlist = filter(lambda x: os.path.isfile(os.path.join(options.filedir, x)), dirlist)

	## no files, so exit
	if len(dirlist) == 0:
		sys.exit(0)
	filenamestosha256s = {}
	if os.path.exists(os.path.join(options.filedir, "SHA256SUM")):
		sha256file = os.path.join(options.filedir, "SHA256SUM")
		sha256lines = open(sha256file, 'r').readlines()
		for i in sha256lines:
			(sha256, filename) = i.strip().split()
			if filename == 'SHA256SUM':
				continue
			if filename == 'LIST':
				continue
			filenamestosha256s[filename] = sha256

	## determine which files need to be scanned
	diffset = set(dirlist).difference(set(filenamestosha256s))
	if len(diffset) == 0:
		sys.exit(0)

	## find hashes in parallel
	shatasks = map(lambda x: (options.filedir, x), diffset)
	pool = multiprocessing.Pool()
	sharesults = pool.map(computehash, shatasks)
	pool.terminate()

	for i in sharesults:
		(filename, sha256) = i
		filenamestosha256s[filename] = sha256

	## write results
	filenameskeys = filenamestosha256s.keys()
	filenameskeys.sort()
	sha256file = open(os.path.join(options.filedir, "SHA256SUM"), 'w')
	for i in filenameskeys:
		sha256file.write("%s  %s\n" % (filenamestosha256s[i], i))
	sha256file.close()

if __name__ == "__main__":
	main(sys.argv)
