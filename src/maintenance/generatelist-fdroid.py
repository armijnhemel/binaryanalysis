#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Helper script to generate the LIST files for the string extraction scripts. While this script is not foolproof, it will save lots of typing :-)
'''

import sys, os, os.path
import bz2, tarfile, gzip
from optparse import OptionParser

## translation table for renames. None currently for F-Droid
packagerenames = {}

def generatelist(filedir):
	files = os.walk(filedir)
	try:
        	while True:
			i = files.next()
			for p in i[2]:
				if p == "LIST" or p == 'SHA256SUM':
					continue
				## first determine things like the extension
				res = p.rsplit('_src.tar.gz', 1)
				if len(res) != 2:
					continue
				(packageversion, extension) =  res
				(package, version) = packageversion.rsplit('_', 1)
				## f-droid specific package renames go here
				if package in packagerenames:
					package = packagerenames[package]
				print "%s\t%s\t%s\tf-droid" % (package, version, p)
				
	except Exception, e:
		print >>sys.stderr, e
		sys.stderr.flush()

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.filedir == None:
		print >>sys.stderr, "Specify dir with files"
		sys.exit(1)
	generatelist(options.filedir)

if __name__ == "__main__":
	main(sys.argv)
