#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

## Stand alone module to determine the version of BusyBox. Has a method for being called
## from bruteforce.py, but can also be invoked separately.

import sys, os
from optparse import OptionParser
import busybox, extractor

def busybox_version(filename, blacklist=[], envvars=None):
	try:
                filesize = os.stat(filename).st_size
		## if the whole file is blacklisted, we don't have to scan
                if extractor.inblacklist(0, blacklist) == filesize:
                        return None
		return busybox.extract_version(filename)
	except Exception, e:
		return None
	

def main(argv):
	parser = OptionParser()
	parser.add_option("-b", "--binary", dest="bb", help="path to BusyBox binary", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.bb == None:
		parser.error("Path to BusyBox binary needed")
	version = busybox_version(options.bb)

	if version != None:
		print version
	else:
		print "No BusyBox found"

if __name__ == "__main__":
        main(sys.argv)
