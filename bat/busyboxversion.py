#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os
from optparse import OptionParser
import busybox

def busybox_version(path):
	try:
		busybox_binary = open(path, 'rb')
		busybox_lines = busybox_binary.read()
		return busybox.extract_version(busybox_lines)
	except Exception, e:
		return None
	

def main(argv):
	parser = OptionParser()
	parser.add_option("-b", "--binary", dest="bb", help="path to BusyBox binary", metavar="FILE")
	(options, args) = parser.parse_args()
	## suck in the BusyBox binary
	if options.bb == None:
		parser.error("Path to BusyBox binary needed")
	version = busybox_version(options.bb)

	if version != None:
		print version
	else:
		print "No BusyBox found"

if __name__ == "__main__":
        main(sys.argv)
