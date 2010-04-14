#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os
from optparse import OptionParser
import busybox

parser = OptionParser()
parser.add_option("-b", "--binary", dest="bb", help="path to BusyBox binary", metavar="FILE")
(options, args) = parser.parse_args()
## suck in the BusyBox binary
if options.bb == None:
	parser.error("Path to BusyBox binary needed")
try:
	busybox_binary = open(options.bb, 'rb')
except:
	print "No valid BusyBox file"
	sys.exit(1)
busybox_lines = busybox_binary.read()
## determine the BusyBox binary
version = busybox.extract_version(busybox_lines)

if version != None:
	print version
else:
	print "No BusyBox found"
