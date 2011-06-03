#!/usr/bin/python

import sys, os
import re
import ftplib
import ConfigParser
from optparse import OptionParser

## Binary Analysis Tool
## Copyright 2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script crawls a mirror of the GNU FTP site, so it can be used to download
the latest GNU packages to build/update a database.
'''

## get a blacklist of extensions or patterns we're not interested in
blacklistfiles = []

## prune dirs we're not interested in (audio, video)
blacklistdirs = []

## first try to get bz2, then gz, xz last

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.cfg != None:
		try:
			configfile = open(options.cfg, 'r')
		except:
			print "Need configuration file"
			sys.exit(1)
	else:
		print "Need configuration file"
		sys.exit(1)

	config.readfp(configfile)

if __name__ == "__main__":
	main(sys.argv)
