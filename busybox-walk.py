#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This program can be used to walk a directory tree and report the names
of the applets that symlink to BusyBox. While not accurate (symlinks could
have been removed) it might come in handy as an extra tool.
'''

import os, sys
from optparse import OptionParser

def busyboxWalk(busyboxdir):
	busybox_applets = []

	osgen = os.walk(busyboxdir)

	try:
		while True:
			i = osgen.next()
			for p in i[2]:
				if os.path.basename(os.path.realpath(os.path.join(i[0], p))) == 'busybox':
					busybox_applets.append(p)
	except StopIteration:
		pass

	busybox_applets.sort()
	return busybox_applets

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--directory", dest="bd", help="directory", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.bd == None:
		parser.error("Path to top level directory of unpacked firmware needed")
	applets = busyboxWalk(options.bd)
	if applets != []:
		print "The following applets were found as symlinks:"
		for a in applets:
			if a != 'busybox':
				print "* %s" % a

if __name__ == "__main__":
        main(sys.argv)
