#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This program can be used to generate a LIST file, like generatelist.py, but
taking two LIST files as input. The first ('correctedlist') is LIST that has
corrected input. The second one is a possibly non-corrected list.

The main use case is when the database has to be regenerated (new license
scanners, better string extraction, and so on), with possibly new input.
Using dumplist.py the (supposedly) corrected list (for old packages) can be
extracted from the database. With generatelist.py a new list can be generated
for the packages. By comparing the two and reusing the corrected results a lot
of effort can be saved.
'''

import os, os.path, sys, sqlite3
from optparse import OptionParser

def main(argv):
	parser = OptionParser()
	parser.add_option("-c", "--correctedlist", action="store", dest="correctedlist", help="path to corrected list", metavar="FILE")
	parser.add_option("-n", "--newlist", action="store", dest="newlist", help="path to new list", metavar="FILE")
	(options, args) = parser.parse_args()

	if options.correctedlist == None:
		parser.error("Need corrected list")
	if options.newlist == None:
		parser.error("Need new list")

	if not os.path.exists(options.correctedlist):
		parser.error("Need corrected list")
	if not os.path.exists(options.newlist):
		parser.error("Need new list")

	## first suck in the corrected data, filename is key
	correctedfiles = {}
	correctedfile_list = open(options.correctedlist).readlines()
	for c in correctedfile_list:
		(package, version, filename, origin) = c.strip().split()
		## this should actually not happen
		if correctedfiles.has_key(filename):
			continue
		else:
			correctedfiles[filename] = (package, version, origin)

	## then suck in the new data, filename is key
	newfiles = {}
	newfile_list = open(options.newlist).readlines()
	for c in newfile_list:
		(package, version, filename, origin) = c.strip().split()
		## this should actually not happen
		if newfiles.has_key(filename):
			continue
		else:
			newfiles[filename] = (package, version, origin)
	listentries = []
	for i in newfiles.keys():
		if correctedfiles.has_key(i):
			## entries are not the same!
			if newfiles[i] != correctedfiles[i]:
				listentries.append("%s\t%s\t%s\t%s" % (correctedfiles[i][0], correctedfiles[i][1], i, correctedfiles[i][2]))
			else:
				listentries.append("%s\t%s\t%s\t%s" % (newfiles[i][0], newfiles[i][1], i, newfiles[i][2]))
		else:
			listentries.append("%s\t%s\t%s\t%s" % (newfiles[i][0], newfiles[i][1], i, newfiles[i][2]))
	listentries.sort()
	for i in listentries:
		print i
if __name__ == "__main__":
	main(sys.argv)
