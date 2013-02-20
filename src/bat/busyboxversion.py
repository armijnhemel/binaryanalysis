#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

## Stand alone module to determine the version of BusyBox. Has a method for being called
## from one of the default scans, but can also be invoked separately.

import sys, os, tempfile
from optparse import OptionParser
import busybox, extractor

def busybox_version(filename, blacklist=[], envvars=None):
	try:
                filesize = os.stat(filename).st_size
		## if the whole file is blacklisted, we don't have to scan
		if blacklist != []:
                	if extractor.inblacklist(0, blacklist) == filesize:
				return None
			datafile = open(filename, 'rb')
			lastindex = 0
			databytes = ""
			datafile.seek(lastindex)
			for i in blacklist:
				if i[0] == lastindex:
					lastindex = i[1] - 1
					datafile.seek(lastindex)
					continue
				if i[0] > lastindex:
					## just concatenate the bytes
					data = datafile.read(i[0] - lastindex)
					databytes = databytes + data
					## set lastindex to the next
					lastindex = i[1] - 1
					datafile.seek(lastindex)
			datafile.close()
			if len(databytes) == 0:
				return None
			tmpfile = tempfile.mkstemp()
			os.write(tmpfile[0], databytes)
			os.fdopen(tmpfile[0]).close()
			scanfile = tmpfile[1]
			bbres = busybox.extract_version(scanfile)
			os.unlink(tmpfile[1])
		else:
			bbres = busybox.extract_version(filename)
		if bbres != None:
			return (['busybox'], bbres)
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
