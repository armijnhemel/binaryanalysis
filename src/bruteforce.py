#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
CLI front end for running the scans in bat/bruteforce.py

See documentation in that file to see how it works.
'''

import sys, os, os.path, tempfile
from optparse import OptionParser
import ConfigParser
import bat.bruteforce
import datetime

def main(argv):
	config = ConfigParser.ConfigParser()
        parser = OptionParser()
	parser.add_option("-b", "--binary", action="store", dest="fw", help="path to binary file", metavar="FILE")
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-o", "--outputfile", action="store", dest="outputfile", help="path to output file", metavar="FILE")
	parser.add_option("-z", "--cleanup", action="store_true", dest="cleanup", help="cleanup after analysis? (default: false)")
	(options, args) = parser.parse_args()
	if options.fw == None:
        	parser.error("Path to binary file needed")
	try:
        	scan_binary = options.fw
	except:
        	print "No file to scan found"
        	sys.exit(1)

	if options.cfg != None:
		try:
        		configfile = open(options.cfg, 'r')
		except:
			print >>sys.stderr, "Need configuration file"
			sys.exit(1)
	else:
		print >>sys.stderr, "Need configuration file"
		sys.exit(1)

	if options.outputfile == None:
        	parser.error("Path to output file needed")
		sys.exit(1)
	try:
		os.stat(options.outputfile)
		print >>sys.stderr, "output file already exists"
		sys.exit(1)
	except Exception, e:
		pass

	config.readfp(configfile)
	scans = bat.bruteforce.readconfig(config)

	scandate = datetime.datetime.utcnow()

	## create temporary directory to store results in
	tempdir=tempfile.mkdtemp()

	(unpackreports, leafreports) = bat.bruteforce.runscan(tempdir, scans, scan_binary)

	res = bat.bruteforce.flatten("%s" % (os.path.basename(scan_binary)), unpackreports, leafreports)
	if not scans['batconfig'].has_key('output'):
		## no printing?
		pass
	else:
		output = bat.bruteforce.prettyprint(scans['batconfig'], res, scandate, scans)
		print output

	bat.bruteforce.writeDumpfile(unpackreports, leafreports, scans, options.outputfile, tempdir, scans['batconfig']['outputlite'])

if __name__ == "__main__":
        main(sys.argv)
