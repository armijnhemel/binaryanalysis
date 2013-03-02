#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
CLI front end for running the scans in bat/bruteforcescan.py

See documentation in that file to see how it works.
'''

import sys, os, os.path, tempfile
from optparse import OptionParser
import ConfigParser
import bat.bruteforcescan
import datetime

def main(argv):
	config = ConfigParser.ConfigParser()
        parser = OptionParser()
	parser.add_option("-b", "--binary", action="store", dest="fw", help="path to binary file", metavar="FILE")
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-o", "--outputfile", action="store", dest="outputfile", help="path to output file", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.fw == None:
        	parser.error("Path to binary file needed")
	if not os.path.exists(options.fw):
        	parser.error("No file to scan found")

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
	scans = bat.bruteforcescan.readconfig(config)
	configfile.close()

	scandate = datetime.datetime.utcnow()

	## create temporary directory for storing results
	tempdir=tempfile.mkdtemp()

	unpackreports = bat.bruteforcescan.runscan(tempdir, scans, options.fw)

	if not scans['batconfig'].has_key('output'):
		## no printing?
		pass
	else:
		output = bat.bruteforcescan.prettyprint(scans['batconfig'], unpackreports, scandate, scans, os.path.basename(options.fw), tempdir)
		print output

	bat.bruteforcescan.writeDumpfile(unpackreports, scans, options.outputfile, os.path.realpath(options.cfg), tempdir, scans['batconfig']['outputlite'])

if __name__ == "__main__":
        main(sys.argv)
