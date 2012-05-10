#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to analyse binary blobs, using a "brute force" approach
and pretty print the analysis in a simple XML format.

The script has a few separate scanning phases:

1. marker scanning phase, to search for specific markers (compression, file systems,
media formats), if available. This information is later used to filter scans and to
carve files.

2. prerun phase for tagging files. This is a first big rough sweep for low hanging fruit,
so we only have to spend little or no time on useless scanning in the following phases.
Some things that are tagged here are text files, XML files, various graphics formats and
some other files.

3. unpack phase for unpacking files. In this phase several methods for unpacking files are
run, using the information from the marker scanning phase (if a file system file or
compressed file actually uses markers, which is not always the case). Also some simple
metadata about files is recorded in this phase. This method runs recursively: if a file
system was found and unpacked all the scans from steps 1, 2, 3 are run on the files that
were unpacked.

4. individual file scanning phase. Here each file will be inspected individually. Based on
the configuration that was given this could be basically anything.

5. output phase. Using a pretty printer a report is pretty printed.

6. postrun phase. In this phase methods that are not necessary for generating output, but
which should be run anyway, are run. Examples are generating pictures or running statistics.

7. packing phase. In this phase several datafiles, plus the state of the running program,
are packed in a tar file.
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

	bat.bruteforce.writeDumpfile(unpackreports, leafreports, scans, options.outputfile, tempdir)

if __name__ == "__main__":
        main(sys.argv)
