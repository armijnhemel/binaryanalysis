#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Helper script to generate the LIST files for the string extraction scripts. While this script is not foolproof, it will save lots of typing :-)
'''

import sys, os, os.path
import bz2, tarfile, gzip
from optparse import OptionParser

## it's either in the form of:
##   package-version.extension
##   package_version.extension
## where extension is tar.gz, tar.bz2, tar.xz, tgz, zip, tbz2, etc.
def generatelist(filedir):
	files = os.walk(filedir)
	try:
        	while True:
			i = files.next()
			for p in i[2]:
				if p == "LIST":
					continue
				## first determine things like the extension
				res = p.rsplit('.', 1)
				if len(res) == 1:
					print >>sys.stderr, "can't split %s -- add manually" % (p,)
					continue
				(packageversion, extension) = res
				if extension in ["tgz", "tbz2"]:
					pass
				else:
					try:
						(packageversion, extension, compression) = p.rsplit('.', 2)
					except:
						continue
					if not (extension in ["tar"] and compression in ["gz", "bz2"]):
						continue
				## exceptions go here
				if "wireless_tools" in packageversion:
					res = packageversion.rsplit(".", 1)
				## first try package-version
				else:
					res = packageversion.rsplit("-", 1)
					if len(res) == 1:
						## then try package_version
						res = packageversion.rsplit("_", 1)
						if len(res) == 1:
							print >>sys.stderr, "can't split %s -- add manually" % (p,)
							continue
				(package, version) = res
				print "%s\t%s\t%s" % (package, version, p)
				
	except Exception, e:
		pass

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.filedir == None:
		print >>sys.stderr, "Specify dir with files"
		sys.exit(1)
	generatelist(options.filedir)

if __name__ == "__main__":
	main(sys.argv)
