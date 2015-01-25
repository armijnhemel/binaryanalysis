#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011-2015 Armijn Hemel for Tjaldur Software Governance Solutions
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
def generatelist(filedir, origin):
	files = os.walk(filedir)
	downloadurls = {}
	if os.path.exists(os.path.join(filedir, "DOWNLOADURL")):
		urls = map(lambda x: x.strip(), open(os.path.join(filedir, "DOWNLOADURL")).readlines())
		for ur in urls:
			filename = ur.rsplit('/', 1)[-1]
			downloadurls[filename] = ur
	try:
        	while True:
			i = files.next()
			for p in i[2]:
				if p == "LIST":
					continue
				if p == "SHA256SUM":
					continue
				if p == "DOWNLOADURL":
					continue
				## first determine things like the extension
				res = p.rsplit('.', 1)
				if len(res) == 1:
					print >>sys.stderr, "can't split %s -- add manually" % (p,)
					continue
				(packageversion, extension) = res
				if extension in ["tgz", "tbz2"]:
					pass
				elif extension in ["jar", "zip"]:
					pass
				else:
					try:
						(packageversion, extension, compression) = p.rsplit('.', 2)
					except:
						continue
					if not (extension in ["tar"] and compression in ["gz", "bz2", "xz", "lz", "lzma", "Z"]):
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
				downloadurl = ""
				(package, version) = res
				if p in downloadurls:
					downloadurl = downloadurls[p]
				print "%s\t%s\t%s\t%s\t%s" % (package, version, p, origin, downloadurl)
				
	except Exception, e:
		pass

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-o", "--origin", action="store", dest="origin", help="origin of packages (default: unknown)", metavar="ORIGIN")
	(options, args) = parser.parse_args()
	if options.filedir == None:
		parser.error("Specify dir with files")
	if options.origin == None:
		origin = "unknown"
	else:
		origin = options.origin
	generatelist(options.filedir, origin)

if __name__ == "__main__":
	main(sys.argv)
