#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Helper script to generate the LIST files for the string extraction scripts. While this script is not foolproof, it will save lots of typing :-)

This variant is specifically for processing a directory full of SRPM files.

1. files are converted to CPIO archives using rpm2cpio
2. files are unpacked using cpio
3. archives (ZIP, tar.gz, tar.bz, tgz, etc.) are moved to a temporary directory. Any patches are put in a special patch
directory.
4. LIST file for temporary directory is created
'''

import sys, os, os.path, subprocess, tempfile
from optparse import OptionParser
from multiprocessing import Pool

## it's either in the form of:
##   package-version.extension
##   package_version.extension
## where extension is tar.gz, tar.bz2, tar.xz, tgz, zip, tbz2, etc.
def generatelist(filedir, origin):
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
				elif extension in ["jar", "zip"]:
					pass
				else:
					try:
						(packageversion, extension, compression) = p.rsplit('.', 2)
					except:
						continue
					if not (extension in ["tar"] and compression in ["gz", "bz2", "xz"]):
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
				print "%s\t%s\t%s\t%s" % (package, version, p, origin)
				
	except Exception, e:
		pass

def unpacksrpm(filedir):
	extensions = [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2"]
	tmpdir = tempfile.mkdtemp()
	files = os.walk(filedir)
	try:
        	while True:
			i = files.next()
			for p in i[2]:
				## first filter out files that are likely no source rpm, just by
				## looking at the extension.
				res = p.rsplit('.', 2)
				if res[-1] != 'srpm' and (res[-1] != 'rpm' and res[-2] != 'src'):
					continue
				else:
					p2 = subprocess.Popen(['rpm', '-qpl', "%s/%s" % (i[0], p)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
					(stanout, stanerr) = p2.communicate()
					files = stanout.strip().rsplit("\n")
					for f in files:
						fsplit = f.lower().rsplit('.', 1)
						if len(fsplit) == 1:
							continue
						(packageversion, extension) = fsplit
						if extension in ["tgz", "tbz2"]:
							pass
						elif extension in ["jar", "zip"]:
							pass
						else:
							try:
								(packageversion, extension, compression) = f.lower().rsplit('.', 2)
							except:
								continue
							if not (extension in ["tar"] and compression in ["gz", "bz2", "xz"]):
								continue
							else:
								print f
					## make a temporary directory
					## unpack
					## copy tarball to tmpdir
	except Exception, e:
		pass
	return tmpdir

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-o", "--origin", action="store", dest="origin", help="origin of packages (default: unknown)", metavar="ORIGIN")
	(options, args) = parser.parse_args()
	if options.filedir == None:
		print >>sys.stderr, "Specify dir with files"
		sys.exit(1)
	if options.origin == None:
		origin = "unknown"
	else:
		origin = options.origin
	srpmdir = unpacksrpm(options.filedir)
	generatelist(srpmdir, origin)

if __name__ == "__main__":
	main(sys.argv)
