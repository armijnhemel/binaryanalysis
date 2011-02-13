#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, os.path, sqlite3, magic, subprocess
import tempfile, bz2, tarfile, gzip, hashlib
from optparse import OptionParser

'''
Use Ninka to extract a license text from source code on a per file basis.
If no license text is found in a source file we let Ninka search for clues in
files like LICENSE, COPYING, and so on.
'''

def gethash(path, file):
	scanfile = open("%s/%s" % (path, file), 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	return h.hexdigest()

## convenience function to see if the pathname starts with:
## package-version
## package_version
## in either lowercase or uppercase, or mixed case
def packageinpath(package, version, path):
	if path.lower() == "%s-%s" % (package, version):
		return True
	if path.lower() == "%s_%s" % (package, version):
		return True
	return False

## copied from batchextractprogramstrings.py, we should put this in a library
def unpack(dir, filename):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	filemagic = ms.file(os.path.realpath("%s/%s" % (dir, filename)))

	## Just assume if it is bz2 or gzip that we are looking
	## at tar files with compression This is ugly, but it will do for now.

	if 'bzip2 compressed data' in filemagic:
		tar = tarfile.open("%s/%s" % (dir, filename), 'r:bz2')
		tmpdir = tempfile.mkdtemp()
		tar.extractall(path=tmpdir)
		tar.close()
		return tmpdir
	elif 'gzip compressed data' in filemagic:
		tar = tarfile.open("%s/%s" % (dir, filename), 'r:gz')
		tmpdir = tempfile.mkdtemp()
		tar.extractall(path=tmpdir)
		tar.close()
		return tmpdir

## Call Ninka, extract licenses and put them in the database. We might want to
## tweak the data a bit instead of using the raw output from Ninka. On the other
## hand, maybe not.
def ninka(srcdir, sqldb, package, version):
	## Ninka needs some tweaks to the environment. Right now it is hardcoded
	## to configuration on my own machine.
	ninkaenv = os.environ
	#ninkaenv['PATH'] = ninkaenv['PATH'] + ":/tmp/ninka-1.0-pre2/comments/comments"
	ninkaenv['PATH'] = ninkaenv['PATH'] + ":/tmp/dmgerman-ninka-7a9a5c4/comments/comments"
        srcdirlen = len(srcdir)+1
	print srcdir
	ninkares = []
	start = True

	osgen = os.walk(srcdir)

	## for each file run Ninka. Just print the result on stdout.
	## Should we just look at the licenses for C/C++ source and
	## header files?
	try:
		while True:
			i = osgen.next()
			if start:
				## only check if we have one top level directory
				if len(i[1]) == 1:
					if packageinpath(package, version, i[1][0]):
						srcdirlen = srcdirlen + len("%s-%s/" % (package, version))
				start = False
			for p in i[2]:
				p_nocase = p.lower()
				if not (p_nocase.endswith('.c') or p_nocase.endswith('.h') or p_nocase.endswith('.cpp') or p_nocase.endswith('.cc') or p_nocase.endswith('.hh')):
					continue
				p1 = subprocess.Popen(["/tmp/dmgerman-ninka-7a9a5c4/ninka.pl", "-d", "%s/%s" % (i[0], p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=ninkaenv)
				(stanout, stanerr) = p1.communicate()
				ninkares.append((i[0][srcdirlen:], p, stanout.strip().split(";")[1:], gethash(i[0], p), package, version))
	except Exception, e:
		print e
	return ninkares

## TODO: add nice configuration options so we can remove the hardcoded stuff
def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="db", help="path to database)", metavar="FILE")
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to dir with GPL tarballs)", metavar="DIR")

	(options, args) = parser.parse_args()
	if options.db == None:
		print >>sys.stderr, "Specify database"
		sys.exit(1)
	if options.filedir == None:
		print >>sys.stderr, "Specify dir with files"
		sys.exit(1)
	conn = sqlite3.connect(options.db)
	c = conn.cursor()

	try:
		c.execute('''create table files (filename text, sha256 text, package text, version text)''')
		c.execute('''create table licenses (sha256 text, license text)''')
		## create an index to speed up searches
		## probably needs another one so we can look up the package, version and filename
		c.execute('''create index filehash_index on extracted(sha256);''')
		c.execute('''create index license_index on licenses(sha256);''')
	except:
		pass

	filelist = open(options.filedir + "/LIST").readlines()
	for unpackfile in filelist:
		(package, version, filename) = unpackfile.split()
		tmpdir = unpack(options.filedir, filename)
		ninkares = ninka(tmpdir, c, package, version)
		print ninkares
		sys.exit(1)

if __name__ == "__main__":
	main(sys.argv)
