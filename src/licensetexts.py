#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, os.path, sqlite3, magic, subprocess
import tempfile, bz2, tarfile, gzip
from optparse import OptionParser

'''
Use Ninka to extract a license text from source code on a per file basis.
If no license text is found in a source file we let Ninka search for clues in
files like LICENSE, COPYING, and so on.
'''

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
## hand, maybe not. Also, people snoring in the train are annoying.
def ninka(srcdir, sqldb, package, pversion):
	## Ninka needs some tweaks to the environment. Right now it is hardcoded
	## to configuration on my own machine.
	ninkaenv = os.environ
	ninkaenv['PATH'] = ninkaenv['PATH'] + ":/tmp/ninka-1.0-pre2/comments/comments"
        srcdirlen = len(srcdir)+1

	osgen = os.walk(srcdir)

	## for each file run Ninka. Just print the result on stdout.
	## Should we just look at the licenses for C/C++ source and
	## header files?
	try:
		while True:
			i = osgen.next()
			for p in i[2]:
				p1 = subprocess.Popen(["/tmp/ninka-1.0-pre2/ninka.pl", "-d", "%s/%s" % (i[0], p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=ninkaenv)
				(stanout, stanerr) = p1.communicate()
				print u"%s/%s  ----  " % (i[0][srcdirlen:], p), stanout.strip().split(";")[1:]
	except Exception, e:
		print e

## TODO: add nice configuration options so we can remove the hardcoded stuff
def main(argv):
	conn = sqlite3.connect('/tmp/sqlicense')
	c = conn.cursor()

	try:
		c.execute('''create table extracted (license text, package text, version text, filename text)''')
		## create an index to speed up searches
		## probably needs another one so we can look up the package, version and filename
		c.execute('''create index license_index on extracted(license);''')
	except:
		pass

	filedir='/tmp/gpl'
	filelist = open(filedir + "/LIST").readlines()
	for unpackfile in filelist:
		(package, version, filename) = unpackfile.split()
		tmpdir = unpack(filedir, filename)
		ninka(tmpdir, c, package, version)

if __name__ == "__main__":
	main(sys.argv[1:])
