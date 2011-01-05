#!/usr/bin/python

'''
Program to process a whole directory full of compressed source code archives
to create a knowledgebase. Needs a file LIST in the directory it is passed as
a parameter.

package version filename

seperated by whitespace.

Compression is determined using magic
'''

import sys, os, magic
import tempfile, bz2, tarfile, gzip
from optparse import OptionParser
import extractprogramstrings

tarmagic = ['POSIX tar archive (GNU)'
           , 'tar archive'
           ]

def unpack(dir, filename):
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        filemagic = ms.file(os.path.realpath("%s/%s" % (dir, filename)))

        ## just assume if it is bz2 or gzip that we are looking at tar files with compression

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

def main(argv):
        parser = OptionParser()
        parser.add_option("-d", "--database", action="store", dest="db", help="path to Lucene database)", metavar="DIR")
        parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack)", metavar="DIR")
        parser.add_option("-v", "--verify", action="store_true", dest="verify", help="verify files, don't process (default: false)")
	# implement later
        #parser.add_option("-z", "--cleanup", action="store_true", dest="cleanup", help="cleanup after unpacking? (default: true)")
        (options, args) = parser.parse_args()
	if options.filedir == None:
		print >>sys.stderr, "Specify dir with files"


        ## TODO: do all kinds of checks here
        filelist = open(options.filedir + "/LIST").readlines()
        for unpackfile in filelist:
                (package, version, filename) = unpackfile.strip().split()
                print >>sys.stderr, filename
		if options.verify:
			try:
				os.stat("%s/%s" % (options.filedir, filename))
			except:
				print >>sys.stderr, "Can't find %s" % filename
		else:
                	temporarydir = unpack(options.filedir, filename)
			if temporarydir != None:
				extractprogramstrings.main(["-i", "/tmp/sqlite", "-d", temporarydir, "-p", package, "-v", version])

if __name__ == "__main__":
        main(sys.argv)
