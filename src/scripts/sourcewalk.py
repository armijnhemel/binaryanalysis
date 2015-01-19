#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This program can quickly determine whether or not a file is in known upstream sources. It uses a pregenerated database containing names and checksums of files (for example the Linux kernel) and reports whether or not it can be found in the database.

The purpose of this script is to find files that differ from upstream files and reduce the search space.

This script will *NOT* catch:

* binary files
* patch/diff files
* anything that does not have an extension from the list
* configuration files
'''

import os, os.path, sys, sqlite3, hashlib
from optparse import OptionParser

## list of extensions, plus what language they should be mapped to
## This is not necessarily correct, but for now it is good enough.
extensions = {'.c'      : 'C',
              '.cc'     : 'C',
              '.cpp'    : 'C',
              '.cxx'    : 'C',
              '.c++'    : 'C',
              '.h'      : 'C',
              '.hh'     : 'C',
              '.hpp'    : 'C',
              '.hxx'    : 'C',
              '.l'      : 'C',
              '.qml'    : 'C',
              '.s'      : 'C',
              '.txx'    : 'C',
              '.y'      : 'C',
              '.cs'     : 'C#',
              '.groovy' : 'Java',
              '.java'   : 'Java',
              '.jsp'    : 'Java',
              '.scala'  : 'Java',
              '.as'     : 'ActionScript',
              '.js'     : 'JavaScript',
             }

def sourceWalk(scandir, dbpath):
	conn = sqlite3.connect(dbpath, check_same_thread = False)

	cursor = conn.cursor()
	osgen = os.walk(scandir)
	lenscandir = len(scandir)
	notfound = 0
	total = 0

	try:
		while True:
			i = osgen.next()
			for p in i[2]:
				if os.stat("%s/%s" % (i[0], p)).st_size == 0:
					continue
				p_nocase = p.lower()
				for extension in extensions.keys():
					if (p_nocase.endswith(extension)):
						total = total + 1
						scanfile = open("%s/%s" % (i[0], p), 'r')
						h = hashlib.new('sha256')
						h.update(scanfile.read())
						scanfile.close()
						filehash = h.hexdigest()
						cursor.execute('''select checksum from processed_file where checksum=? limit 1''', (filehash,))
						res = cursor.fetchall()
						## there is at least one hit, so ignore
						if len(res) != 0:
							continue
						## no hits, so this is an interesting file
						else:
							print "%s" % os.path.join(scandir, i[0][lenscandir:],p)
							notfound = notfound + 1
				pass
	except StopIteration:
		pass
	print "Total files: %d" % total
	print "Files not found in database: %d" % notfound

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="db", help="path to database", metavar="FILE")
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to top level directory containing source tree", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.filedir == None:
		parser.error("Specify dir with files")
	if options.db == None:
		parser.error("Specify path to database")

        sourceWalk(options.filedir, options.db)

if __name__ == "__main__":
        main(sys.argv)
