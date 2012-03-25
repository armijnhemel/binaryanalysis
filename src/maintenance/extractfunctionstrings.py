#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, string, re
from optparse import OptionParser
import sqlite3

## extract function names and store them in a database
## TODO: add database
funexprs = []
funexprs.append(re.compile("(?:static|extern|unsigned|const|void|int)\s+(?:\w+\s+)*\*?\s*(\w+)\s*\(", re.MULTILINE))

## list of extensions, plus what language they should be mapped to
## This is not necessarily correct, but right now it is the best we have.
extensions = {'.c'      : 'C',
	'.h'      : 'C',
	'.cc'     : 'C',
	'.hh'     : 'C',
	'.c++'    : 'C',
	'.cpp'    : 'C',
	'.hpp'    : 'C',
	'.cxx'    : 'C',
	'.hxx'    : 'C',
	'.S'      : 'C',
	'.qml'    : 'C',
             }

def extractfunctionnames(srcdir):
	srcdirlen = len(srcdir)+1
	osgen = os.walk(srcdir)

	try:
		while True:
                	i = osgen.next()
			## everything inside the Documentation directory can be skipped for now
			if "/Documentation" in i[0]:
				continue
                	for p in i[2]:
				p_nocase = p.lower()
				## right now we are just interested in C/C++/assembler files
				for extension in extensions.keys():
                                	if (p_nocase.endswith(extension)):
						source = open("%s/%s" % (i[0], p)).read()
		
						results = []
						for funex in funexprs:
							results = results + funex.findall(source)
						print results, i[0] + '/' + p
	
	except StopIteration:
		pass

def main(argv):
        parser = OptionParser()
        parser.add_option("-s", "--sourcedir", dest="kd", help="path to source codedirectory", metavar="DIR")
        (options, args) = parser.parse_args()
        if options.kd == None:
                parser.error("Path to source code directory needed")

	# strip trailing slash, will not work this way if there are tons of slashes
	if options.kd.endswith('/'):
		srcdir = options.kd[:-1]
	else:
		srcdir = options.kd

	extractfunctionnames(srcdir)


if __name__ == "__main__":
        main(sys.argv)
