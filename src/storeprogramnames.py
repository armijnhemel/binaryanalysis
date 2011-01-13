#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script stores the mapping between a package and program names into a
knowledgebase. Many vendors do not change the default names of programs in
packages, so a certain name might be a good indication.
'''

import sys, os, string, re
import os.path
from optparse import OptionParser
import sqlite3

def namecleanup(names):
	return map(lambda x: os.path.basename(x), names)

## (packagename, [programnames])
def storematch(packagename, programnames, dbcursor):
	for programname in programnames:
		dbcursor.execute('''INSERT INTO programnames values (?, ?)''', (packagename, programname.strip()))

def main(argv):
        parser = OptionParser()
        parser.add_option("-i", "--index", dest="id", help="path to database", metavar="DIR")
        parser.add_option("-p", "--package", dest="package", help="name of the package", metavar="PACKAGE")
        parser.add_option("-l", "--programlist", dest="programlist", help="file with program names", metavar="FILE")
        (options, args) = parser.parse_args()
        if options.id == None:
                parser.error("Path to database needed")
        if options.package == None:
                parser.error("Package name needed")
        if options.programlist == None:
                parser.error("Programlist needed")

	programnames = namecleanup(open(options.programlist).readlines())

        conn = sqlite3.connect(options.id)
        c = conn.cursor()

        try:
                c.execute('''create table programnames (packagename text, programname text)''')
        except:
                pass

	storematch(options.package, programnames, c)

        conn.commit()
        c.close()

if __name__ == "__main__":
        main(sys.argv)
