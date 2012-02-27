#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This tool stores a list of program names that can be typically found in a
package. Since very often the names of the programs are not changed when
installing a package these names can provide an indication which package
is used in a firmware.

We should also look into things like configuration files, help files, init
scripts, etc.
'''

import sys, os, string, re
import os.path
from optparse import OptionParser
import sqlite3

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

	programnames = map(lampda(x: os.path.basename(x), (open(options.programlist).readlines()))

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
