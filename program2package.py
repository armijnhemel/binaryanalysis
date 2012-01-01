#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This tool maps the name of a program to the name of one or more packages.
'''

import os, sys, re, subprocess
import os.path
import sqlite3
from optparse import OptionParser
import magic


def program2package(name, dbcursor):
	progs = []
	dbcursor.execute('''SELECT packagename from programnames WHERE programname=?''', (name,))
	progs = map(lambda x: x[0], dbcursor.fetchall())
	return progs
						

def main(argv):
	parser = OptionParser()
	parser.add_option("-i", "--index", dest="index", help="path to database", metavar="DIR")
	parser.add_option("-p", "--program", dest="programname", help="program name")
	(options, args) = parser.parse_args()
	if options.index == None:
		## check if this directory actually exists
		parser.error("Path to database needed")
	if options.programname == None:
		parser.error("program name needed")
        conn = sqlite3.connect(options.index)
        c = conn.cursor()


	print program2package(options.programname, c)

        conn.commit()
        c.close()

if __name__ == "__main__":
        main(sys.argv)
