#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This tool maps the name of a program to the name of one or more packages.
'''

import os, sys, re, subprocess
import os.path
import lucene
from optparse import OptionParser
import magic


def name2program(name, dbcursor):
	progs = []
	for lucenesearchstring in ["programname"]:
		searchterm = lucene.Term(lucenesearchstring, name)
		query = lucene.TermQuery(searchterm)

		scoreDocs = searcher.search(query, 50).scoreDocs
		if len(scoreDocs) != 0:
			for scoreDoc in scoreDocs:
				doc = searcher.doc(scoreDoc.doc)
				progs.append(doc.get("packagename"))
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
        conn = sqlite3.connect(options.id)
        c = conn.cursor()


	print name2program(options.programname, c)

        conn.commit()
        c.close()

if __name__ == "__main__":
        main(sys.argv)
