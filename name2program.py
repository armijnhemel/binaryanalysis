#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This tool maps the name of a program to the name of one or more packages, and optionally to
the names sections in the bruteforce configuration.
'''

import os, sys, re, subprocess
import os.path
import lucene
from optparse import OptionParser
import magic


def name2program(name, searcher):
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
	parser.add_option("-i", "--index", dest="index", help="path to Lucene index directory", metavar="DIR")
	parser.add_option("-p", "--program", dest="programname", help="program name")
	(options, args) = parser.parse_args()
	if options.index == None:
		## check if this directory actually exists
		parser.error("Path to Lucene index directory needed")
	if options.programname == None:
		parser.error("program name needed")

	STORE_DIR = options.index

	lucene.initVM()

	directory = lucene.SimpleFSDirectory(lucene.File(STORE_DIR))
	searcher = lucene.IndexSearcher(directory, True)
	analyzer = lucene.StandardAnalyzer(lucene.Version.LUCENE_CURRENT)

	print name2program(options.programname, searcher)
	searcher.close()

if __name__ == "__main__":
        main(sys.argv)
