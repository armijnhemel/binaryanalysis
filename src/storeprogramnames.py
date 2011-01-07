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
import lucene

def namecleanup(names):
	return map(lambda x: os.path.basename(x), names)

## (packagename, [programnames])
def storematch(packagename, programnames, lucenewriter):
	doc = lucene.Document()
	doc.add(lucene.Field("packagename", packagename,
		lucene.Field.Store.YES,
		lucene.Field.Index.NOT_ANALYZED))
	#lucenewriter.addDocument(doc)
	for prog in programnames:
		doc.add(lucene.Field("programname", prog.strip(),
			lucene.Field.Store.YES,
			lucene.Field.Index.NOT_ANALYZED))
	lucenewriter.addDocument(doc)

def main(argv):
        parser = OptionParser()
        parser.add_option("-i", "--index", dest="id", help="path to Lucene index directory", metavar="DIR")
        parser.add_option("-p", "--package", dest="package", help="name of the package", metavar="PACKAGE")
        parser.add_option("-l", "--programlist", dest="programlist", help="file with program names", metavar="FILE")
        (options, args) = parser.parse_args()
        if options.id == None:
                parser.error("Path to Lucene index directory needed")
        if options.package == None:
                parser.error("Package name needed")
        if options.programlist == None:
                parser.error("Programlist needed")

	programnames = namecleanup(open(options.programlist).readlines())
	lucene.initVM()

	storeDir = options.id
        store = lucene.SimpleFSDirectory(lucene.File(storeDir))
	analyzer = lucene.StandardAnalyzer(lucene.Version.LUCENE_CURRENT)
        writer = lucene.IndexWriter(store, analyzer, True,
                                    lucene.IndexWriter.MaxFieldLength.LIMITED)
        writer.setMaxFieldLength(1048576)

	storematch(options.package, programnames, writer)

        writer.optimize()
        writer.close()


if __name__ == "__main__":
        main(sys.argv)
