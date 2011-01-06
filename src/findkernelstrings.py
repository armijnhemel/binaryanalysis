#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import os, sys, re, subprocess
import os.path
import lucene
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-a", "--architecture", dest="arch", help="hardware architecture (optional)")
parser.add_option("-f", "--found", dest="found", action="store_true", help="print symbols that can be found (default)")
parser.add_option("-c", "--configindex", dest="configindex", help="path to database with configs", metavar="DIR")
parser.add_option("-i", "--index", dest="index", help="path to database with kernel strings", metavar="DIR")
parser.add_option("-k", "--kernel", dest="kernel", help="path to Linux kernel image", metavar="FILE")
parser.add_option("-m", "--missing", dest="missing", action="store_true", help="print symbols that can't be found", metavar=None)
parser.add_option("-s", "--size", dest="stringsize", help="stringsize (default 6)")
(options, args) = parser.parse_args()
if options.index == None:
	## check if this directory actually exists
	parser.error("Path to directory with kernel strings needed")
if options.kernel == None:
	parser.error("Path to Linux kernel image needed")
if options.missing == None and options.found == None:
	options.found = True
if options.stringsize == None:
	stringsize = 6
else:
	stringsize = int(options.stringsize)

STORE_DIR = options.index
try:
	p = subprocess.Popen(['/usr/bin/strings', options.kernel], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (stanuit, stanerr) = p.communicate()
except:
	sys.exit(1)

kernelstrings = stanuit.split("\n")

lucene.initVM()

directory = lucene.SimpleFSDirectory(lucene.File(STORE_DIR))
searcher = lucene.IndexSearcher(directory, True)
analyzer = lucene.StandardAnalyzer(lucene.Version.LUCENE_CURRENT)

if options.configindex != None:
	configdirectory = lucene.SimpleFSDirectory(lucene.File(options.configindex))
	configsearcher = lucene.IndexSearcher(configdirectory, True)
	configanalyzer = lucene.StandardAnalyzer(lucene.Version.LUCENE_CURRENT)

seenlinux = False
seenstrings = []
#seenaaaaaa = False
for kernelstring in kernelstrings:
	kstring = kernelstring.strip()
	if "inux" in kstring:
		seenlinux = True
	#if kstring == "AAAAAA":
	#	seenaaaaaa = True
	if len(kstring) >= stringsize and seenlinux:
		if re.match("(\<\d\>)", kstring) != None:
			searchstring = kstring[3:]
		else:
			searchstring = kstring
		if searchstring in seenstrings:
			continue
		found = False
		for lucenesearchstring in ["printstring", "symbolstring", "functionname"]:
			searchterm = lucene.Term(lucenesearchstring, searchstring.strip())
			query = lucene.TermQuery(searchterm)

			scoreDocs = searcher.search(query, 50).scoreDocs
			if len(scoreDocs) != 0:
				#print "%s total matching documents with %s" % (len(scoreDocs), searchstring)
				if options.found:
					print 'found string "%s"' % (searchstring,)
				docs = {}
				for scoreDoc in scoreDocs:
					doc = searcher.doc(scoreDoc.doc)
					docs[doc.get("name")] = 1
				for d in docs.keys():
					if options.found:
						if options.arch != None:
							if "arch/" in d and options.arch not in d:
								continue
							if "asm-" in d and options.arch not in d:
								continue
						if options.configindex != None:
							configsearchterm = lucene.Term("name", d)
							#configsearchterm = lucene.Term("name", os.path.dirname(d) + "/")
							configquery = lucene.TermQuery(configsearchterm)

							configscoreDocs = configsearcher.search(configquery, 50).scoreDocs
							if len(configscoreDocs) == 0:
									print '    This string is defined in path:', d
							for configscoreDoc in configscoreDocs:
								config = configsearcher.doc(configscoreDoc.doc).get("configstring")
								if config != None:
									print '    This string is defined in path: %s (config %s)' % (d, config)
						else:
									print '    This string is defined in path:', d
							
				found = True
		#if not found and options.missing and not seenaaaaaa:
		if not found and options.missing:
			print 'did not find string "%s"' % (searchstring,)
		seenstrings.append(searchstring)

searcher.close()
sys.exit()
