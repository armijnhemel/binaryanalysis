#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, string, re
from optparse import OptionParser
import lucene

## helper method for processing stuff
## output is a tuple (file/dirname, config) for later processing
def matchconfig(filename, dirname, config, kerneldirlen):
	if filename.endswith(".o"):
		try:
			os.stat("%s/%s" % (dirname, filename[:-2] + ".c"))
			return ("%s/%s" % (dirname[kerneldirlen:], filename[:-2] + ".c"), config)
		except:
			return None
	else:
		if "arch" in filename:
			if dirname.split("/")[-2:] == filename.split("/")[:2]:
				try:
					newpath = dirname.split("/") + filename.split("/")[2:]
					os.stat(reduce(lambda x, y: x + "/" + y, newpath))
					return ("%s/%s" % (dirname[kerneldirlen:], filename), config)
				except:
					return None
			else:
				return None
		else:
			try:
				os.stat("%s/%s" % (dirname, filename))
				return ("%s/%s" % (dirname[kerneldirlen:], filename), config)
			except:
				return None

def extractkernelstrings(kerneldir):
	kerneldirlen = len(kerneldir)+1
	osgen = os.walk(kerneldir)
	searchresults = []

	try:
		while True:
                	i = osgen.next()
			## some top level dirs are not interesting
			if 'Documentation' in i[1] and i[0][kerneldirlen:] == "":
				i[1].remove('Documentation')
			if "scripts" in i[1] and i[0][kerneldirlen:] == "":
				i[1].remove('scripts')
			if "usr" in i[1] and i[0][kerneldirlen:] == "":
				i[1].remove('usr')
			if "samples" in i[1] and i[0][kerneldirlen:] == "":
				i[1].remove('samples')
                	for p in i[2]:
				## we only want Makefiles
				if p != 'Makefile':
					continue
				## not interested in the top level Makefile
				if i[0][kerneldirlen:] == "":
					continue
				source = open("%s/%s" % (i[0], p)).readlines()

				continued = False
				inif = False
				iniflevel = 0
				currentconfig = ""
				for line in source:
					if line.strip().startswith('#'):
						continue
					if line.strip().startswith('echo'):
						continue
					if line.strip().startswith('@'):
						continue
					if line.strip() == "":
						continue
					# if statements can be nested, so keep track of levels
					if line.strip() == "endif":
						inif = False
						iniflevel = iniflevel -1
						continue
					# if statements can be nested, so keep track of levels
					if re.match("ifn?\w+", line.strip()):
						inif = True
						iniflevel = iniflevel +1
					if not continued and line.strip().endswith("\\") and "=" in line.strip():
						## weed out more stuff
						## we are interested in three cases:
						## +=
						## :=
						## =  but only if there are object files or dirs defined in the right hand part
						continued = True
						currentconfig = ""
					elif continued and currentconfig != "":
						if line.strip().endswith("\\"):
							continued = True
							files = line.strip()[:-1].split()
						else:
							continued = False
							files = line.strip().split()
						for f in files:
							match = matchconfig(f, i[0], currentconfig, kerneldirlen)
							if match != None:
								searchresults.append(match)
					else:
						continued = False
						currentconfig = ""

					res = re.match("([\w\.]+)\-\$\(CONFIG_(\w+)\)\s*[:+]=\s*([\w\-\.\s/]*)", line.strip())
					if res != None:
						## current issues: ARCH (SH, Xtensa, h8300) is giving some issues
						if "flags" in res.groups()[0]:
							continue
						if "FLAGS" in res.groups()[0]:
							continue
						if "zimage" in res.groups()[0]:
							continue
						if res.groups()[0] == "defaultimage":
							continue
						if res.groups()[0] == "cacheflag":
							continue
						if res.groups()[0] == "cpuincdir":
							continue
						if res.groups()[0] == "cpuclass":
							continue
						if res.groups()[0] == "cpu":
							continue
						if res.groups()[0] == "machine":
							continue
						if res.groups()[0] == "model":
							continue
						if res.groups()[0] == "load":
							continue
						if res.groups()[0] == "dataoffset":
							continue
						if res.groups()[0] == "CPP_MODE":
							continue
						if res.groups()[0] == "LINK":
							continue
						config = "CONFIG_" + res.groups()[1]
						files = res.groups()[2].split()
						currentconfig = config
						for f in files:
							match = matchconfig(f, i[0], currentconfig, kerneldirlen)
							if match != None:
								searchresults.append(match)
				continue
	except StopIteration:
		return searchresults

def storematch(results, lucenewriter):
	## store two things:
	## 1. if we have a path/subdir, we store subdir + configuration
	##    making it searchable by subdir
	## 2. if we have an objectfile, we store name of source(!) file+ configuration
	##    making it searchable by source file
	## these can and will overlap
	for res in results:
		pathstring = res[0]
		configstring = res[1]
		doc = lucene.Document()
		doc.add(lucene.Field("name", pathstring,
			lucene.Field.Store.YES,
			lucene.Field.Index.NOT_ANALYZED))
		doc.add(lucene.Field("configstring", configstring,
			lucene.Field.Store.YES,
			lucene.Field.Index.NOT_ANALYZED))
		lucenewriter.addDocument(doc)

def main(argv):
        parser = OptionParser()
        parser.add_option("-d", "--directory", dest="kd", help="path to Linux kernel directory", metavar="DIR")
        parser.add_option("-i", "--index", dest="id", help="path to Lucene index directory", metavar="DIR")
        (options, args) = parser.parse_args()
        if options.kd == None:
                parser.error("Path to Linux kernel directory needed")
        if options.id == None:
                parser.error("Path to Lucene index directory needed")
        #try:
        	## open the Linux kernel directory and do some sanity checks
                #kernel_path = open(options.kd, 'rb')
        #except:
                #print "No valid Linux kernel directory"
                #sys.exit(1)
	# strip trailing slash, will not work this way if there are tons of slashes
	if options.kd.endswith('/'):
		kerneldir = options.kd[:-1]
	else:
		kerneldir = options.kd
	lucene.initVM()

	storeDir = options.id
        store = lucene.SimpleFSDirectory(lucene.File(storeDir))
	analyzer = lucene.StandardAnalyzer(lucene.Version.LUCENE_CURRENT)
        writer = lucene.IndexWriter(store, analyzer, True,
                                    lucene.IndexWriter.MaxFieldLength.LIMITED)
        writer.setMaxFieldLength(1048576)

	results = extractkernelstrings(kerneldir)
	storematch(results, writer)

        writer.optimize()
        writer.close()


if __name__ == "__main__":
        main(sys.argv)
