import sys, os, string, re
from optparse import OptionParser
import lucene

def extractsourcestrings(srcdir, writer, package, pversion):
        srcdirlen = len(srcdir)+1
        osgen = os.walk(srcdir)

        try:
                while True:
                        i = osgen.next()
                        for p in i[2]:
				## we're only interested in a few files, perhaps add more
				if p.endswith('.c') or p.endswith('.h'):
					source = open("%s/%s" % (i[0], p)).read()
					results = re.findall("\"(.*?)(?<!\\\)\"", source, re.MULTILINE|re.DOTALL)
					for res in results:
                                        	## some strings are simply not interesting
                                        	if res.strip() == "\\n":
                                        		continue
                                        	if res.strip() == "\\n\\n":
                                                	continue
                                        	elif res.strip() == "\\t":
                                                	continue
                                        	elif res.strip() == "%s%s":
                                                	continue
                                        	elif res.strip() == "%s:":
                                                	continue
                                        	elif res.strip() == "%s":
                                                	continue
                                        	elif res.strip() == "%d":
                                                	continue
                                        	elif res.strip() == ":":
                                                	continue
                                        	elif res.strip() == ",":
                                                	continue
                                        	elif res.strip() == "(":
                                                	continue
                                        	elif res.strip() == ")":
                                                	continue
                                        	elif res.strip() == "()":
                                                	continue
                                        	elif res.strip() == "|":
                                                	continue
                                        	elif res.strip() == "":
                                                	continue
						if res.strip().endswith("\\n"):
                                                	storestring = res.strip()[:-2]
                                        	else:
                                                	storestring = res.strip()
                                        	if storestring.startswith("\\n"):
                                                	storestring = storestring[2:].strip()
                                        	# replace tabs
                                        	storestring = storestring.replace("\\t", "\t").strip()
                                        	#storestring = storestring.replace("\\n", "\n")
                                        	doc = lucene.Document()
                                        	doc.add(lucene.Field("filename", "%s/%s" % (i[0][srcdirlen:], p),
                                               		lucene.Field.Store.YES,
                                                	lucene.Field.Index.NOT_ANALYZED))
                                        	doc.add(lucene.Field("printstring", storestring,
                                                	lucene.Field.Store.YES,
                                                	lucene.Field.Index.NOT_ANALYZED))
                                        	doc.add(lucene.Field("package", package,
                                                	lucene.Field.Store.YES,
                                                	lucene.Field.Index.NOT_ANALYZED))
                                        	doc.add(lucene.Field("version", pversion,
                                                	lucene.Field.Store.YES,
                                                	lucene.Field.Index.NOT_ANALYZED))
                                        	writer.addDocument(doc)


	except Exception, e:
		print e


def main(argv):
        parser = OptionParser()
        parser.add_option("-d", "--directory", dest="kd", help="path to sources directory", metavar="DIR")
	parser.add_option("-i", "--index", dest="id", help="path to Lucene index directory", metavar="DIR")
	parser.add_option("-p", "--package", dest="package", help="package name", metavar="PACKAGE")
	parser.add_option("-v", "--version", dest="pversion", help="package version", metavar="PACKAGEVERSION")
        (options, args) = parser.parse_args()
        if options.kd == None:
                parser.error("Path to sources directory needed")
        if options.id == None:
                parser.error("Path to Lucene index directory needed")
        if options.package == None:
                parser.error("Package name needed")
        if options.pversion == None:
                parser.error("Package version needed")
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

	extractsourcestrings(kerneldir, writer, options.package, options.pversion)

        writer.optimize()
        writer.close()

if __name__ == "__main__":
        main(sys.argv)
