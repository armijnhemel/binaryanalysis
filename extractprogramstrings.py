import sys, os, string, re, subprocess, magic
from optparse import OptionParser
import lucene

ms = magic.open(magic.MAGIC_NONE)
ms.load()

def extractsourcestrings(srcdir, writer, package, pversion):
        srcdirlen = len(srcdir)+1
        osgen = os.walk(srcdir)

        try:
                while True:
                        i = osgen.next()
                        for p in i[2]:
				## we're only interested in a few files right now, will add more in the future
				## some filenames might have uppercase extensions, so lowercase them first
				p_nocase = p.lower()
				if p_nocase.endswith('.c') or p_nocase.endswith('.h') or p_nocase.endswith('.cpp'):
					## Remove all C and C++ style comments. If a file is in iso-8859-1
					## instead of ASCII or UTF-8 we need to do some extra work by
					## converting it first using iconv.
					## This is not failsafe, because magic gets it wrong sometimes, so we
					## need some way to kill the subprocess if it is running too long.
					#print p
					datatype = ms.file("%s/%s" % ( i[0], p))
					if "ISO-8859" in datatype:
						src = open("%s/%s" % (i[0], p)).read()
						p1 = subprocess.Popen(["iconv", "-f", "latin1", "-t", "utf-8"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
						cleanedup_src = p1.communicate(src)[0]
						p2 = subprocess.Popen(['./remccoms3.sed'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,close_fds=True)
						(stanout, stanerr) = p2.communicate(cleanedup_src)
						source = stanout
					## we don't know what this is, assuming it's latin1, but we could be wrong
					elif "data" in datatype or "ASCII" in datatype:
						src = open("%s/%s" % (i[0], p)).read()
						p1 = subprocess.Popen(["iconv", "-f", "latin1", "-t", "utf-8"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
						cleanedup_src = p1.communicate(src)[0]
						p2 = subprocess.Popen(['./remccoms3.sed'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,close_fds=True)
						(stanout, stanerr) = p2.communicate(cleanedup_src)
						source = stanout
					else:
						p1 = subprocess.Popen(['./remccoms3.sed', "%s/%s" % (i[0], p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
                        			(stanout, stanerr) = p1.communicate()
                        			if p1.returncode != 0:
							continue
						else:
							source = stanout
					## if " is directly preceded by an uneven amount of \ it should not be used
					## TODO: fix for uneveness
					results = re.findall("(?<!')\"(.*?)(?<!\\\)\"", source, re.MULTILINE|re.DOTALL)
					#results = re.findall("\"(.*?)(?<!\\\)\"", source, re.MULTILINE|re.DOTALL)
					for res in results:
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
		pass
		#print e


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

	## initiate Lucene, launch JVM
        lucene.initVM()

        storeDir = options.id
        store = lucene.SimpleFSDirectory(lucene.File(storeDir))
	
        analyzer = lucene.StandardAnalyzer(lucene.Version.LUCENE_CURRENT)

	## If we already have an index at the specified location we simply add to it.
	## If not we create a new index. The drawback is that if you add
	## sources twice they will end up in the knowledgebase twice so take
	## care that you only add something once.
	exists = lucene.IndexReader.indexExists(store)

        writer = lucene.IndexWriter(store, analyzer, not exists,
                                    lucene.IndexWriter.MaxFieldLength.LIMITED)
        writer.setMaxFieldLength(1048576)

	extractsourcestrings(kerneldir, writer, options.package, options.pversion)

        writer.optimize()
        writer.close()

if __name__ == "__main__":
        main(sys.argv)
