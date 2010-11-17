import sys, os, string, re, subprocess, magic
from optparse import OptionParser
import sqlite3

ms = magic.open(magic.MAGIC_NONE)
ms.load()

def extractsourcestrings(srcdir, sqldb, package, pversion):
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
					## TODO correctly remove strip() statements everywhere, correctly store the string we extracted
					for res in results:
						storestring = res
						#if res.strip().endswith("\\n"):
                                                #	storestring = res.strip()[:-2]
                                        	#else:
                                                #	storestring = res.strip()
                                        	#if storestring.startswith("\\n"):
                                                #	storestring = storestring[2:].strip()
                                        	# replace tabs
                                        	#storestring = storestring.replace("\\t", "\t").strip()
						#print storestring
						sqldb.execute('''insert into extracted (programstring, package, version, filename) values (?, ?, ?, ?)''', (storestring, package, pversion, u"%s/%s" % (i[0][srcdirlen:], p)))
	except Exception, e:
		#print e
		pass


def main(argv):
        parser = OptionParser()
        parser.add_option("-d", "--directory", dest="kd", help="path to sources directory", metavar="DIR")
	parser.add_option("-i", "--index", dest="id", help="path to Lucene index directory", metavar="DIR")
	parser.add_option("-p", "--package", dest="package", help="package name", metavar="PACKAGE")
	parser.add_option("-v", "--version", dest="pversion", help="package version", metavar="PACKAGEVERSION")
        (options, args) = parser.parse_args(argv)
        #(options, args) = parser.parse_args()
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

        conn = sqlite3.connect(options.id)
	c = conn.cursor()

	try:
		c.execute('''create table extracted (programstring text, package text, version text, filename text)''')
	except:
		pass

	extractsourcestrings(kerneldir, c, options.package, options.pversion)
	conn.commit()
	c.close()

if __name__ == "__main__":
        main(sys.argv[1:])
