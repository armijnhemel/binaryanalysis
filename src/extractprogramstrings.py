import sys, os, string, re
from optparse import OptionParser

def extractsourcestrings(srcdir):
        srcdirlen = len(srcdir)+1
        osgen = os.walk(srcdir)

        try:
                while True:
                        i = osgen.next()
                        for p in i[2]:
				## we're only interested in a few files
				if p.endswith('.c') or p.endswith('.h'):
					print p
					source = open("%s/%s" % (i[0], p)).read()
					results = re.findall("(\".*\")", source, re.MULTILINE)
					for res in results:
						print res
	except:
		pass


def main(argv):
        parser = OptionParser()
        parser.add_option("-d", "--directory", dest="kd", help="path to sources directory", metavar="DIR")
        (options, args) = parser.parse_args()
        if options.kd == None:
                parser.error("Path to sources directory needed")
        if options.kd.endswith('/'):
                kerneldir = options.kd[:-1]
        else:
                kerneldir = options.kd
	extractsourcestrings(kerneldir)

if __name__ == "__main__":
        main(sys.argv)
