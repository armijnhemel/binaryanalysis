#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, string, re
from optparse import OptionParser
import sqlite3

'''
This tool extracts configurations from Makefiles in kernels and tries to
determine which files are included by a certain configuration directive.
This information is useful to try and determine a reverse mapping from a
binary kernel image to a configuration.
'''

## helper method for processing stuff
## output is a tuple (file/dirname, config) for later processing
def matchconfig(filename, dirname, config, kerneldirlen):
	if filename.endswith(".o"):
		try:
			os.stat("%s/%s" % (dirname, filename[:-2] + ".c"))
			return ("%s/%s" % (dirname[kerneldirlen:], filename[:-2] + ".c"), config)
		except:
			pass
		try:
			os.stat("%s/%s" % (dirname, filename[:-2] + ".S"))
			return ("%s/%s" % (dirname[kerneldirlen:], filename[:-2] + ".S"), config)
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
		dirstoconfigs = {}
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
				## only process Makefiles
				if p != 'Makefile':
					continue
				## not interested in the top level Makefile
				if i[0][kerneldirlen:] == "":
					continue
				source = open("%s/%s" % (i[0], p)).readlines()

				## temporary store
				tmpobjs = {}
				tmpconfigs = {}

				continued = False

				## first clean up the Makefile, filter out uninteresting
				## lines and process line continuations
				makefile = []
				storeline = ""
				for line in source:
					if not continued:
						if line.strip().startswith('#'):
							continue
						if line.strip().startswith('echo'):
							continue
						if line.strip().startswith('@'):
							continue
						if line.strip() == "":
							continue
					if line.strip().endswith("\\"):
						storeline = storeline + line.strip()[:-1]
						continued = True
						continue
					else:
						storeline = storeline + line.strip()
						continued = False

					if not continued:
						if storeline == "":
							makefile.append(line.strip())
						else:
							makefile.append(storeline)
							storeline = ""

				inif = False
				iniflevel = 0

				nomatches = []

				for line in makefile:
					if line.strip().startswith('.PHONY:'):
						continue
					if line.strip().startswith('doc:'):
						continue
					if line.strip().startswith('cleandoc:'):
						continue
					if line.strip().startswith('clean:'):
						continue
					if line.strip().startswith('clean-files'):
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
						if res.groups()[0] == "entrypoint":
							continue
						if res.groups()[0] == "textaddr":
							continue
						if res.groups()[0] == "CPP_MODE":
							continue
						if res.groups()[0] == "LINK":
							continue
						config = "CONFIG_" + res.groups()[1]
						files = res.groups()[2].split()
						for f in files:
							match = matchconfig(f, i[0], config, kerneldirlen)
							if match != None:
								if not f.endswith('.o'):
									if dirstoconfigs.has_key(os.path.join(i[0][kerneldirlen:], f)):
										dirstoconfigs[os.path.join(i[0][kerneldirlen:], f)].append(config)
									else:
										dirstoconfigs[os.path.join(i[0][kerneldirlen:], f)] = [config]
								searchresults.append(match)
							else:
								if f.endswith('.o'):
									tmpconfigs[f[:-2]] = config
					else:
						nomatches.append(line.strip())

				for line in nomatches:
					res = re.match("([\w\.\-]+)\-objs\s*[:+]=\s*([\w\-\.\s/]*)", line.strip())
					if res != None:
						tmpkey = res.groups()[0]
						tmpvals = res.groups()[1].split()
						tmpobjs[tmpkey] = tmpvals
						if tmpconfigs.has_key(tmpkey):
							for f in tmpobjs[tmpkey]:
								match = matchconfig(f, i[0], tmpconfigs[tmpkey], kerneldirlen)
								if match != None:
									searchresults.append(match)
					else:
						res = re.match("([\w\.\-]+)\-y\s*[:+]=\s*([\w\-\.\s/]*)", line.strip())
						if res != None:
							tmpkey = res.groups()[0]
							tmpvals = res.groups()[1].split()
							tmpobjs[tmpkey] = tmpvals
							if tmpconfigs.has_key(tmpkey):
								for f in tmpobjs[tmpkey]:
									match = matchconfig(f, i[0], tmpconfigs[tmpkey], kerneldirlen)
									if match != None:
										searchresults.append(match)
	except StopIteration:
		return searchresults

def storematch(results, dbcursor):
	## store two things:
	## 1. if we have a path/subdir, we store subdir + configuration
	##    making it searchable by subdir
	## 2. if we have an objectfile, we store name of source(!) file+ configuration
	##    making it searchable by source file
	## these can and will overlap
	for res in results:
		pathstring = res[0]
		configstring = res[1]
		dbcursor.execute('''insert into config (configstring, filename) values (?, ?)''', (configstring, pathstring))

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--directory", dest="kd", help="path to Linux kernel directory", metavar="DIR")
	parser.add_option("-i", "--index", dest="id", help="path to database", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.kd == None:
		parser.error("Path to Linux kernel directory needed")
	if options.id == None:
		parser.error("Path to database needed")
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

	conn = sqlite3.connect(options.id)
	c = conn.cursor()

	c.execute('''create table if not exists config (configstring text, filename text)''')

	results = extractkernelstrings(kerneldir)
	storematch(results, c)

	conn.commit()
	c.close()
	conn.close()

if __name__ == "__main__":
        main(sys.argv)
