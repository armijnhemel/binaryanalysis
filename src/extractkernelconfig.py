#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, os.path, string, re
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
			os.stat(os.path.join(dirname, filename[:-2] + ".c"))
			return (os.path.join(dirname[kerneldirlen:], filename[:-2] + ".c"), config)
		except:
			pass
		try:
			os.stat(os.path.join(dirname, filename[:-2] + ".S"))
			return (os.path.join(dirname[kerneldirlen:], filename[:-2] + ".S"), config)
		except:
			return None
	else:
		## first see if the directory is relative to the current directory
		try:
			os.stat(os.path.join(dirname, filename))
			return (os.path.join(dirname[kerneldirlen:], filename), config)
		except:
			## then see if it is relative to the top level directory
			try:
				os.stat(os.path.join(dirname[:kerneldirlen], filename))
				return (os.path.join(dirname[:kerneldirlen], filename), config)
			except:
				return None
			else:
				return None

def extractkernelstrings(kerneldir):
	kerneldirlen = len(kerneldir)+1
	osgen = os.walk(kerneldir)
	searchresults = []
	version = ""

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
				## only interested in the top level Makefile for determining the versions
				if i[0][kerneldirlen:] == "":
					source = open(os.path.join(i[0], p)).readlines()
					for l in source:
						if l.startswith("VERSION"):
							version = version + l.split('=')[-1].strip()
						elif l.startswith("PATCHLEVEL"):
							patchlevel = l.split('=')[-1].strip()
							version = version + "." + patchlevel
						elif l.startswith("SUBLEVEL"):
							sublevel = l.split('=')[-1].strip()
							if sublevel != "":
								version = version + "." + sublevel
						elif l.startswith("EXTRAVERSION"):
							extraversion = l.split('=')[-1].strip()
							if extraversion != "":
								version = version + "." + extraversion
						else:
							continue
				source = open(os.path.join(i[0], p)).readlines()

				## temporary store
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
						## replace \ with a space, then concatenate lines
						storeline = storeline + line.strip()[:-1] + " "
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

					res = re.match("([\w\.]+)\-\$\(CONFIG_(\w+)\)\s*[:+]=\s*([\w\-\.\s/=]*)", line.strip())
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
						if "=" in res.groups()[2]:
							continue
						config = "CONFIG_" + res.groups()[1]
						files = res.groups()[2].split()
						for f in files:
							match = matchconfig(f, i[0], config, kerneldirlen)
							if match != None:
								if not f.endswith('.o'):
									dirpath = os.path.normpath(os.path.join(i[0][kerneldirlen:], f))
									if dirstoconfigs.has_key(dirpath):
										dirstoconfigs[dirpath].append(config)
									else:
										dirstoconfigs[dirpath] = [config]
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
						if tmpconfigs.has_key(tmpkey):
							for f in tmpvals:
								match = matchconfig(f, i[0], tmpconfigs[tmpkey], kerneldirlen)
								if match != None:
									searchresults.append(match)
						else:
							if dirstoconfigs.has_key(os.path.normpath(i[0][kerneldirlen:])):
								for f in tmpvals:
									for m in dirstoconfigs[os.path.normpath(i[0][kerneldirlen:])]:
										match = matchconfig(f, i[0], m, kerneldirlen)
										if match != None:
											searchresults.append(match)
					else:
						res = re.match("([\w\.\-]+)\-y\s*[:+]=\s*([\w\-\.\s/=]*)", line.strip())
						if res != None:
							tmpkey = res.groups()[0]
							tmpvals = res.groups()[1].split()
							if tmpconfigs.has_key(tmpkey):
								for f in tmpvals:
									match = matchconfig(f, i[0], tmpconfigs[tmpkey], kerneldirlen)
									if match != None:
										searchresults.append(match)
	except StopIteration:
		return (searchresults, version)

def storematch(results, dbcursor, version):
	## store two things:
	## 1. if it is a path/subdir, store subdir + configuration
	##    making it searchable by subdir
	## 2. if it is an objectfile, store name of source(!) file + configuration
	##    making it searchable by source file
	## These can and will overlap
	for res in results:
		pathstring = res[0]
		configstring = res[1]
		dbcursor.execute('''insert into config (configstring, filename, version) values (?, ?, ?)''', (configstring, pathstring, version))

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

	kerneldir = os.path.normpath(options.kd)

	conn = sqlite3.connect(options.id)
	c = conn.cursor()

	## TODO: add whether or not a configuration - filename mapping is 1:1
	c.execute('''create table if not exists config (configstring text, filename text, version text)''')
	## TODO: process Kconfig files too

	(results, version) = extractkernelstrings(kerneldir)
	storematch(results, c, version)

	conn.commit()
	c.close()
	conn.close()

if __name__ == "__main__":
        main(sys.argv)
