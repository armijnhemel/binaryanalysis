#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, os.path, string, re
from optparse import OptionParser
import sqlite3

'''
This tool extracts configurations from Makefiles and Kconfig files in kernels
and tries to determine which files are included by a configuration directives.
This information is useful to try and determine a mapping from a binary kernel
image and modules back to a configuration.
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
	makefileresults = []
	kconfigresults = []
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
				## only process Makefiles and Kconfig
				if p != 'Makefile' and not 'Kconfig' in p:
					continue

				source = open(os.path.join(i[0], p)).readlines()

				if p == 'Makefile':
					if i[0][kerneldirlen:] == "":
						## only interested in the top level Makefile for determining the versions
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
									makefileresults.append(match)
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
										makefileresults.append(match)
							else:
								if dirstoconfigs.has_key(os.path.normpath(i[0][kerneldirlen:])):
									for f in tmpvals:
										for m in dirstoconfigs[os.path.normpath(i[0][kerneldirlen:])]:
											match = matchconfig(f, i[0], m, kerneldirlen)
											if match != None:
												makefileresults.append(match)
						else:
							res = re.match("([\w\.\-]+)\-y\s*[:+]=\s*([\w\-\.\s/=]*)", line.strip())
							if res != None:
								tmpkey = res.groups()[0]
								tmpvals = res.groups()[1].split()
								if tmpconfigs.has_key(tmpkey):
									for f in tmpvals:
										match = matchconfig(f, i[0], tmpconfigs[tmpkey], kerneldirlen)
										if match != None:
											makefileresults.append(match)
				else:
					configs = []
					inhelp = False
					inconfig = False
					currentconfig = ""
					configtype = ""

					## menus can be stacked. Inside menus there can be definitions that
					## apply to all configurations inside the menu.
					## Files might also have global definitions that apply to every
					## configuration in the file.
					menus = []
					menuconfigs = []
					globalcfgs = []

					ifcfgs = []

					for line in source:
						## ignore comments
						if line.strip().startswith('#'):
							continue
						## ignore empty lines
						if line.strip() == "":
							continue
						if not (line.startswith(" ") or line.startswith("\t")):
							inhelp = False
							inconfig = False
						## new config starts here. Store the old configuration, with all
						## its definitions and dependencies.
						if line.strip().startswith('config '):
							## sanity check, config line always has just 2
							## elements, separated by whitespace.
							if len(line.strip().split()) != 2:
								continue
							inconfig = True
							configdirective = "CONFIG_%s" % line.strip().split()[-1]
							currentconfig = configdirective
							continue
						if line.strip() == '---help---' or line.strip() == 'help':
							inhelp = True
							continue
						if inhelp:
							continue
						if line.strip().startswith('if '):
							ifcfgs.append([])
							continue
						if line.strip().startswith('endif'):
							print line.strip(), i[0]
							ifcfgs.pop()
							continue
						if line.strip().startswith('menu '):
							currentconfig = ""
							continue
						if line.strip().startswith('select'):
							pass
						## add depends and constraints
						## These can be configuration specific, menu specific or file wide
						if line.strip().startswith('depends '):
							depends = line.strip()
							if depends[0] == 'on':
								depends = depends[1:]
							#print currentconfig, depends
						if line.strip().startswith('tristate'):
							configtype = 'tristate'
							continue
						if line.strip().startswith('bool'):
							configtype = 'bool'
							continue
						if line.strip().startswith('int'):
							configtype = 'int'
							continue
			print
	except StopIteration:
		return (makefileresults, kconfigresults, version)

def storematch(makefileresults, kconfigresults, dbcursor, version):
	## store two things:
	## 1. if it is a path/subdir, store subdir + configuration
	##    making it searchable by subdir
	## 2. if it is an objectfile, store name of source(!) file + configuration
	##    making it searchable by source file
	## These can and will overlap
	for res in makefileresults:
		pathstring = res[0]
		configstring = res[1]
		dbcursor.execute('''insert into makefile (configstring, filename, version) values (?, ?, ?)''', (configstring, pathstring, version))

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
	c.execute('''create table if not exists makefile (configstring text, filename text, version text)''')
	## TODO: process Kconfig files too
	c.execute('''create table if not exists kconfig (configstring text, type text)''')

	(makefileresults, kconfigresults, version) = extractkernelstrings(kerneldir)
	storematch(makefileresults, kconfigresults, c, version)

	conn.commit()
	c.close()
	conn.close()

if __name__ == "__main__":
        main(sys.argv)
