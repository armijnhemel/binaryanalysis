#!/usr/bin/python
# -*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2009-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Program to process a whole directory full of compressed source code archives
to create a knowledgebase. Needs a file LIST in the directory it is passed as
a parameter, which has the following format:

package version filename origin

separated by whitespace

Compression is currently determined using libmagic

Currently the following information is stored in the knowledgebase:

* string constants (all languages)
* function names (C)
* variable names (C/Java)
* class names (Java)
* method names (Java/C#)
* licenses (all languages)
* copyright information (all languages)
* limited security information (C)

Files that are processed:
* have a certain extension
* are explicitely defined in the configuration file (per package)
* configure.ac from packages using GNU autotools

Sometimes files are explicitely ignored in packages.

For the Linux kernel additional information is extracted:

* symbols
* module alias
* module author
* module description
* module firmware file names
* module license
* module parameters + parameter descriptions
* module version

This tool extracts configurations from Makefiles and Kconfig files in Linux
kernels and tries to determine which files are included by a configuration
directives. This information is useful to try and determine a mapping from a
binary kernel image and modules back to a configuration.
'''

import sys, os, magic, string, re, subprocess, shutil, stat, datetime
import tempfile, bz2, tarfile, gzip, ConfigParser
from optparse import OptionParser
import sqlite3, hashlib, zlib, urlparse, tokenize, multiprocessing
import batextensions
try:
        import tlsh
	tlshscan = True
except Exception, e:
	tlshscan = False

tarmagic = ['POSIX tar archive (GNU)'
           , 'tar archive'
           ]

ms = magic.open(magic.MAGIC_NONE)
ms.load()

kernelexprs = []

## lots of things with _ATTR, like DEVICE_ATTR and friends. This list should be expanded.
kernelexprs.append(re.compile("__ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("__ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("__ATTR_WO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("__ATTR_RW\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("__ATTR_IGNORE_LOCKDEP\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("ATTRIBUTE_GROUPS\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("BIN_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("BLK_TRACE_DEVICE_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("BRPORT_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("BUS_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("CCN_FORMAT_ATTR\s*\((\w+),", re.MULTILINE))
kernelexprs.append(re.compile("CFQ_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("CHILDLESS_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("CLASS_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("CLASS_ATTR_STRING\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("CLUSTER_ATTR\s*\((\w+),", re.MULTILINE))
kernelexprs.append(re.compile("DECLARE_STATS_COUNTER\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_CACHE_ATTR\((\w+),\s*", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_IPL_ATTR_RO\s*\(\w+,\s*([\w\-\.]+)", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_IPL_ATTR_RW\s*\(\w+,\s*([\w\-\.]+)", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_IPL_ATTR_STR_RW\s*\(\w+,\s*([\w\-\.]+)", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_RAPL_FORMAT_ATTR\(\w+,\s*(\w+),", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_UNCORE_FORMAT_ATTR\(\w+,\s*(\w+),", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_WRITEBACK_WORK_EVENT\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_EVENT\s*\(\w+,\s*(\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DEV_ATTR_WO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DEVICE_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DEVICE_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DEVICE_ATTR_RW\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DEVICE_ATTR_WO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DEVICE_PREFIX_ATTR\s*\(\w+,\s*(\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DMI_SYSFS_SEL_FIELD\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DRIVER_ATTR_WO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EEH_SHOW_ATTR\((\w+),\s*", re.MULTILINE))
kernelexprs.append(re.compile("EP_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EVENT_ATTR_STR\s*\(([\w\-\.]+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_DEPRECATED_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_INFO_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_RO_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_RW_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_RW_ATTR_SBI_UI\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile(" FORMAT\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("KSM_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("HSTATE_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("HSTATE_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("HV_CONF_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("HYPERVISOR_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("INTEL_UNCORE_EVENT_DESC\(\s*(\w+),", re.MULTILINE))
kernelexprs.append(re.compile("KSM_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("MODINFO_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("NILFS_CHECKPOINTS_RO_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("NILFS_DEV_RO_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("NILFS_FEATURE_RO_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("NILFS_MOUNTED_SNAPSHOTS_RO_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("NILFS_SEGCTOR_RO_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("NILFS_SEGMENTS_RO_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("NILFS_SNAPSHOT_RO_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("NILFS_SUPERBLOCK_RO_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("NILFS_SUPERBLOCK_RW_ATTR\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("^\s*PARAM\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("PMU_FORMAT_ATTR\s*\((\w+),\s*\"[\w:-]+\"\)", re.MULTILINE))
kernelexprs.append(re.compile("PCIE_GADGET_TARGET_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("PCIE_GADGET_TARGET_ATTR_RW\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("PCIE_GADGET_TARGET_ATTR_WO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("PORT_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("POWER_SUPPLY_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("PROC\(\s*(\w+),", re.MULTILINE))
kernelexprs.append(re.compile("QPN_ATTR_RO\s*\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("READ_ATTR\s*\(\w+,\s*\w+,\s*\w+,\s*(\w+)", re.MULTILINE))
kernelexprs.append(re.compile("SCHED_FEAT\(\s*(\w+),", re.MULTILINE))
kernelexprs.append(re.compile("SENSOR_DEVICE_ATTR_2\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_CONN_RD_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_DEV_ATTRIBUTE\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_LINK_ATTRIBUTE\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_PORT_ATTRIBUTE\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_SESSION_RD_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("SLAB_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("SLAB_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("SPACE_INFO_ATTR\s*\((\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("^TRACE_EVENT\s*\(\s*(\w+),", re.MULTILINE))
kernelexprs.append(re.compile("power_attr\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("show_sdev_iostat\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("sdev_rd_attr\(\s*(\w+)\s*,", re.MULTILINE))
kernelexprs.append(re.compile("shost_rd_attr\(\s*(\w+)\s*,", re.MULTILINE))
kernelexprs.append(re.compile("fc_private_host_rd_attr\(\s*(\w+)\s*,", re.MULTILINE))
kernelexprs.append(re.compile("NETSTAT_ENTRY\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("KERNEL_ATTR_RO\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("GENERIC_EVENT_ATTR\(([\w\-\.]+),\s*", re.MULTILINE))
kernelexprs.append(re.compile("PAGE_0_ATTR\(([\w\-\.]+),\s*", re.MULTILINE))
kernelexprs.append(re.compile("scsi_msgbyte_name\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("scsi_opcode_name\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("scsi_statusbyte_name\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("VMCOREINFO_LENGTH\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("VMCOREINFO_NUMBER\s*\((\w+)", re.MULTILINE))
#SYSCALL_DEFINE + friends go here
#COMPAT_SYSCALL_DEFINE

## some more precompiled regex
recopyright = re.compile('^\s*\[(\d+):\d+:(\w+)] \'(.*)\'$')
recopyright2 = re.compile('^\s*\[(\d+):\d+:(\w+)] \'(.*)')

## precompiled regular expression for extracting security information
## ENV33-C
resystem = re.compile('system\(.*\);')

## MSC24-C -- https://www.securecoding.cert.org/confluence/display/seccode/MSC24-C.+Do+not+use+deprecated+or+obsolescent+functions
msc24checks = []
msc24checks.append((re.compile('gets\(.*\);'), 'gets'))
msc24obsolescent = ["asctime","atof", "atoi", "atol", "atoll", "ctime", "fopen", "freopen", "rewind", "setbuf"]
for m in msc24obsolescent:
	msc24checks.append((re.compile('\s+%s\(.*\);' % m), m))
## TODO
#msc24uncheckedobsolescent = ["bsearch", "fprintf", "fscanf", "fwprintf", "fwscanf", "getenv", "gmtime", "localtime", "mbsrtowcs", "mbstowcs", "memcpy", "memmove", "printf", "qsort", "setbuf", "snprintf", "sprintf", "sscanf", "strcat", "strcpy", "strerror", "strncat", "strncpy", "strtok", "swprintf", "swscanf", "vfprintf", "vfscanf", "vfwprintf", "vfwscanf", "vprintf", "vscanf", "vsnprintf", "vsprintf", "vsscanf", "vswprintf", "vswscanf", "vwprintf", "vwscanf", "wcrtomb", "wcscat", "wcscpy", "wcsncat", "wcsncpy", "wcsrtombs", "wcstok", "wcstombs", "wctomb", "wmemcpy", "wmemmove", "wprintf", "wscanf"]

oldallowedvals= ["b", "c", "h", "i", "l", "s"]

reoldallowedexprs = []

for v in oldallowedvals:
	reoldallowedexprs.append(re.compile("\d+%s" % v))
	reoldallowedexprs.append(re.compile("\d+\-\d+%s+" % v))

rechar = re.compile("c\d+")

## from FOSSology
fossologyurlre = re.compile("((:?ht|f)tps?\\:\\/\\/[^\\s\\<]+[^\\<\\.\\,\\s])")
fossologyemailre = re.compile("[\\<\\(]?([\\w\\-\\.\\+]{1,100}@[\\w\\-\\.\\+]{1,100}\\.[a-z]{1,12})[\\>\\)]?")

extensions = batextensions.extensions

## extensions, without leading .
extensionskeys = set(map(lambda x: x[1:], extensions.keys()))

languages = set(extensions.values())

## a list of characters that 'strings' will split on when processing a binary file
splitcharacters = map(lambda x: chr(x), range(0,9) + range(14,32) + [127])

## process the contents of list with rewrites
## The file has per line the following fields, separated by spaces or tabs:
## * package name
## * version
## * filename
## * origin
## * sha256
## * new package name
## * new version name
def readrewritelist(rewritelist):
	## rewrite is a hash. Key is sha256 of the file.
	rewrite = {}
	try:
		rewritefile = open(rewritelist, 'r')
		rewritelines = rewritefile.readlines()
		rewritefile.close()
		for r in rewritelines:
			rs = r.strip().split()
			## format error, bail out
			if len(rs) != 7:
				return {}
			else:
				(package, version, filename, origin, sha256, newp, newv) = rs
				## dupe, skip
				if rewrite.has_key(sha256):
					continue
				else:
					rewrite[sha256] = {'package': package, 'version': version, 'filename': filename, 'origin': origin, 'newpackage': newp, 'newversion': newv}
	except:
		return {}
	return rewrite

## split on the special characters, plus remove special control characters that are
## at the beginning and end of the string in escaped form.
## Return a list of strings.
def splitSpecialChars(s):
	splits = [s]
	final_splits = []
	splitchars = []
	for i in splitcharacters:
		if i in s:
			splitchars.append(i)
	if splitchars != []:
		for i in splitchars:
			splits = filter(lambda x: x != '', reduce(lambda x, y: x + y, map(lambda x: x.split(i), splits), []))
	## Now make sure to get rid of leading control characters.
	## The reason to remove them only at the beginning and end
	## (for now) is because it is a lot easier. In the future try to
	## split on them mid-string.
	remove_chars = ["\\a", "\\b", "\\v", "\\f", "\\n", "\\r", "\\e", "\\0"]
	for i in splits:
		processed = False
		lensplit = len(i)
		while not processed and lensplit != 0:
			for c in remove_chars:
				if i.startswith(c):
					i = i[2:]
					break
				if i.endswith(c) and len(i) > 3:
					if i[-3] != "\\":
						i = i[:-2]
						break
			if lensplit == len(i):
				processed = True
				final_splits.append(i)
				break
			else:
				lensplit = len(i)
	return final_splits

def parsepython((filedir, filepath, unpackdir)):
	comments = []
	strings = []
	pathname = os.path.join(filedir, filepath)

	returndict = {}

	parseiterator = open(pathname, 'r').readline

	parsetokens = tokenize.generate_tokens(parseiterator)

	for p in parsetokens:
	        if p[0] == tokenize.COMMENT:
			comments.append(p[1])
	        elif p[0] == tokenize.STRING:
			strings.append(p[1])

	if comments != [] or strings != []:
		commentsfile = None
		stringsfile = None
		if comments != []:
			## there are comments, so print them to a file
			commentsfile = tempfile.mkstemp(dir=unpackdir)
			for c in comments:
				os.write(commentsfile[0], c)
				os.write(commentsfile[0], "\n")
			os.fdopen(commentsfile[0]).close()
			commentsfile = os.path.basename(commentsfile[1])
		if strings != []:
			## there are comments, so print them to a file
			stringsfile = tempfile.mkstemp(dir=unpackdir)
			for c in strings:
				os.write(stringsfile[0], c)
				os.write(stringsfile[0], "\n")
			os.fdopen(stringsfile[0]).close()
			stringsfile = os.path.basename(stringsfile[1])
		returndict = {'unpackdir': unpackdir, 'commentsfile': commentsfile, 'stringsfile': stringsfile}
		return (filedir, filepath, returndict)
	return None

## walk the Linux kernel directory and process all the Makefiles
def extractkernelconfiguration(kerneldir):
	kerneldirlen = len(kerneldir)+1
	osgen = os.walk(kerneldir)
	makefileresults = []
	kconfigresults = []
	moduleresults = []

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
										moduleresults.append((os.path.normpath(match[0]),tmpkey))
							else:
								if dirstoconfigs.has_key(os.path.normpath(i[0][kerneldirlen:])):
									for f in tmpvals:
										for m in dirstoconfigs[os.path.normpath(i[0][kerneldirlen:])]:
											match = matchconfig(f, i[0], m, kerneldirlen)
											if match != None:
												makefileresults.append(match)
												moduleresults.append((os.path.normpath(match[0]),tmpkey))
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
											moduleresults.append((os.path.normpath(match[0]),tmpkey))
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
						if not (line.startswith(" ") or line.startswith("\t")):
							inhelp = False
							inconfig = False
						if inhelp:
							continue
						## ignore comments
						if line.strip().startswith('#'):
							continue
						## ignore empty lines
						if line.strip() == "":
							continue
						## new config starts here. Store the old configuration, with all
						## its definitions and dependencies.
						if line.startswith('config '):
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
						if line.strip().startswith('if '):
							ifcfgs.append([])
							continue
						if line.strip().startswith('endif'):
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
						if line.strip().startswith('hex'):
							configtype = 'hex'
							continue
						if line.strip().startswith('int'):
							configtype = 'int'
							continue
						if line.strip().startswith('string'):
							configtype = 'string'
							continue
	except StopIteration:
		return (makefileresults, kconfigresults, moduleresults)

## helper method for processing information from Linux kernel Makefiles
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
				return (os.path.join(dirname[kerneldirlen:], filename), config)
			except:
				return None
			else:
				return None

## unpack the directories to be scanned. For speed improvements it might be
## wise to use a ramdisk or tmpfs for this, although when using Ninka and
## FOSSology it is definitely not I/O bound...
def unpack(directory, filename, unpackdir):
	try:
		os.stat(os.path.join(directory, filename))
	except:
		print >>sys.stderr, "Can't find %s" % filename
		return None

        filemagic = ms.file(os.path.realpath(os.path.join(directory, filename)))

        ## Assume if the files are bz2 or gzip compressed they are compressed tar files
        if 'bzip2 compressed data' in filemagic:
		if unpackdir != None:
       			tmpdir = tempfile.mkdtemp(dir=unpackdir)
		else:
       			tmpdir = tempfile.mkdtemp()
		## for some reason the tar.bz2 unpacking from python doesn't always work, like
		## aeneas-1.0.tar.bz2 from GNU, so use a subprocess instead of using the
		## Python tar functionality.
 		p = subprocess.Popen(['tar', 'jxf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			print >>sys.stderr, "corrupt bz2 archive %s/%s" % (directory, filename)
			try:
				shutil.rmtree(tmpdir)
			except:
				pass
			return None
        elif 'LZMA compressed data, streamed' in filemagic:
		if unpackdir != None:
       			tmpdir = tempfile.mkdtemp(dir=unpackdir)
		else:
       			tmpdir = tempfile.mkdtemp()
 		p = subprocess.Popen(['tar', 'ixf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			shutil.rmtree(tmpdir)
			return
        elif 'XZ compressed data' in filemagic or ('data' in filemagic and filename.endswith('.xz')):
		if unpackdir != None:
       			tmpdir = tempfile.mkdtemp(dir=unpackdir)
		else:
       			tmpdir = tempfile.mkdtemp()
 		p = subprocess.Popen(['tar', 'ixf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			shutil.rmtree(tmpdir)
			return
	elif 'gzip compressed data' in filemagic or 'compress\'d data 16 bits' in filemagic or ('Minix filesystem' in filemagic and filename.endswith('.gz')) or ('JPEG 2000 image' in filemagic and filename.endswith('.gz')):
		if unpackdir != None:
       			tmpdir = tempfile.mkdtemp(dir=unpackdir)
		else:
       			tmpdir = tempfile.mkdtemp()
 		p = subprocess.Popen(['tar', 'zxf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			shutil.rmtree(tmpdir)
			return
	elif 'Zip archive data' in filemagic:
		try:
			if unpackdir != None:
       				tmpdir = tempfile.mkdtemp(dir=unpackdir)
			else:
       				tmpdir = tempfile.mkdtemp()
			p = subprocess.Popen(['unzip', "-B", os.path.join(directory, filename), '-d', tmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0 and p.returncode != 1:
				print >>sys.stderr, "unpacking ZIP failed for", filename, stanerr
				shutil.rmtree(tmpdir)
				return None
		except Exception, e:
			print >>sys.stderr, "unpacking ZIP failed", e
			return None
	osgen = os.walk(tmpdir)
	while True:
		try:
			i = osgen.next()
			## make sure all directories and files can be accessed
			for d in i[1]:
				if not os.path.islink(os.path.join(i[0], d)):
					os.chmod(os.path.join(i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			for p in i[2]:
				if not os.path.islink(os.path.join(i[0], p)):
					os.chmod(os.path.join(i[0], p), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
		except StopIteration:
			break
		except Exception, e:
			if str(e) != "":
				print >>sys.stderr, e
			break
	return tmpdir

def unpack_verify(filedir, filename):
	try:
		os.stat(os.path.join(filedir, filename))
	except:
		print >>sys.stderr, "Can't find %s" % filename

## get strings plus the license. This method should be renamed to better
## reflect its true functionality...
def unpack_getstrings(filedir, package, version, filename, origin, checksums, downloadurl, dbpath, cleanup, license, copyrights, security, pool, extractconfig, licensedb, authlicensedb, authdb, authcopy, securitydb, oldpackage, oldsha256, rewrites, batarchive, packageconfig, unpackdir, extrahashes, update, newlist, allfiles):
	## unpack the archive. If it fails, cleanup and return.
	## TODO: make temporarydir configurable

	if not batarchive:
		filehash = checksums['sha256']
	else:
		temporarydir = unpack(filedir, filename, unpackdir)
		if temporarydir == None:
			return None
		## override the data for package, version, filename, origin, filehash
		## first unpack
		## first extract the MANIFEST.BAT file from the BAT archive
		if not os.path.exists(os.path.join(temporarydir, "MANIFEST.BAT")):
			return
		manifest = os.path.join(temporarydir, "MANIFEST.BAT")
		manifestfile = open(manifest)
		manifestlines = manifestfile.readlines()
		manifestfile.close()
		inheader = False
		infiles = False
		inextensions = False
		emptyarchive = True
		for i in manifestlines:
			if "START META" in i:
				inheader = True
				continue
			if "END META" in i:
				inheader = False
				continue
			if "START DUPLICATE_FILES" in i:
				infiles = True
				continue
			if "END DUPLICATE_FILES" in i:
				infiles = False
				continue
			if "START EXTENSIONS" in i:
				inextensions = True
				continue
			if "END EXTENSIONS" in i:
				inextensions = False
				continue
			if inheader:
				if i.startswith('package'):
					package = i.split(':')[1].strip()
				elif i.startswith('version'):
					version = i.split(':')[1].strip()
				elif i.startswith('origin'):
					origin = i.split(':')[1].strip()
				elif i.startswith('filename'):
					filename = i.split(':')[1].strip()
				elif i.startswith('sha256'):
					filehash = i.split(':')[1].strip()
				continue
			if infiles:
				## if there is one valid line the 'FILES' section the archive is not empty
				emptyarchive = False
		checksums = checksums[filename]
		downloadurl = downloadurl.get(filename, None)

	filetohash = {}

	has_manifest = False
	manifestdir = os.path.join(filedir, "MANIFESTS")
	if os.path.exists(manifestdir):
		if os.path.isdir(manifestdir):
			manifestfile = os.path.join(manifestdir, "%s.bz2" % filehash)
			if os.path.exists(manifestfile):
				has_manifest = True

	if has_manifest:
		manifest = bz2.BZ2File(manifestfile, 'r')
		manifestlines = manifest.readlines()
		manifest.close()
		checksumsused = manifestlines[0].strip().split()
		## first line is always a list of supported hashes.
		process = True
		if set(checksumsused).intersection(set(extrahashes)) != set(extrahashes):
			## if the checksums recorded in the file are not the same
			## as in the hashes wanted, then don't process the manifest file
			process = False
			print >>sys.stderr, "something is wrong, please regenerate your manifest files with the right hashes"
		if process:
			for i in manifestlines[1:]:
				i = i.strip().replace('\t\t', '\t')
				entries = i.split('\t')
				if len(entries) != 2 + len(extrahashes):
					## if this happens there is a newline
					## in the file name which is pure evil
					continue
				fileentry = entries[0]
				## sha256 is always the first hash
				hashentry = entries[1]
				filetohash[fileentry] = {}
				filetohash[fileentry]['sha256'] = hashentry
				counter = 1
				for c in checksumsused[1:]:
					## only record results for hashes that are in 'extrahashes'
					if c in extrahashes:
						filetohash[fileentry][c] = entries[counter+1]
					counter += 1
		pkgconf = packageconfig.get(package,{})
		processstatus = set()
		for f in filetohash.keys():
			if filetohash[f]['sha256'] in oldsha256:
				continue
			processstatus.add(filterfilename(f, pkgconf)[0])

		if True in processstatus:
			temporarydir = unpack(filedir, filename, unpackdir)
			if temporarydir == None:
				return None
		else:
			return None
	else:
		temporarydir = unpack(filedir, filename, unpackdir)
		if temporarydir == None:
			return None

	print >>sys.stdout, "processing", filename, datetime.datetime.utcnow().isoformat()
	sys.stdout.flush()

        conn = sqlite3.connect(dbpath, check_same_thread = False)
	conn.text_factory = str
	c = conn.cursor()
	c.execute('PRAGMA synchronous=off')

	## First see if this exact version is in the rewrite list. If so, rewrite.
	if rewrites.has_key(filehash):
		if origin == rewrites[filehash]['origin']:
			if filename == rewrites[filehash]['filename']:
				if package == rewrites[filehash]['package']:
					if version == rewrites[filehash]['version']:
						package = rewrites[filehash]['newpackage']
						version = rewrites[filehash]['newversion']

	allchmod = False
	## Then check if version exists in the database.
	c.execute('''select checksum from processed where package=? and version=? LIMIT 1''', (package, version))
	checkres = c.fetchall()
	if len(checkres) == 0:
		## If the version is not in 'processed' check if there are already any strings
		## from program + version. If so, first remove the results before adding to
		## avoid unnecessary duplication.
		c.execute('''select checksum from processed_file where package=? and version=? LIMIT 1''', (package, version))
		if len(c.fetchall()) != 0:
			c.execute('''delete from processed_file where package=? and version=?''', (package, version))
			conn.commit()
	else:
		## If the version is in 'processed' then it should be checked if every file is in processed_file
		## If they are, then the versions are equivalent and no processing is needed.
		## If not, one of the versions should be renamed.
		## TODO: support for batarchive
		osgen = os.walk(temporarydir)
		pkgconf = packageconfig.get(package,{})

		try:
			scanfiles = []
			while True:
				i = osgen.next()
				for p in i[2]:
					scanfiles.append((i[0], p, pkgconf))
		except Exception, e:
			if str(e) != "":
				print >>sys.stderr, package, version, e

		## first filter out the uninteresting files
		scanfiles = filter(lambda x: x != None, pool.map(filterfiles, scanfiles, 1))
		## compute the hashes in parallel
		## TODO: use filetohash if available
		scanfiles = map(lambda x: x + (extrahashes,), scanfiles)
		scanfile_result = filter(lambda x: x != None, pool.map(computehash, scanfiles, 1))
		identical = True
		## compare amount of checksums for this version and the one recorded in the database.
		## If they are not equal the package is not identical.
		origlen = len(conn.execute('''select checksum from processed_file where package=? and version=?''', (package, version)).fetchall())
		if len(scanfile_result) == origlen:
			tasks = map(lambda x: (dbpath, package, version, x[2]['sha256']), scanfile_result)
			nonidenticals = filter(lambda x: x[1] == False, pool.map(grabhash, tasks, 1))
			if len(nonidenticals) != 0:
				identical = False
		else:
			identical = False

		if not identical:
			## rewrite the version number and process further
			version = "%s-%s-%s" % (version, origin, filehash)
			## If the version is not in 'processed' check if there are already any strings
			## from program + version. If so, first remove the results before adding to
			## avoid unnecessary duplication.
			c.execute('''select checksum from processed_file where package=? and version=? LIMIT 1''', (package, version))
			if len(c.fetchall()) != 0:
				c.execute('''delete from processed_file where package=? and version=?''', (package, version))
				conn.commit()
		else:
			if cleanup:
				cleanupdir(temporarydir)
			c.close()
			conn.close()
			return

	extractionresults = traversefiletree(temporarydir, conn, c, package, version, license, copyrights, security, pool, extractconfig, licensedb, authlicensedb, authdb, authcopy, securitydb, oldpackage, oldsha256, batarchive, filetohash, packageconfig, unpackdir, extrahashes, update, newlist, allfiles)
	if extractionresults != None:
		if extractionresults != []:
			## Add the file to the database: name of archive, sha256, packagename and version
			## This is to be able to just update the database instead of recreating it.
			c.execute('''insert into processed (package, version, filename, origin, checksum, downloadurl) values (?,?,?,?,?,?)''', (package, version, filename, origin, filehash, downloadurl))
			process_extra_hashes = set()

			c.execute('''select sha256 from hashconversion where sha256=? LIMIT 1''', (filehash,))
			if len(c.fetchall()) == 0:
				c.execute('''insert into hashconversion (sha256) values (?)''', (filehash,))
				for k in checksums.keys():
					if k == 'sha256':
						continue
					query = "update hashconversion set %s='%s' where sha256=?" % (k, checksums[k])
					c.execute(query, (filehash,))
		elif batarchive and not emptyarchive:
			c.execute('''insert into processed (package, version, filename, origin, checksum, download) values (?,?,?,?,?,?)''', (package, version, filename, origin, filehash, downloadurl))
	conn.commit()
	c.close()
	conn.close()
	if cleanup:
		cleanupdir(temporarydir)
	return extractionresults

def cleanupdir(temporarydir):
	try:
		shutil.rmtree(temporarydir)
	except:
		## nothing that can be done right now, so just give up
		pass

def grabhash((db, package, version, checksum)):
	conn = sqlite3.connect(db)
	c = conn.cursor()
	c.execute('''select checksum from processed_file where package=? and version=? and checksum=?''', (package, version, checksum))
	cres = c.fetchall()
	if len(cres) == 0:
		identical = False
	else:
		identical = True
	c.close()
	conn.close()
	return (checksum, identical)

def filterfilename(filename, pkgconf):
	## some filenames might have uppercase extensions, so lowercase them first
	p_nocase = filename.lower()
	process = False
	language = None
	extension = p_nocase.split('.')[-1]
	if extension != p_nocase:
		if extension in extensionskeys:
			process = True
			language = extensions['.%s' % extension]
	if filename == 'configure.ac':
		process = True
		language = 'C'
	if not process:
		## now check the package specific extensions
		if pkgconf.has_key('extensions'):
			for extlang in pkgconf['extensions']:
				(extension, language) = extlang
				if (p_nocase.endswith(extension)) and not p_nocase == extension:
					process = True
					break
	return (process, extension, language)

## Compute the SHA256 for a single file.
def filterfiles((filedir, filename, pkgconf, allfiles)):
	resolved_path = os.path.join(filedir, filename)
	if os.path.islink(resolved_path):
        	return None
	if 'blacklist' in pkgconf:
		if filename in pkgconf['blacklist']:
			return None
	## nothing to determine about an empty file, so skip
	if os.stat(resolved_path).st_size == 0:
		return None

	(process, extension, language) = filterfilename(filename, pkgconf)

	if not process and not allfiles:
		return None
	elif not process and allfiles:
		language = None

	filemagic = ms.file(os.path.realpath(resolved_path))
	if filemagic == "AppleDouble encoded Macintosh file":
		return None
	return (filedir, filename, extension, language)

def computehash((filedir, filename, extension, language, extrahashes)):
	filehashes = {}
	resolved_path = os.path.join(filedir, filename)
	scanfile = open(resolved_path, 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	filehashes['sha256'] = h.hexdigest()
	if len(extrahashes) != 0:
		scanfile = open(resolved_path, 'r')
		data = scanfile.read()
		scanfile.close()
		for i in extrahashes:
			if i == 'crc32':
				crcdata = scanfile.read()
				filehashes[i] = zlib.crc32(data) & 0xffffffff
			elif i == 'tlsh':
				if os.stat(resolved_path).st_size >= 512:
					tlshhash = tlsh.hash(data)
					filehashes[i] = tlshhash
				else:
					filehashes[i] = None
			else:
				h = hashlib.new(i)
				h.update(data)
				filehashes[i] = h.hexdigest()
		
	return (filedir, filename, filehashes, extension, language)

def traversefiletree(srcdir, conn, cursor, package, version, license, copyrights, security, pool, extractconfig, licensedb, authlicensedb, authdb, authcopy, securitydb, oldpackage, oldsha256, batarchive, filetohash, packageconfig, unpackdir, extrahashes, update, newlist, allfiles):
	osgen = os.walk(srcdir)

	pkgconf = packageconfig.get(package,{})

	try:
		scanfiles = []
		while True:
			i = osgen.next()
			for p in i[2]:
				if batarchive:
					if p == 'MANIFEST.BAT':
						continue
				scanfiles.append((i[0], p, pkgconf, allfiles))
	except Exception, e:
		if str(e) != "":
			print >>sys.stderr, package, version, e
			return
		pass

	srcdirlen = len(srcdir)+1

	## first filter out the uninteresting files
	scanfiles = filter(lambda x: x != None, pool.map(filterfiles, scanfiles, 1))
	## compute the hashes in parallel, or if available, use precomputed SHA256 from the MANIFEST file
	if filetohash != {}:
		scanfile_result = []
		new_scanfiles = []
		for i in scanfiles:
			(scanfilesdir, scanfilesfile, scanfileextension, language) = i
			if filetohash.has_key(os.path.join(scanfilesdir[srcdirlen:], scanfilesfile)):
				scanfile_result.append((scanfilesdir, scanfilesfile, filetohash[os.path.join(scanfilesdir[srcdirlen:], scanfilesfile)], scanfileextension, language))
			else:
				new_scanfiles.append((scanfilesdir, scanfilesfile, scanfileextension, language, extrahashes))
		## sanity checks in case the MANIFEST file is incomplete
		if new_scanfiles != []:
			scanfile_result += filter(lambda x: x != None, pool.map(computehash, new_scanfiles, 1))
	else:
		scanfiles = map(lambda x: x + (extrahashes,), scanfiles)
		scanfile_result = filter(lambda x: x != None, pool.map(computehash, scanfiles, 1))

	miscfiles = filter(lambda x: x[4] == None, scanfile_result)
	scanfile_result = filter(lambda x: x[4] != None, scanfile_result)

	ninkaversion = "1.3rc1"
	brokenninka = True
	#brokenninka = False
	insertfiles = []
	tmpsha256s = set()
	filehashes = {}
	filestoscan = []
	ninkacomments = extractconfig['ninkacomments']

	## loop through the files to see which files should be scanned.
	## A few assumptions are made:
	## * all tables are in a consistent state
	## * all tables are generated at the same time
	## So this is not robust if one of the databases (say, licenses)
	## is modified by another tool, or deleted and needs to be
	## regenerated.
	addtofiletohash = False
	if filetohash == {}:
		addtofiletohash = True
	filestoscanextra = []
	for s in scanfile_result:
		(path, filename, extractedfilehashes, extension, language) = s
		filehash = extractedfilehashes['sha256']
		insertfiles.append((os.path.join(path[srcdirlen:],filename), extractedfilehashes))
		if addtofiletohash:
			filetohash[os.path.join(path[srcdirlen:],filename)] = filehash

		## if many versions of a single package are processed there is likely going to be
		## overlap. Avoid hitting the disk by remembering the SHA256 from a previous run.
		## This only really helps if the files are scanned in release order to decrease
		## the deltas.
		if package == oldpackage:
			if filehash in oldsha256:
				continue
		if filehash in tmpsha256s:
			continue
		cursor.execute("select * from processed_file where checksum=? LIMIT 1", (filehash,))
		testres = cursor.fetchall()
		if len(testres) != 0:
			continue
		tmpsha256s.add(filehash)
		cursor.execute('''select * from extracted_string where checksum=? LIMIT 1''', (filehash,))
		if len(cursor.fetchall()) != 0:
			#print >>sys.stderr, "duplicate %s %s: %s/%s" % (package, version, i[0], p)
			continue
		if filename == 'configure.ac':
			filestoscanextra.append((package, version, path, filename, language, filehash))
		else:
			filestoscan.append((package, version, path, filename, language, filehash, ninkaversion, extractconfig))
		if filehashes.has_key(filehash):
			filehashes[filehash].append((path, filename))
		else:
			filehashes[filehash] = [(path, filename)]

	unpackenv = os.environ.copy()
	if not unpackenv.has_key('TMPDIR'):
		if unpackdir != None:
			unpackenv['TMPDIR'] = unpackdir

	filestoscan_extract = map(lambda x: x + (unpackenv, security, authdb, pkgconf), filestoscan)
	## process the files to scan in parallel, then process the results
	extracted_results = pool.map(extractidentifiers, filestoscan_extract, 1)

	## parse Python files and write comments and identifiers
	## to temporary files. This is to increase fidelity in FOSSology
	## TODO: add other languages
	## TODO: make configurable
	parsepythonfiles = False
	pythonfiles = []
	if parsepythonfiles:
		pythonfiles = filter(lambda x: x[4] == 'Python', filestoscan)
	if pythonfiles != []:
		pythonparsefiles = map(lambda x: (x[2], x[3], unpackdir), pythonfiles)
		pythonres = filter(lambda x: x != None, pool.map(parsepython, pythonparsefiles, 1))
		if pythonres != []:
			pythonresdict = {}
			for p in pythonres:
				pythonresdict[(p[0], p[1])] = p[2]

			filestoscan_fossology = []
			for fil in filestoscan:
				## (fil[2], fil[3]) are (path, filename)
				if ((fil[2], fil[3])) in pythonresdict:
					tmpunpackdir = pythonresdict[(fil[2], fil[3])]['unpackdir']
					commentsfile = pythonresdict[(fil[2], fil[3])]['commentsfile']
					stringsfile = pythonresdict[(fil[2], fil[3])]['stringsfile']
					if commentsfile != None:
						filestoscan_fossology.append((fil[:2]) + (tmpunpackdir, commentsfile) + fil[4:])
					if stringsfile != None:
						filestoscan_fossology.append((fil[:2]) + (tmpunpackdir, stringsfile) + fil[4:])
				else:
					filestoscan_fossology.append(fil)
		else:
			filestoscan_fossology = filestoscan
	else:
		filestoscan_fossology = filestoscan

	## extract data from configure.ac instances
	## TODO: make it less specific for configure.ac
	if filestoscanextra != []:
		for f in filestoscanextra:
			(package, version, path, filename, language, filehash) = f
			configureac = open(os.path.join(path, filename), 'r')
			configureaclines = configureac.read()
			configureac.close()
			if "AC_INIT" in configureaclines:
				## name, version, bugreport address, possibly other things like URL
				## The bugreport address is the most interesting at the moment
				configureres = re.search("AC_INIT\(\[[\w\s]+\],\s*(?:[\w]+\()?\[?[\w\s/\-\.]+\]?\)?,\s*\[([\w\-@:/\.+]+)\]", configureaclines, re.MULTILINE)
				if configureres != None:
					configureresgroups = configureres.groups()
					ac_init_pos = configureaclines.find('AC_INIT(')
					lineno = configureaclines.count('\n', 0, ac_init_pos) + 1
					cursor.execute('''insert into extracted_string (stringidentifier, checksum, language, linenumber) values (?,?,?,?)''', (configureresgroups[0], filehash, language, lineno))

	if license:
		ninkaconn = sqlite3.connect(ninkacomments, check_same_thread = False)
		ninkacursor = ninkaconn.cursor()

		licenseconn = sqlite3.connect(licensedb, check_same_thread = False)
		licensecursor = licenseconn.cursor()
		licensecursor.execute('PRAGMA synchronous=off')

		ignorefiles = set()

		## if authlicensedb is not empty see if the checksum can be found in this database
		if authlicensedb != None:
			authlicenseconn = sqlite3.connect(authlicensedb, check_same_thread = False)
			authlicensecursor = authlicenseconn.cursor()
			authlicensecursor.execute('PRAGMA synchronous=off')
			## TODO: check for presence of licenses

			## then check for every file in filestoscan to see if they are already in authlicensedb
			for f in filestoscan:
				authlicensecursor.execute("select distinct * from licenses where checksum=?", (f[5],))
				authlicenses = authlicensecursor.fetchall()
				if len(authlicenses) != 0:
					for a in authlicenses:
						licensecursor.execute("insert into licenses values (?,?,?,?)", a)
					licenseconn.commit()
					ignorefiles.add(f[5])
			authlicensecursor.close()
			authlicenseconn.close()

		if len(ignorefiles) != 0:
			filtered_files = filter(lambda x: x[5] not in ignorefiles, filestoscan)
			filtered_files_fossology = filter(lambda x: x[5] not in ignorefiles, filestoscan_fossology)
		else:
			filtered_files = filestoscan
			filtered_files_fossology = filestoscan_fossology

		if 'patch' in languages:
			## patch files should not be scanned for license information
			comments_results = pool.map(extractcomments, map(lambda x: x+ (brokenninka,), filter(lambda x: x[4] != 'patch', filtered_files)), 1)
		else:
			comments_results = pool.map(extractcomments, map(lambda x: x + (brokenninka,), filtered_files), 1)
		commentshash = {}
		commentshash2 = {}
		for c in comments_results:
			if commentshash.has_key(c[0]):
				continue
			else:
				commentshash[c[0]] = c[1]
			if commentshash2.has_key(c[1]):
				commentshash2[c[1]].append(c[0])
			else:
				commentshash2[c[1]] = [c[0]]

		licensefilestoscan = []
		for c in commentshash2:
			ninkacursor.execute('''select license, version from ninkacomments where checksum=?''', (c,))
			res = ninkacursor.fetchall()
			if len(res) > 0:
				## store all the licenses that are already known for this comment
				for r in res:
					(filelicense, scannerversion) = r
					for f in commentshash2[c]:
						## only use this if there actually are duplicates
						#licensecursor.execute('''delete from licenses where checksum = ? and license = ? and scanner = ? and version = ?''', (f, filelicense, "ninka", scannerversion))
						licensecursor.execute('''insert into licenses (checksum, license, scanner, version) values (?,?,?,?)''', (f, filelicense, "ninka", scannerversion))
			else:
				licensefilestoscan.append(commentshash2[c][0])
		licenseconn.commit()

		licensescanfiles = []

		for l in licensefilestoscan:
			licensescanfiles.append((filehashes[l][0][0], filehashes[l][0][1], l, ninkaversion, brokenninka))
		license_results = pool.map(runfullninka, licensescanfiles, 1)

		## we now know the licenses for files we didn't know before. So:
		## 1. find the corresponding commentshash
		## 2. store the licenses for this file, plus for the commentshash
		## 3. for each file that has the same commentshash, store the license as well
		for l in license_results:
			licenses = l[1]
			for license in licenses:
				ninkacursor.execute('''insert into ninkacomments (checksum, license, version) values (?,?,?)''', (commentshash[l[0]], license, ninkaversion))
				for f in commentshash2[commentshash[l[0]]]:
					licensecursor.execute('''insert into licenses (checksum, license, scanner, version) values (?,?,?,?)''', (f, license, "ninka", ninkaversion))
		licenseconn.commit()
		ninkaconn.commit()

		## cleanup
		ninkacursor.close()
		ninkaconn.close()

		## TODO: sync names of licenses as found by FOSSology and Ninka
		nomoschunks = extractconfig['nomoschunks']
		fossology_chunks = []
		if 'patch' in languages:
			fossyfiles = filter(lambda x: x[4] != 'patch', filtered_files_fossology)
		else:
			fossyfiles = filtered_files_fossology
		for i in range(0,len(fossyfiles),nomoschunks):
			fossology_chunks.append((fossyfiles[i:i+nomoschunks]))
		fossology_res = filter(lambda x: x != None, pool.map(licensefossology, fossology_chunks, 1))
		## this requires FOSSology 2.3.0 or later
		p2 = subprocess.Popen(["/usr/share/fossology/nomos/agent/nomossa", "-V"], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
		(stanout, stanerr) = p2.communicate()
		res = re.match("nomos build version: ([\d\.]+) ", stanout)
		if res != None:
			fossology_version = res.groups()[0]
		else:
			## hack for not working version number in 2.4.0
			fossology_version = '2.4.0'

		## now combine the results for each file, which might have been obtained from several files
		filehash_to_license = {}
		for f in fossology_res:
			for ff in f:
				(filehash, fres) = ff
				if filehash in filehash_to_license:
					filehash_to_license[filehash].update(fres)
				else:
					filehash_to_license[filehash] = fres


		for filehash in filehash_to_license:
			fres = filehash_to_license[filehash]
			for license in fres:
				if license == 'No_license_found' and len(fres) > 1:
					continue
				#licensecursor.execute('''delete from licenses where checksum = ? and license = ? and scanner = ? and version = ?''', (filehash, license, "fossology", fossology_version))
				licensecursor.execute('''insert into licenses (checksum, license, scanner, version) values (?,?,?,?)''', (filehash, license, "fossology", fossology_version))
		licenseconn.commit()
		licensecursor.close()
		licenseconn.close()

	## extract copyrights
	if copyrights:
		licenseconn = sqlite3.connect(licensedb, check_same_thread = False)
		licenseconn.text_factory = str
		licensecursor = licenseconn.cursor()
		licensecursor.execute('PRAGMA synchronous=off')

		ignorefiles = set()
		## if authlicensedb is not empty see if the checksum can be found in this database
		if authlicensedb != None:
			authlicenseconn = sqlite3.connect(authlicensedb, check_same_thread = False)
			authlicensecursor = authlicenseconn.cursor()
			authlicensecursor.execute('PRAGMA synchronous=off')
			## TODO: check for presence of extracted_copyright

			## then check for every file in filestoscan to see if they are already in authlicensedb
			for f in filestoscan:
				authlicensecursor.execute("select distinct * from extracted_copyright where checksum=?", (f[5],))
				authlicenses = authlicensecursor.fetchall()
				if len(authlicenses) != 0:
					for a in authlicenses:
						licensecursor.execute("insert into extracted_copyright values (?,?,?,?)", a)
					licenseconn.commit()
					ignorefiles.add(f[5])
			authlicensecursor.close()
			authlicenseconn.close()

		if len(ignorefiles) != 0:
			filtered_files = filter(lambda x: x[5] not in ignorefiles, filestoscan_fossology)
		else:
			filtered_files = filestoscan_fossology

		if 'patch' in languages:
			## patch files should not be scanned for copyright information
			copyrightsres = pool.map(extractcopyrights, filter(lambda x: x[4] != 'patch', filtered_files), 1)
		else:
			copyrightsres = pool.map(extractcopyrights, filtered_files, 1)
		if copyrightsres != None:
			if pythonfiles != []:
				## reconstruct the right
				pass
			for c in filter(lambda x: x != None, copyrightsres):
				(filehash, cres) = c
				for cr in cres:
					## OK, this delete is *really* stupid because we don't have an index for this
					## combination of parameters.
					#licensecursor.execute('''delete from extracted_copyright where checksum = ? and copyright = ? and type = ? and byteoffset = ?''', (filehash, cr[1], cr[0], cr[2]))
					licensecursor.execute('''insert into extracted_copyright (checksum, copyright, type, byteoffset) values (?,?,?,?)''', (filehash, cr[1], cr[0], cr[2]))
		licenseconn.commit()
		licensecursor.close()
		licenseconn.close()

	## now clean up the temporary Python files
	if pythonfiles != []:
		for p in pythonres:
			if p[2]['commentsfile'] != None:
				os.unlink(os.path.join(p[2]['unpackdir'], p[2]['commentsfile']))
			if p[2]['stringsfile'] != None:
				os.unlink(os.path.join(p[2]['unpackdir'], p[2]['stringsfile']))

	## extract configuration from the Linux kernel Makefiles
	## store two things:
	## 1. if it is a path/subdir, store subdir + configuration
	##    making it searchable by subdir
	## 2. if it is an objectfile, store name of source(!) file + configuration
	##    making it searchable by source file
	## These can and will overlap
	if package == 'linux':
		(makefileresults, kconfigresults, moduleresults) = extractkernelconfiguration(srcdir)
		filehashtomodule = {}
		for res in makefileresults:
			pathstring = res[0]
			configstring = res[1]
			cursor.execute('''insert into kernel_configuration(configstring, filename, version) values (?, ?, ?)''', (configstring, pathstring, version))
		for res in moduleresults:
			(kernelfilename, modulename) = res
			if filetohash.has_key(kernelfilename):
				if filehashtomodule.has_key(filetohash[kernelfilename]['sha256']):
					filehashtomodule[filetohash[kernelfilename]['sha256']].append(modulename)
				else:
					filehashtomodule[filetohash[kernelfilename]['sha256']] = [modulename]
		conn.commit()

	if security:
		securityconn = sqlite3.connect(securitydb, check_same_thread = False)
		securityc = securityconn.cursor()
		securityc.execute('PRAGMA synchronous=off')

	for extractres in extracted_results:
		(filehash, language, origlanguage, stringres, moduleres, results, securityresults) = extractres
		if security:
			for res in securityresults:
				(securitybug, linenumber, function) = res
				securityc.execute('''insert into security_cert (checksum, securitybug, linenumber, function, whitelist) values (?,?,?,?,?)''', (filehash, securitybug, linenumber, function, False))
		for res in stringres:
			(pstring, linenumber) = res
			cursor.execute('''insert into extracted_string (stringidentifier, checksum, language, linenumber) values (?,?,?,?)''', (pstring, filehash, language, linenumber))
		if moduleres.has_key('parameters'):
			for res in moduleres['parameters']:
				(pstring, ptype) = res
				if filehashtomodule.has_key(filehash):
					modulenames = filehashtomodule[filehash]
					for modulename in modulenames:
						cursor.execute('''insert into kernelmodule_parameter (checksum, modulename, paramname, paramtype) values (?,?,?,?)''', (filehash, modulename, pstring, ptype))
				else:
					cursor.execute('''insert into kernelmodule_parameter (checksum, modulename, paramname, paramtype) values (?,?,?,?)''', (filehash, None, pstring, ptype))
		if moduleres.has_key('alias'):
			for res in moduleres['alias']:
				if filehashtomodule.has_key(filehash):
					modulenames = filehashtomodule[filehash]
					for modulename in modulenames:
						cursor.execute('''insert into kernelmodule_alias (checksum, modulename, alias) values (?,?,?)''', (filehash, modulename, res))
				else:
					cursor.execute('''insert into kernelmodule_alias (checksum, modulename, alias) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('author'):
			for res in moduleres['author']:
				if filehashtomodule.has_key(filehash):
					modulenames = filehashtomodule[filehash]
					for modulename in modulenames:
						cursor.execute('''insert into kernelmodule_author (checksum, modulename, author) values (?,?,?)''', (filehash, modulename, res))
				else:
					cursor.execute('''insert into kernelmodule_author (checksum, modulename, author) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('descriptions'):
			for res in moduleres['descriptions']:
				if filehashtomodule.has_key(filehash):
					modulenames = filehashtomodule[filehash]
					for modulename in modulenames:
						cursor.execute('''insert into kernelmodule_description (checksum, modulename, description) values (?,?,?)''', (filehash, modulename, res))
				else:
					cursor.execute('''insert into kernelmodule_description (checksum, modulename, description) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('firmware'):
			for res in moduleres['firmware']:
				if filehashtomodule.has_key(filehash):
					modulenames = filehashtomodule[filehash]
					for modulename in modulenames:
						cursor.execute('''insert into kernelmodule_firmware (checksum, modulename, firmware) values (?,?,?)''', (filehash, modulename, res))
				else:
					cursor.execute('''insert into kernelmodule_firmware (checksum, modulename, firmware) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('license'):
			for res in moduleres['license']:
				if filehashtomodule.has_key(filehash):
					modulenames = filehashtomodule[filehash]
					for modulename in modulenames:
						cursor.execute('''insert into kernelmodule_license (checksum, modulename, license) values (?,?,?)''', (filehash, modulename, res))
				else:
					cursor.execute('''insert into kernelmodule_license (checksum, modulename, license) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('versions'):
			for res in moduleres['versions']:
				if filehashtomodule.has_key(filehash):
					modulenames = filehashtomodule[filehash]
					for modulename in modulenames:
						cursor.execute('''insert into kernelmodule_version (checksum, modulename, version) values (?,?,?)''', (filehash, modulename, res))
				else:
					cursor.execute('''insert into kernelmodule_version (checksum, modulename, version) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('param_descriptions'):
			for res in moduleres['param_descriptions']:
				if filehashtomodule.has_key(filehash):
					modulenames = filehashtomodule[filehash]
					for modulename in modulenames:
						cursor.execute('''insert into kernelmodule_parameter_description (checksum, modulename, paramname, description) values (?,?,?,?)''', (filehash, modulename) + res)
				else:
					cursor.execute('''insert into kernelmodule_parameter_description (checksum, modulename, paramname, description) values (?,?,?,?)''', (filehash, None) + res)

		if language == 'C':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'function':
					cursor.execute('''insert into extracted_function (checksum, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
				elif nametype == 'kernelfunction':
					cursor.execute('''insert into extracted_function (checksum, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, 'linuxkernel', linenumber))
				else:
					cursor.execute('''insert into extracted_name (checksum, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, language, linenumber))
		elif language == 'C#':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'method':
					cursor.execute('''insert into extracted_function (checksum, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
		elif language == 'Java':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'method':
					cursor.execute('''insert into extracted_function (checksum, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
				else:
					cursor.execute('''insert into extracted_name (checksum, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, language, linenumber))

		elif language == 'PHP':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'function':
					cursor.execute('''insert into extracted_function (checksum, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
				else:
					cursor.execute('''insert into extracted_name (checksum, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, language, linenumber))

		elif language == 'Python':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'function' or nametype == 'member':
					cursor.execute('''insert into extracted_function (checksum, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
				else:
					cursor.execute('''insert into extracted_name (checksum, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, language, linenumber))
		elif language == 'Ruby':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'method':
					cursor.execute('''insert into extracted_function (checksum, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
				else:
					cursor.execute('''insert into extracted_name (checksum, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, language, linenumber))
	conn.commit()
	if security:
		securityconn.commit()
		securityc.close()
		securityconn.close()

	if update:
		updatefile = open(newlist, 'a')
		for extractres in extracted_results:
			(filehash, language, origlanguage, stringres, moduleres, results) = extractres
			updatefile.write("%s\t%s\n" % (filehash, language))
		for f in filestoscanextra:
			(package, version, path, filename, language, filehash) = f
			updatefile.write("%s\t%s\n" % (filehash, language))
		updatefile.close()
	for i in insertfiles:
		filehash = i[1]['sha256']
		cursor.execute('''insert into processed_file (package, version, pathname, checksum, filename) values (?,?,?,?,?)''', (package, version, i[0], filehash, os.path.basename(i[0])))
		if len(i[1]) != 1:
			cursor.execute('''select sha256 from hashconversion where sha256=? LIMIT 1''', (filehash,))
			if len(cursor.fetchall()) == 0:
				cursor.execute('''insert into hashconversion (sha256) values (?)''', (filehash,))
				for k in i[1].keys():
					if k == 'sha256':
						continue
					query = "update hashconversion set %s='%s' where sha256=?" % (k, i[1][k])
					cursor.execute(query, (filehash,))
	conn.commit()

	if batarchive:
		if not os.path.exists(os.path.join(srcdir, "MANIFEST.BAT")):
			return
		manifest = os.path.join(srcdir, "MANIFEST.BAT")
		manifestfile = open(manifest)
		manifestlines = manifestfile.readlines()
		manifestfile.close()
		inheader = False
		infiles = False
		inextensions = False
		for i in manifestlines:
			if "START META" in i:
				inheader = True
				continue
			if "END META" in i:
				inheader = False
				continue
			if "START DUPLICATE_FILES" in i:
				infiles = True
				continue
			if "END DUPLICATE_FILES" in i:
				infiles = False
				continue
			if "START EXTENSIONS" in i:
				inextensions = True
				continue
			if "END EXTENSIONS" in i:
				inextensions = False
				continue
			if infiles:
				(archivepath, archivechecksum, archiveversion) = i.strip().split('\t')
				cursor.execute('''insert into processed_file (package, version, pathname, checksum, filename) values (?,?,?,?,?)''', (package, version, archivepath, archivechecksum, os.path.basename(archivepath)))
		conn.commit()

	return (scanfile_result)

## extract comments in parallel
def extractcomments((package, version, i, p, language, filehash, ninkaversion, extractconfig, brokenninka)):
	## first generate a .comments file with Ninka and see if it is already
	## known. This is because often license headers are identical, and
	## there is no need to rescan the files if the headers are identical.
	## For gtk+ 2.20.1 scanning time dropped with about 25%.
	ninkaenv = os.environ.copy()
	ninkabasepath = '/gpl/ninka/ninka-%s' % ninkaversion
	ninkaenv['PATH'] = ninkaenv['PATH'] + ":%s/comments" % ninkabasepath

	broken = False
	if brokenninka:
		for b in ['$', ' ', ';', '(', ')', '[', ']', '`', '\'', '\\', '&']:
			if b in i:
				broken = True
				break
			if b in p:
				broken = True
				break
	if broken:
		while True:
			ninkatmp = tempfile.mkstemp()
			os.fdopen(ninkatmp[0]).close()
			if '$' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if ' ' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if ';' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '(' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if ')' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '[' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if ']' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '`' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '\'' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '\\' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '&' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			break
		shutil.copy(os.path.join(i,p), ninkatmp[1])
		p1 = subprocess.Popen(["%s/ninka.pl" % ninkabasepath, "-c", ninkatmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ninkaenv)
	else:
		p1 = subprocess.Popen(["%s/ninka.pl" % ninkabasepath, "-c", os.path.join(i, p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ninkaenv)

	(stanout, stanerr) = p1.communicate()
	if broken:
		os.unlink(ninkatmp[1])
		commentsfile = "%s.comments" % ninkatmp[1]
	else:
		commentsfile = os.path.join(i, "%s.comments" % p)
	if not os.path.exists(commentsfile):
		for j in ['$', ';', ' ', '(', ')', '[', ']', '`', '\'', '\\', '&']:
			if j in p:
				p = p.replace(j, '\%s' % j)
		commentsfile = os.path.join(i, "%s.comments" % p)
	scanfile = open(commentsfile, 'r')
	ch = hashlib.new('sha256')
	ch.update(scanfile.read())
	scanfile.close()
	commentshash = ch.hexdigest()
	if broken:
		os.unlink(commentsfile)
	os.unlink(commentsfile)
	return (filehash, commentshash)

def runfullninka((i, p, filehash, ninkaversion, brokenninka)):
	ninkaenv = os.environ.copy()
	ninkabasepath = '/gpl/ninka/ninka-%s' % ninkaversion
	ninkaenv['PATH'] = ninkaenv['PATH'] + ":%s/comments" % ninkabasepath

	ninkares = set()

	broken = False
	if brokenninka:
		for b in ['$', ' ', ';', '(', ')', '[', ']', '`', '\'', '\\', '&']:
			if b in i:
				broken = True
				break
			if b in p:
				broken = True
				break
	if broken:
		while True:
			ninkatmp = tempfile.mkstemp()
			os.fdopen(ninkatmp[0]).close()
			if '$' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if ' ' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if ';' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '(' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if ')' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '[' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if ']' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '`' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '\'' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '\\' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			if '&' in ninkatmp[1]:
				os.unlink(ninkatmp[1])
				continue
			break
		shutil.copy(os.path.join(i,p), ninkatmp[1])
		p2 = subprocess.Popen(["%s/ninka.pl" % ninkabasepath, "-d", ninkatmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ninkaenv)
	else:
		p2 = subprocess.Popen(["%s/ninka.pl" % ninkabasepath, os.path.join(i, p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ninkaenv)
	(stanout, stanerr) = p2.communicate()
	if broken:
		os.unlink(ninkatmp[1])
		## cleanup
		if os.path.exists("%s.license" % ninkatmp[1]):
			os.unlink("%s.license" % ninkatmp[1])
	## TODO: handle cases with ';' in filename
	ninkasplit = stanout.strip().split(';')[1:]
	## filter out the licenses that can't be determined.
	if ninkasplit[0] == '':
		ninkares = set(['UNKNOWN'])
	else:
		licenses = ninkasplit[0].split(',')
		ninkares = set(licenses)
	return (filehash, ninkares)

## extract copyrights from the file. Previous versions of this method invoked the
## FOSSology copyright agent. This method mimics the behaviour of the FOSSology
## copyright agent.
def extractcopyrights((package, version, i, p, language, filehash, ninkaversion, extractconfig)):
	filepath = os.path.join(i,p)
	srcfile = open(filepath, 'r')
	srcdata = srcfile.read()
	srcfile.close()
	## FOSSology uses lowercase data
	srcdata = srcdata.lower()
	copyrightsres = []
	examples = ["example.org", "example.com", "example.net"]
	## first the e-mail address results
	## TODO: more checks from http://tools.ietf.org/html/rfc5321
	if '@' in srcdata:
		res = fossologyemailre.findall(srcdata)
		offset = 0
		for e in res:
			exampleskip = False
			## ignore all e-mail addresses from example.com/net/org
			for em in examples:
				if "@%s" % em in e:
					exampleskip = True
					break
				if e.endswith('.%s' % em):
					exampleskip = True
					break
			if exampleskip:
				continue
			if '..' in e:
				## double dots not allowed in mail addresses
				continue
			if e.startswith('.'):
				continue
			offset = srcdata.find(e, offset)
			copyrightsres.append(('email', e, offset))
			offset += 1

	## hack for now.
	if language == 'JavaScript':
		return (filehash, copyrightsres)
	## then URLs
	if '://' in srcdata:
		res = fossologyurlre.finditer(srcdata)
		urlcutoff = extractconfig['urlcutoff']
		offset = 0
		for urlres in res:
			e = urlres.groups()[0]

			offset = srcdata.find(e, offset)

			## parse the hostname and see if there is nonsense in there
			try:
				hostname = urlparse.urlparse(e).hostname
			except Exception, ex:
				continue
			if hostname == None:
				## something is going on here, probably some characters preceding
				## the result. TODO: find out what to do with this
				continue

			## hostnames should at least have a '.' in the name
			if not '.' in hostname:
				continue
			if hostname == '127.0.0.1':
				continue
			if hostname in examples:
				continue
			if "example" in e:
				## filter out anything with example.com/net/org
				exampleskip = False
				for em in examples:
					if hostname.endswith(".%s" % em):
						exampleskip = True
						break
				if exampleskip:
					continue
			## filter out some more things. This needs to be much expanded
			## first private addresses
			if hostname.startswith('192.168.'):
				continue
			if hostname.startswith('10.'):
				continue
			#if hostname.startswith('172.'):
			#	continue
			## some IPv6 things
			if hostname == "[::1]":
				continue
			if hostname == "::1":
				continue
			## cut off URLs that are larger than a certain limit
			if len(e) > urlcutoff:
				continue
			copyrightsres.append(('url', e, offset))
			offset += 1
	## then statements. This is a TODO.
	return (filehash, copyrightsres)

def licensefossology((packages)):
	## Also run FOSSology. This requires that the user has enough privileges to actually connect to the
	## FOSSology database, for example by being in the correct group.
	fossologyres = []
	fossscanfiles = map(lambda x: os.path.join(x[2], x[3]), packages)
	scanargs = ["/usr/share/fossology/nomos/agent/nomossa"] + fossscanfiles
	p2 = subprocess.Popen(scanargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	(stanout, stanerr) = p2.communicate()
	if "FATAL" in stanout:
		## TODO: better error handling
		return None
	else:
		fosslines = stanout.strip().split("\n")
		for j in range(0,len(fosslines)):
			fossysplit = fosslines[j].strip().rsplit(" ", 1)
			licenses = fossysplit[-1].split(',')
			fossologyres.append((packages[j][5], set(licenses)))
	return fossologyres

## TODO: get rid of ninkaversion before we call this method
## TODO: process more files at once to reduce overhead of calling ctags
def extractidentifiers((package, version, i, p, language, filehash, ninkaversion, extractconfig, unpackenv, security, authdb, pkgconf)):
	newlanguage = language

	if 'TMPDIR' in unpackenv:
		unpackdir = unpackenv['TMPDIR']
	else:
		unpackdir = None

	scanidentifiers = True
	if authdb != None:
		if not 'alwaysscan' in pkgconf:
			authconn = sqlite3.connect(authdb)
			authcursor = authconn.cursor()
			moduleres = {}
			authres = authcursor.execute('select distinct package from processed_file where checksum=?', (filehash,)).fetchall()
			if len(authres) != 0:
				filterres = len(filter(lambda x: x[0] == 'linux', authres))
				if filterres == 0:
					scanidentifiers = False
					stringres = []
					funcvarresults = set()
					## first get all string identifiers
					authcursor.execute('select stringidentifier, language, linenumber from extracted_string where checksum=?', (filehash,))
					for f in authcursor.fetchall():
						(stringidentifier, newlanguage, linenumber) = f
						stringres.append((stringidentifier, linenumber))
					## then get all function names/variable names
					authcursor.execute('select functionname, language, linenumber from extracted_function where checksum=?', (filehash,))
					for f in authcursor.fetchall():
						(cname, newlanguage, linenumber) = f
						if newlanguage in ['C', 'Python', 'PHP']:
							nametype = 'function'
						elif newlanguage == 'linuxkernel':
							scanidentifiers = True
							newlanguage = 'C'
							#nametype = 'kernelfunction'
							break
						else:
							nametype = 'method'
						funcvarresults.add((cname, linenumber, nametype))

					if not scanidentifiers:
						authcursor.execute('select name, language, type, linenumber from extracted_name where checksum=?', (filehash,))
						for f in authcursor.fetchall():
							(cname, newlanguage, nametype, linenumber) = f
							funcvarresults.add((cname, linenumber, nametype))
			authcursor.close()
			authconn.close()

	## always scan security results for now
	securityresults = []
	if security:
		if language == 'C':
			securityresults = securityScan(i,p)

	if not scanidentifiers:
		## no scanning is needed, so just pass the results that were extracted from the database instead
		return (filehash, newlanguage, language, stringres, moduleres, funcvarresults, securityresults)

	if language == 'patch':
		## The file is a patch/diff file. Take the following steps to deal with it:
		## 1. find out what kind of diff file it is. Stick to dealing with a unified diff file for now
		## 2. find out how many files are inside the diff
		## 3. find out which files these manipulate and if these would have been processed
		## 4. find out which lines are added to the files
		## 5. set newlanguage to the orginal language of the patched file, if possible
		patchfile = open(os.path.join(i,p))
		patchcontent = patchfile.read()
		patchfile.close()
		patchlines = patchcontent.split('\n')

		unified = False

		## keep track of how many patches are in the file
		#unifiedpatches = 0
		addlines = []
		unifiedmin = False
		unifiedplus = False
		skippatch = False
		oldfile = ""
		newfile = ""

		## keep track of how many lines are in the patch
		linecounter = 0
		for l in patchlines:
			linecounter += 1
			if unifiedmin and unifiedplus:
				## at least one patch in the file seems to be valid
				unified = True
			if l.startswith('---'):
				if unifiedmin:
					## this should not happen, malformed patch
					## unclear what to do with this so ignore for now
					pass
				unifiedmin = True
				## reset some values
				skippatch = False
				unifiedplus = False
				patchsplits = l.split()
				if len(patchsplits) < 2:
					## this should not happen, malformed patch
					skippatch = True
					continue
				oldfile = os.path.basename(patchsplits[1])
				continue
			if l.startswith('+++'):
				if not unifiedmin:
					## this should not happen, malformed patch
					skippatch = True
					continue
				## TODO: the line starting with '+++' should follow the line with '---' immediately
				## assume for now that this happens
				patchsplits = l.split()
				if len(patchsplits) < 2:
					## this should not happen, malformed patch
					skippatch = True
					continue

				process = False
				newfile = os.path.basename(patchsplits[1])

				## check whether or not the file is an interesting file. TODO: fix for
				## of patches for package specific extensions
				if newfile == oldfile:
					## easy case since both file names have the same name.
					p_nocase = oldfile.lower()
					for extension in extensions.keys():
						if (p_nocase.endswith(extension)) and not p_nocase == extension:
							process = True
							newlanguage = extensions[extension]
							break
				else:
					## either oldfile or newfile needs to match
					p_nocase = oldfile.lower()
					for extension in extensions.keys():
						if (p_nocase.endswith(extension)) and not p_nocase == extension:
							process = True
							newlanguage = extensions[extension]
							break
					if not process:
						p_nocase = newfile.lower()
						for extension in extensions.keys():
							if (p_nocase.endswith(extension)) and not p_nocase == extension:
								process = True
								newlanguage = extensions[extension]
								break

				if not process:
					skippatch = True
					continue
				unifiedplus = True
			if not unifiedmin:
				## first few lines of the patch
				continue
			if skippatch:
				continue
			## now process the lines
			if l.startswith ('-'):
				continue
			if l.startswith (' '):
				continue
			## store the current line number in a list of lines that start with '+'
			addlines.append(linecounter)

		if not unified:
			stringres = []
			moduleres = {}
		else:
			## TODO: clean up
			(patchstringres, moduleres) = extractsourcestrings(p, i, language, package, unpackdir)
			stringres = []
			for sql in patchstringres:
				(res, linenumber) = sql
				if linenumber in addlines:
					stringres.append(sql)
	else:
		(stringres, moduleres) = extractsourcestrings(p, i, language, package, unpackdir)

	funcvarresults = set()

	## extract function names using ctags, except functions from
	## the Linux kernel, since it will never be dynamically linked
	## but variable names are sometimes stored in a special ELF
	## section called __ksymtab__strings
	# (name, linenumber, type)

	if (newlanguage in ['C', 'C#', 'Java', 'PHP', 'Python', 'Ruby']):

		p2 = subprocess.Popen(["ctags", "-f", "-", "-x", '--language-force=%s' % newlanguage, os.path.join(i, p)], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=unpackenv)
		(stanout2, stanerr2) = p2.communicate()
		if p2.returncode != 0:
			pass
		elif stanout2.strip() == "":
			pass
		else:
			stansplit = stanout2.strip().split("\n")
			for res in stansplit:
				csplit = res.strip().split()
				if filter(lambda x: x not in string.printable, csplit[0]) != "":
					continue
				identifier = csplit[0]
				tagtype = csplit[1]
				if newlanguage == 'Java':
					if tagtype not in ['method', 'class', 'field']:
						continue
				elif newlanguage == 'C#':
					if tagtype not in ['method']:
						continue
				elif newlanguage == 'PHP':
					if tagtype not in ['variable', 'function', 'class']:
						continue
				elif newlanguage == 'Python':
					if tagtype not in ['variable', 'member', 'function', 'class']:
						continue
				elif newlanguage == 'Ruby':
					## TODO: fix for "singleton method"
					if tagtype not in ['module', 'method', 'class']:
						continue
				linenumber = int(csplit[2])
				if language == 'patch':
					if not linenumber in addlines:
						continue
				if newlanguage == 'C':
					if package == 'linux':
						## for the Linux kernel the variable names are sometimes
						## stored in a special ELF section __ksymtab_strings
						if tagtype == 'variable':
							## TODO: is this correct?
							if len(csplit) < 5:
								funcvarresults.add((identifier, linenumber, 'variable'))
							if "EXPORT_SYMBOL_GPL" in csplit[4]:
								funcvarresults.add((identifier, linenumber, 'gplkernelsymbol'))
							elif "EXPORT_SYMBOL" in csplit[4]:
								funcvarresults.add((identifier, linenumber, 'kernelsymbol'))
							else:
								## TODO: is this correct?
								funcvarresults.add((identifier, linenumber, 'variable'))
						elif tagtype == 'function':
							funcvarresults.add((identifier, linenumber, 'kernelfunction'))
					else:
						if tagtype == 'variable':
							if len(csplit) < 5:
								funcvarresults.add((identifier, linenumber, 'variable'))
							else:
								if "EXPORT_SYMBOL_GPL" in csplit[4]:
									funcvarresults.add((identifier, linenumber, 'gplkernelsymbol'))
								elif "EXPORT_SYMBOL" in csplit[4]:
									funcvarresults.add((identifier, linenumber, 'kernelsymbol'))
								else:
									funcvarresults.add((identifier, linenumber, 'variable'))
						elif tagtype == 'function':
							funcvarresults.add((identifier, linenumber, 'function'))
				if newlanguage == 'C#':
					for i in ['method']:
						if tagtype == i:
							funcvarresults.add((identifier, linenumber, i))
				if newlanguage == 'Java':
					for i in ['method', 'class', 'field']:
						if tagtype == i:
							funcvarresults.add((identifier, linenumber, i))
				if newlanguage == 'PHP':
					## ctags does not nicely handle comments, so sometimes there are
					## false positives.
					for i in ['variable', 'function', 'class']:
						if tagtype == i:
							funcvarresults.add((identifier, linenumber, i))
				if newlanguage == 'Python':
					## TODO: would be nice to store members with its surrounding class
					for i in ['variable', 'member', 'function', 'class']:
						if identifier == '__init__':
							break
						if tagtype == i:
							funcvarresults.add((identifier, linenumber, i))
							break
				if newlanguage == 'Ruby':
					for i in ['module', 'method', 'class']:
						if tagtype == i:
							funcvarresults.add((identifier, linenumber, i))

	## return all results, as well as the original language, which is important in the case of 'patch'
	return (filehash, newlanguage, language, stringres, moduleres, funcvarresults, securityresults)

## Scan the file for possible security bugs, try to classify them according to the
## CERT secure coding standard and possibly some other standards.
def securityScan(i,p):
	## first slurp in the file
	fc = open(os.path.join(i,p), 'r')
	filecontent = fc.read()
	fc.close()
	smells = []

	## Then check for a few smells
	## ENV33-C
	res = resystem.search(filecontent)
	if res != None:
		## additional checks to weed out false positives
		## find the line where the command can be found
		## with a crude hack
		systempos = -1 
		while True:
			systempos = filecontent.find('system(', systempos + 1)
			if systempos == -1:
				break
			lineno = filecontent.count('\n', 0, systempos) + 1
			smells.append(('ENV33-C', lineno, 'system'))
	for m in msc24checks:
		res = m[0].search(filecontent)
		if res != None:
			## additional checks to weed out false positives
			## find the line where the command can be found
			## with a crude hack
			systempos = -1 
			while True:
				systempos = filecontent.find('%s(' % m[1], systempos + 1)
				if systempos == -1:
					break
				lineno = filecontent.count('\n', 0, systempos) + 1
				smells.append(('MSC24-C', lineno, m[1]))
	return smells

## Extract strings using xgettext. Apparently this does not always work correctly. For example for busybox 1.6.1:
## $ xgettext -a -o - fdisk.c
##  xgettext: Non-ASCII string at fdisk.c:203.
##  Please specify the source encoding through --from-code.
## We fix this by rerunning xgettext with --from-code=utf-8
## The results might not be perfect, but they are acceptable.
## TODO: use version from bat/extractor.py
## TODO: process more files at once to reduce overhead of calling xgettext
def extractsourcestrings(filename, filedir, language, package, unpackdir):
	remove_chars = ["\\a", "\\b", "\\v", "\\f", "\\e", "\\0"]
	stringres = []

	## moduleres is only used for storing information about Linux kernel modules
	## TODO: fix for out of tree kernel modules
	moduleres = {}

	## For files that likely are in the 'C' family first check for unprintable
	## characters like \0. xgettext doesn't like these and will stop as soon as it
	## encounters one of these characters, possibly missing out on some very significant
	## strings that might end up in the binary.
	## Solution: First replace these characters with \n, then run xgettext.
	## TODO: fix for octal values, like \010

	scanfile = os.path.join(filedir, filename)

	if language == 'C':
		changed = False
		openscanfile = open(os.path.join(filedir, filename))
		filecontents = openscanfile.read()
		openscanfile.close()

		## suck in the file and look for __ATTR and friends, since the
		## first parameter is given to stringify(). __ATTR was gradually
		## introduced in kernel 2.6.8.
		if package == 'linux':
			paramres = []
			licenseres = []
			aliasres = []
			authorres = []
			descriptionres = []
			regresults = []
			firmwareres = []
			versionres = []
			paramdescriptionres = []
			for ex in kernelexprs:
				regexres = ex.findall(filecontents)
				if regexres != []:
					regresults = regresults + regexres
			if regresults != []:
				## first filter 'name' and '_name' since those are frequently
				## used in the #define statements for __ATTR etc.
				## The linenumber is set to 0 since using regular expressions
				## it is not easy to find that out unless an extra step is performed.
				## This is something for a future TODO.
				stringres += map(lambda x: (x, 0), filter(lambda x: x != '_name' and x != 'name', list(set(regresults))))
			## Extract a whole bunch of information relating to modules. Using regular expressions is
			## actually not the right way to do it since some of the information is hidden in macros
			## and #defines and what not, so actually the source tree needs to be properly preprocessed
			## first. However, this will do for now.
			## TODO: partially replace with call to xgettext and grep -n for weird accents

			## Both module_param and MODULE_PARM formats were in use at the same time
			## include/linux/moduleparam.h in Linux kernel sources documents various types
			allowedvals= ["bool", "byte", "charp", "int", "uint", "string", "short", "ushort", "long", "ulong"]
			oldallowedvals= ["b", "c", "h", "i", "l", "s"]
			if "module_param" in filecontents:
				## first try module_param()
				regexres = re.findall("module_param\s*\(([\w\d]+),\s*(\w+)", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in allowedvals, regexres)
					for p in parres:
						paramres.append(p)

				## then module_param_named()
				regexres = re.findall("module_param_named\s*\(([\w\d]+),\s*[\w\d]+,\s*(\w+)", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in allowedvals, regexres)
					for p in parres:
						paramres.append(p)

				## then module_param_array()
				regexres = re.findall("module_param_array\s*\(([\w\d]+),\s*(\w+)", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in allowedvals, regexres)
					## oh, this is ugly...does this even work correctly with localised versions?
					parres = map(lambda x: (x[0], "array of %s" % x[1]), parres)
					for p in parres:
						paramres.append(p)

				## then module_param_array_named()
				regexres = re.findall("module_param_array_named\s*\(([\w\d]+),\s*[\w\d]+,\s*(\w+)", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in allowedvals, regexres)
					## oh, this is ugly...does this even work correctly with localised versions?
					parres = map(lambda x: (x[0], "array of %s" % x[1]), parres)
					for p in parres:
						paramres.append(p)

				## finally module_param_string()
				regexres = re.findall("module_param_string\s*\(([\w\d]+),", filecontents, re.MULTILINE)
				if regexres != []:
					parres = map(lambda x: (x, "string"), regexres)
					for p in parres:
						paramres.append(p)

			if "MODULE_PARM" in filecontents:
				regexres = re.findall("MODULE_PARM\s*\(([\w\d]+),\s*\"([\w\d\-]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in oldallowedvals, regexres)
					parres2 = filter(lambda x: x[1] not in oldallowedvals, regexres)
					for p in parres:
						paramres.append(p)
					for p in parres2:
						for v in reoldallowedexprs:
							if v.search(p[1]) != None:
								paramres.append(p)
								break
						## and special case for characters
						#if re.search("c\d+", p[1]) != None:
						if rechar.search(p[1]) != None:
							paramres.append(p)
			moduleres['parameters'] = paramres

			## extract information from the MODULE_ALIAS field
			if "MODULE_ALIAS" in filecontents:
				regexres = re.findall("MODULE_ALIAS\s*\(\s*\"([\w\d:,\-\_\s/\[\]\*]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in set(regexres):
						aliasres.append(p)
			moduleres['alias'] = aliasres

			## extract information from the MODULE_AUTHOR field
			## TODO: this does not work well with accents and characters from various languages
			## TODO: combine with extracted strings to increase quality
			if "MODULE_AUTHOR" in filecontents:
				regexres = re.findall("MODULE_AUTHOR\s*\(\s*\"([\w\d/\s,\.\-:<>@\(\)[\]\+&;'~\\\\]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in set(regexres):
						authorres.append(p)
			moduleres['author'] = authorres

			## extract information from the MODULE_DESCRIPTION field
			## Although these are already stored as generic strings it makes sense to also store them
			## separately with more module information
			## TODO: combine with extracted strings to increase quality
			if "MODULE_DESCRIPTION" in filecontents:
				regexres = re.findall("MODULE_DESCRIPTION\s*\(\s*\"([\w\d/_\(\)\[\]\\\\\!\?;#$%^\*&<>\{\}\':+=\|\-\.,\s]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in set(regexres):
						descriptionres.append(p)
			moduleres['descriptions'] = descriptionres

			## extract information from the MODULE_FIRMWARE field
			if "MODULE_FIRMWARE" in filecontents:
				regexres = re.findall("MODULE_FIRMWARE\s*\(\s*\"([\w\d/_\-\.]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in set(regexres):
						firmwareres.append(p)
			moduleres['firmware'] = firmwareres

			## extract information from the MODULE_LICENSE field
			if "MODULE_LICENSE" in filecontents:
				regexres = re.findall("MODULE_LICENSE\s*\(\s*\"([\w\d/\s]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in set(regexres):
						licenseres.append(p)
			moduleres['license'] = licenseres

			## extract information from the MODULE_VERSION field
			if "MODULE_VERSION" in filecontents:
				regexres = re.findall("MODULE_VERSION\s*\(\s*\"([\w\d/_\-\.\s]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in set(regexres):
						versionres.append(p)
			moduleres['versions'] = versionres

			if "MODULE_PARM_DESC" in filecontents:
				regexres = re.findall("MODULE_PARM_DESC\s*\(\s*([\w\d]+),\s*\"([\w\d/_\(\)\[\]\\\\\!\?;#$%^\*&<>\{\}\':+=\|\-\.,\s]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in set(regexres):
						paramdescriptionres.append(p)
			moduleres['param_descriptions'] = paramdescriptionres

		for r in remove_chars:
			if r in filecontents:
				changed = True
				filecontents = filecontents.replace(r, '\\n')
		if changed:
			tmpscanfile = tempfile.mkstemp(dir=unpackdir)
			os.fdopen(tmpscanfile[0]).close()
			scanfile = tmpscanfile[1]
			openscanfile = open(scanfile, 'w')
			openscanfile.write(filecontents)
			openscanfile.close()

	p1 = subprocess.Popen(['xgettext', '-a', "--omit-header", "--no-wrap", scanfile, '-o', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(stanout, stanerr) = p1.communicate()
	if p1.returncode != 0:
		## analyze stderr first
		if "Non-ASCII" in stanerr:
			## rerun xgettext with a different encoding
			p2 = subprocess.Popen(['xgettext', '-a', "--omit-header", "--no-wrap", "--from-code=utf-8", scanfile, '-o', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			## overwrite stanout
			(stanout, pstanerr) = p2.communicate()
			if p2.returncode != 0:
				return (stringres, moduleres)
	source = stanout 
	lines = []
	linenumbers = []
	linecutoff = 5000

	## escape just once to speed up extraction of filenumbers
	filename_escape = re.escape(os.path.basename(scanfile))

	for l in stanout.split("\n"):
		## skip comments and hints
		if l.startswith("#, "):
			continue
		if l.startswith("#: "):
			## there can actually be more than one entry on a single line
			res = re.findall("%s:(\d+)" % (filename_escape,), l[3:])
			if res != None:
				linenumbers = linenumbers + map(lambda x: int(x), res)
			else:
				linenumbers.append(0)

		if l.startswith("msgid "):
			lines = []
			lines.append(l[7:-1])
		## when we see msgstr "" we have reached the end of a block and we can start
		## processing
		elif l.startswith("msgstr \"\""):
			count = len(linenumbers)
			for xline in lines:
				splits=splitSpecialChars(xline)
				if splits == []:
					continue
				for splitline in splits:
					for line in splitline.split("\\r\\n"):
						for sline in line.split("\\n"):
							## is this really needed?
							sline = sline.replace("\\\n", "")

							## unescape a few values
							sline = sline.replace("\\\"", "\"")
							sline = sline.replace("\\t", "\t")
							sline = sline.replace("\\\\", "\\")
	
							## don't store empty strings, they won't show up in binaries
							## but they do make the database a lot larger
							if sline == '':
								continue
							## don't store strings that are larger or equal to linecutoff
							## as some database engines have trouble processing them
							if len(sline) >= linecutoff:
								continue
							for i in range(0, len(linenumbers)):
								stringres.append((sline, linenumbers[i]))
			linenumbers = []
		## the other strings are added to the list of strings we need to process
		else:
			lines.append(l[1:-1])

	if language == 'C':
		if changed:
			os.unlink(scanfile)
	return (stringres, moduleres)

def checkalreadyscanned((filedir, package, version, filename, origin, downloadurl, batarchive, dbpath, checksum, archivechecksums)):
	resolved_path = os.path.join(filedir, filename)
	try:
		os.stat(resolved_path)
	except:
		print >>sys.stderr, "Can't find %s" % filename
		return None
	if batarchive:
		if archivechecksums.has_key(filename):
			(filehash, package) = archivechecksums[filename]
		else:
			## first extract the MANIFEST.BAT file from the BAT archive
			## TODO: add support for unpackdir
			archivedir = tempfile.mkdtemp()
			tar = tarfile.open(resolved_path, 'r')
			tarmembers = tar.getmembers()
			for i in tarmembers:
				## TODO: sanity check to see if there is a MANIFEST.BAT
				if i.name.endswith('MANIFEST.BAT'):
					tar.extract(i, path=archivedir)
			manifest = os.path.join(archivedir, "MANIFEST.BAT")
			manifestfile = open(manifest)
			manifestlines = manifestfile.readlines()
			manifestfile.close()
			shutil.rmtree(archivedir)
			for i in manifestlines:
				## for later checks the package and filehash are important
				## The rest needs to be overriden later anyway
				if i.startswith('package'):
					package = i.split(':')[1].strip()
				elif i.startswith('sha256'):
					filehash = i.split(':')[1].strip()
					break
	else:
		if checksum != None:
			filehash = checksum['sha256']
		else:
			scanfile = open(resolved_path, 'r')
			h = hashlib.new('sha256')
			h.update(scanfile.read())
			scanfile.close()
			filehash = h.hexdigest()

	conn = sqlite3.connect(dbpath, check_same_thread = False)
	c = conn.cursor()
	## Check if we've already processed this file. If so, we can easily skip it and return.
	c.execute('''select * from processed where checksum=?''', (filehash,))
	if len(c.fetchall()) != 0:
		res = None
	else:
		res = (package, version, filename, origin, filehash, downloadurl, batarchive)
	c.close()
	conn.close()

	return res

def main(argv):
	config = ConfigParser.ConfigParser()

	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")

	## the following options are provided on the commandline
	parser.add_option("-b", "--blacklist", action="store", dest="blacklist", help="path to blacklist file", metavar="FILE")
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-n", "--newlist", action="store", dest="newlist", help="path to file with list to write new hashes to")
	parser.add_option("-t", "--rewritelist", action="store", dest="rewritelist", help="path to rewrite list", metavar="FILE")
	#parser.add_option("-u", "--updatelicense", action="store_true", dest="updatelicense", help="update licenses", default=False)
	parser.add_option("-v", "--verify", action="store_true", dest="verify", help="verify files, don't process (default: false)")
	(options, args) = parser.parse_args()

	## placeholder for now
	options.updatelicense = False

	if options.cfg == None:
		parser.error("Specify configuration file")
	else:
		if not os.path.exists(options.cfg):
			parser.error("Configuration file does not exist")
		try:
			configfile = open(options.cfg, 'r')
		except:
			parser.error("Configuration file not readable")
		config.readfp(configfile)
		configfile.close()

	update = False
	if options.newlist != None:
		if os.path.exists(options.newlist):
			try:
				updatefile = open(options.newlist, 'a')
				updatefile.close()
				update = True
			except:
				print >>sys.stderr, "Cannot open %s for appending", options.newlist
				sys.exit(1)
		else:
			## extra sanity check to see if the parent directory exists.
			## If not, bail out.
			if os.path.exists(os.path.dirname(options.newlist)):
				update = True
			else:
				print >>sys.stderr, "Cannot open %s for appending", options.newlist
				sys.exit(1)

	if options.filedir == None:
		parser.error("Specify dir with files")
	else:
		try:
			filelist = open(os.path.join(options.filedir,"LIST")).readlines()
		except:
			parser.error("'LIST' not found in file dir")

	if options.blacklist != None:
		try:
			blacklistlines = open(options.blacklist).readlines()
		except:
			parser.error("blacklist defined but not found/accessible")
	else:
		blacklistlines = []

	## TODO: fix format for blacklist
	## package version filename origin sha256sum
	## with sha256sum being decisive 
	blacklistsha256sums = []
	for i in blacklistlines:
		try:
			unpacks = i.strip().split()
			(package, version, filename, origin, sha256sum) = unpacks
			blacklistsha256sums.append(sha256sum)
		except Exception, e:
			# oops, something went wrong
			print >>sys.stderr, e

	packageconfig = {}

	## search configuration to see if it is correct and/or not malformed
	## first search for a section called 'extractconfig' with configtype = global
	for section in config.sections():
		if section == "extractconfig":
			try:
				sec = config.get(section, 'scancopyright')
				if sec == 'yes':
					scancopyright = True
				else:
					scancopyright = False
			except:
				scancopyright = False
			try:
				sec = config.get(section, 'scanlicense')
				if sec == 'yes':
					scanlicense = True
				else:
					scanlicense = False
			except:
				scanlicense = False
			try:
				sec = config.get(section, 'scansecurity')
				if sec == 'yes':
					scansecurity = True
				else:
					scansecurity = False
			except:
				scansecurity = False
			try:
				masterdatabase = config.get(section, 'database')
			except:
				print >>sys.stderr, "Database location not defined in configuration file. Exiting..."
				sys.exit(1)
			try:
				sec = config.get(section, 'cleanup')
				if sec == 'yes':
					cleanup = True
				else:
					cleanup = False
			except:
				cleanup = False
			try:
				sec = config.get(section, 'wipe')
				if sec == 'yes':
					wipe = True
				else:
					wipe = False
			except:
				wipe = False
			try:
				sec = config.get(section, 'allfiles')
				if sec == 'yes':
					allfiles = True
				else:
					allfiles = False
			except:
				allfiles = False
			try:
				licensedb = config.get(section, 'licensedb')
			except:
				licensedb = None
			try:
				authlicensedb = config.get(section, 'authlicensedb')
			except:
				authlicensedb = None
			try:
				authdb = config.get(section, 'authdatabase')
			except:
				authdb = None
			try:
				authcopy = config.get(section, 'authcopy').split(':')
			except:
				authcopy = []
			try:
				nomoschunks = int(config.get(section, 'nomoschunks'))
			except:
				nomoschunks = 10
			try:
				ninkacomments = config.get(section, 'ninkacommentsdb')
			except:
				ninkacomments = None
			try:
				securitydb = config.get(section, 'securitydb')
			except:
				securitydb = None
			try:
				unpackdir = config.get(section, 'unpackdir')
			except:
				unpackdir = None
			try:
				urlcutoff = int(config.get(section, 'urlcutoff'))
			except:
				urlcutoff = 1000
			try:
				extrahashes = []
				sec = config.get(section, 'extrahashes')
				hashvalues = sec.split(':')
				for h in hashvalues:
					if h in hashlib.algorithms:
						extrahashes.append(h)
					elif h == 'crc32':
						extrahashes.append(h)
					elif h == 'tlsh':
						if tlshscan:
							extrahashes.append(h)
			except:
				extrahashes = []
		else:
			sec = config.get(section, 'configtype')
			if sec != 'package':
				continue
			try:
				sec = config.get(section, 'extensions')
				## extensions should be declared as "extension:language", for example:
				## extensions = .foo:C .bar:Java
				extensions = sec.split()
				if extensions != []:
					for e in extensions:
						extlang = e.split(':')
						if len(extlang) != 2:
							continue
						(ext, lang) = extlang
						## skip if the language of the extra extension is not
						## in the list of currently supported languages
						if not lang in languages:
							continue
						if packageconfig.has_key(section):
							if packageconfig[section].has_key('extensions'):
								packageconfig[section]['extensions'].append((ext,lang))
							else:
								packageconfig[section]['extensions'] [(ext,lang)]
						else:
							packageconfig[section] = {}
							packageconfig[section]['extensions'] = [(ext,lang)]
			except:
				pass
			try:
				sec = config.get(section, 'alwaysscan')
				alwaysscanitems = sec.split(':')
				if alwaysscanitems != []:
					for b in alwaysscanitems:
						if packageconfig.has_key(section):	
							if packageconfig[section].has_key('alwaysscan'):
								packageconfig[section]['alwaysscan'].append(b)
							else:
								packageconfig[section]['alwaysscan'] = [b]
						else:
							packageconfig[section] = {}
							packageconfig[section]['alwaysscan'] = [b]
			except Exception, e:
				pass
			try:
				sec = config.get(section, 'blacklist')
				blacklistitems = sec.split(':')
				if blacklistitems != []:
					for b in blacklistitems:
						if packageconfig.has_key(section):	
							if packageconfig[section].has_key('blacklist'):
								packageconfig[section]['blacklist'].append(b)
							else:
								packageconfig[section]['blacklist'] = [b]
						else:
							packageconfig[section] = {}
							packageconfig[section]['blacklist'] = [b]
			except Exception, e:
				pass
	if scanlicense:
		license = True
		if licensedb == None:
			parser.error("License scanning enabled, but no path to licensing database supplied")
		if ninkacomments == None:
			parser.error("License scanning enabled, but no path to ninkacomments database supplied")
		if ninkacomments == masterdatabase:
			parser.error("Database and ninkacomments database cannot be the same")
		if authlicensedb != None:
			if licensedb == authlicensedb:
				authlicensedb = None
			if not os.path.exists(authlicensedb):
				authlicensedb = None
	else:
		license = False

	if authdb != None:
		if not os.path.exists(authdb):
			authdb = None

	if scancopyright:
		copyrights = True
		if licensedb == None:
			parser.error("Copyright scanning enabled, but no path to copyright database supplied")
	else:
		copyrights = False

	if scansecurity:
		security = True
		## TODO: more checks
	else:
		security = False
	if unpackdir != None:
		try:
			testfile = tempfile.mkstemp(dir=unpackdir)
			os.unlink(testfile[1])
		except Exception, e:
			print >>sys.stderr, "Can't use %s for unpacking" % unpackdir
			unpackdir = None

	## optionally rewrite files
	if options.rewritelist != None:
		if not os.path.exists(options.rewritelist):
			parser.error("rewrite list specified, but does not exist")
		if not (os.path.isfile(options.rewritelist) or os.path.islink(options.rewritelist)):
			parser.error("rewrite list specified, but is not a file")
		rewrites = readrewritelist(options.rewritelist)
	else:
		rewrites = {}

	if (scanlicense or scancopyright) and licensedb == None:
		print >>sys.stderr, "Specify path to licenses/copyrights database"
		sys.exit(1)

	if scansecurity and securitydb == None:
		print >>sys.stderr, "Specify path to security database"
		sys.exit(1)

	masterdbdir = os.path.dirname(masterdatabase)
	if not os.path.exists(masterdbdir):
		print >>sys.stderr, "Cannot create database %s, directory %s does not exist" % (masterdatabase, masterdbdir)
		sys.exit(1)
	try:
		conn = sqlite3.connect(masterdatabase, check_same_thread = False)
	except:
		print >>sys.stderr, "Cannot create database %s" % masterdatabase
		sys.exit(1)
	c = conn.cursor()
	#c.execute('PRAGMA synchronous=off')

	if scanlicense:
		ninkaconn = sqlite3.connect(ninkacomments, check_same_thread = False)
		ninkac = ninkaconn.cursor()

	if scanlicense or scancopyright:
		licenseconn = sqlite3.connect(licensedb, check_same_thread = False)
		licensec = licenseconn.cursor()

	if scansecurity:
		securityconn = sqlite3.connect(securitydb, check_same_thread = False)
		securityc = securityconn.cursor()

	if scanlicense and options.updatelicense:
		try:
			licensec.execute('''drop table licenses''')
			licenseconn.commit()
		except:
			pass
		try:
			ninkac.execute('''drop table ninkacomments''')
			ninkaconn.commit()
		except:
			pass
	if wipe:
		## drop all tables and all the indexes. Probably this option should not be used...
		c.execute("select name from sqlite_master where type='table'")
		tables = c.fetchall()
		if len(tables) != 0:
			for t in tables:
				try:
					c.execute('''drop table %s''' % t)
				except Exception, e:
					print >>sys.stderr, e
		conn.commit()
		try:
			licensec.execute('''drop table licenses''')
			licensec.execute('''drop table extracted_copyright''')
			licenseconn.commit()
		except:
			pass
		try:
			ninkac.execute('''drop table ninkacomments''')
			ninkaconn.commit()
		except:
			pass
		try:
			securityc.execute('''drop table security''')
			securityconn.commit()
		except:
			pass
        try:
		## Keep an archive of which packages and archive files (tar.gz, tar.bz2, etc.) we've already
		## processed, so we don't repeat work.
		c.execute('''create table if not exists processed (package text, version text, filename text, origin text, checksum text, downloadurl text)''')
		c.execute('''create index if not exists processed_index on processed(package, version)''')
		c.execute('''create index if not exists processed_checksum on processed(checksum)''')
		c.execute('''create index if not exists processed_origin on processed(origin)''')

		## Keep an archive of which packages are blacklisted. This is useful during database creation,
		## or during database expansion.
		#c.execute('''create table if not exists blacklist (package text, version text, filename text, origin text, checksum text)''')
		#c.execute('''create index if not exists blacklist_index on blacklist(package, version)''')

		## Since there is a lot of duplication inside source packages we store strings per checksum
		## which we can later link with files
		c.execute('''create table if not exists processed_file (package text, version text, pathname text, checksum text, filename text, thirdparty tinyint(1))''')
		c.execute('''create index if not exists processedfile_package_checksum_index on processed_file(checksum, package)''')
		c.execute('''create index if not exists processedfile_package_version_index on processed_file(package, version)''')
		c.execute('''create index if not exists processedfile_filename_index on processed_file(filename)''')
		## TODO: use analyze processedfile_package_version_index and processedfile_package_checksum_index

		## Store the extracted strings per checksum, not per (package, version, filename).
		## This saves a lot of space in the database
		## The field 'language' denotes what 'language' (family) the file the string is extracted from
		## is in. Possible values: extensions.values()
		c.execute('''create table if not exists extracted_string (stringidentifier text, checksum text, language text, linenumber int)''')
		c.execute('''create index if not exists stringidentifier_index on extracted_string(stringidentifier,language)''')
		c.execute('''create index if not exists extracted_hash_index on extracted_string(checksum)''')
		c.execute('''create index if not exists extracted_language_index on extracted_string(language);''')

		## Store the function names extracted, per checksum
		c.execute('''create table if not exists extracted_function (checksum text, functionname text, language text, linenumber int)''')
		c.execute('''create index if not exists function_index on extracted_function(checksum);''')
		c.execute('''create index if not exists functionname_index on extracted_function(functionname)''')
		c.execute('''create index if not exists functionname_language on extracted_function(language);''')

		## Store variable names/etc extracted
		c.execute('''create table if not exists extracted_name (checksum text, name text, type text, language text, linenumber int)''')
		c.execute('''create index if not exists name_checksum_index on extracted_name(checksum);''')
		c.execute('''create index if not exists name_name_index on extracted_name(name)''')
		c.execute('''create index if not exists name_type_index on extracted_name(type)''')
		c.execute('''create index if not exists name_language_index on extracted_name(language);''')

		## Store information about Linux kernel configuration directives
		## TODO: check if this should be changed to use SHA256 instead of file names.
		## TODO: add whether or not a configuration - filename mapping is 1:1
		c.execute('''create table if not exists kernel_configuration(configstring text, filename text, version text)''')
		c.execute('''create index if not exists kernel_configuration_filename on kernel_configuration(filename)''')

		## Store information about Linux kernel modules
		c.execute('''create table if not exists kernelmodule_alias(checksum text, modulename text, alias text)''')
		c.execute('''create table if not exists kernelmodule_author(checksum text, modulename text, author text)''')
		c.execute('''create table if not exists kernelmodule_description(checksum text, modulename text, description text)''')
		c.execute('''create table if not exists kernelmodule_firmware(checksum text, modulename text, firmware text)''')
		c.execute('''create table if not exists kernelmodule_license(checksum text, modulename text, license text)''')
		c.execute('''create table if not exists kernelmodule_parameter(checksum text, modulename text, paramname text, paramtype text)''')
		c.execute('''create table if not exists kernelmodule_parameter_description(checksum text, modulename text, paramname text, description text)''')
		c.execute('''create table if not exists kernelmodule_version(checksum text, modulename text, version text)''')

		c.execute('''create index if not exists kernelmodule_alias_index on kernelmodule_alias(alias)''')
		c.execute('''create index if not exists kernelmodule_author_index on kernelmodule_author(author)''')
		c.execute('''create index if not exists kernelmodule_description_index on kernelmodule_description(description)''')
		c.execute('''create index if not exists kernelmodule_firmware_index on kernelmodule_firmware(firmware)''')
		c.execute('''create index if not exists kernelmodule_license_index on kernelmodule_license(license)''')
		c.execute('''create index if not exists kernelmodule_parameter_index on kernelmodule_parameter(paramname)''')
		c.execute('''create index if not exists kernelmodule_parameter_description_index on kernelmodule_parameter_description(description)''')
		c.execute('''create index if not exists kernelmodule_version_index on kernelmodule_version(version)''')

		c.execute('''create index if not exists kernelmodule_alias_checksum_index on kernelmodule_alias(checksum)''')
		c.execute('''create index if not exists kernelmodule_author_checksum_index on kernelmodule_author(checksum)''')
		c.execute('''create index if not exists kernelmodule_description_checksum_index on kernelmodule_description(checksum)''')
		c.execute('''create index if not exists kernelmodule_firmware_checksum_index on kernelmodule_firmware(checksum)''')
		c.execute('''create index if not exists kernelmodule_license_checksum_index on kernelmodule_license(checksum)''')
		c.execute('''create index if not exists kernelmodule_parameter_checksum_index on kernelmodule_parameter(checksum)''')
		c.execute('''create index if not exists kernelmodule_parameter_description_checksum_index on kernelmodule_parameter_description(checksum)''')
		c.execute('''create index if not exists kernelmodule_version_checksum_index on kernelmodule_version(checksum)''')

		## keep information specifically about for files
		c.execute('''create table if not exists rpm(rpmname text, checksum text, downloadurl text)''')
		c.execute('''create index if not exists rpm_checksum_index on rpm(checksum)''')
		c.execute('''create index if not exists rpm_rpmname_index on rpm(rpmname)''')

		## keep information about aliases of archives (different origins, etc.)
		c.execute('''create table if not exists archivealias(checksum text, archivename text, origin text, downloadurl text)''')
		c.execute('''create index if not exists archivealias_checksum_index on archivealias(checksum)''')

		## keep information about other files, such as media files, configuration files,
		## and so on, for "circumstantial evidence"
		c.execute('''create table if not exists misc(checksum text, name text)''')
		c.execute('''create index if not exists misc_checksum_index on misc(checksum)''')
		c.execute('''create index if not exists misc_name_index on misc(name)''')
		if extrahashes != []:
			c.execute('''create table if not exists hashconversion (sha256 text)''')
			c.execute('''create index if not exists hashconversion_sha256_index on hashconversion(sha256);''')
			for h in extrahashes:
				## TODO: check whether or not these columns already exist
				tablequery = "alter table hashconversion add column %s text;" % h
				indexquery = "create index if not exists hashconversion_%s_index on hashconversion(%s)" % (h, h)
				c.execute(tablequery)
				c.execute(indexquery)
		conn.commit()

		if scanlicense or scancopyright:
			## Store the extracted licenses per checksum.
			licensec.execute('''create table if not exists licenses (checksum text, license text, scanner text, version text)''')
			licensec.execute('''create index if not exists license_index on licenses(checksum);''')

			## Store the copyrights extracted by FOSSology, per checksum
			## type can be:
			## * email
			## * statement
			## * url
			licensec.execute('''create table if not exists extracted_copyright (checksum text, copyright text, type text, byteoffset int)''')
			licensec.execute('''create index if not exists copyright_index on extracted_copyright(checksum);''')
			licensec.execute('''create index if not exists copyright_type_index on extracted_copyright(copyright, type);''')
			licenseconn.commit()
			licensec.close()
			licenseconn.close()

		if scanlicense:
			## Store the comments extracted by Ninka per checksum.
			ninkac.execute('''create table if not exists ninkacomments (checksum text, license text, version text)''')
			ninkac.execute('''create index if not exists comments_index on ninkacomments(checksum);''')

			ninkaconn.commit()
			ninkac.close()
			ninkaconn.close()
		if scansecurity:
			securityc.execute('''create table if not exists security_cert(checksum text, securitybug text, linenumber int, function text, whitelist tinyint(1))''')
			securityc.execute('''create index if not exists security_cert_checksum_index on security_cert(checksum);''')
			securityc.execute('''create table if not exists security_cve(checksum text, cve text)''')
			securityc.execute('''create index if not exists security_cve_checksum_index on security_cve(checksum);''')
			securityc.execute('''create table if not exists security_password(hash text, password text)''')
			securityc.execute('''create index if not exists security_password_hash_index on security_cve(checksum);''')

			securityconn.commit()
			securityc.close()
			securityconn.close()
	except Exception, e:
		print >>sys.stderr, e

	c.close()
	conn.close()

	processors = multiprocessing.cpu_count()
	pool = multiprocessing.Pool(processes=processors)

	pkgmeta = []

	checksums = {}
	if os.path.exists(os.path.join(options.filedir, "SHA256SUM")):
		checksumlines = open(os.path.join(options.filedir, "SHA256SUM")).readlines()
		tmpextrahashes = checksumlines[0].strip().split()
		for c in checksumlines[1:]:
			archivechecksums = {}
			checksumsplit = c.strip().split()
			archivefilename = checksumsplit[0]
			## sha256 is always the first hash
			archivechecksums['sha256'] = checksumsplit[1]
			counter = 2
			for h in tmpextrahashes:
				if h == 'sha256':
					continue
				if h not in extrahashes:
					continue
				archivechecksums[h] = checksumsplit[counter]
				counter += 1
			checksums[archivefilename] = archivechecksums
	else:
		print >>sys.stderr, "SHA256SUM not found"
		sys.exit(1)
	archivechecksums = {}
	if os.path.exists(os.path.join(options.filedir, "SHA256SUM-ARCHIVE")):
		checksumlines = open(os.path.join(options.filedir, "SHA256SUM-ARCHIVE")).readlines()
		for c in checksumlines:
			checksumsplit = c.strip().split()
			if len(checksumsplit) != 3:
				continue
			(archivefilename, origchecksum, origfilename) = checksumsplit
			archivechecksums[archivefilename] = (origchecksum, origfilename)
	downloadurls = {}
	if os.path.exists(os.path.join(options.filedir, "DOWNLOADURL")):
		downloadlines = map(lambda x: x.strip(), open(os.path.join(options.filedir, "DOWNLOADURL")).readlines())
		for d in downloadlines:
			archivefilename = d.rsplit('/', 1)[-1]
			downloadurls[archivefilename] = d

	## TODO: do all kinds of checks here
	for unpackfile in filelist:
		try:
			unpacks = unpackfile.strip().split()
			if len(unpacks) == 4:
				(package, version, filename, origin) = unpacks
				batarchive = False
			elif len(unpacks) == 5:
				(package, version, filename, origin, bat) = unpacks
				if bat == 'batarchive':
					batarchive = True
				else:
					batarchive = False
			if not batarchive:
				pkgmeta.append((options.filedir, package, version, filename, origin, downloadurls.get(filename,None), batarchive, masterdatabase, checksums.get(filename, None), archivechecksums))
			else:
				pkgmeta.append((options.filedir, package, version, filename, origin, downloadurls, batarchive, masterdatabase, checksums.get(filename, None), archivechecksums))
		except Exception, e:
			# oops, something went wrong
			print >>sys.stderr, e
	res = filter(lambda x: x != None, pool.map(checkalreadyscanned, pkgmeta, 1))

	oldpackage = ""
	oldres = []
	processed_hashes = set()

	batarchives = []
	resordered = []

	## first loop through everything to filter out all the files that don't
	## need processing, plus moving any batarchives to the end of the queue
	for i in res:
		(package, version, filename, origin, filehash, downloadurl, batarchive) = i
		if filehash in blacklistsha256sums:
			continue
		## no need to process some files twice, even if they
		## are under a different name.
		if filehash in processed_hashes:
			continue
		if batarchive:
			batarchives.append(i)
		else:
			resordered.append(i)
		processed_hashes.add(filehash)

	extractconfig = {}
	extractconfig['nomoschunks'] = nomoschunks
	extractconfig['urlcutoff'] = urlcutoff
	extractconfig['ninkacomments'] = ninkacomments

	res = resordered + batarchives
	for i in res:
		try:
			(package, version, filename, origin, filehash, downloadurl, batarchive) = i
			if package != oldpackage:
				oldres = set()
			if not batarchive:
				unpackres = unpack_getstrings(options.filedir, package, version, filename, origin, checksums[filename], downloadurl, masterdatabase, cleanup, license, copyrights, security, pool, extractconfig, licensedb, authlicensedb, authdb, authcopy, securitydb, oldpackage, oldres, rewrites, batarchive, packageconfig, unpackdir, extrahashes, update, options.newlist, allfiles)
			else:
				unpackres = unpack_getstrings(options.filedir, package, version, filename, origin, checksums, downloadurl, masterdatabase, cleanup, license, copyrights, security, pool, extractconfig, licensedb, authlicensedb, authdb, authcopy, securitydb, oldpackage, oldres, rewrites, batarchive, packageconfig, unpackdir, extrahashes, update, options.newlist, allfiles)
			if unpackres != None:
				oldres = set(map(lambda x: x[2]['sha256'], unpackres))
				## by updating oldres instead of overwriting itsome more files could be filtered
				## earlier. However, in some cases (Linux kernel) it could cost a lot more memory
				#oldres.update(map(lambda x: x[2]['sha256'], unpackres))
				oldpackage = package
		except Exception, e:
				# oops, something went wrong
				print >>sys.stderr, "unpacking error", e
	pool.close()

if __name__ == "__main__":
    main(sys.argv)
