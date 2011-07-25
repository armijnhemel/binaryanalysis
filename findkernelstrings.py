#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to take strings from a binary and match it with files from
a Linux kernel source tree, and if available, configurations from that same
source tree, to trace which files were used to compile the kernel. This is not
fool proof since there are many different kernel trees.
'''

import os, sys, re, subprocess
import os.path
import sqlite3
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
	parser.error("Path to database with kernel strings needed")
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
        (stanout, stanerr) = p.communicate()
except:
	sys.exit(1)

kernelstrings = stanout.split("\n")

conn = sqlite3.connect(options.index)
c = conn.cursor()

## if we have a database with configuration mappings open it
if options.configindex != None:
	configconn = sqlite3.connect(options.configindex)
	configc = configconn.cursor()

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
		res = []
		c.execute("SELECT filename FROM extracted WHERE printstring=?", (searchstring.strip(),))
		res = res + map(lambda x: x[0], c.fetchall())
		c.execute("SELECT filename FROM symbol WHERE symbolstring=?", (searchstring.strip(),))
		res = res + map(lambda x: x[0], c.fetchall())
		c.execute("SELECT filename FROM function WHERE functionstring=?", (searchstring.strip(),))
		res = res + map(lambda x: x[0], c.fetchall())
		if len(res) != 0:
			if options.found:
				print 'found string "%s"' % (searchstring,)
			for d in res:
				if options.found:
					if options.arch != None:
						if "arch/" in d and options.arch not in d:
							continue
						if "asm-" in d and options.arch not in d:
							continue
					if options.configindex != None:
						configc.execute("SELECT configstring FROM config WHERE filename=?", (d,))
						configres = map(lambda x: x[0], configc.fetchall())

						if len(configres) == 0:
								print '    This string is defined in path:', d
						for cres in configres:
							if cres != None:
								print '    This string is defined in path: %s (config %s)' % (d, cres)
					else:
								print '    This string is defined in path:', d
						
				found = True
		#if not found and options.missing and not seenaaaaaa:
		if not found and options.missing:
			print 'did not find string "%s"' % (searchstring,)
		seenstrings.append(searchstring)

sys.exit()
