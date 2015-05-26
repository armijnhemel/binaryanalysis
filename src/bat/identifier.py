#!/usr/bin/python
#-*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2011-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains code to extract identifiers (strings, function names,
variable names, etc.) from binaries and make them available for further
processing by various other scans.

Configuration parameters for databases are:

BAT_NAMECACHE_$LANGUAGE :: location of database containing cached
                           function names and variable names per package.
                           This is only used to look up Linux kernel functions.
'''

import string, re, os, os.path, sys, tempfile, shutil, copy
import bat.batdb
import subprocess
import extractor

## mapping of names for databases per language
namecacheperlanguage = { 'C':       'BAT_NAMECACHE_C'
                       , 'Java':    'BAT_NAMECACHE_JAVA'
                       }

## some regular expressions for Java, precompiled
rejavaclass = re.compile("This class: \d+=([\w\.$]+), super")
rejavaattribute = re.compile("Attribute \"SourceFile\", length:\d+, #\d+=\"([\w\.]+)\"")
rejavafield = re.compile("Field name:\"([\w$]+)\"")
rejavamethod= re.compile("Method name:\"([\w$]+)\"")
rejavastring = re.compile("#\d+: String \d+=\"")
reconststring = re.compile("\s+const-string\s+v\d+")

splitcharacters = map(lambda x: chr(x), range(0,9) + range(14,32) + [127])

## Main part of the scan
##
## 1. extract string constants, function names, variable names, etc.
## 2. Then run strings through computeScore, that queries the database and does
## funky statistics as described in our paper.
##
## Original code (in Perl) was written by Eelco Dolstra.
## Reimplementation in Python done by Armijn Hemel.
##
def searchGeneric(filepath, tags, blacklist=[], scanenv={}, offsets={}, scandebug=False, unpacktempdir=None):
	filesize = os.stat(filepath).st_size
	## whole file is blacklisted, so no need to scan
	if extractor.inblacklist(0, blacklist) == filesize:
		return None

	## Only consider strings that are len(stringcutoff) or larger
	## it is *very* important to keep this value in sync with the
	## database creation scripts!
	if scanenv.has_key('BAT_STRING_CUTOFF'):
		try:
			stringcutoff = int(scanenv['BAT_STRING_CUTOFF'])
			if stringcutoff < 1:
				stringcutoff = 5
		except ValueError, e:
			stringcutoff = 5
	else:
		stringcutoff = 5

	## use extra information for a few file types
	## * ELF files
	## * bFLT files
	## * Java class files + Dalvik VM files
	## * Windows executables and libraries
	## * Mono/.NET files
	## * Flash/ActionScript

	if 'elf' in tags:
		language = 'C'
	elif "java" in tags:
		language = 'Java'
	elif "dalvik" in tags:
		language = 'Java'
	else:
		## Treat everything else as C
		## TODO check for Javascript, .NET and others
		## JavaScript
		language='C'

	linuxkernel = False

	if 'linuxkernel' in tags:
		linuxkernel = True

	if language == 'C':
		res = extractC(filepath, tags, scanenv, filesize, stringcutoff, linuxkernel, blacklist, scandebug, unpacktempdir)
		if res == None:
			return None
		cmeta = res
		empty = True
		for c in cmeta.keys():
			if len(cmeta[c]) != 0:
				empty = False
				break
		if empty:
			return None
		if linuxkernel:
			res = extractKernelData(cmeta['strings'], filepath, scanenv, scandebug)
			if res != None:
				if res.has_key('kernelfunctions'):
					if res['kernelfunctions'] != []:
						cmeta['kernelfunctions'] = copy.deepcopy(res['kernelfunctions'])
		cmeta['language'] = language
		return (['identifier'], cmeta)
	elif language == 'Java':
		res = extractJava(filepath, tags, scanenv, filesize, stringcutoff, blacklist, scandebug, unpacktempdir)
		if res == None:
			return None
		javameta = res
		javameta['language'] = language
		return (['identifier'], javameta)

def extractC(filepath, tags, scanenv, filesize, stringcutoff, linuxkernel, blacklist=[], scandebug=False, unpacktempdir=None):
	## special var to indicate whether or not the file is a Linux kernel
	## image. If so extra checks can be done.
	kernelsymbols = []
	cmeta = {}

	## ELF files are always scanned as a whole. Sometimes there are sections that
	## contain compressed data, like .gnu_debugdata which should not trigger the
	## black list.

	createdtempfile = False
	if "elf" in tags:
		scanfile = filepath
	else:
		## The file contains a Linux kernel image and it is not an ELF file.
		## Kernel symbols recorded in the image could lead to false positives,
		## so they first have to be found and be blacklisted.
		if linuxkernel:
			kernelfile = open(filepath, 'r')
			## TODO: this is inefficient
			kerneldata = kernelfile.read()
			kernelfile.close()
			jiffy_pos = -1
			jiffies = []
			jiffycount = kerneldata.count('loops_per_jiffy')
			## first find a known symbol, such as loops_per_jiffy
			if jiffycount == 1:
				jiffies = [kerneldata.find('loops_per_jiffy')]
			else:
				jiffyoffset = 0
				for i in xrange(0, jiffycount):
					jiffy = kerneldata.find('loops_per_jiffy', jiffyoffset)
					if jiffy != -1:
						jiffies.append(jiffy)
						jiffyoffset = jiffy + 1

			## check all jiffies, grab the first one that is surrounded by NULL characters
			## If it is the first symbol it could happen that it is only *followed* by a NULL
			## character but not *preceded* by a NULL characeter
			for jiff in jiffies:
				if extractor.inblacklist(jiff, blacklist) != None:
					continue
				if extractor.check_null(kerneldata, jiff, 'loops_per_jiffy'):
					jiffy_pos = jiff
					break
				else:
					## sometimes "loops_per_jiffy" is not preceded by a NULL character.
					## For now only consider this if there only is one "loops_per_jiffy"
					## in the file.
					if len(jiffies) == 1:
						if kerneldata[jiff + len('loops_per_jiffy')] == chr(0x00):
							jiffy_pos = jiff
							break
			if jiffy_pos != -1:
				## work forwards until a symbol that is
				## found that is either not a printable character
				## or a NULL character.
				offset = jiffy_pos + len('loops_per_jiffy')
				lastnull = offset + 1
				while True:
					if not kerneldata[offset] in string.printable:
						if not kerneldata[offset] == chr(0x00):
							break
						else:
							lastnull = offset
					offset += 1

				if extractor.check_null(kerneldata, jiffy_pos, 'loops_per_jiffy'):
					## loops_per_jiffy is not the first symbol in the list
					## so work backwards
					offset = jiffy_pos
					firstnull = jiffy_pos - 1

					while True:
						if not kerneldata[offset] in string.printable:
							if not kerneldata[offset] == chr(0x00):
								break
							else:
								firstnull = offset
						offset -= 1
				else:
					firstnull = jiffy_pos
				kernelsymdata = kerneldata[firstnull:lastnull]
				kernelsymbols = filter(lambda x: x != '', kernelsymdata.split('\x00'))
				blacklist.append((firstnull,lastnull))

		## If part of the file is blacklisted the blacklisted byte ranges
		## should be ignored. Examples are firmwares, where there is a
		## bootloader, followed by a file system. The bootloader should be
		## analyzed, the file system should have been unpacked and been
		## blacklisted.
		if blacklist == []:
			scanfile = filepath
		else:
			## The blacklist is not empty. This could be a problem if
			## the Linux kernel is an ELF file and contains for example
			## an initrd.
			## Parts of the file were already scanned, so
			## carve the right parts from the file first
			datafile = open(filepath, 'rb')
			lastindex = 0
			databytes = ""
			datafile.seek(lastindex)
			## make a copy and add a bogus value for the last
			## byte to a temporary blacklist to make the loop work
			## well.
			blacklist_tmp = copy.deepcopy(blacklist)
			## oh, this is an ugly hack. The blacklisting code really
			## should be fixed.
			blacklist_tmp.sort()

			blacklist_tmp.append((filesize,filesize))
			for i in blacklist_tmp:
				if i[0] == lastindex:
					lastindex = i[1] - 1
					datafile.seek(lastindex)
					continue
				if i[0] > lastindex:
					## just concatenate the bytes
					data = datafile.read(i[0] - lastindex)
					databytes = databytes + data
					## set lastindex to the next
					lastindex = i[1] - 1
					datafile.seek(lastindex)
			datafile.close()
			if len(databytes) == 0:
				return None
			tmpfile = tempfile.mkstemp(dir=unpacktempdir)
			os.write(tmpfile[0], databytes)
			os.fdopen(tmpfile[0]).close()
			scanfile = tmpfile[1]
			createdtempfile = True
	## store the extracted string constants in the order
	## in which they appear in the file
	lines = []

	## store the extracted function/method names and extracted variable names
	functionnames = set()
	variablenames = set()

	## For ELF binaries concentrate on just a few sections of the
	## binary, namely the .rodata and .data sections.
	## The .rodata section might also contain other data, so expect
	## false positives until there is a better way to get only the string
	## constants :-(
	## Also, in case of certain compiler flags string constants might be in
	## different sections.
	## TODO: find out which compilation settings influence this and how it
	## can be detected that strings were moved to different sections.
	if "elf" in tags:
		elfscanfiles = []
		## first determine the size and offset of .data and .rodata sections,
		## carve these sections from the ELF file, then run 'strings'
       		try:
			p = subprocess.Popen(['readelf', '-SW', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			## check if there actually are sections. On some systems the
			## binary is somewhat corrupted and does not have section headers
			## TODO: localisation fixes
			if "There are no sections in this file." in stanout:
				p = subprocess.Popen(['strings', '-a', '-n', str(stringcutoff), scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					if createdtempfile:
						## cleanup the tempfile
						os.unlink(tmpfile[1])
					return None
				lines = stanout.split("\n")
			else:
				st = stanout.strip().split("\n")
				datafile = open(filepath, 'rb')
				datafile.seek(0)
				for s in st[3:]:
					for section in [".data", ".rodata"]:
						if section in s:
							elfsplits = s[7:].split()
							if elfsplits[0].startswith(section):
								## section actually contains no data, so skip
								if elfsplits[1] == 'NOBITS':
									continue
								elfoffset = int(elfsplits[3], 16)
								elfsize = int(elfsplits[4], 16)
								## sanity check
								if (elfoffset + elfsize) > os.stat(filepath).st_size:
									continue
								elftmp = tempfile.mkstemp(dir=unpacktempdir,suffix=section)
								unpackelf = True
								if blacklist != []:
									if extractor.inblacklist(elfoffset, blacklist) != None:
										unpackelf = False
									if extractor.inblacklist(elfoffset+elfoffset, blacklist) != None:
										unpackelf = False
								if unpackelf:
									datafile.seek(elfoffset)
									data = datafile.read(elfsize)
									os.write(elftmp[0], data)
									os.fdopen(elftmp[0]).close()
									elfscanfiles.append(elftmp[1])
								else:
									os.unlink(elftmp[1])
				datafile.close()

				for i in elfscanfiles:
					## TODO: check if -Tbinary is needed or not
       					p = subprocess.Popen(['strings', '-a', '-n', str(stringcutoff), i], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
       					(stanout, stanerr) = p.communicate()

       					st = stanout.split("\n")

       					for s in st:
                       				printstring = s
               					if len(printstring) >= stringcutoff:
                       					lines.append(printstring)
					os.unlink(i)
			if linuxkernel:
				## no functions can be extracted from a Linux kernel ELF image
				functionnames = set()
				if scanenv.has_key('BAT_KERNELSYMBOL_SCAN'):
					kernelsymbols = extractkernelsymbols(scanfile, scanenv, unpacktempdir)
			else:
				dynres = extractDynamicFromELF(filepath)
				if dynres != None:
					(functionnames, variablenames) = dynres
		except Exception, e:
			print >>sys.stderr, "string scan failed for:", filepath, e, type(e)
			if blacklist != [] and not linuxkernel:
				## cleanup the tempfile
				os.unlink(tmpfile[1])
			return None
	else:
		## extract all strings from the binary. Only look at strings
		## that are a certain amount of characters or longer. This is
		## configurable through "stringcutoff" although the gain will be relatively
		## low by also scanning strings < stringcutoff
		try:
			p = subprocess.Popen(['strings', '-a', '-n', str(stringcutoff), scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0:
				if createdtempfile:
					## cleanup the tempfile
					os.unlink(tmpfile[1])
				return None
			if stanout == '':
				lines = []
			else:
				if stanout.endswith('\n'):
					lines = stanout[:-1].split("\n")
				else:
					lines = stanout.split("\n")
		except Exception, e:
			print >>sys.stderr, "string scan failed for:", filepath, e, type(e)
			if blacklist != [] and not linuxkernel:
				## cleanup the tempfile
				os.unlink(tmpfile[1])
			return None
	if createdtempfile:
		## cleanup the tempfile
		os.unlink(tmpfile[1])
	cmeta['strings'] = lines
	cmeta['functionnames'] = functionnames
	cmeta['variablenames'] = variablenames
	cmeta['kernelsymbols'] = kernelsymbols
	return cmeta

def extractJava(scanfile, tags, scanenv, filesize, stringcutoff, blacklist=[], scandebug=False, unpacktempdir=None):
	if 'dalvik' in tags:
		javatype = 'dalvik'
	else:
		javatype = 'java'
	if blacklist == []:
		javares = extractJavaInfo(scanfile, scanenv, stringcutoff, javatype, unpacktempdir)
	else:
		javares = None
	if javares == None:
		return None
	return javares

'''
def extractJavaScript(path, tags, scanenv, filesize, stringcutoff, blacklist=[], scandebug=False, unpacktempdir=None):
	## JavaScript can be minified, but using xgettext it is still
	## possible to extract the strings from it
	## results = extractor.extractStrings(os.path.dirname(path), os.path.basename(path))
	## for r in results:
	##	lines.append(r[0])
	lines = []

	return (lines, functionRes, variablepvs)
'''

## extract information from Java file, both Dalvik DEX and regular Java class files
## 1. string constants
## 2. class names
## 3. variable names
## 4. source file names
## 5. method names
def extractJavaInfo(scanfile, scanenv, stringcutoff, javatype, unpacktempdir):
	lines = []
        if javatype == 'java':
		classname = []
		sourcefile = []
		fields = []
		methods = []

		p = subprocess.Popen(['jcf-dump', '--print-constants', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return None
		javalines = stanout.splitlines()
		for i in javalines:
			## extract the classname
			## TODO: deal with inner classes properly
			if i.startswith("This class: "):
				res = rejavaclass.match(i)
				if res != None:
					classname = [res.groups()[0]]
			## extract the SourceFile attribute, if available
			if i.startswith("Attribute \"SourceFile\","):
				res = rejavaattribute.match(i)
				if res != None:
					attribute = res.groups()[0]
					sourcefile = [attribute]
			## extract fields
			if i.startswith("Field name:\""):
				res = rejavafield.match(i)
				if res != None:
					fieldname = res.groups()[0]
					if '$' in fieldname:
						continue
					if fieldname != 'serialVersionUID':
						fields.append(fieldname)
			## extract methods
			if i.startswith("Method name:\""):
				res = rejavamethod.match(i)
				if res != None:
					method = res.groups()[0]
					## ignore synthetic methods that are inserted by the Java compiler
					if not method.startswith('access$'):
						methods.append(method)
			## process each line of stanout, looking for lines that look like this:
			## #13: String 45="/"
			if rejavastring.match(i) != None:
				printstring = i.split("=", 1)[1][1:-1]
				printstring = printstring.decode('string-escape')
				## now remove characthers like '\n' and '\r'
				## first the easy case
				printstring = printstring.strip('\0\n\r')
        			if len(printstring) < stringcutoff:
					continue
				## then split mid string
				splitchars = filter(lambda x: x in printstring, splitcharacters)
				if splitchars == []:
					lines.append(printstring)
				#else:
				#	for cc in splitchars:
				#		splitlines = printstring.split(cc)
				#		for sl in splitlines:
        			#			if len(printstring) < stringcutoff:
				#				continue
				#			## TODO: now check for the other splitchars
				#			lines.append(sl)
		javameta = {'classes': classname, 'methods': list(set(methods)), 'fields': list(set(fields)), 'sourcefiles': sourcefile, 'javatype': javatype, 'strings': lines}
	elif javatype == 'dalvik':
		## Using dedexer http://dedexer.sourceforge.net/ extract information from Dalvik
		## files, then process each file in $tmpdir and search file for lines containing
		## "const-string" and other things as well.
		## TODO: Research http://code.google.com/p/smali/ as a replacement for dedexer
		skipfields = ['public', 'private', 'protected', 'static', 'final', 'volatile', 'transient']
		javameta = {'classes': [], 'methods': [], 'fields': [], 'sourcefiles': [], 'javatype': javatype}
		classnames = set()
		sourcefiles = set()
		methods = set()
		fields = set()
		dex_tmpdir = None
		if scanenv.has_key('DEX_TMPDIR'):
			dex_tmpdir = scanenv['DEX_TMPDIR']
		if dex_tmpdir != None:
			dalvikdir = tempfile.mkdtemp(dir=dex_tmpdir)
		else:
			dalvikdir = tempfile.mkdtemp(dir=unpacktempdir)
		p = subprocess.Popen(['java', '-jar', '/usr/share/java/bat-ddx.jar', '-d', dalvikdir, scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode == 0:
			osgen = os.walk(dalvikdir)
			try:
				while True:
					ddxfiles = osgen.next()
					for ddx in ddxfiles[2]:
						ddxlines = open("%s/%s" % (ddxfiles[0], ddx)).readlines()
						for d in ddxlines:
							## search for string constants
							if "const-string" in d:
								reres = reconststring.match(d)
								if reres != None:
									printstring = d.strip().split(',', 1)[1][1:-1]
        								if len(printstring) >= stringcutoff:
										lines.append(printstring)
							## extract method names
							elif d.startswith(".method"):
								method = (d.split('(')[0]).split(" ")[-1]
								if method == '<init>' or method == '<clinit>':
									pass
								elif method.startswith('access$'):
									pass
								else:
									methods.add(method)
							## extract class files, including inner classes
							elif d.startswith(".class") or d.startswith(".inner"):
								classname = d.strip().split('/')[-1]
								if "$" in classname:
									classname = classname.split("$")[0]
								classnames.add(classname)
							## extract source code files
							elif d.startswith(".source"):
								sourcefile = d.strip().split(' ')[-1]
								sourcefiles.add(sourcefile)
							## extract fields
							elif d.startswith(".field"):
								field = d.strip().split(';')[0]
								fieldstmp = field.split()
								ctr = 1
								for f in fieldstmp[1:]:
									## these are keywords
									if f in skipfields:
										ctr = ctr + 1
										continue
									if '$' in f:
										break
									## often generated, so useless
									if "serialVersionUID" in f:
										break
									fields.add(f)
									break
			except StopIteration:
				pass
		javameta['classes'] = list(classnames)
		javameta['sourcefiles'] = list(sourcefiles)
		javameta['methods'] = list(methods)
		javameta['fields'] = list(fields)
		javameta['strings'] = lines

		## cleanup
		shutil.rmtree(dalvikdir)
	return javameta

## Linux kernels that are stored as statically linked ELF files and Linux kernel
## modules often have a section __ksymtab_strings. This section contains variables
## that are exported by the kernel using the EXPORT_SYMBOL* macros in the Linux
## kernel source tree.
def extractkernelsymbols(scanfile, scanenv, unpacktempdir):
	p = subprocess.Popen(['readelf', '-SW', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	st = stanout.strip().split("\n")

	elftmp = tempfile.mkstemp(dir=unpacktempdir, suffix=".ksymtab")
	datafile = open(scanfile, 'rb')
	datafile.seek(0)
	for s in st[3:]:
		if "__ksymtab_strings" in s:
			elfsplits = s[7:].split()
			if elfsplits[0].startswith("__ksymtab_strings"):
				elfoffset = int(elfsplits[3], 16)
				elfsize = int(elfsplits[4], 16)
				datafile.seek(elfoffset)
				data = datafile.read(elfsize)
				os.write(elftmp[0], data)
				os.fdopen(elftmp[0]).close()
				break
	datafile.close()
	if os.stat(elftmp[1]).st_size == 0:
		os.unlink(elftmp[1])
		return {}

	variables = set()
        #p = subprocess.Popen(['strings', '-a', '-n', str(stringcutoff), elftmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        p = subprocess.Popen(['strings', '-a', elftmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (stanout, stanerr) = p.communicate()
	st = stanout.split("\n")
	for s in st:
		printstring = s
		if len(printstring) > 0:
			variables.add(printstring)
	os.unlink(elftmp[1])
	return variables

## extract dynamic linking information from the dynamic symbols table from an ELF
## binary and return two sets:
## 1. function names
## 2. variable names
def extractDynamicFromELF(scanfile):
 	p = subprocess.Popen(['readelf', '-W', '--dyn-syms', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		## perhaps an older readelf that does not support --dyn-syms
 		p = subprocess.Popen(['readelf', '-W', '-s', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return (set(), set())

	st = stanout.strip().split("\n")

	## there is nothing in the dynamic ELF section
	if st == ['']:
		return (set(), set())

	## Walk through the output of readelf, and split results accordingly
	## in function names and variables.
	functionnames = set()
	mangles = []
	variables = set()
	for i in st[3:]:
		dynstr = i.split()
		if len(dynstr) < 8:
			continue
		if '@' in dynstr[7]:
			continue
		if dynstr[6] == 'UND':
			continue
		if dynstr[3] != 'FUNC':
			if dynstr[3] == 'OBJECT':
				if dynstr[4] == 'WEAK':
					continue
				variables.add(dynstr[7])
				continue
		## every program has 'main', so skip
		if dynstr[7] == 'main':
			continue
		## _init _fini _start are in the ELF standard and/or added by GCC to everything, so skip
		if dynstr[7] == '_init' or dynstr[7] == '_fini' or dynstr[7] == '_start':
			continue
		## __libc_csu_init __libc_csu_fini are in the ELF standard and/or added by GCC to everything, so skip
		if dynstr[7] == '__libc_csu_init' or dynstr[7] == '__libc_csu_fini':
			continue
		## C++ string, needs to be demangled first
		if dynstr[7].startswith("_Z"):
			mangles.append(dynstr[7])
		else:
			functionnames.add(dynstr[7])
	## run c++filt in batched mode to avoid launching many processes
	## C++ demangling is tricky: the types declared in the function in the source code
	## are not necessarily what demangling will return.
	if mangles != []:
		step = 100
		for i in xrange(0, len(mangles), step):
			offset = i
			args = ['c++filt'] + mangles[offset:offset+step]
			offset = offset + step
			p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0:
				continue
			for f in stanout.strip().split('\n'):
				funcname = f.split('(', 1)[0].rsplit('::', 1)[-1].strip()
				## TODO more sanity checks here, since demangling
				## will sometimes not return a single function name
				functionnames.add(funcname)
	return (functionnames, variables)

## extract Linux kernel data from a binary file. False positives could exist.
def extractKernelData(lines, filepath, scanenv, scandebug):
	if len(lines) == 0:
		return None

	## setup code guarantees that this database exists and that sanity
	## checks were done.
	if scanenv.get('BAT_KERNELFUNCTION_SCAN') == '1':
		batdb = bat.batdb.BatDb(scanenv['DBBACKEND'])
		funccache = scanenv.get(namecacheperlanguage['C'])
		kernelconn = batdb.getConnection(funccache,scanenv)
		kernelcursor = kernelconn.cursor()
	else:
		return None

	dbbackend = scanenv['DBBACKEND']

	kernelfuncres = []
	kernelparamres = []
	oldline = None

	lenlines = len(lines)

	if scandebug:
		print >>sys.stderr, "total extracted strings for %s: %d" %(filepath, lenlines)

	query = batdb.getQuery("select package FROM linuxkernelfunctionnamecache WHERE functionname = %s;")
	for line in lines:
		if scandebug:
			print >>sys.stderr, "processing <|%s|>" % line
		if line == oldline:
			continue
		kernelfunctionmatched = False
		## skip empty lines
		if line == "": continue
		oldline = line

		## This is where things get a bit ugly. The strings in a Linux
		## kernel image could also be function names, not string constants.
		## There could be false positives here...
		kernelcursor.execute(query, (line,))
		kernelres = kernelcursor.fetchall()
		if len(kernelres) != 0:
			kernelfuncres.append(line)
			continue

	returnres = {}
	if kernelfuncres != []:
		returnres['kernelfunctions'] = kernelfuncres
	kernelcursor.close()
	kernelconn.close()
	return returnres

def extractidentifiersetup(scanenv, debug=False):
	if not 'DBBACKEND' in scanenv:
		return (False, None)
	if scanenv['DBBACKEND'] == 'sqlite3':
		return extractidentifiersetup_sqlite3(scanenv, debug)
	if scanenv['DBBACKEND'] == 'postgresql':
		return extractidentifiersetup_postgresql(scanenv, debug)
	return (False, None)

def extractidentifiersetup_postgresql(scanenv, debug=False):
	## TODO: DEX checks
	newenv = copy.deepcopy(scanenv)
	batdb = bat.batdb.BatDb('postgresql')
	conn = batdb.getConnection(None,scanenv)
	if conn == None:
		return (False, None)
	## TODO: more checks
	conn.close()
	return (True, scanenv)

## method that makes sure that everything is set up properly and modifies
## the environment, as well as determines whether the scan should be run at
## all.
## Returns tuple (run, environment)
## * run: boolean indicating whether or not the scan should run
## * environment: (possibly) modified
def extractidentifiersetup_sqlite3(scanenv, debug=False):
	## TODO: verify if the following programs are available and work:
	## * strings
	## * jcf-dump
	## * java
	## * readelf
	## * c++filt

	newenv = copy.deepcopy(scanenv)

	if scanenv.has_key('DEX_TMPDIR'):
		dex_tmpdir = scanenv['DEX_TMPDIR']
		if os.path.exists(dex_tmpdir):
			## TODO: make sure this check is only done once through a setup scan
			try:
				tmpfile = tempfile.mkstemp(dir=dex_tmpdir)
				os.fdopen(tmpfile[0]).close()
				os.unlink(tmpfile[1])
			except OSError, e:
				del newenv['DEX_TMPDIR']
		else:
			del newenv['DEX_TMPDIR']

	batdb = bat.batdb.BatDb(scanenv['DBBACKEND'])

	## check the various caching databases, first for C
	if scanenv.has_key(namecacheperlanguage['C']):
		namecache = scanenv.get(namecacheperlanguage['C'])
		## the cache should exist. If it doesn't exist then something is horribly wrong.
		if not os.path.exists(namecache):
			if newenv.has_key('BAT_KERNELSYMBOL_SCAN'):
				del newenv['BAT_KERNELSYMBOL_SCAN']
			if newenv.has_key('BAT_KERNELFUNCTION_SCAN'):
				del newenv['BAT_KERNELFUNCTION_SCAN']
			if newenv.has_key(namecacheperlanguage['C']):
				del newenv[namecacheperlanguage['C']]
		else:
			## TODO: add checks for each individual table
			if not newenv.has_key('BAT_KERNELSYMBOL_SCAN'):
				newenv['BAT_KERNELSYMBOL_SCAN'] = 1

			## Sanity check for kernel function names
			cacheconn = batdb.getConnection(namecache)
			cachecursor = cacheconn.cursor()
			cachecursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='linuxkernelfunctionnamecache';")

			kernelfuncs = cachecursor.fetchall()
			if kernelfuncs == []:
				if newenv.has_key('BAT_KERNELFUNCTION_SCAN'):
					del newenv['BAT_KERNELFUNCTION_SCAN']
			else:
				if not newenv.has_key('BAT_KERNELFUNCTION_SCAN'):
					newenv['BAT_KERNELFUNCTION_SCAN'] = 1
			cachecursor.close()
			cacheconn.close()
	else:
		## undefined, so disable kernel scanning, variable/function name scanning
		if newenv.has_key('BAT_KERNELSYMBOL_SCAN'):
			del newenv['BAT_KERNELSYMBOL_SCAN']
		if newenv.has_key('BAT_KERNELFUNCTION_SCAN'):
			del newenv['BAT_KERNELFUNCTION_SCAN']

	scanenvkeys = newenv.keys()
	envcheck = set(map(lambda x: x in scanenvkeys, namecacheperlanguage.values()))
	if envcheck == set([False]):
		return (False, None)
	return (True, newenv)
