#!/usr/bin/python
#-*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2011-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains the ranking algorithm as described in the paper
"Finding Software License Violations Through Binary Code Clone Detection"
by Armijn Hemel, Karl Trygve Kalleberg, Eelco Dolstra and Rob Vermaas, as
presented at the Mining Software Repositories 2011 conference.

Configuration parameters for databases are:

BAT_RANKING_FULLCACHE :: indication whether or not a full cached database is
                         used, reducing the need to generate it "just in time"

BAT_CLONE_DB :: location of database containing information about which packages
                should be treated as equivalent from a scanning point of view,
                like renamed packages.

Per language:
BAT_STRINGSCACHE_$LANGUAGE :: location of database with cached strings
                              in $LANGUAGE per package to reduce lookups

An additional classification method for dynamically linked executables or
Java binaries based on function or method names takes an additional parameter:

BAT_NAMECACHE_$LANGUAGE :: location of database containing cached
                           function names and variable names per package
                           to reduce lookups
'''

import string, re, os, os.path, magic, sys, tempfile, shutil, copy
import sqlite3
import subprocess
import xml.dom.minidom
import extractor

ms = magic.open(magic.MAGIC_NONE)
ms.load()

## mapping of names for databases per language
namecacheperlanguage = { 'C':       'BAT_NAMECACHE_C'
                       , 'Java':    'BAT_NAMECACHE_JAVA'
                       }

stringsdbperlanguage = { 'C':              'BAT_STRINGSCACHE_C'
                       , 'Java':           'BAT_STRINGSCACHE_JAVA'
                       , 'C#':             'BAT_STRINGSCACHE_C#'
                       , 'ActionScript':   'BAT_STRINGSCACHE_ACTIONSCRIPT'
                       }

## Main part of the scan
##
## 1. extract the strings using 'strings' and only consider strings >= 5,
## although this should be configurable
## 2. Then run it through extractGeneric, that queries the database and does
## funky statistics as described in our paper.
##
## Original code (in Perl) was written by Eelco Dolstra.
## Reimplementation in Python done by Armijn Hemel.
def searchGeneric(path, tags, blacklist=[], offsets={}, debug=False, envvars=None, unpacktempdir=None):
	filesize = filesize = os.stat(path).st_size
	## whole file is blacklisted, so no need to scan
	if extractor.inblacklist(0, blacklist) == filesize:
		return None

	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	## Some methods use a database to lookup renamed packages.
	clonedb = scanenv.get('BAT_CLONE_DB')
	clones = {}
	if clonedb != None:
		conn = sqlite3.connect(clonedb)
		c = conn.cursor()
		clonestmp = c.execute("SELECT originalname,newname from renames").fetchall()
		for cl in clonestmp:
			(originalname,newname) = cl
			if not clones.has_key(originalname):
				clones[originalname] = newname
		c.close()
		conn.close()

	## Only consider strings that are len(stringcutoff) or larger
	stringcutoff = 5
	## use extra information for a few file types
	## * ELF files
	## * bFLT files
	## * Java class files + Dalvik VM files
	## * Windows executables and libraries
	## * Mono/.NET files
	## * Flash/ActionScript

	if 'elf' in tags:
		mstype = "ELF"
		language = 'C'
	else:
		## TODO: use more information already present in tags, like Dalvik or Java.
		mstype = ms.file(path)
	if "bFLT" in mstype:
		language = 'C'
	elif "compiled Java" in mstype:
		language = 'Java'
	elif "Dalvik dex file" in mstype:
		language = 'Java'
	else:
		## first check the filename extension. If it is .js treat it as
		## JavaScript, else just consider it as 'C'.
		language='C'

	## special var to indicate whether or not the file is a Linux kernel
	## image. If so extra checks can be done.
	linuxkernel = False

	if 'linuxkernel' in tags:
		linuxkernel = True
		kernelsymbols = []

	## ELF files are always scanned as a whole. Sometimes there are sections that
	## contain compressed data, like .gnu_debugdata which should not trigger the
	## black list.

	createdtempfile = False
	if "elf" in tags:
		scanfile = path
	else:
		## The file contains a Linux kernel image and it is not an ELF file.
		## Kernel symbols recorded in the image could lead to false positives,
		## so they first have to be found and be blacklisted.
		if 'linuxkernel' in tags:
			kernelfile = open(path, 'r')
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
			for jiff in jiffies:
				if extractor.check_null(kerneldata, jiff, 'loops_per_jiffy'):
					jiffy_pos = jiff
					break
			if jiffy_pos != -1:
				if not extractor.check_null(kerneldata, jiffy_pos, 'loops_per_jiffy'):
					pass
				else:
					## then work forwards until a symbol that is
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

					## and backwards
					offset = jiffy_pos
					firstnull = jiffy_pos - 1

					while True:
						if not kerneldata[offset] in string.printable:
							if not kerneldata[offset] == chr(0x00):
								break
							else:
								firstnull = offset
						offset -= 1
					kernelsymdata = kerneldata[firstnull:lastnull]
					kernelsymbols = filter(lambda x: x != '', kernelsymdata.split('\x00'))
				blacklist.append((firstnull,lastnull))

		## If part of the file is blacklisted the blacklisted byte ranges
		## should be ignored. Examples are firmwares, where there is a
		## bootloader, followed by a file system. The bootloader should be
		## analyzed, the file system should have been unpacked and been
		## blacklisted.
		if blacklist == []:
			scanfile = path
		else:
			## The blacklist is not empty. This could be a problem if
			## the Linux kernel is an ELF file and contains for example
			## an initrd.
			## Parts of the file were already scanned, so
			## carve the right parts from the file first
			datafile = open(path, 'rb')
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
        try:
		lines = []
		dynamicRes = {}
		variablepvs = {}
		if language == 'C':
			## For ELF binaries concentrate on just a few sections of the
			## binary, namely the .rodata and .data sections.
			## The .rodata section might also contain other data, so expect
			## false positives until there is a better way to get only the string
			## constants :-(
			## Also, in case of certain compiler flags string constants might be in
			## different sections.
			## TODO: find out which compilation settings influence this and how it
			## can be detected that strings were moved to different sections.
			if "ELF" in mstype:
				if linuxkernel:
					dynamicRes = {}
					if scanenv.has_key('BAT_KERNELSYMBOL_SCAN'):
						kernelvars = extractkernelsymbols(scanfile, scanenv, unpacktempdir)
						variablepvs = scankernelsymbols(kernelvars, scanenv, clones)
				else:
					dynres = extractDynamic(path, scanenv, clones)
					if dynres != None:
						(dynamicRes,variablepvs) = dynres
				elfscanfiles = []
				## first determine the size and offset of .data and .rodata and carve them from the file
				p = subprocess.Popen(['readelf', '-SW', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				## check if there actually are sections. On some systems the
				## binary is somewhat corrupted and does not have section headers
				## TODO: localisation fixes
				if "There are no sections in this file." in stanout:
					p = subprocess.Popen(['strings', '-n', str(stringcutoff), scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
					(stanout, stanerr) = p.communicate()
					if p.returncode != 0:
						if createdtempfile:
							## cleanup the tempfile
							os.unlink(tmpfile[1])
						return None
					lines = stanout.split("\n")
				else:
					st = stanout.strip().split("\n")
					datafile = open(path, 'rb')
					datafile.seek(0)
					for s in st[3:]:
						for section in [".data", ".rodata"]:
							if section in s:
								elfsplits = s[7:].split()
								if elfsplits[0].startswith(section):
									elfoffset = int(elfsplits[3], 16)
									elfsize = int(elfsplits[4], 16)
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
					datafile.close()

					for i in elfscanfiles:
						## run strings to get rid of weird characters that we don't even want to scan
						## TODO: check if -Tbinary is needed or not
        					p = subprocess.Popen(['strings', '-n', str(stringcutoff), i], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        					(stanout, stanerr) = p.communicate()

        					st = stanout.split("\n")

        					for s in st:
                        				printstring = s
                					if len(printstring) >= stringcutoff:
                        					lines.append(printstring)
						os.unlink(i)
			else:
				if linuxkernel:
					if scanenv.has_key('BAT_KERNELSYMBOL_SCAN'):
						variablepvs = scankernelsymbols(kernelsymbols, scanenv, clones)
				## extract all strings from the binary. Only look at strings
				## that are a certain amount of characters or longer. This is
				## configurable through "stringcutoff" although the gain will be relatively
				## low by also scanning strings < 5.
				p = subprocess.Popen(['strings', '-n', str(stringcutoff), scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					if createdtempfile:
						## cleanup the tempfile
						os.unlink(tmpfile[1])
					return None
				if stanout == '':
					lines = []
				else:
					lines = stanout.split("\n")
		elif language == 'Java':
			## TODO: check here if there are caches already or not. If there are none it makes
			## no sense to continue.
			lines = []
        		if "compiled Java" in mstype and blacklist == []:
				classname = []
				sourcefile = []
				fields = []
				methods = []
				lines = []

				p = subprocess.Popen(['jcf-dump', '--print-constants', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					if createdtempfile:
						## cleanup the tempfile
						os.unlink(tmpfile[1])
					return None
				javalines = stanout.splitlines()
				for i in javalines:
					## extract the classname
					## TODO: deal with inner classes properly
					if i.startswith("This class: "):
						res = re.match("This class: \d+=([\w\.$]+), super", i)
						if res != None:
							classname = [res.groups()[0]]
					## extract the SourceFile attribute, if available
					if i.startswith("Attribute \"SourceFile\","):
						res = re.match("Attribute \"SourceFile\", length:\d+, #\d+=\"([\w\.]+)\"", i)
						if res != None:
							sourcefile = [res.groups()[0]]
					## extract fields
					if i.startswith("Field name:\""):
						res = re.match("Field name:\"([\w$]+)\"", i)
						if res != None:
							fieldname = res.groups()[0]
							if '$' in fieldname:
								continue
							if fieldname != 'serialVersionUID':
								fields.append(fieldname)
					## extract methods
					if i.startswith("Method name:\""):
						res = re.match("Method name:\"([\w$]+)\"", i)
						if res != None:
							method = res.groups()[0]
							## ignore synthetic methods that are inserted by the Java compiler
							if not method.startswith('access$'):
								methods.append(method)
					## process each line of stanout, looking for lines that look like this:
					## #13: String 45="/"
					if re.match("#\d+: String \d+=\"", i) != None:
						printstring = i.split("=", 1)[1][1:-1]
        					if len(printstring) >= stringcutoff:
							lines.append(printstring)
				javameta = {'classes': classname, 'methods': list(set(methods)), 'fields': list(set(fields)), 'sourcefiles': sourcefile}
			elif "Dalvik dex" in mstype and blacklist == []:
				## Using dedexer http://dedexer.sourceforge.net/ extract information from Dalvik
				## files, then process each file in $tmpdir and search file for lines containing
				## "const-string" and other things as well.
				## alternatively, use code from here http://code.google.com/p/smali/
				javameta = {'classes': [], 'methods': [], 'fields': [], 'sourcefiles': []}
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
										reres = re.match("\s+const-string\s+v\d+", d)
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
											if f in ['public', 'private', 'protected', 'static', 'final', 'volatile', 'transient']:
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

				## cleanup
				shutil.rmtree(dalvikdir)
			variablepvs = extractVariablesJava(javameta, scanenv, clones)
			dynamicRes = extractJavaNames(javameta, scanenv, clones)
		elif language == 'JavaScipt':
			## JavaScript can be minified, but using xgettext it is still
			## possible to extract the strings from it
			## results = extractor.extractStrings(os.path.dirname(path), os.path.basename(path))
			## for r in results:
			##	lines.append(r[0])
			lines = []
		else:
			lines = []

		res = extractGeneric(lines, path, scanenv, clones, linuxkernel, stringcutoff, language)
		if res != None:
			if createdtempfile:
				## a tempfile was made because of blacklisting, so cleanup
				os.unlink(tmpfile[1])
		else:
			if createdtempfile:
				## a tempfile was made because of blacklisting, so cleanup
				os.unlink(tmpfile[1])
		if res == None and dynamicRes == {} and variablepvs == {}:
			return None
		return (['ranking'], (res, dynamicRes, variablepvs, language))

	except Exception, e:
		print >>sys.stderr, "string scan failed for:", path, e, type(e)
		if blacklist != [] and not linuxkernel:
			## cleanup the tempfile
			os.unlink(tmpfile[1])
		return None

def extractJavaNames(javameta, scanenv, clones):
	if not scanenv.has_key(namecacheperlanguage['Java']):
		return {}

	dynamicRes = {}  # {'namesmatched': 0, 'totalnames': int, 'uniquematches': int, 'packages': {} }
	namesmatched = 0
	uniquematches = 0
	uniquepackages = {}
	matches = []

	classname = javameta['classes']
	methods = javameta['methods']
	fields = javameta['fields']
	sourcefile = javameta['sourcefiles']

	funccache = scanenv.get(namecacheperlanguage['Java'])

	conn = sqlite3.connect(funccache)
	conn.text_factory = str
	c = conn.cursor()

	if scanenv.has_key('BAT_METHOD_SCAN'):
		for meth in methods:
			if meth == 'main':
				continue
			res = c.execute("select distinct package from functionnamecache where functionname=?", (meth,)).fetchall()
			if res != []:
				matches.append(meth)
				namesmatched += 1
				packages_tmp = []
				for r in res:
					if clones.has_key(r[0]):
						package_tmp = clones[r[0]]
						packages_tmp.append(package_tmp)
					else:
						packages_tmp.append(r[0])
				packages_tmp = list(set(packages_tmp))

				## unique match
				if len(packages_tmp) == 1:
					uniquematches += 1
					if uniquepackages.has_key(packages_tmp[0]):
						uniquepackages[packages_tmp[0]].append(meth)
					else:
						uniquepackages[packages_tmp[0]] = [meth]
	c.close()
	conn.close()

	dynamicRes['namesmatched'] = namesmatched
	dynamicRes['totalnames'] = len(set(methods))
	dynamicRes['uniquepackages'] = uniquepackages
	dynamicRes['uniquematches'] = uniquematches

	## unique matches found. 
	if uniquematches != 0:
		dynamicRes['packages'] = {}
	## these are the unique function names only, just add some stubs here
	for i in uniquepackages:
		versions = []
		dynamicRes['packages'][i] = []
	return dynamicRes

def extractVariablesJava(javameta, scanenv, clones):
	if not scanenv.has_key(namecacheperlanguage['Java']):
		return {}

	variablepvs = {}
	if javameta.has_key('fields'):
		fields = javameta['fields']
	else:
		fields = []
	if javameta.has_key('classes'):
		classes = javameta['classes']
	else:
		classes = []
	if javameta.has_key('sourcefiles'):
		sourcefiles = javameta['sourcefiles']
	else:
		sourcefiles = []

	## open the database containing function names that were extracted
	## from source code.

	funccache = scanenv.get(namecacheperlanguage['Java'])

	conn = sqlite3.connect(funccache)
	conn.text_factory = str
	c = conn.cursor()

	classpvs = {}
	sourcepvs = {}
	fieldspvs = {}

	## classes and source file names are searched in a similar way.
	## Of course, it could be that the source file is different from the
	## class file (apart from the extension of course) but this is very
	## uncommon. TODO: merge class name and source file name searching
	if scanenv.has_key('BAT_CLASSNAME_SCAN'):
		classes = set(map(lambda x: x.split('$')[0], classes))
		for i in classes:
			pvs = []
			## first try the name as found in the binary. If it can't
			## be found and has dots in it split it on '.' and
			## use the last component only.
			classname = i
			classres = c.execute("select package from classcache where classname=?", (classname,)).fetchall()
			if classres == []:
				## check just the last component
				classname = classname.split('.')[-1]
				classres = c.execute("select package from classcache where classname=?", (classname,)).fetchall()
			## check the cloning database
			if classres != []:
				classres_tmp = []
				for r in classres:
					if clones.has_key(r[0]):
						class_tmp = clones[r[0]]
						classres_tmp.append(class_tmp)
					else:   
						classres_tmp.append(r[0])
				classres_tmp = list(set(classres_tmp))
				classres = map(lambda x: (x, 0), classres_tmp)
				classpvs[classname] = classres

		for i in javameta['sourcefiles']:
			pvs = []
			## first try the name as found in the binary. If it can't
			## be found and has dots in it split it on '.' and
			## use the last component only.
			if i.lower().endswith('.java'):
				classname = i[0:-5]
			else:
				classname = i

			## first try the name as found in the binary. If it can't
			## be found and has dots in it split it on '.' and
			## use the last component only.
			classres = c.execute("select package from classcache where classname=?", (classname,)).fetchall()
			## check the cloning database
			if classres != []:
				classres_tmp = []
				for r in classres:
					if clones.has_key(r[0]):
						class_tmp = clones[r[0]]
						classres_tmp.append(class_tmp)
					else:   
						classres_tmp.append(r[0])
				classres_tmp = set(classres_tmp)
				classres = map(lambda x: (x, 0), classres_tmp)
				sourcepvs[classname] = classres

	## Keep a list of which sha256s were already seen. Since the files are
	## likely only coming from a few packages there is no need to hit the database
	## that often.
	sha256cache = {}
	if scanenv.has_key('BAT_FIELDNAME_SCAN'):
		for f in fields:
			## a few fields are so common that they will be completely useless
			## for reporting, but processing them will take a *lot* of time, so
			## just skip them. This list is based on research of many many Java
			## source code files.
			if f in ['value', 'name', 'type', 'data', 'options', 'parent', 'description', 'instance', 'port', 'out', 'properties', 'project', 'next', 'id', 'listeners', 'status', 'target', 'result', 'index', 'buffer', 'values', 'count', 'size', 'key', 'path', 'cache', 'map', 'file', 'context', 'initialized', 'verbose', 'version', 'debug', 'message', 'attributes', 'url', 'DEBUG', 'NAME', 'state', 'source', 'password', 'text', 'start', 'factory', 'entries', 'buf', 'args', 'logger', 'config', 'length', 'encoding', 'method', 'resources', 'timeout', 'filename', 'offset', 'server', 'mode', 'in', 'connection']:
				continue
			pvs = []

			fieldres = c.execute("select package from fieldcache where fieldname=?", (f,)).fetchall()
			if fieldres != []:
				fieldres_tmp = []
				for r in fieldres:
					if clones.has_key(r[0]):
						field_tmp = clones[r[0]]
						fieldres_tmp.append(field_tmp)
					else:   
						fieldres_tmp.append(r[0])
				fieldres_tmp = set(fieldres_tmp)
				fieldres = map(lambda x: (x, 0), fieldres_tmp)
				fieldspvs[f] = fieldres

	variablepvs['fields'] = fieldspvs
	variablepvs['sources'] = sourcepvs
	variablepvs['classes'] = classpvs
	c.close()
	conn.close()
	return variablepvs

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
        #p = subprocess.Popen(['strings', '-n', str(stringcutoff), elftmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        p = subprocess.Popen(['strings', elftmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (stanout, stanerr) = p.communicate()
	st = stanout.split("\n")
	for s in st:
		printstring = s
		if len(printstring) > 0:
			variables.add(printstring)
	os.unlink(elftmp[1])
	return variables

def scankernelsymbols(variables, scanenv, clones):
	kernelcache = scanenv.get(namecacheperlanguage['C'])
	conn = sqlite3.connect(kernelcache)
	## there are only byte strings in our database, not utf-8 characters...I hope
	conn.text_factory = str
	c = conn.cursor()
	vvs = {}
	variablepvs = {}
	for v in variables:
		pvs = []
		res = c.execute("select distinct package from kernelcache where varname=?", (v,)).fetchall()
		if res != []:
			## set version to 0 for now
			pvs = map(lambda x: (x[0],0), res)

		pvs_tmp = []
		for r in pvs:
			if clones.has_key(r[0]):
				pvs_tmp.append((clones[r[0]],r[1]))
			else:
				pvs_tmp.append(r)
		vvs[v] = pvs_tmp
	c.close()
	conn.close()

	vvs_rewrite = {}
	for v in vvs.keys():
		vvs_rewrite[v] = {}
		for vs in vvs[v]:
			(program, version) = vs
			if not vvs_rewrite[v].has_key(program):
				vvs_rewrite[v][program] = [version]
			else:
				vvs_rewrite[v][program] = list(set(vvs_rewrite[v][program] + [version]))
	if vvs_rewrite != {}:
		variablepvs['kernelvariables'] = vvs_rewrite
	return variablepvs

## From dynamically linked ELF files it is possible to extract the dynamic
## symbol table. This table lists the functions and variables which are needed
## from external libraries, but also lists local functions and variables.
## By searching a database that contains which function names and variable names
## can be found in which packages it is possible to identify which package was
## used.
def extractDynamic(scanfile, scanenv, clones, olddb=False):
	dynamicRes = {}
	variablepvs = {}

	if not scanenv.has_key(namecacheperlanguage['C']):
		return (dynamicRes, variablepvs)

 	p = subprocess.Popen(['readelf', '-W', '--dyn-syms', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return (dynamicRes, variablepvs)

	st = stanout.strip().split("\n")

	if st == ['']:
		return (dynamicRes, variablepvs)

	## open the database containing function names that were extracted
	## from source code.
	funccache = scanenv.get(namecacheperlanguage['C'])
	conn = sqlite3.connect(funccache)
	## we have byte strings in our database, not utf-8 characters...I hope
	conn.text_factory = str
	c = conn.cursor()

	## Walk through the output of readelf, and split results accordingly
	## in function names and variables.
	scanstr = []
	mangles = []
	variables = []
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
				variables.append(dynstr[7])
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
			funcname = dynstr[7]
			scanstr.append(funcname)

	if scanenv.has_key('BAT_FUNCTION_SCAN'):
		## run c++filt in batched mode to avoid launching many processes
		## C++ demangling is tricky: the types declared in the function in the source code
		## are not necessarily what demangling will return.
		step = 100
		if mangles != []:
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
					scanstr.append(funcname)

		uniquepackages = {}
		namesmatched = 0
		matches = []
		uniquematches = 0

		## caching datastructure, only needed in case there is no full cache
		sha256_packages = {}

		## the database made from ctags output only has function names, not the types. Since
		## C++ functions could be in an executable several times with different types we
		## deduplicate first
		for funcname in set(scanstr):
			c.execute("select package from functionnamecache where functionname=?", (funcname,))
			res = c.fetchall()
			pkgs = []
			if res != []:
				packages_tmp = []
				for r in res:
					if clones.has_key(r[0]):
						package_tmp = clones[r[0]]
						packages_tmp.append(package_tmp)
					else:
						packages_tmp.append(r[0])
				packages_tmp = list(set(packages_tmp))
				matches.append(funcname)
				namesmatched += 1
				## unique match
				if len(packages_tmp) == 1:
					uniquematches += 1
					if uniquepackages.has_key(packages_tmp[0]):
						uniquepackages[packages_tmp[0]] += [funcname]
					else:
						uniquepackages[packages_tmp[0]] = [funcname]
		dynamicRes['namesmatched'] = namesmatched
		dynamicRes['uniquepackages'] = uniquepackages
		dynamicRes['totalnames'] = len(set(scanstr))

		## unique matches found. 
		dynamicRes['uniquematches'] = uniquematches
		if uniquematches != 0:
			dynamicRes['packages'] = {}
			dynamicRes['versionresults'] = {}
		## these are the unique function names only
		## TODO: here versions for function names were computed. This needs clean ups.
		for package in uniquepackages:
			versions = []
			dynamicRes['versionresults'][package] = []

			dynamicRes['packages'][package] = []
			for v in set(versions):
				dynamicRes['packages'][package].append((v, versions.count(v)))

	## Scan C variables extracted from dynamically linked files.
	if scanenv.get('BAT_VARNAME_SCAN'):
		vvs = {}
		for v in variables:
			## These variable names are very generic and would not be useful, so skip.
			## This is based on research of millions of C files.
			if v in ['options', 'debug', 'options', 'verbose', 'optarg', 'optopt', 'optfind', 'optind', 'opterr']:
				continue
			pvs = []
			res = c.execute("select distinct package from varnamecache where varname=?", (v,)).fetchall()
			if res != []:
				pvs = map(lambda x: (x[0],0), res)

			pvs_tmp = []
			for r in pvs:
				if clones.has_key(r[0]):
					pvs_tmp.append((clones[r[0]],r[1]))
				else:
					pvs_tmp.append(r)
			vvs[v] = pvs_tmp

		vvs_rewrite = {}
		for v in vvs.keys():
			vvs_rewrite[v] = {}
			for vs in vvs[v]:
				(program, version) = vs
				if not vvs_rewrite[v].has_key(program):
					vvs_rewrite[v][program] = [version]
				else:
					vvs_rewrite[v][program] = list(set(vvs_rewrite[v][program] + [version]))
		variablepvs['variables'] = vvs_rewrite
	c.close()
	conn.close()
	return (dynamicRes, variablepvs)

## Look up strings in the database
def extractGeneric(lines, path, scanenv, clones, linuxkernel, stringcutoff, language='C'):
	if len(lines) == 0:
		return None
	lenStringsFound = 0
	uniqueMatches = {}
	uniqueScore = {}
	nonUniqueScore = {}
	nrUniqueMatches = 0
	stringsLeft = {}
	sameFileScore = {}
	alpha = 5.0
	gaincutoff = 1
	scorecutoff = 1.0e-20
	nonUniqueMatches = {}
	nonUniqueMatchLines = []
	nonUniqueAssignments = {}
	unmatched = []

	## setup code guarantees that this database exists and that sanity
	## checks were done.
	if not scanenv.has_key(stringsdbperlanguage[language]):
		return None

	stringscache = scanenv.get(stringsdbperlanguage[language])
	## open the database containing all the strings that were extracted
	## from source code.
	conn = sqlite3.connect(stringscache)
	## we have byte strings in our database, not utf-8 characters...I hope
	conn.text_factory = str
	c = conn.cursor()

	scankernelfunctions = False
	kernelfuncres = []
	if linuxkernel:
		if scanenv.get('BAT_KERNELFUNCTION_SCAN') == '1':
			scankernelfunctions = True
			funccache = scanenv.get(namecacheperlanguage['C'])
			kernelconn = sqlite3.connect(funccache)
			kernelcursor = kernelconn.cursor()

	## keep a dict of versions per package and license per package found. Stub, empty by default.
	packageversions = {}
	packagelicenses = {}

	## keep a copy of the original lines, in the original order
	#origlines = copy.deepcopy(lines)

	## sort the lines first, so it is easy to skip duplicates
	lines.sort()

	lenlines = len(lines)

	print >>sys.stderr, "total extracted strings for %s: %d" %(path, lenlines)

	matchedlines = 0
	oldline = None
	matched = False

	## TODO: this should be done per language
	if scanenv.has_key('BAT_SCORE_CACHE'):
		precomputescore = True
	else:
		precomputescore = False

	for line in lines:
		#print >>sys.stderr, "processing <|%s|>" % line
		## speedup if the line happens to be the same as the old one
		## This does *not* alter the score in any way, but perhaps
		## it should: having a very significant string a few times
		## is a strong indication.
		if line == oldline:
			if matched:
				matchedlines = matchedlines + 1
			continue
		matched = False
		oldline = line
		kernelfunctionmatched = False
		## skip empty lines
		if line == "": continue

		## An extra check for lines that score extremely low. This
		## helps reduce load on databases stored on slower disks
		if precomputescore:
			scoreres = conn.execute("select packages, score from scores where programstring=? LIMIT 1", (line,)).fetchone()
		else:
			scoreres = None
		if scoreres != None:
			## If the score is so low it will not have any influence on the final
			## score, why even bother hitting the disk?
			## Since there might be package rewrites this should be a bit less than the
			## cut off value that was defined.
			if scoreres[1] < scorecutoff/100:
				lenStringsFound = lenStringsFound + len(line)
				matched = True
				matchedlines = matchedlines + 1
				nonUniqueMatchLines.append(line)
				continue

		## if scoreres is None it could still be something else like a kernel function, or a
		## kernel string in a different format, so keep searching.
		## If the image is a Linux kernel image first try the Linux kernel specific matching
		## like function names, then continue as normal.

		if linuxkernel:
			## This is where things get a bit ugly. The strings in a Linux
			## kernel image could also be function names, not string constants.
			## There could be false positives here...
			if scankernelfunctions:
				kernelres = kernelconn.execute("select package FROM kernelfunctionnamecache WHERE functionname=?", (line,)).fetchall()
				if len(kernelres) != 0:
					kernelfuncres.append(line)
					kernelfunctionmatched = True

		res = []
		## then see if there is anything in the cache at all
		if not kernelfunctionmatched:
			res = conn.execute("select package, filename FROM stringscache WHERE programstring=?", (line,)).fetchall()
		else:
			res = []

		if len(res) == 0 and linuxkernel and not kernelfunctionmatched:
			origline = line
			## try a few variants that could occur in the Linux kernel
			## The values of KERN_ERR and friends have changed in the years.
			## In 2.6 it used to be for example <3> (defined in include/linux/kernel.h
			## or include/linux/printk.h )
			## In later kernels this was changed.
			matchres = re.match("<[\d+cd]>", line)
			if matchres != None:
				scanline = line.split('>', 1)[1]
				if len(scanline) < stringcutoff:
					continue
				res = conn.execute("select package, filename FROM stringscache WHERE programstring=?", (scanline,)).fetchall()
				if len(res) != 0:
					line = scanline
				else:
					scanline = scanline.split(':', 1)
					if len(scanline) > 1:
						scanline = scanline[1]
						if scanline.startswith(" "):
							scanline = scanline[1:]
						if len(scanline) < stringcutoff:
							continue
						res = conn.execute("select package, filename FROM stringscache WHERE programstring=?", (scanline,)).fetchall()
						if len(res) != 0:
							if len(scanline) != 0:
								line = scanline
			else:
				scanline = line.split(':', 1)
				if len(scanline) > 1:
					scanline = scanline[1]
					if scanline.startswith(" "):
						scanline = scanline[1:]
					if len(scanline) < stringcutoff:
						continue
					res = conn.execute("select package, filename FROM stringscache WHERE programstring=?", (scanline,)).fetchall()
					if len(res) != 0:
						if len(scanline) != 0:
							line = scanline

				## In include/linux/kern_levels.h since kernel 3.6 a different format is
				## used. TODO: actually check in the binary whether or not a match (if any)
				## is preceded by 0x01
				if len(res) == 0:
					matchres = re.match("\d+", line)
					if matchres != None:
						scanline = line[1:]
						if len(scanline) < stringcutoff:
							continue
						res = conn.execute("select package, filename FROM stringscache WHERE programstring=?", (scanline,)).fetchall()
						if len(res) != 0:
							if len(scanline) != 0:
								line = scanline

		## nothing in the cache
		if len(res) == 0 and not kernelfunctionmatched:
			unmatched.append(line)
		if len(res) != 0:
			## Assume:
			## * database has no duplicates
			## * filenames in the database have been processed using os.path.basename()
			## If not, uncomment the following few lines:
			#res = map(lambda (x,y): (x, os.path.basename(y)), res)
			#res = list(set(res))

			## Add the length of the string to lenStringsFound.
			## We're not really using it, except for reporting.
			lenStringsFound = lenStringsFound + len(line)
			matched = True

			## for statistics it's nice to see how many lines were matched
			matchedlines = matchedlines + 1

			print >>sys.stderr, "\n%d matches found for <(|%s|)> in %s" % (len(res), line, path)

			pkgs = {}    ## {package name: [filenames without path]}
	
			filenames = {}

			## For each string determine in how many packages (without version) the string
			## is found.
			## If the string is only found in one package the string is unique to the package
			## so record it as such and add its length to a score.
			for result in res:
				(package, filename) = result
				if clones.has_key(package):
					package = clones[package]
				if not pkgs.has_key(package):
					pkgs[package] = [filename]
				else:
					pkgs[package].append(filename)
				if not filenames.has_key(filename):
					filenames[filename] = [package]
				else:
					filenames[filename] = list(set(filenames[filename] + [package]))

			if len(pkgs) != 1:
				nonUniqueMatchLines.append(line)
				## The string found is not unique to a package, but is it 
				## unique to a filename?
				## This method assumes that files that are named the same
				## also contain the same or similar content. This could lead
				## to incorrect results.
				## now determine the score for the string
				try:
					score = len(line) / pow(alpha, (len(filenames) - 1))
				except Exception, e:
					## pow(alpha, (len(filenames) - 1)) is overflowing here
					## so the score would be very close to 0. The largest value
					## is sys.maxint, so use that one. The score will be
					## small enough...
					score = len(line) / sys.maxint
					continue

				if score > scorecutoff:
					for packagename in pkgs:
						if not nonUniqueMatches.has_key(packagename):
							nonUniqueMatches[packagename] = [line]
						else:
							nonUniqueMatches[packagename].append(line)
				else:
					continue

				## After having computed a score determine if the files
				## the string was found in in are all called the same.
				## filenames {name of file: { name of package: 1} }
				if filter(lambda x: len(filenames[x]) != 1, filenames.keys()) == []:
					for fn in filenames:
						## The filename fn containing the matched string can only
						## be found in one package.
						## For example: string 'foobar' is present in 'foo.c' in package 'foo'
						## and 'bar.c' in package 'bar', but not in 'foo.c' in package 'bar'
						## or 'bar.c' in foo (if any).
						fnkey = filenames[fn][0]
						nonUniqueScore[fnkey] = nonUniqueScore.get(fnkey,0) + score
				else:
					for fn in filenames:
						## There are multiple packages in which the same
						## filename contains this string, for example 'foo.c'
						## in packages 'foo' and 'bar. This is likely to be
						## internal cloning in the repo.  This string is
						## assigned to a single package in the loop below.
						## Some strings will not signficantly contribute to the score, so they
						## could be ignored and not added to the list.
						## For now exclude them, but in the future they could be included for
						## completeness.
						stringsLeft['%s\t%s' % (line, fn)] = {'string': line, 'score': score, 'filename': fn, 'pkgs' : filenames[fn]}

			else:
				## the string is unique to this package and this package only
				uniqueScore[package] = uniqueScore.get(package, 0) + len(line)

				nrUniqueMatches = nrUniqueMatches + 1

				## store the uniqueMatches without any information about checksums
				if not uniqueMatches.has_key(package):
					uniqueMatches[package] = [(line, [])]
				else:
					uniqueMatches[package].append((line, []))
	if lenlines != 0:
		pass
		#print >>sys.stderr, "matchedlines: %d for %s" % (matchedlines, path)
		#print >>sys.stderr, matchedlines/(lenlines * 1.0)

	del lines

	## def computeScores(stringsLeft, uniqueScore, uniqueMatches, sameFileScore, nonUniqueAssignments):
	## If the string is not unique, do a little bit more work to determine which
	## file is the most likely, so also record the filename.
	##
	## 1. determine whether the string is unique to a package
	## 2. if not, determine which filenames the string is in
	## 3. for each filename, determine whether or not this file (containing the string)
	##    is unique to a package
	## 4. if not, try to determine the most likely package the string was found in

	## For each string that occurs in the same filename in multiple
	## packages (e.g., "debugXML.c", a cloned file of libxml2 in several
	## packages), assign it to one package.  We do this by picking the
	## package that would gain the highest score increment across all
	## strings that are left.  This is repeated until no strings are left.
	pkgsScorePerString = {}
	for stri in stringsLeft:
		pkgsSortedTmp = map(lambda x: {'package': x, 'uniquescore': uniqueScore.get(x, 0)}, stringsLeft[stri]['pkgs'])

		## get the unique score per package and sort in reverse order
		pkgsSorted = sorted(pkgsSortedTmp, key=lambda x: x['uniquescore'], reverse=True)
		## and get rid of the unique scores again. Now it's sorted.
		pkgsSorted = map(lambda x: x['package'], pkgsSorted)
		pkgs2 = []

		for pkgSort in pkgsSorted:
			if uniqueScore.get(pkgSort, 0) == uniqueScore.get(pkgsSorted[0], 0):
				pkgs2.append(pkgSort)
		pkgsScorePerString[stri] = pkgs2

	## suck the average string scores database into memory. Even with a few million packages
	## this will not cost much memory and it prevents many database lookups.
	avgscores = {}
	res = conn.execute("select package, avgstrings from avgstringscache").fetchall()
	c.close()
	conn.close()

	for r in filter(lambda x: x[1] != 0, res):
		avgscores[r[0]] = r[1]

	newgain = {}
	for stri in stringsLeft:
		for p2 in pkgsScorePerString[stri]:
			newgain[p2] = newgain.get(p2, 0) + stringsLeft[stri]['score']

	useless_packages = set()
	for p in newgain.keys():
		## check if packages could ever contribute usefully.
		if newgain[p] < gaincutoff:
			useless_packages.add(p)

	## walk through the data again, filter out useless stuff
	new_stringsleft = {}

	string_split = {}

	for stri in stringsLeft:
		## filter out the strings that only occur in packages that will contribute
		## to the score. Ignore the rest.
		if filter(lambda x: x not in useless_packages, pkgsScorePerString[stri]) != []:
			new_stringsleft[stri] = stringsLeft[stri]
			strsplit = stri.rsplit('\t', 1)[0]
			if string_split.has_key(strsplit):
				string_split[strsplit].append(stri)
			else:
				string_split[strsplit] = [stri]

	stringsLeft = new_stringsleft

	roundNr = 0
	strleft = len(stringsLeft)

	## keep track of which strings were already found. This is because each string
	## is only considered once anyway.
	while strleft > 0:
		roundNr = roundNr + 1
		#print >>sys.stderr, "round %d: %d strings left" % (roundNr, strleft)
		gain = {}
		stringsPerPkg = {}
		## Determine to which packages the remaining strings belong.
		for stri in stringsLeft:
			for p2 in pkgsScorePerString[stri]:
				if p2 in useless_packages:
					continue
				gain[p2] = gain.get(p2, 0) + stringsLeft[stri]['score']
				if not stringsPerPkg.has_key(p2):
					stringsPerPkg[p2] = set()
				stringsPerPkg[p2].add(stri)

		for p2 in gain.keys():
			## check if packages could ever contribute usefully.
			if gain[p2] < gaincutoff:
				useless_packages.add(p2)

		## gain_sorted contains the sort order, gain contains the actual data
		gain_sorted = sorted(gain, key = lambda x: gain.__getitem__(x), reverse=True)
		if gain_sorted == []:
			break

		## so far value is the best, but that might change
		best = gain_sorted[0]

		## Possible optimisation: skip the last step if the gain is not high enough
		if filter(lambda x: x[1] > gaincutoff, gain.items()) == []:
			break

		## if multiple packages have a big enough gain, add them to 'close'
		## and 'fight' to see which package is the most likely hit.
		close = filter(lambda x: gain[x] > (gain[best] * 0.9), gain_sorted)

       		## Let's hope "sort" terminates on a comparison function that
       		## may not actually be a proper ordering.	
		if len(close) > 1:
			# print >>sys.stderr, "  doing battle royale between [close]"
			## reverse sort close, then best = close_sorted[0][0]
			close_sorted = map(lambda x: (x, avgscores[x]), close)
			close_sorted = sorted(close_sorted, key = lambda x: x[1], reverse=True)
			## If we don't have a unique score *at all* it is likely that everything
			## is cloned. There could be a few reasons:
			## 1. there are duplicates in the database due to renaming
			## 2. package A is completely contained in package B (bundling).
			## If there are no hits for package B, it is more likely we are
			## actually seeing package A.
			if uniqueScore == {}:
				best = close_sorted[-1][0]
			else:
				best = close_sorted[0][0]
		best_score = 0
		## for each string in the package with the best gain add the score
		## to the package and move on to the next package.
		todelete = set()
		for xy in stringsPerPkg[best]:
			best_score += 1

			x = stringsLeft[xy]
			sameFileScore[best] = sameFileScore.get(best, 0) + x['score']
			strsplit = xy.rsplit('\t', 1)[0]
			todelete.add(strsplit)
		for a in todelete:
			for st in string_split[a]:
				del stringsLeft[st]
		## store how many non unique strings were assigned per package
		nonUniqueAssignments[best] = best_score
		if gain[best] < gaincutoff:
			break
		strleft = len(stringsLeft)

	scores = {}
	for k in uniqueScore.keys() + sameFileScore.keys():
		scores[k] = uniqueScore.get(k, 0) + sameFileScore.get(k, 0) + nonUniqueScore.get(k,0)
	scores_sorted = sorted(scores, key = lambda x: scores.__getitem__(x), reverse=True)

	rank = 1
	reports = []
	if scores == {}:
		totalscore = 0.0
	else:
		totalscore = float(reduce(lambda x, y: x + y, scores.values()))

	for s in scores_sorted:
		try:
			percentage = (scores[s]/totalscore)*100.0
		except:
			percentage = 0.0
		reports.append((rank, s, uniqueMatches.get(s,[]), percentage, packageversions.get(s, {}), packagelicenses.get(s, [])))
		rank = rank+1
	'''
	for s in scores_sorted:
		if not nonUniqueMatches.has_key(s):
			continue
		correlation_sort = {}
		for r in nonUniqueMatches:
			if r == s:
				continue
			correlation = len(set(nonUniqueMatches[s]).intersection(set(nonUniqueMatches[r])))
			if correlation != 0:
				correlation_sort[r] = correlation
		corr_sorted = sorted(correlation_sort, key = lambda x: correlation_sort.__getitem__(x), reverse=True)
		for c in corr_sorted:
			print >>sys.stderr, s, c, correlation_sort[c]
	'''
	if matchedlines == 0 and unmatched == []:
		return
	return {'matchedlines': matchedlines, 'extractedlines': lenlines, 'reports': reports, 'nonUniqueMatches': nonUniqueMatches, 'nonUniqueAssignments': nonUniqueAssignments, 'unmatched': unmatched, 'scores': scores}


def xmlprettyprint(leafreports, root, envvars=None):
	(res, dynamicRes, variablepvs, language) = leafreports
	## TODO: we might have different results available
	if res['matchedlines'] == 0:
		return None
	tmpnode = root.createElement('ranking')
	stringsnode = root.createElement('strings')
	tmpnode.appendChild(stringsnode)

	matchedlines = root.createElement('matchedlines')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = str(res['matchedlines'])
	matchedlines.appendChild(tmpnodetext)
	stringsnode.appendChild(matchedlines)

	extractedlines = root.createElement('extractedlines')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = str(res['extractedlines'])
	extractedlines.appendChild(tmpnodetext)
	stringsnode.appendChild(extractedlines)

	for k in res['reports']:
		(rank, name, uniqueMatches, percentage, packageversions, packagelicenses) = k

		## add package name
		packagenode = root.createElement('package')
		tmpnodetext = root.createElement('name')
		namenode = xml.dom.minidom.Text()
		namenode.data = name
		tmpnodetext.appendChild(namenode)
		packagenode.appendChild(tmpnodetext)

		## add unique matches, if any
		if len(uniqueMatches) > 0:
			uniquenode = root.createElement('uniquematches')
			for match in uniqueMatches:
				matchnode = root.createElement('unique')
				tmpnodetext = xml.dom.minidom.Text()
				## TODO: not every character is legal in XML,
				## so a translation step is needed
				## here that rewrites illegal characters!
				tmpnodetext.data = match[0]
				matchnode.appendChild(tmpnodetext)
				uniquenode.appendChild(matchnode)
			countnode = root.createElement('uniquecount')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = str(len(uniqueMatches))
			countnode.appendChild(tmpnodetext)
			uniquenode.appendChild(countnode)
			packagenode.appendChild(uniquenode)

		## add rank
		ranknode = root.createElement('rank')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = str(rank)
		ranknode.appendChild(tmpnodetext)

		## add score percentage
		percentagenode = root.createElement('percentage')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = str(percentage)
		percentagenode.appendChild(tmpnodetext)

		## add versions
		if not packageversions == {}:
			sortedversions = sorted(packageversions, key=lambda x: packageversions.__getitem__(x), reverse=True)
			for v in sortedversions:
				versionsnode = root.createElement('version')
				versionnode = root.createElement('number')
				tmpnodetext = xml.dom.minidom.Text()
				tmpnodetext.data = str(v)
				versionnode.appendChild(tmpnodetext)

				countnode = root.createElement('count')
				tmpnodetext = xml.dom.minidom.Text()
				tmpnodetext.data = str(packageversions[v])
				countnode.appendChild(tmpnodetext)
				versionsnode.appendChild(versionnode)
				versionsnode.appendChild(countnode)
				packagenode.appendChild(versionsnode)

		## add licenses
		if not packagelicenses == []:
			licensesnode = root.createElement('licenses')
			for v in packagelicenses:
				licensenode = root.createElement('license')
				tmpnodetext = xml.dom.minidom.Text()
				tmpnodetext.data = str(v[0])
				licensenode.appendChild(tmpnodetext)
				licensesnode.appendChild(licensenode)
			packagenode.appendChild(licensesnode)

		## add everything to the root node
		packagenode.appendChild(ranknode)
		packagenode.appendChild(percentagenode)
		stringsnode.appendChild(packagenode)

	## process any results for dynamically linked executables
	if dynamicRes != {}:
		functionnode = root.createElement('functions')

		totalnamesnode = root.createElement('totalnames')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = str(dynamicRes['totalnames'])
		totalnamesnode.appendChild(tmpnodetext)

		uniquematchesnode = root.createElement('uniquematches')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = str(dynamicRes['uniquematches'])
		uniquematchesnode.appendChild(tmpnodetext)

		namesmatchednode = root.createElement('namesmatched')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = str(dynamicRes['namesmatched'])
		namesmatchednode.appendChild(tmpnodetext)

		functionnode.appendChild(totalnamesnode)
		functionnode.appendChild(uniquematchesnode)
		functionnode.appendChild(namesmatchednode)

		if dynamicRes.has_key('packages'):
			packages = dynamicRes['packages']
			for p in packages:
				packagenode = root.createElement('package')
				namenode = root.createElement('name')
				packagenode.appendChild(namenode)
				tmpnodetext = xml.dom.minidom.Text()
				tmpnodetext.data = str(p)
				namenode.appendChild(tmpnodetext)
				functionnode.appendChild(packagenode)
				for pv in packages[p]:
					versionnode = root.createElement('version')

					numbernode = root.createElement('number')
					tmpnodetext = xml.dom.minidom.Text()
					tmpnodetext.data = str(pv[0])
					numbernode.appendChild(tmpnodetext)

					countnode = root.createElement('count')
					tmpnodetext = xml.dom.minidom.Text()
					tmpnodetext.data = str(pv[1])
					countnode.appendChild(tmpnodetext)

					versionnode.appendChild(numbernode)
					versionnode.appendChild(countnode)
					packagenode.appendChild(versionnode)
		tmpnode.appendChild(functionnode)
	return tmpnode

## stub for method that makes sure that everything is set up properly and modifies
## the environment, as well as determines whether the scan should be run at
## all.
## Returns tuple (run, envvars)
## * run: boolean indicating whether or not the scan should run
## * envvars: (possibly) modified
def rankingsetup(envvars, debug=False):
	scanenv = os.environ.copy()
	newenv = {}
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
				newenv[envname] = envvalue
			except Exception, e:
				pass

	## caches are needed
	rankingfull = False
	if scanenv.get('BAT_RANKING_FULLCACHE', 0) == '1':
		rankingfull = True
	if not rankingfull:
		return (False, None)

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

	for language in stringsdbperlanguage.keys():
		if scanenv.has_key(stringsdbperlanguage[language]):
			## sanity checks to see if the database exists.
			stringscache = scanenv.get(stringsdbperlanguage[language])
			if not os.path.exists(stringscache):
				## remove from the configuration
				if newenv.has_key(stringsdbperlanguage[language]):
					del newenv[stringsdbperlanguage[language]]
				continue

			stringscache = scanenv.get(stringsdbperlanguage[language])
			conn = sqlite3.connect(stringscache)
			conn.text_factory = str
			c = conn.cursor()

			## TODO: check if the format of the cache database is sane

			## check if there is a precomputed scores table and if it has any content.
			## TODO: this really has to be done per language
			res = c.execute("select * from sqlite_master where type='table' and name='scores'").fetchall()
			if res != []:
				if not newenv.has_key('BAT_SCORE_CACHE'):
					newenv['BAT_SCORE_CACHE'] = 1
				res = c.execute("select * from scores LIMIT 1")
				if res == []:
					## if there are no precomputed scores remove it again to save queries later
					if newenv.has_key('BAT_SCORE_CACHE'):
						del newenv['BAT_SCORE_CACHE']
			c.close()
			conn.close()
		else:
			## strings cache is not defined, but it should be there according to
			## the configuration so remove from the configuration
			if newenv.has_key(stringsdbperlanguage[language]):
				del newenv[stringsdbperlanguage[language]]

	## check the cloning database. If it does not exist, or does not have
	## the right schema remove it from the configuration
	if scanenv.has_key('BAT_CLONE_DB'):
		clonedb = scanenv.get('BAT_CLONE_DB')
		if os.path.exists(clonedb):
			conn = sqlite3.connect(clonedb)
			c = conn.cursor()
			c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='renames';")
			if c.fetchall() == []:
				if newenv.has_key('BAT_CLONE_DB'):
					del newenv['BAT_CLONE_DB']
			c.close()
			conn.close()
		else:
			if newenv.has_key('BAT_CLONE_DB'):
				del newenv['BAT_CLONE_DB']

	## check the various caching databases, first for C
	if scanenv.has_key(namecacheperlanguage['C']):
		namecache = scanenv.get(namecacheperlanguage['C'])
		## the cache should exist. If it doesn't exist then something is horribly wrong.
		if not os.path.exists(namecache):
			if newenv.has_key('BAT_KERNELSYMBOL_SCAN'):
				del newenv['BAT_KERNELSYMBOL_SCAN']
			if newenv.has_key('BAT_KERNELFUNCTION_SCAN'):
				del newenv['BAT_KERNELFUNCTION_SCAN']
			if newenv.has_key('BAT_VARNAME_SCAN'):
				del newenv['BAT_VARNAME_SCAN']
			if newenv.has_key('BAT_FUNCTION_SCAN'):
				del newenv['BAT_FUNCTION_SCAN']
			if newenv.has_key(namecacheperlanguage['C']):
				del newenv[namecacheperlanguage['C']]
		else:
			## TODO: add checks for each individual table
			if not newenv.has_key('BAT_KERNELSYMBOL_SCAN'):
				newenv['BAT_KERNELSYMBOL_SCAN'] = 1
			if not newenv.has_key('BAT_VARNAME_SCAN'):
				newenv['BAT_VARNAME_SCAN'] = 1
			if not newenv.has_key('BAT_FUNCTION_SCAN'):
				newenv['BAT_FUNCTION_SCAN'] = 1

			## Sanity check for kernel function names
			cacheconn = sqlite3.connect(namecache)
			cachecursor = cacheconn.cursor()
			cachecursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kernelfunctionnamecache';")

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
		if newenv.has_key('BAT_VARNAME_SCAN'):
			del newenv['BAT_VARNAME_SCAN']
		if newenv.has_key('BAT_FUNCTION_SCAN'):
			del newenv['BAT_FUNCTION_SCAN']

	## then check for Java
	if scanenv.has_key(namecacheperlanguage['Java']):
		namecache = scanenv.get(namecacheperlanguage['Java'])
		## check if the cache exists. If not, something is wrong.
		if not os.path.exists(namecache):
			if newenv.has_key('BAT_CLASSNAME_SCAN'):
				del newenv['BAT_CLASSNAME_SCAN']
			if newenv.has_key('BAT_FIELDNAME_SCAN'):
				del newenv['BAT_FIELDNAME_SCAN']
			if newenv.has_key('BAT_METHOD_SCAN'):
				del newenv['BAT_METHOD_SCAN']
			if newenv.has_key(namecacheperlanguage['Java']):
				del newenv[namecacheperlanguage['Java']]
		else:
			## TODO: add checks for each individual table
			if not newenv.has_key('BAT_CLASSNAME_SCAN'):
				newenv['BAT_CLASSNAME_SCAN'] = 1
			if not newenv.has_key('BAT_FIELDNAME_SCAN'):
				newenv['BAT_FIELDNAME_SCAN'] = 1
			if not newenv.has_key('BAT_METHOD_SCAN'):
				newenv['BAT_METHOD_SCAN'] = 1
	else:
		## undefined, so disable classname/fieldname/method name scan
		if newenv.has_key('BAT_CLASSNAME_SCAN'):
			del newenv['BAT_CLASSNAME_SCAN']
		if newenv.has_key('BAT_FIELDNAME_SCAN'):
			del newenv['BAT_FIELDNAME_SCAN']
		if newenv.has_key('BAT_METHOD_SCAN'):
			del newenv['BAT_METHOD_SCAN']

	return (True, newenv)
