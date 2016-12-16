#!/usr/bin/python
#-*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2011-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains code to extract identifiers (strings, function names,
variable names, etc.) from binaries and make them available for further
processing by various other scans.
'''

import string, os, os.path, sys, tempfile, shutil, copy, struct, zlib, cStringIO
import subprocess
import extractor, javacheck, elfcheck

splitcharacters = map(lambda x: chr(x), range(0,9) + range(14,32) + [127])

## Dalvik opcodes, with the number of arguments.
## These can largely be found at https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html
## but it should be noted that ODEX opcodes are not documented there
## and the Android source code should be used instead:
##
## https://android.googlesource.com/platform/dalvik.git/+/master/libdex/DexOpcodes.h
##
## Information about ODEX opcodes was lifted from:
## https://android.googlesource.com/platform/dalvik.git/+/master/opcode-gen/bytecode.txt
dalvik_opcodes_no_argument = [ 0x00, 0x01, 0x04, 0x07, 0x0a, 0x0b, 0x0c
                             , 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x1d
                             , 0x1e, 0x21, 0x27, 0x28, 0x3e, 0x3f, 0x40
                             , 0x41, 0x42, 0x43, 0x73, 0x79, 0x7a, 0x7b
                             , 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82
                             , 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89
                             , 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0xb0
                             , 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7
                             , 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe
                             , 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5
                             , 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc
                             , 0xcd, 0xce, 0xcf, 0xec, 0xf1, 0xff]

dalvik_opcodes_single_argument = [ 0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19
                                 , 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x29, 0x2d
                                 , 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34
                                 , 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b
                                 , 0x3c, 0x3d, 0x44, 0x45, 0x46, 0x47, 0x48
                                 , 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
                                 , 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56
                                 , 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d
                                 , 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64
                                 , 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b
                                 , 0x6c, 0x6d, 0x90, 0x91, 0x92, 0x93, 0x94
                                 , 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b
                                 , 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2
                                 , 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9
                                 , 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xd0
                                 , 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7
                                 , 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde
                                 , 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5
                                 , 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xed, 0x1a
                                 , 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xfc, 0xfd, 0xfe]

dalvik_opcodes_two_arguments = [ 0x03, 0x06, 0x09, 0x14, 0x17, 0x24, 0x25
                               , 0x26, 0x2a, 0x2b, 0x2c, 0x6e, 0x6f, 0x70
                               , 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78
                               , 0x1b, 0xee, 0xef, 0xf0, 0xf8, 0xf9, 0xfa
                               , 0xfb]

dex_opcodes_extra_data = {}

for i in dalvik_opcodes_no_argument:
        dex_opcodes_extra_data[i] = 0
for i in dalvik_opcodes_single_argument:
        dex_opcodes_extra_data[i] = 1
for i in dalvik_opcodes_two_arguments:
        dex_opcodes_extra_data[i] = 2
dex_opcodes_extra_data[0x18] = 4

unused = [ 0x73, 0x79, 0x7a, 0x3e, 0x3f, 0x40, 0x41
         , 0x42, 0x43, 0xff]

## Main part of the scan
##
## 1. extract string constants, function names, variable names, etc.
## 2. Then run strings through computeScore, that queries the database and does
## funky statistics as described in our paper. This part is done in other files
##
## Original code (in Perl) was written by Eelco Dolstra.
## Reimplementation in Python done by Armijn Hemel.
##
def searchGeneric(filepath, tags, cursor, conn, filehashresults, blacklist=[], scanenv={}, offsets={}, scandebug=False, unpacktempdir=None):
	filesize = os.stat(filepath).st_size
	## whole file is blacklisted, so no need to scan
	if extractor.inblacklist(0, blacklist) == filesize:
		return None

	## Only consider strings that are len(stringcutoff) or larger
	## it is *very* important to keep this value in sync with the
	## database creation scripts!
	if 'BAT_STRING_CUTOFF' in scanenv:
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
		if 'oat' in tags:
			language = 'Java'
		else:
			language = 'C'
	elif 'bflt' in tags:
		language = 'C'
	elif "java" in tags:
		language = 'Java'
	elif "dalvik" in tags:
		language = 'Java'
	elif 'serializedjava' in tags:
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
			if len(cmeta['strings']) != 0:
				if 'BAT_KERNELFUNCTION_SCAN' in scanenv:
					res = extractKernelData(cmeta['strings'], filepath, cursor, conn, scandebug)
					if res != None:
						if 'kernelfunctions' in res:
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

## Extract identifiers from files that are treated as C
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
		if linuxkernel:
			## The file contains a Linux kernel image and it is not an ELF file.
			## Kernel symbols recorded in the image could lead to false positives,
			## so they first have to be found and be blacklisted.
			kernelfile = open(filepath, 'r')
			validkernelfile = True
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
			seenjiffies = 0
			for jiff in jiffies:
				seenjiffies += 1
				if extractor.inblacklist(jiff, blacklist) != None:
					continue
				if extractor.check_null(kerneldata, jiff, 'loops_per_jiffy'):
					## if "loops_per_jiffy" is surrounded by NULL characters on both
					## ends it is in the list of kernel symbols
					jiffy_pos = jiff
					break
				else:
					## sometimes "loops_per_jiffy" is not preceded by a NULL character
					## because it is at the start of the list of kernel symbols.
					## Right now only do it if jiffies has length 1 or if it is the
					## last in the list of jiffies
					if len(jiffies) == seenjiffies:
						if kerneldata[jiff + len('loops_per_jiffy')] == chr(0x00):
							jiffy_pos = jiff
							break
			if jiffy_pos != -1:
				## work forwards until a symbol that is
				## found that is either not a printable character
				## or a NULL character.
				offset = jiffy_pos + len('loops_per_jiffy')
				lastnull = offset + 1
				lenkerneldata = len(kerneldata)
				while True:
					if offset == lenkerneldata:
						validkernelfile = False
						break
					if not kerneldata[offset] in string.printable:
						if not kerneldata[offset] == chr(0x00):
							break
						else:
							lastnull = offset
					offset += 1

				if validkernelfile:
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

	## list of possible filenames of possible source code that was used
	## to build the binary
	filenames = []

	## store the extracted function/method names, extracted variable names
	## and any file names possibly extracted from debugging sections
	functionnames = set()
	variablenames = set()
	symbolfilenames = set()

	## For ELF binaries concentrate on just a few sections of the
	## binary, namely the .rodata and .data sections.
	## The .rodata section might also contain other data, so expect
	## false positives until there is a better way to get only the string
	## constants :-(
	## Also, in case of certain compiler flags string constants might be in
	## different sections.
	## TODO: find out which compilation settings influence this and how it
	## can be detected that strings were moved to different sections.
	validsectionswithstrings = set(['.data', '.rodata', '.rodata.str1.1', '.rodata.str1.8'])
	if "elf" in tags:
		elfscanfiles = []
		## first determine the size and offset of .data and .rodata sections,
		## carve these sections from the ELF file, then run 'strings'
       		try:
			(totalelf, elfres) = elfcheck.parseELF(scanfile)

			validelf = True
			if elfres == None:
				validelf = False
			else:
				if elfres['sections'] == {}:
					validelf = False

			## check if there actually are sections. On some systems the
			## ELF header is corrupted and does not have section headers
			if not validelf:
				p = subprocess.Popen(['strings', '-a', '-n', str(stringcutoff), scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					if createdtempfile:
						## cleanup the tempfile
						os.unlink(tmpfile[1])
					return None
				lines = stanout.split("\n")
			else:
				datafile = open(filepath, 'rb')
				for s in elfres['sections']:
					section = elfres['sections'][s]['name']
					if not section in validsectionswithstrings:
						continue
					## not interested in NOBITS
					if elfres['sections'][s]['sectiontype'] == 8:
						continue
					unpackelf = True
					elfoffset = elfres['sections'][s]['sectionoffset']
					elfsize = elfres['sections'][s]['sectionsize']
					if blacklist != []:
						if extractor.inblacklist(elfoffset, blacklist) != None:
							unpackelf = False
						if extractor.inblacklist(elfoffset+elfsize, blacklist) != None:
							unpackelf = False
					if unpackelf:
						elftmp = tempfile.mkstemp(dir=unpacktempdir,suffix=section)
						datafile.seek(elfoffset)
						data = datafile.read(elfsize)
						os.write(elftmp[0], data)
						os.fdopen(elftmp[0]).close()
						elfscanfiles.append(elftmp[1])
				datafile.close()

				for i in elfscanfiles:
					## TODO: check if -Tbinary is needed or not
       					p = subprocess.Popen(['strings', '-a', '-n', str(stringcutoff), i], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
				kernelsymbols = extractkernelsymbols(scanfile, scanenv, unpacktempdir)
			else:
				dynres = extractSymbolsFromELF(filepath)
				if dynres != None:
					(functionnames, variablenames, symbolfilenames) = dynres
		except Exception, e:
			print >>sys.stderr, "string scan failed for:", filepath, e, type(e)
			if blacklist != [] and not linuxkernel:
				## cleanup the tempfile
				if createdtempfile:
					os.unlink(tmpfile[1])
			return None
	elif 'bflt' in tags:
		## first check the flags to see if the data section
		## is gzip compressed
		bfltfile = open(scanfile, 'rb')
		bfltfile.seek(12)
		bfltbytes = bfltfile.read(4)
		data_start = struct.unpack('>I', bfltbytes)[0]
		bfltbytes = bfltfile.read(4)
		data_end = struct.unpack('>I', bfltbytes)[0]
		bfltfile.seek(36)
		bfltbytes = bfltfile.read(4)
		bfltfile.seek(data_start)
		databytes = bfltfile.read(data_end-data_start)
		bfltfile.close()
		
		## write the bytes to a temporary file
		bfltdata = tempfile.mkstemp()
		flags = struct.unpack('>I', bfltbytes)[0]
		if flags & 0x04 != 0:
			deflateobj = zlib.decompressobj(-zlib.MAX_WBITS)
			uncompresseddata = deflateobj.decompress(databytes)
			os.write(bfltdata[0], uncompresseddata)
		else:
			os.write(bfltdata[0], databytes)
		os.fdopen(bfltdata[0]).close()

		## TODO: check if -Tbinary is needed or not
       		p = subprocess.Popen(['strings', '-a', '-n', str(stringcutoff), bfltdata[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       		(stanout, stanerr) = p.communicate()

      		st = stanout.split("\n")

       		for s in st:
			printstring = s
               		if len(printstring) >= stringcutoff:
				lines.append(printstring)
		os.unlink(bfltdata[1])
	else:
		## extract all strings from the binary. Only look at strings
		## that are a certain amount of characters or longer. This is
		## configurable through "stringcutoff" although the gain will be relatively
		## low by also scanning strings < stringcutoff
		try:
			p = subprocess.Popen(['strings', '-a', '-n', str(stringcutoff), scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
			if linuxkernel:
				for l in lines:
					if l.endswith('.c') or l.endswith('.h') or l.endswith('.S'):
						filenames.append(l)
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
	cmeta['filenames'] = filenames
	cmeta['functionnames'] = functionnames
	cmeta['variablenames'] = variablenames
	cmeta['kernelsymbols'] = kernelsymbols
	cmeta['symbolfilenames'] = symbolfilenames
	return cmeta

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
def extractJava(scanfile, tags, scanenv, filesize, stringcutoff, blacklist=[], scandebug=False, unpacktempdir=None):
	if blacklist != []:
		return None

	## first try to determine the type of Java file
	if 'dex' in tags:
		javatype = 'dex'
	elif 'odex' in tags:
		javatype = 'odex'
	elif 'oat' in tags:
		javatype = 'oat'
	elif 'serializedjava' in tags:
		javatype = 'serializedjava'
		## TODO: find out what to do with this
		return None
	else:
		javatype = 'java'

	lines = []
	filesize = os.stat(scanfile).st_size
        if javatype == 'java':
		classname = []
		sourcefile = []
		fields = []
		methods = []

		javares = javacheck.parseJava(scanfile, 0)
		if javares == None:
			return None

		classname = javares['classname']
		if javares['sourcefile'] != None:
			sourcefile = [javares['sourcefile']]
		fields = javares['fields']
		methods = javares['methods']
		javalines = javares['strings']

		for i in javalines:
			printstring = i.strip('\0\n\r')
        		if len(printstring) < stringcutoff:
				continue
			## then split mid string
			splitchars = filter(lambda x: x in printstring, splitcharacters)
			if splitchars == []:
				lines.append(printstring)
		javameta = {'classes': classname, 'methods': list(set(methods)), 'fields': list(set(fields)), 'sourcefiles': sourcefile, 'javatype': javatype, 'strings': lines}
	elif javatype == 'dex' or javatype == 'odex' or javatype == 'oat':
		javameta = {'classes': [], 'methods': [], 'fields': [], 'sourcefiles': [], 'javatype': javatype}
		classnames = set()
		sourcefiles = set()
		methods = set()
		fields = set()
		## Further parse the Dex file
		## https://source.android.com/devices/tech/dalvik/dex-format.html
		if javatype == 'oat':
			## first try older oat
			sectionres = elfcheck.getSection(scanfile, '.rodata')
			if sectionres == None:
				return
			elffile = open(scanfile, 'rb')
			elffile.seek(sectionres['sectionoffset'])
			elfdata = elffile.read(sectionres['sectionsize'])
			elffile.close()
			dexfile = cStringIO.StringIO(elfdata)
		else:
			dexfile = open(scanfile, 'rb')

		## assume little endian for now
		dexoffset = 0
		if javatype == 'odex':
			## For odex the dex header is after the
			## odex header.
			dexfile.seek(8)
			androidbytes = dexfile.read(4)
			dexoffset = struct.unpack('<I', androidbytes)[0]
		elif javatype == 'oat':
			## grab the version number
			## The version number is changing very frequently:
			## https://android.googlesource.com/platform/art/+log/master/runtime/oat.h
			dexfile.seek(4)
			oatversion = dexfile.read(4)
			if len(oatversion) != 4:
				dexfile.close()
				return
			## only support 064 for now
			if oatversion !=  '064\x00':
				dexfile.close()
				return
			## for oat the dex header is after the oat header
			## https://www.blackhat.com/docs/asia-15/materials/asia-15-Sabanal-Hiding-Behind-ART-wp.pdf page 7
			dexfile.seek(20)
			androidbytes = dexfile.read(4)
			if len(androidbytes) != 4:
				dexfile.close()
				return
			dexfilecount = struct.unpack('<I', androidbytes)[0]
			if dexfilecount != 1:
				## TODO: what if there are multiple dex files included?
				dexfile.close()
				return

			if oatversion == '064\x00':
				## skip many fields and go straight to key_value_store_size
				dexfile.seek(68)
			androidbytes = dexfile.read(4)
			if len(androidbytes) != 4:
				dexfile.close()
				return
			key_value_store_size = struct.unpack('<I', androidbytes)[0]
			androidbytes = dexfile.read(key_value_store_size)
			if len(androidbytes) != key_value_store_size:
				dexfile.close()
				return

			## then there are a few OAT dex file headers
			for n in xrange(0,dexfilecount):
				## first the dex_file_location_size
				androidbytes = dexfile.read(4)
				if len(androidbytes) != 4:
					dexfile.close()
					return
				dex_file_location_size = struct.unpack('<I', androidbytes)[0]
				## then dex_file_location_data (original path of the input DEX)
				androidbytes = dexfile.read(dex_file_location_size)
				if len(androidbytes) != dex_file_location_size:
					dexfile.close()
					return
				## then the location of the checksum, skip
				androidbytes = dexfile.read(4)
				if len(androidbytes) != 4:
					dexfile.close()
					return
				## then the dex_file_pointer, which is what is needed
				androidbytes = dexfile.read(4)
				if len(androidbytes) != 4:
					dexfile.close()
					return
				dex_file_pointer = struct.unpack('<I', androidbytes)[0]
				## dex data cannot be outside of the oat data
				if dex_file_pointer > len(elfdata):
					dexfile.close()
					return
				dexoffset = dex_file_pointer

		## skip most of the header, as it has already been parsed
		## by the prerun scan
		dexfile.seek(52 + dexoffset)

		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		map_off = struct.unpack('<I', dexbytes)[0] + dexoffset
		if map_off > filesize:
			dexfile.close()
			return

		## get the length of the string identifiers section and the offset
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		string_ids_size = struct.unpack('<I', dexbytes)[0]
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		string_ids_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
		if string_ids_offset > filesize:
			## string_ids_offset cannot be outside of the file
			dexfile.close()
			return

		## get the length of the type identifiers and the offset
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		type_ids_size = struct.unpack('<I', dexbytes)[0]
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		type_ids_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
		if type_ids_offset > filesize:
			## type_ids_offset cannot be outside of the file
			dexfile.close()
			return

		## get the length of the prototype identifiers and the offset
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		proto_ids_size = struct.unpack('<I', dexbytes)[0]
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		proto_ids_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
		if proto_ids_offset > filesize:
			## proto_ids_offset cannot be outside of the file
			dexfile.close()
			return

		## get the length of the field identifiers and the offset
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		field_ids_size = struct.unpack('<I', dexbytes)[0]
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		field_ids_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
		if field_ids_offset > filesize:
			## field_ids_offset cannot be outside of the file
			dexfile.close()
			return

		## get the length of the class definitions and the offset
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		methods_defs_size = struct.unpack('<I', dexbytes)[0]
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		methods_defs_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
		if methods_defs_offset > filesize:
			dexfile.close()
			return

		## get the length of the class definitions and the offset
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		class_defs_size = struct.unpack('<I', dexbytes)[0]
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		class_defs_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
		if class_defs_offset > filesize:
			dexfile.close()
			return

		## get the length of the data section and the offset
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		data_size = struct.unpack('<I', dexbytes)[0]
		dexbytes = dexfile.read(4)
		if len(dexbytes) != 4:
			dexfile.close()
			return
		data_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
		if data_offset > filesize:
			dexfile.close()
			return

		## mapping of string id to the actual string value
		## this is a combination of string literals, method names
		## class names, signatures, and so on.
		string_id_to_value = {}
		if string_ids_offset != 0:
			dexfile.seek(string_ids_offset)
			for dr in range(0, string_ids_size):
				## find the offset of the string identifier in the file
				string_id_offset = struct.unpack('<I', dexfile.read(4))[0] + dexoffset

				## store the old offset so it can be
				## returned to later
				oldoffset = dexfile.tell()

				## jump to the place of the string identifier
				## and read its contents until a NULL byte is encountered
				dexfile.seek(string_id_offset)
				dexdata = ''
				dexread = dexfile.read(1)
				while dexread != '\x00':
					dexdata += dexread
					dexread = dexfile.read(1)

				if len(dexdata) != 0:
					## The string data (string_data_item in Dalvik
					## specificiations) consists of the length of the
					## (as ULEB-128), followed by the the actual data
					## so all that is needed here is to make sure to
					## skip all the bytes that make up the ULEB-128
					## part.
					lencount = 0
					startbyteseen = False
					for c in dexdata:
						lencount += 1
						## most significant bit means that the next byte
						## is also part of the length
						if (ord(c) & 0x80) == 0:
							break
					stringtoadd = dexdata[lencount:].replace('\xc0\x80', '\x00')
					string_id_to_value[dr] = stringtoadd.decode('utf-8')
				else:
					string_id_to_value[dr] = u''

				## jump back to the old offset to read
				## the next item
				dexfile.seek(oldoffset)

		## TODO: sanity checks for the map and the values in the header
		map_contents = {}

		## jump to the map and parse it
		if map_off != 0:
			dexfile.seek(map_off)
			dexbytes = dexfile.read(4)
			if len(dexbytes) != 4:
				dexfile.close()
				return
			map_size = struct.unpack('<I', dexbytes)[0]
			## walk all the map items
			for m in range(0,map_size):
				dexbytes = dexfile.read(2)
				if len(dexbytes) != 2:
					dexfile.close()
					return
				map_item_type = struct.unpack('<H', dexbytes)[0]
				## discard the next two bytes
				dexfile.read(2)
				## then read the size of the map item and the offset
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				map_item_size = struct.unpack('<I', dexbytes)[0]
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				map_item_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
				map_contents[map_item_type] = {'offset': map_item_offset, 'size': map_item_size}

		## some of the interesting bits are located in the
		## code section. In particular, the instructions for
		## const-string and const-string/jumbo are interesting
		## https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html
		## TYPE_TYPE_ID_ITEM == 0x0002
		type_ids = {}
		if 0x0002 in map_contents:
			map_offset = map_contents[0x0002]['offset']
			map_item_size = map_contents[0x0002]['size']
			dexfile.seek(map_offset)
			for m in range(0,map_item_size):
				pos = dexfile.tell()
				## items are 4 byte aligned
				if pos%4 != 0:
					dexfile.read(4 - pos%4)
				descriptor_idx = struct.unpack('<I', dexfile.read(4))[0]
				type_ids[m] = descriptor_idx
		## TYPE_FIELD_ID_ITEM == 0x0004
		## TYPE_METHOD_ID_ITEM == 0x0005
		if 0x0004 in map_contents:
			map_offset = map_contents[0x0004]['offset']
			map_item_size = map_contents[0x0004]['size']
			dexfile.seek(map_offset)
			for m in range(0,map_item_size):
				pos = dexfile.tell()
				## items are 4 byte aligned
				if pos%4 != 0:
					dexfile.read(4 - pos%4)
				class_idx = struct.unpack('<H', dexfile.read(2))[0]
				proto_idx = struct.unpack('<H', dexfile.read(2))[0]
				name_idx = struct.unpack('<I', dexfile.read(4))[0]
				## TODO: sanity checks
				field = string_id_to_value[name_idx]
				if field == 'serialVersionUID':
					continue
				if '$' in field:
					continue
				fields.add(field)
		## TYPE_METHOD_ID_ITEM == 0x0005
		if 0x0005 in map_contents:
			map_offset = map_contents[0x0005]['offset']
			map_item_size = map_contents[0x0005]['size']
			dexfile.seek(map_offset)
			for m in range(0,map_item_size):
				pos = dexfile.tell()
				## items are 4 byte aligned
				if pos%4 != 0:
					dexfile.read(4 - pos%4)
				class_idx = struct.unpack('<H', dexfile.read(2))[0]
				proto_idx = struct.unpack('<H', dexfile.read(2))[0]
				name_idx = struct.unpack('<I', dexfile.read(4))[0]
				## TODO: sanity checks
				method = string_id_to_value[name_idx]
				if method == '<init>' or method == '<clinit>':
					pass
				elif method.startswith('access$'):
					pass
				else:
					methods.add(method)
		## TYPE_CLASS_DEF_ITEM == 0x0006
		if 0x0006 in map_contents:
			map_offset = map_contents[0x0006]['offset']
			map_item_size = map_contents[0x0006]['size']
			dexfile.seek(map_offset)
			for m in range(0,map_item_size):
				pos = dexfile.tell()
				## items are 4 byte aligned
				if pos%4 != 0:
					dexfile.read(4 - pos%4)
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				class_idx = struct.unpack('<I', dexbytes)[0]

				## TODO: sanity checks
				classname = string_id_to_value[type_ids[class_idx]]
				if classname.startswith('L') and classname.endswith(';'):
					classname = classname[1:-1]
					if "$" in classname:
						classname = classname.split("$")[0]
					classnames.add(classname)
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				access_flags = struct.unpack('<I', dexbytes)[0]
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				superclass_idx = struct.unpack('<I', dexbytes)[0]
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				interfaces_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				sourcefile_index = struct.unpack('<I', dexbytes)[0]
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				annotations_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				classdata_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				static_values_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
				if sourcefile_index in string_id_to_value:
					sourcefiles.add(string_id_to_value[sourcefile_index])
				else:
					## broken
					pass

		## The code items are stored in the map_contents, as TYPE_CODE_ITEM
		## which is 0x2001.
		if 0x2001 in map_contents:
			map_offset = map_contents[0x2001]['offset']
			map_item_size = map_contents[0x2001]['size']
			dexfile.seek(map_offset)

			## for each piece of byte code look at the instructions and
			## try to filter out the interesting ones
			for m in range(0,map_item_size):
				pos = dexfile.tell()
				## code items are 4 byte aligned
				if pos%4 != 0:
					dexfile.read(4 - pos%4)
				dexbytes = dexfile.read(2)
				if len(dexbytes) != 2:
					dexfile.close()
					return
				registers_size = struct.unpack('<H', dexbytes)[0]
				dexbytes = dexfile.read(2)
				if len(dexbytes) != 2:
					dexfile.close()
					return
				ins_size = struct.unpack('<H', dexbytes)[0]
				dexbytes = dexfile.read(2)
				if len(dexbytes) != 2:
					dexfile.close()
					return
				outs_size = struct.unpack('<H', dexbytes)[0]
				dexbytes = dexfile.read(2)
				if len(dexbytes) != 2:
					dexfile.close()
					return
				tries_size = struct.unpack('<H', dexbytes)[0]
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				debug_info_offset = struct.unpack('<I', dexbytes)[0] + dexoffset
				dexbytes = dexfile.read(4)
				if len(dexbytes) != 4:
					dexfile.close()
					return
				insns_size = struct.unpack('<I', dexbytes)[0]

				## keep track of how many 16 bit code units were read
				bytecodecounter = 0
				skipbytes = {}
				while bytecodecounter < insns_size:
					opcode_location = dexfile.tell()
					## find out the opcode.
					opcodebytes = dexfile.read(2)
					if len(opcodebytes) != 2:
						## something is wrong here
						dexfile.close()
						return
					opcode = struct.unpack('<H', opcodebytes)[0] & 0xff
					## opcode (and possible register instructions) is
					## one 16 bite code unit
					if opcode_location in skipbytes:
						dexfile.seek(opcode_location+skipbytes[opcode_location])
						bytecodecounter += skipbytes[opcode_location]/2
						continue

					bytecodecounter += 1

					## find out how many extra code units need to be read
					bytecodecounter += dex_opcodes_extra_data[opcode]
					extradatacount = dex_opcodes_extra_data[opcode] * 2
					if extradatacount != 0:
						extradata = dexfile.read(extradatacount)
						if len(extradata) != extradatacount:
							## something is wrong here
							dexfile.close()
							return
						if opcode == 0x1a:
							string_id = struct.unpack('<H', extradata)[0]
							try:
								stringtoadd = string_id_to_value[string_id]
								lines.append(stringtoadd)
							except Exception, e:
								## lookup failed for some reason, so just skip
								pass
						elif opcode == 0x1b:
							string_id = struct.unpack('<I', extradata)[0]
							try:
								stringtoadd = string_id_to_value[string_id]
								lines.append(stringtoadd)
							except Exception, e:
								## lookup failed for some reason, so just skip
								pass
						elif opcode == 0x26:
							## some extra work might be needed here, as the
							## data might be in "packed-switch-payload"
							branch_offset = struct.unpack('<I', extradata)[0]
							if opcode_location + branch_offset*2 > filesize:
								pass
							curoffset = dexfile.tell()
							dexfile.seek(opcode_location + branch_offset*2)
							dexbytes = dexfile.read(2)
							if len(dexbytes) != 2:
								## something is wrong here
								dexfile.close()
								return
							if dexbytes == '\x00\x03':
								dexbytes = dexfile.read(2)
								if len(dexbytes) != 2:
									## something is wrong here
									dexfile.close()
									return
								element_width = struct.unpack('<H', dexbytes)[0]
								dexbytes = dexfile.read(4)
								if len(dexbytes) != 4:
									## something is wrong here
									dexfile.close()
									return
								number_of_elements = struct.unpack('<I', dexbytes)[0]
								skipbytes[opcode_location + branch_offset*2] = 2*((number_of_elements * element_width + 1) / 2 + 4)
							dexfile.seek(curoffset)
						elif opcode == 0x2b:
							## some extra work might be needed here, as the
							## data might be in "packed-switch-payload"
							branch_offset = struct.unpack('<I', extradata)[0]
							if opcode_location + branch_offset*2 > filesize:
								pass
							curoffset = dexfile.tell()
							dexfile.seek(opcode_location + branch_offset*2)
							dexbytes = dexfile.read(2)
							if len(dexbytes) != 2:
								## something is wrong here
								dexfile.close()
								return
							if dexbytes == '\x00\x01':
								dexbytes = dexfile.read(2)
								if len(dexbytes) != 2:
									## something is wrong here
									dexfile.close()
									return
								packedsize = struct.unpack('<H', dexbytes)[0]
								skipbytes[opcode_location + branch_offset*2] = 2*(packedsize * 2+4)
							dexfile.seek(curoffset)
						elif opcode == 0x2c:
							## some extra work might be needed here, as the
							## data might be in "sparse-switch-payload"
							branch_offset = struct.unpack('<I', extradata)[0]
							if opcode_location + branch_offset*2 > filesize:
								pass
							curoffset = dexfile.tell()
							dexfile.seek(opcode_location + branch_offset*2)
							dexbytes = dexfile.read(2)
							if len(dexbytes) != 2:
								## something is wrong here
								dexfile.close()
								return
							if dexbytes == '\x00\x02':
								dexbytes = dexfile.read(2)
								if len(dexbytes) != 2:
									## something is wrong here
									dexfile.close()
									return
								packedsize = struct.unpack('<H', dexbytes)[0]
								skipbytes[opcode_location + branch_offset*2] = 2*(packedsize * 4+2)
							dexfile.seek(curoffset)

				if tries_size != 0:
					## first the list of try_items
					if insns_size%2 != 0:
						dexbytes = dexfile.read(2)
						if len(dexbytes) != 2:
							## something is wrong here
							dexfile.close()
							return
						padding = struct.unpack('<H', dexbytes)[0]
					for t in range(0,tries_size):
						dexbytes = dexfile.read(4)
						if len(dexbytes) != 4:
							## something is wrong here
							dexfile.close()
							return
						start_addr = struct.unpack('<I', dexbytes)[0]
						dexbytes = dexfile.read(2)
						if len(dexbytes) != 2:
							## something is wrong here
							dexfile.close()
							return
						insn_count = struct.unpack('<H', dexbytes)[0]
						dexbytes = dexfile.read(2)
						if len(dexbytes) != 2:
							## something is wrong here
							dexfile.close()
							return
						handler_offset = struct.unpack('<H', dexbytes)[0] + dexoffset
					## then the encoded_catch_handler_list
					lenstr = ""
					while True:
						uleb128byte = dexfile.read(1)
						if len(uleb128byte) != 1:
							## something is wrong here
							dexfile.close()
							return
						lenstr = "{:0>8b}".format(ord(uleb128byte))[1:] + lenstr
						## most significant bit means that the next byte
						## is also part of the length. Prepend to the string.
						if (ord(uleb128byte) & 0x80) == 0:
							break
					for ca in xrange(0, int(lenstr, 2)):
						## The number of catches is encoded in SLEB-128 notation
						## instead of ULEB-128. Depending on the sign there might
						## or might not be a default catch defined.
						catchlenstr = ''
						bytecount = 0
						bytestr = ''
						while True:
							sleb128byte = dexfile.read(1)
							if len(sleb128byte) != 1:
								## something is wrong here
								dexfile.close()
								return
							bytecount += 1
							catchlenstr = "{:0>8b}".format(ord(sleb128byte))[1:] + catchlenstr
							bytestr += sleb128byte
							## most significant bit means that the next byte
							## is also part of the length. Prepend to the string.
							if (ord(sleb128byte) & 0x80) == 0:
								break
						if bytecount == 1:
							## now convert the sleb bytes to a number
							catchsize = 0
							shift = 0
							for bb in bytestr:
								catchsize |= ((ord(bb) & 0x7f) << shift)
								shift += 7
							if catchsize != 0:
								if ord(bb) & 0x40 == 0x40:
									catchsize |= - ( 1 << shift )
						else:
							pass
						for ct in xrange(0,abs(catchsize)):
							## Then read the encoded_type_addr_pair items
							## but don't actually use their data
							while True:
								uleb128byte = dexfile.read(1)
								if len(uleb128byte) != 1:
									## something is wrong here
									dexfile.close()
									return
								## most significant bit means that the next byte
								## is also part of the length.
								if (ord(uleb128byte) & 0x80) == 0:
									break
							while True:
								uleb128byte = dexfile.read(1)
								if len(uleb128byte) != 1:
									## something is wrong here
									dexfile.close()
									return
								## most significant bit means that the next byte
								## is also part of the length.
								if (ord(uleb128byte) & 0x80) == 0:
									break
						if catchsize < 1:
							## the address for the "catch all"
							while True:
								uleb128byte = dexfile.read(1)
								if len(uleb128byte) != 1:
									## something is wrong here
									dexfile.close()
									return
								## most significant bit means that the next byte
								## is also part of the length.
								if (ord(uleb128byte) & 0x80) == 0:
									break
		dexfile.close()

		javameta['classes'] = list(classnames)
		javameta['sourcefiles'] = list(sourcefiles)
		javameta['methods'] = list(methods)
		javameta['fields'] = list(fields)
		javameta['strings'] = lines

	return javameta

## Linux kernels that are stored as statically linked ELF files and Linux kernel
## modules often have a section __ksymtab_strings. This section contains variables
## that are exported by the kernel using the EXPORT_SYMBOL* macros in the Linux
## kernel source tree.
def extractkernelsymbols(filename, scanenv, unpacktempdir):
	variables = set()
	sectionres = elfcheck.getSection(filename, '__ksymtab_strings')
	if sectionres == None:
		return variables

	datafile = open(filename, 'rb')
	datafile.seek(sectionres['sectionoffset'])
	data = datafile.read(sectionres['sectionsize'])
	datafile.close()

	if len(data) == 0:
		return variables

	variables = set(filter(lambda x: x != '', data.split('\x00')))

	return variables

## extract informationfrom the symbol tables (debug symbols, plus dynamic symbols from an ELF
## binary and return three sets:
## 1. function names
## 2. variable names
## 3. file names (from debugging section)
def extractSymbolsFromELF(scanfile):
	symres = elfcheck.getAllSymbols(scanfile)
	if symres == []:
		return (set(), set(), set())

	## Split results in function names, variables and file names
	functionnames = set()
	mangles = []
	variables = set()
	filenames = set()

	for i in symres:
		if i['type'] == 'notype':
			continue
		elif i['type'] == 'section':
			continue
		elif i['type'] == 'file':
			filenames.add(i['name'])
			continue
		elif i['type'] == 'object':
			if i['binding'] == 'weak':
				continue
			variables.add(i['name'])
		elif i['type'] == 'func':
			if i['name'] == 'main':
				continue
			## _init _fini _start are in the ELF standard and/or added by GCC to everything, so skip
			if i['name'] == '_init' or i['name'] == '_fini' or i['name'] == '_start':
				continue
			## __libc_csu_init __libc_csu_fini are in the ELF standard and/or added by GCC to everything, so skip
			if i['name'] == '__libc_csu_init' or i['name'] == '__libc_csu_fini':
				continue
			if i['name'].startswith("_Z"):
				mangles.append(i['name'])
			else:
				functionnames.add(i['name'])
	## run c++filt in batched mode to avoid launching many processes
	## C++ demangling is tricky: the types declared in the function in the source code
	## are not necessarily what demangling will return.
	if mangles != []:
		step = 100
		for i in xrange(0, len(mangles), step):
			offset = i
			args = ['c++filt'] + mangles[offset:offset+step]
			offset = offset + step
			p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0:
				continue
			for f in stanout.strip().split('\n'):
				funcname = f.split('(', 1)[0].rsplit('::', 1)[-1].strip()
				## TODO more sanity checks here, since demangling
				## will sometimes not return a single function name
				functionnames.add(funcname)
	return (functionnames, variables, filenames)

## extract Linux kernel data from a binary file. False positives could exist.
def extractKernelData(lines, filepath, kernelcursor, kernelconn, scandebug):
	kernelfuncres = []
	kernelparamres = []
	oldline = None

	lenlines = len(lines)

	if scandebug:
		print >>sys.stderr, "total extracted strings for %s: %d" %(filepath, lenlines)

	query = "select package FROM linuxkernelfunctionnamecache WHERE functionname = %s;"
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
		kernelconn.commit()
		if len(kernelres) != 0:
			kernelfuncres.append(line)

	returnres = {}
	if kernelfuncres != []:
		returnres['kernelfunctions'] = kernelfuncres
	return returnres

def extractidentifiersetup(scanenv, cursor, conn, debug=False):
	newenv = copy.deepcopy(scanenv)
	if 'BAT_KERNELFUNCTION_SCAN' in newenv:
		if cursor != None:
			cursor.execute("select table_name from information_schema.tables where table_type='BASE TABLE' and table_schema='public'")
			tablenames = map(lambda x: x[0], cursor.fetchall())
			conn.commit()

			## Now verify the names of the tables

			if not 'linuxkernelfunctionnamecache' in tablenames:
				del newenv['BAT_KERNELFUNCTION_SCAN']
		else:
			del newenv['BAT_KERNELFUNCTION_SCAN']

	return (True, newenv)
