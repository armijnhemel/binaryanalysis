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

import string, re, os, os.path, sys, tempfile, shutil, copy, struct
import subprocess
import extractor, javacheck

## some regular expressions for Java, precompiled
reconststring = re.compile("\s+const-string\s+v\d+")

splitcharacters = map(lambda x: chr(x), range(0,9) + range(14,32) + [127])

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
                             , 0xcd, 0xce, 0xcf, 0xe3, 0xe4, 0xe5, 0xe6
                             , 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed
                             , 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4
                             , 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb
                             , 0xfc, 0xfd, 0xfe, 0xff]

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
                                 , 0xdf, 0xe0, 0xe1, 0xe2, 0x1a]

dalvik_opcodes_two_arguments = [ 0x03, 0x06, 0x09, 0x14, 0x17, 0x24, 0x25
                               , 0x26, 0x2a, 0x2b, 0x2c, 0x6e, 0x6f, 0x70
                               , 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0x1b]

dex_opcodes_extra_data = {}

for i in dalvik_opcodes_no_argument:
        dex_opcodes_extra_data[i] = 0
for i in dalvik_opcodes_single_argument:
        dex_opcodes_extra_data[i] = 1
for i in dalvik_opcodes_two_arguments:
        dex_opcodes_extra_data[i] = 2
dex_opcodes_extra_data[0x18] = 4

unused = [ 0x73, 0x79, 0x7a, 0x3e, 0x3f, 0x40, 0x41
         , 0x42, 0x43, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7
         , 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee
         , 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5
         , 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc
         , 0xfd, 0xfe, 0xff]

## Main part of the scan
##
## 1. extract string constants, function names, variable names, etc.
## 2. Then run strings through computeScore, that queries the database and does
## funky statistics as described in our paper.
##
## Original code (in Perl) was written by Eelco Dolstra.
## Reimplementation in Python done by Armijn Hemel.
##
def searchGeneric(filepath, tags, cursor, conn, blacklist=[], scanenv={}, offsets={}, scandebug=False, unpacktempdir=None):
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

	## list of possible filenames of possible source code that was used
	## to build the binary
	filenames = []

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
			p = subprocess.Popen(['readelf', '-SW', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stanout, stanerr) = p.communicate()
			## check if there actually are sections. On some systems the
			## binary is somewhat corrupted and does not have section headers
			## TODO: localisation fixes
			if "There are no sections in this file." in stanout:
				p = subprocess.Popen(['strings', '-a', '-n', str(stringcutoff), scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
					if l.endswith('.c') or l.endswith('.h'):
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
	return cmeta

def extractJava(scanfile, tags, scanenv, filesize, stringcutoff, blacklist=[], scandebug=False, unpacktempdir=None):
	if 'dex' in tags:
		javatype = 'dex'
	elif 'odex' in tags:
		javatype = 'odex'
	elif 'oat' in tags:
		javatype = 'oat'
		## TODO: find out what to do with this
		return None
	elif 'serializedjava' in tags:
		javatype = 'serializedjava'
		## TODO: find out what to do with this
		return None
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

		javares = javacheck.parseJava(scanfile)
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
	elif javatype == 'dex' or javatype == 'odex':
		'''
		if javatype == 'dex':
			## Further parse the Dex file
			## https://source.android.com/devices/tech/dalvik/dex-format.html

			## assume little endian for now
			dexfile = open(scanfile, 'rb')

			## skip most of the header, as it has already been parsed
			## by the prerun scan
			dexfile.seek(52)

			map_off = struct.unpack('<I', dexfile.read(4))[0]

			## get the length of the string identifiers and the offset
			string_ids_size = struct.unpack('<I', dexfile.read(4))[0]
			string_ids_offset = struct.unpack('<I', dexfile.read(4))[0]

			## get the length of the type identifiers and the offset
			type_ids_size = struct.unpack('<I', dexfile.read(4))[0]
			type_ids_offset = struct.unpack('<I', dexfile.read(4))[0]

			## get the length of the prototype identifiers and the offset
			proto_ids_size = struct.unpack('<I', dexfile.read(4))[0]
			proto_ids_offset = struct.unpack('<I', dexfile.read(4))[0]

			## get the length of the field identifiers and the offset
			field_ids_size = struct.unpack('<I', dexfile.read(4))[0]
			field_ids_offset = struct.unpack('<I', dexfile.read(4))[0]

			## get the length of the class definitions and the offset
			class_defs_size = struct.unpack('<I', dexfile.read(4))[0]
			class_defs_offset = struct.unpack('<I', dexfile.read(4))[0]

			## get the length of the data section and the offset
			data_size = struct.unpack('<I', dexfile.read(4))[0]
			data_offset = struct.unpack('<I', dexfile.read(4))[0]

			string_id_to_value = {}
			if string_ids_offset != 0:
				dexfile.seek(string_ids_offset)
				for dr in range(0, string_ids_size):
					## find the offset of the string identifier in the file
					string_id_offset = struct.unpack('<I', dexfile.read(4))[0]

					## store the old offset so it can be
					## returned to later
					oldoffset = dexfile.tell()

					## jump to the place of the string identifier
					## and read its contents
					dexfile.seek(string_id_offset)
					dexdata = ''
					dexread = dexfile.read(1)
					while dexread != '\x00':
						dexdata += dexread
						dexread = dexfile.read(1)

					if len(dexdata) != 0:
						## the data is length (LEB-128) followed by the actual data
						lenstr = ""
						lencount = 0
						startbyteseen = False
						for c in dexdata:
							lencount += 1
							## add 7 bits
							lenstr = "{:0>8b}".format(ord(c))[1:] + lenstr
							## most significant bit means that the next byte
							## is also part of the length
							if (ord(c) & 0x80) == 0:
								break
						string_id_to_value[dr] = dexdata[lencount:]

					## jump back to the old offset to read
					## the next item
					dexfile.seek(oldoffset)

			map_contents = {}

			## jump to the map and parse it
			if map_off != 0:
				dexfile.seek(map_off)
				map_size = struct.unpack('<I', dexfile.read(4))[0]
				## walk all the map items
				for m in range(0,map_size):
					map_item_type = struct.unpack('<H', dexfile.read(2))[0]
					## discard the next two bytes
					dexfile.read(2)
					## then read the size of the map item and the offset
					map_item_size = struct.unpack('<I', dexfile.read(4))[0]
					map_item_offset = struct.unpack('<I', dexfile.read(4))[0]
					map_contents[map_item_type] = {'offset': map_item_offset, 'size': map_item_size}

			## some of the interesting bits are located in the
			## code section. In particular, the instructions for
			## const-string and const-string/jumbo are interesting
			## https://source.android.com/devices/tech/dalvik/dalvik-bytecode.html
			## The code items are stored in the map_contents, as TYPE_CODE_ITEM
			## which is 0x2001.
			if 0x2001 in map_contents:
				map_offset = map_contents[0x2001]['offset']
				map_item_size = map_contents[0x2001]['size']
				dexfile.seek(map_offset)

				## for each piece of byte code look at the instructions and
				## try to filter out the interesting ones
				print "MAP_ITEM_SIZE", map_item_size
				sys.stdout.flush()
				for m in range(0,map_item_size):
					pos = dexfile.tell()
					## code items are 4 byte aligned
					if pos%4 != 0:
						dexfile.read(4 - pos%4)
					registers_size = struct.unpack('<H', dexfile.read(2))[0]
					print m, "registers_size", registers_size
					ins_size = struct.unpack('<H', dexfile.read(2))[0]
					print "ins", m, ins_size
					outs_size = struct.unpack('<H', dexfile.read(2))[0]
					print "outs", m, outs_size
					tries_size = struct.unpack('<H', dexfile.read(2))[0]
					print "tries", m, tries_size
					debug_info_offset = struct.unpack('<I', dexfile.read(4))[0]
					insns_size = struct.unpack('<I', dexfile.read(4))[0]
					print insns_size

					## keep track of how many 16 bit code units were read
					bytecodecounter = 0
					while bytecodecounter < insns_size:
						## find out the opcode.
						opcode = struct.unpack('<H', dexfile.read(2))[0] & 0xff
						## opcode (and possible register instructions) is
						## one 16 bite code unit
						bytecodecounter += 1

						print m, "opcode", hex(opcode), dex_opcodes_extra_data[opcode]
						if opcode in unused:
							print "UNUSED", opcode
						sys.stdout.flush()

						## find out how many extra code units need to be read
						bytecodecounter += dex_opcodes_extra_data[opcode]
						extradatacount = dex_opcodes_extra_data[opcode] * 2
						if extradatacount != 0:
							extradata = dexfile.read(extradatacount)
							if opcode == 0x1a:
								string_id = struct.unpack('<H', extradata)[0]
							elif opcode == 0x1b:
								string_id = struct.unpack('<I', extradata)[0]
							elif opcode == 0x2b:
								print "2B", hex(dexfile.tell())
								## some extra work might be needed here, as the
								## data might be in "packed-switch-format"
								#print ord(extradata)

								pass
					print 'equal?', bytecodecounter, insns_size, bytecodecounter == insns_size
					sys.stdout.flush()
					if tries_size != 0:
						if insns_size%2 != 0:
							padding = struct.unpack('<H', dexfile.read(2))[0]
						for t in range(0,tries_size):
							start_addr = struct.unpack('<I', dexfile.read(4))[0]
							insn_count = struct.unpack('<H', dexfile.read(2))[0]
							handler_offset = struct.unpack('<H', dexfile.read(2))[0]
							pass
					#break
			dexfile.close()
		'''

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
		if 'UNPACK_TEMPDIR' in scanenv:
			dex_tmpdir = scanenv['UNPACK_TEMPDIR']
		if dex_tmpdir != None:
			dalvikdir = tempfile.mkdtemp(dir=dex_tmpdir)
		else:
			dalvikdir = tempfile.mkdtemp(dir=unpacktempdir)
		p = subprocess.Popen(['java', '-jar', '/usr/share/java/bat-ddx.jar', '-d', dalvikdir, scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
	p = subprocess.Popen(['readelf', '-SW', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(stanout, stanerr) = p.communicate()
	st = stanout.strip().split("\n")

	variables = set()
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
		return variables

        p = subprocess.Popen(['strings', '-a', elftmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
 	p = subprocess.Popen(['readelf', '-W', '--dyn-syms', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		## perhaps an older readelf that does not support --dyn-syms
 		p = subprocess.Popen(['readelf', '-W', '-s', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
			p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
