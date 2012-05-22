#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains methods that should be run before any of the other
scans.

Most of these methods are to verify the type of a file, so it can be tagged
and subsequently be ignored by other scans. For example, if it can already be
determined that an entire file is a GIF file, it can safely be ignored by a
method that only applies to file systems.

Tagging files reduces false positives (especially ones caused by LZMA
unpacking), and in many cases also speeds up the process, because it is clear
very early in the process which files can be ignored.

The methods here are conservative: not all files that could be tagged will be
tagged. Since tagging is just an optimisation this does not really matter: the
files will be scanned and tagged properly later on, but more time might be
spent, plus there might be false positives (mostly LZMA).
'''

import sys, os, subprocess, os.path, shutil, stat, array
import tempfile, re, magic
import fsmagic, fssearch, extractor

## method to search for all the markers in magicscans
## Although it is in this method it is actually not a pre-run scan, so perhaps
## it should be moved to bruteforce.py instead.
def genericMarkerSearch(filename, magicscans, envvars=None):
	datafile = open(filename, 'rb')
	databuffer = []
	order = []
	offsets = {}
	offset = 0
	datafile.seek(offset)
	databuffer = datafile.read(100000)
        marker_keys = magicscans
	for key in marker_keys:
		offsets[key] = []
	while databuffer != '':
		for key in marker_keys:
			res = databuffer.find(fsmagic.fsmagic[key])
			if res == -1:
				continue
			else:
				while res != -1:
					## we should return this differently, so we can sort per offset and
					## do a possibly better scan
					#offsets[key].append((offset + res, key))
					offsets[key].append(offset + res)
					res = databuffer.find(fsmagic.fsmagic[key], res+1)
					if not key in order:
						order.append(key)
		## move the offset 99950
		datafile.seek(offset + 99950)
		## read 100000 bytes with a 50 bytes overlap with the previous
		## read so we don't miss any pattern. This needs to be updated
		## as soon as we have patterns >= 50
		databuffer = datafile.read(100000)
		if len(databuffer) >= 50:
			offset = offset + 99950
		else:
			offset = offset + len(databuffer)
	datafile.close()
	return (offsets, order)

## Verify a file is an XML file using xmllint.
## Actually we *could* do this with xml.dom.minidom (although some parser settings should be set
## to deal with unresolved entities) to avoid launching another process
def searchXML(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	p = subprocess.Popen(['xmllint','--noout', "--nonet", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode == 0:
		newtags.append("xml")
	return newtags

## Verify a file only contains text. This depends on the settings of the
## Python installation.
## The default encoding in Python 2 is 'ascii'. We can't guarantee
## that it has been set by the user to another encoding (possibly we could).
## Since other encodings also contain ASCII it should not be much of an issue.
##
## Interesting link with background info:
## * http://fedoraproject.org/wiki/Features/PythonEncodingUsesSystemLocale
def verifyText(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	datafile = open(filename, 'rb')
	databuffer = []
	offset = 0
	datafile.seek(offset)
	databuffer = datafile.read(100000)
	while databuffer != '':
		if not extractor.isPrintables(databuffer):
			datafile.close()
			newtags.append("binary")
			return newtags
		## move the offset 100000
		datafile.seek(offset + 100000)
		databuffer = datafile.read(100000)
		offset = offset + len(databuffer)
	newtags.append("text")
	datafile.close()
	return newtags

## Quick check to verify if a file is a graphics file.
def verifyGraphics(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if "text" in tags or "compressed" in tags or "audio" in tags:
		return newtags
	newtags = verifyJPEG(filename, tempdir, tags, offsets, envvars)
	if newtags == []:
		newtags = verifyPNG(filename, tempdir, tags, offsets, envvars)
	if newtags == []:
		newtags = verifyGIF(filename, tempdir, tags, offsets, envvars)
	if newtags == []:
		newtags = verifyBMP(filename, tempdir, tags, offsets, envvars)
	return newtags

def verifyBMP(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not offsets.has_key('bmp'):
		return newtags
	if not 0 in offsets['bmp']:
		return newtags
	p = subprocess.Popen(['bmptopnm', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0 or "warning" in stanerr:
		return newtags
	newtags.append("bmp")
	newtags.append("graphics")
	return newtags

def verifyGIF(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	## sanity checks
	if not filename.lower().endswith('.gif'):
		return newtags
	if not offsets.has_key('gif87') and not offsets.has_key('gif89'):
		return newtags
	if len(offsets['gif87'] + offsets['gif89']) > 1:
		return newtags
	if not 0 in (offsets['gif87'] + offsets['gif89']):
		return newtags
	filesize = os.stat(filename).st_size
	giffile = open(filename)
	giffile.seek(filesize - 1)
	## read last byte, it should be ';' according to GIF specifications
	lastbyte = giffile.read(1)
	giffile.close()
	if lastbyte != ';':
		return newtags
	## Now we have a good chance that the file is indeed a GIF file, but
	## we need to be more sure. gifinfo will happily classify files as GIF,
	## even when there is a lot of other stuff following the actual GIF
	## file, so we need to be very very careful here.
	## 1. read the entire file and if there is more than one match for a
	##    trailer, we return. Since the GIF trailer is very very generic
	##    this will also happen for correct GIFs. This is not a problem.
	## 2. run gifinfo
	## 3. for every file that remains we are *very* sure it is a GIF file
	## TODO: make this more efficient
	giffile = open(filename)
	gifdata = giffile.read()
	giffile.close()
	trailer = gifdata.find(';')
	if trailer != filesize - 1:
		return newtags

	p = subprocess.Popen(['gifinfo', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	newtags.append('graphics')
	newtags.append('gif')
	return newtags

def verifyJPEG(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not offsets.has_key('jpeg') or not offsets.has_key('jpegtrailer'):
		return newtags
	if len(offsets['jpeg']) != 1:
		return newtags
	if not 0 in offsets['jpeg']:
		return newtags
	p = subprocess.Popen(['jpegtopnm', '-multiple', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	## multiple jpegs in this file, so we need to unpack, which we don't do here
	if len(stanerr.strip().split("\n")) > 1:
		return newtags
	newtags.append("jpeg")
	newtags.append("graphics")
	return newtags

def verifyPNG(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not offsets.has_key('png'):
		return newtags
	if not offsets.has_key('pngtrailer'):
		return newtags
	if not 0 in offsets['png']:
		return newtags
	if (offsets['pngtrailer'][0] + 8) != os.stat(filename).st_size:
		return newtags
	## now we have a good chance that we have a PNG image, so verify
	p = subprocess.Popen(['webpng', '-d', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	newtags.append("png")
	newtags.append("graphics")
	return newtags

## Check to verify if a file is a gzip compressed file. This requires
## launching an external process, possibly for big files, so we first run a
## few checks to make sure we only do that in promising cases.
def verifyGzip(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if "text" in tags or "graphics" in tags or "compressed" in tags or "audio" in tags:
		return newtags
	if not offsets.has_key('gzip'):
		return newtags
	## if gzip identifier 0x1f 0x8b 0x08 happens to be in there multiple times
	## it might be that we have several gzip files that are concatenated, without
	## padding or extra data and we can't easily see that without full unpacking,
	## so we move on for now.
	if len(offsets['gzip']) != 1:
		return newtags
	if offsets['gzip'][0] != 0:
		return newtags
	p = subprocess.Popen(['gunzip', '-t', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	## possibly multiple gzips in this file, or gzip with trailing data
	if "trailing garbage ignored" in stanerr:
		return newtags
	## the file contains one or more gzip archives
	newtags.append("gzip")
	newtags.append("compressed")
	return newtags

def verifyBZ2(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if "text" in tags or "graphics" in tags or "compressed" in tags:
		return newtags
	if not offsets.has_key('bz2'):
		return newtags
	if not 0 in offsets['bz2']:
		return newtags
	p = subprocess.Popen(['bunzip2', '-tvv', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	## possibly multiple bzip2 in this file, or bzip2 with trailing data
	if len(stanerr.strip().split("\n")) > 1:
		if "trailing garbage after EOF ignored" in stanerr:
			return newtags
		else:
			## output would look like:
			## $ bunzip2 -tvv foo.bz2 
			##  foo.bz2: 
			##    [1: huff+mtf rt+rld]
			##    ok
			## so splitting it on "\n" would give us a list of length 3 in this case
			## perhaps more in other cases. More bzip2 files concatenated would mean
			## that the length of stanerr would be significantly more than the number
			## of the last block that it reports.
			stanerrlines = stanerr.strip().split("\n")
			try:
				blocks = int(stanerrlines[-2].split(':')[0][5:])
				if blocks != (len(stanerrlines) - 2):
					return newtags
			except:
				return newtags
	newtags.append("bz2")
	newtags.append("compressed")
	return newtags

## Verify if this is an Android "binary XML" file. We check if the name of the
## file ends in '.xml', plus check the first four bytes of the file
## If it is an Android XML file, we mark it as a 'resource' file
## TODO: have a better check here to increase fidelity
def verifyAndroidXML(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not filename.endswith('.xml'):
		return newtags
	## now we read the first four bytes
	androidfile = open(filename, 'rb')
	androidbytes = androidfile.read(4)
	androidfile.close()
	if androidbytes == '\x03\x00\x08\x00':
		newtags.append('androidxml')
		newtags.append('resource')
	return newtags

## Verify if this is an Android/Dalvik classes file. We check if the name of
## the file is 'classes.dex', plus check the first four bytes of the file, plus
## verify a length checksum in the header.
## The main reason for this check is to bring down false positives for lzma unpacking
def verifyAndroidDex(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not os.path.basename(filename) == 'classes.dex':
		return newtags
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	## now we read the first 36 bytes
	androidfile = open(filename, 'rb')
	androidbytes = androidfile.read(36)
	androidfile.close()
	if len(androidbytes) != 36:
		return newtags
	if androidbytes[:4] == 'dex\n':
		## good chance we have an Android Dex file, so verify more by
		## checking the size header in the header
		dexarray = array.array('I')
		dexarray.fromstring(androidbytes[-4:])
		dexsize = os.stat(filename).st_size
		if dexarray.pop() == dexsize:
			newtags.append('dalvik')
	return newtags

## verify if this is a GNU message catalog. We check if the name of the
## file ends in '.po', plus check the first few bytes of the file
## If it is a GNU message catalog, we mark it as a 'resource' file
def verifyMessageCatalog(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not filename.endswith('.mo'):
		return newtags
	## now we read the first four bytes
	catalogfile = open(filename, 'rb')
	catbytes = catalogfile.read(4)
	catalogfile.close()
	if catbytes == '\xde\x12\x04\x95' or catbytes == '\x95\x04\x12\xde':
		## now check if it is a valid file by running msgunfmt
		p = subprocess.Popen(['msgunfmt', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return newtags
		## we now know for sure this is a valid GNU message catalog, so tag it as such
		newtags.append('messagecatalog')
		newtags.append('resource')
	return newtags

## Extremely simple verifier for Ogg files.
## This will not tag all Ogg files, but it will be good enough
## for the common cases
def verifyOgg(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not filename.endswith('.ogg'):
		return newtags
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not offsets.has_key('ogg'):
		return newtags
	if not 0 in offsets['ogg']:
		return newtags
	## now check if it is a valid file by running ogginfo
	p = subprocess.Popen(['ogginfo', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	newtags.append('ogg')
	newtags.append('audio')
	return newtags

## extremely simple verifier for MP4 to reduce false positives
def verifyMP4(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not filename.endswith('.mp4'):
		return newtags
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags or 'audio' in tags:
		return newtags
	mp4file = open(filename, 'rb')
	mp4bytes = mp4file.read(8)
	mp4file.close()
	## only check for "ISO Media" at the moment. As soon as I get more
	## test files more will be added.
	if not mp4bytes.endswith('ftyp'):
		return newtags
	## now check if it is a valid file by running mp4dump
	p = subprocess.Popen(['mp4dump', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	if "invalid atom size" in stanout:
		return newtags
	newtags.append('mp4')
	newtags.append('video')
	return newtags

## very simplistic verifier for some TrueType fonts
def verifyTTF(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not filename.endswith('.ttf'):
		return newtags
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	## a TrueType font file starts with '\x00\x01\x00\x00\x00'
	## Since this is a very generic marker it is best to just search
	## for it here, instead of in every file.
	ttffile = open(filename, 'rb')
	ttfbytes = ttffile.read(5)
	ttffile.close()
	if ttfbytes != '\x00\x01\x00\x00\x00':
		return newtags
	## we are getting close. Now run mkeot to verify.
	p = subprocess.Popen(['mkeot', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	newtags.append('ttf')
	newtags.append('resource')
	newtags.append('font')
	return newtags

## simplistic method to verify if a file is an ELF file
## This might not work for all ELF files and it is a conservative verification, only used to
## reduce false positives of LZMA scans.
## This does for sure not work for Linux kernel modules on some devices.
def verifyELF(filename, tempdir=None, tags=[], offsets={}, envvars=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	elffile = open(filename, 'rb')
	elfbytes = elffile.read(4)
	elffile.close()
	if elfbytes != '\x7f\x45\x4c\x46':
		return newtags
	p = subprocess.Popen(['readelf', '-h', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	## process output of readelf
	for i in stanout.strip().split("\n"):
		if "Size of this header" in i:
			res = re.match("\s*Size of this header:\s+(\d+)\s+\(bytes\)", i)
			if res == None:
				return newtags
			else:
				thisheadersize = int(res.groups()[0])
		if "Size of program headers" in i:
			res = re.match("\s*Size of program headers:\s+(\d+)\s+\(bytes\)", i)
			if res == None:
				return newtags
			else:
				programheadersize = int(res.groups()[0])
		if "Number of program headers" in i:
			res = re.match("\s*Number of program headers:\s+(\d+)", i)
			if res == None:
				return newtags
			else:
				numberprogramheaders = int(res.groups()[0])
		if "Size of section headers" in i:
			res = re.match("\s*Size of section headers:\s+(\d+)\s+\(bytes\)", i)
			if res == None:
				return newtags
			else:
				sectionheadersize = int(res.groups()[0])
		if "Number of section headers" in i:
			res = re.match("\s*Number of section headers:\s+(\d+)", i)
			if res == None:
				return newtags
			else:
				numbersectionheaders = int(res.groups()[0])
		if "Start of section headers" in i:
			res = re.match("\s*Start of section headers:\s+(\d+)\s+\(bytes into file\)", i)
			if res == None:
				return newtags
			else:
				startsectionheader = int(res.groups()[0])

		if "Start of program headers" in i:
			res = re.match("\s*Start of program headers:\s+(\d+)\s+\(bytes into file\)", i)
			if res == None:
				return newtags
			else:
				startprogramheader = int(res.groups()[0])

	if thisheadersize != startprogramheader:
		return newtags
	totalsize = startsectionheader + sectionheadersize * numbersectionheaders
	if totalsize == os.stat(filename).st_size:
		newtags.append("elf")
	return newtags
