#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011-2016 Armijn Hemel for Tjaldur Software Governance Solutions
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

import sys, os, subprocess, os.path, shutil, stat, struct, zlib
import tempfile, re, magic, hashlib, HTMLParser
import fsmagic, extractor, javacheck

## method to search for all the markers in magicscans
## Although it is in this method it is actually not a pre-run scan, so perhaps
## it should be moved to bruteforcescan.py instead.
def genericMarkerSearch(filename, magicscans, optmagicscans, offset=0, length=0, debug=False):
	datafile = open(filename, 'rb')
	databuffer = []
	offsets = {}
	datafile.seek(offset)
	if length == 0:
		databuffer = datafile.read(2000000)
	else:
		databuffer = datafile.read(length)
	marker_keys = magicscans + optmagicscans
	bufkeys = []
	for key in marker_keys:
		## use a set to have automatic deduplication. Each offset
		## should be in the list only once.
		offsets[key] = set()
		if not fsmagic.fsmagic.has_key(key):
			continue
		bufkeys.append((key,fsmagic.fsmagic[key]))
	while databuffer != '':
		for bkey in bufkeys:
			(key, bufkey) = bkey
			if not bufkey in databuffer:
				continue
			res = databuffer.find(bufkey)
			while res != -1:
				offsets[key].add(offset + res)
				res = databuffer.find(bufkey, res+1)
		if length != 0:
			break
		## move the offset 1999950
		datafile.seek(offset + 1999950)
		## read 2000000 bytes with a 50 bytes overlap with the previous
		## read so we don't miss any pattern. This needs to be updated
		## as soon as patterns >= 50 are used.
		databuffer = datafile.read(2000000)
		if len(databuffer) >= 50:
			offset = offset + 1999950
		else:
			offset = offset + len(databuffer)
	datafile.close()
	for key in marker_keys:
		offsets[key] = list(offsets[key])
		## offsets are expected to be sorted.
		offsets[key].sort()
	return offsets

## Verify a file is an XML file using xmllint.
## Actually this *could* be done with xml.dom.minidom (although some parser settings should be set
## to deal with unresolved entities) to avoid launching another process
def searchXML(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	datafile = open(filename, 'rb')
	offset = 0
	datafile.seek(offset)
	firstchar = datafile.read(1)
	datafile.close()
	## xmllint expects a file to start either with whitespace,
	## or a < character
	if firstchar not in ['\n', '\r', '\t', ' ', '\v', '<']:
		return newtags
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
def verifyText(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
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
	newtags.append("ascii")
	datafile.close()
	return newtags

## Quick check to verify if a file is a graphics file.
def verifyGraphics(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if "text" in tags or "compressed" in tags or "audio" in tags or "graphics" in tags:
		return newtags
	newtags = verifyBMP(filename, tempdir, tags, offsets, scanenv)
	return newtags

def verifyBMP(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'bmp' in offsets:
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

## Verify if this is an Android resources file. These files can be found in
## Android APK archives and are always called "resources.arsc".
## There are various valid types of resource files, which are documented here:
##
## https://android.googlesource.com/platform/frameworks/base.git/+/d24b8183b93e781080b2c16c487e60d51c12da31/include/utils/ResourceTypes.h
##
## At line 155 the definition starts. Currently there are four types:
## * NULL type
## * String pool
## * table
## * XML
## 
## Each of these can be constructed in a different way. Focus is on tables first.
def verifyAndroidResource(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not os.path.basename(filename) == 'resources.arsc':
		return newtags
	## open the file and read the header (8 bytes)
	androidfile = open(filename, 'rb')
	androidbytes = androidfile.read(8)
	androidfile.close()
	restype = struct.unpack('<H', androidbytes[:2])[0]
	## NULL type, handle later
	if restype == 0:
		return newtags
	## string pool type, handle later
	elif restype == 1:
		return newtags
	## table type
	elif restype == 2:
		## header size, skip for now
		headersize = struct.unpack('<H', androidbytes[2:4])[0]
		chunksize = struct.unpack('<I', androidbytes[4:8])[0]
		filesize = os.stat(filename).st_size
		## only check if the file consists of a single chunk for now
		if chunksize == filesize:
			newtags.append('androidresource')
			newtags.append('resource')
			return newtags
	## XML type, handle later
	elif restype == 3:
		return newtags
	return newtags

## Verify and tag Chrome/Chromium/WebView .pak files
## http://dev.chromium.org/developers/design-documents/linuxresourcesandlocalizedstrings
def verifyChromePak(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not filename.endswith('.pak'):
		return newtags

	filesize = os.stat(filename).st_size
	## needs header, number of entries and encoding at the minimum
	if filesize < 9:
		return newtags

	## now read the first four bytes
	pakfile = open(filename, 'rb')
	header = struct.unpack('<I', pakfile.read(4))[0]
	if header != 4:
		pakfile.close()
		return newtags
	numberofentries = struct.unpack('<I', pakfile.read(4))[0]
	encoding = struct.unpack('<B', pakfile.read(1))[0]
	if not encoding in [1,2,3]:
		pakfile.close()
		return newtags

	for i in range(0,numberofentries):
		try:
			resourceid = struct.unpack('<H', pakfile.read(2))[0]
			resourceoffset = struct.unpack('<I', pakfile.read(4))[0]
			if resourceoffset > filesize:
				pakfile.close()
				return newtags
		except:
			pakfile.close()
			return newtags

	## Then two zero bytes
	try:
		if struct.unpack('<H', pakfile.read(2))[0] != 0:
			pakfile.close()
			return newtags
	except:
		pakfile.close()
		return newtags
	## followed by the end of the last resource. This should be the same
	## as the file size
	try:
		endoflastresource = struct.unpack('<I', pakfile.read(4))[0]
	except:
		pakfile.close()
		return newtags
	pakfile.close()
	if endoflastresource == filesize:
		newtags.append("resource")
		newtags.append("pak")
	return newtags

## Verify if this is an Android "binary XML" file. First check if the name of the
## file ends in '.xml', plus check the first four bytes of the file
## If it is an Android XML file, mark it as a 'resource' file
## TODO: have a better check here to increase fidelity
def verifyAndroidXML(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not filename.endswith('.xml'):
		return newtags
	## now read the first four bytes
	androidfile = open(filename, 'rb')
	androidbytes = androidfile.read(4)
	androidfile.close()
	if androidbytes == '\x03\x00\x08\x00':
		newtags.append('androidxml')
		newtags.append('resource')
	return newtags

## Verify if this is an Android/Dalvik classes file. First check if the name of
## the file is 'classes.dex', then check the header and the checksum.
## Header information from https://source.android.com/devices/tech/dalvik/dex-format.html
def verifyAndroidDex(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'dex' in offsets:
		return newtags
	if not os.path.basename(filename) == 'classes.dex':
		return newtags
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags

	## Dex header is 112 bytes
	dexsize = os.stat(filename).st_size
	if dexsize < 112:
		return newtags
	newtags = verifyAndroidDexGeneric(filename, dexsize, 0, verifychecksum=True)
	return newtags

def verifyAndroidDexGeneric(filename, dexsize, offset, verifychecksum=True):
	newtags = []
	byteswapped = False
	## Parse the Dalvik header.
	androidfile = open(filename, 'rb')
	androidfile.seek(offset)

	## magic header, already checked
	magic_bytes = androidfile.read(8)

	## Adler32 checksum
	checksum_bytes = androidfile.read(4)

	## SHA1 checksum
	signature_bytes = androidfile.read(20)

	## file size
	filesize_bytes = androidfile.read(4)

	## header size (should be 112)
	headersize_bytes = androidfile.read(4)

	## endianness (almost guaranteed to be little endian)
	endian_bytes = androidfile.read(4)
	androidfile.close()

	## check if the file is big endian or little endian
	if struct.unpack('<I', endian_bytes)[0] != 0x12345678:
		byteswapped = True

	if byteswapped:
		declared_size = struct.unpack('>I', filesize_bytes)[0]
		dexheadersize = struct.unpack('>I', headersize_bytes)[0]
		dexchecksum = struct.unpack('>I', checksum_bytes)[0]
	else:
		declared_size = struct.unpack('<I', filesize_bytes)[0]
		dexheadersize = struct.unpack('<I', headersize_bytes)[0]
		dexchecksum = struct.unpack('<I', checksum_bytes)[0]

	## The size field in the header should be 0x70
	if dexheadersize != 0x70:
		return newtags
	if declared_size != dexsize:
		return newtags

	if verifychecksum:
		## now compute the Adler32 checksum for the file
		androidfile = open(filename, 'rb')
		androidfile.seek(12)

		## TODO: not very efficient
		checksumdata = androidfile.read(dexsize)
		androidfile.close()
		if zlib.adler32(checksumdata) & 0xffffffff != dexchecksum:
			return newtags

		## Then compute the SHA-1 checksum. Reuse the data from the previous check
		h = hashlib.new('sha1')
		h.update(checksumdata[20:])
		if h.hexdigest().decode('hex') != signature_bytes:
			return newtags

	newtags.append('dalvik')
	newtags.append('dex')
	return newtags

## Verify if this is an optimised Android/Dalvik file. Check if the name of
## the file ends in '.odex', plus verify a length checksum in the header.
## The main reason for this check is to bring down false positives for lzma unpacking
## The specification of the header can be found at:
## https://android.googlesource.com/platform/dalvik.git/+/master/libdex/DexFile.h
## in the struct DexOptHeader
def verifyAndroidOdex(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not 'odex' in offsets:
		return newtags
	if not 'dex' in offsets:
		return newtags
	if len(offsets['dex']) == 0 or len(offsets['odex']) == 0:
		return newtags
	if not offsets['odex'][0] == 0:
		return newtags
	if not os.path.basename(filename).endswith('.odex'):
		return newtags

	seekoffset = 8
	## check the Odex files. First check the header.
	androidfile = open(filename, 'rb')
	androidfile.seek(seekoffset)
	androidbytes = androidfile.read(4)

	## the dex identifier should be defined at this location
	dexoffset = struct.unpack('<I', androidbytes)[0]
	if dexoffset != offsets['dex'][0]:
		androidfile.close()
		return newtags

	seekoffset += 4

	## There are a few interesting values in the Odex header
	androidfile.seek(seekoffset)

	## 1. length of Dex file
	androidbytes = androidfile.read(4)
	dexlength = struct.unpack('<I', androidbytes)[0]

	## 2. offset of optimised DEX dependency table
	androidbytes = androidfile.read(4)
	dependencytableoffset = struct.unpack('<I', androidbytes)[0]

	## 3. length of optimised DEX dependency table
	androidbytes = androidfile.read(4)
	dependencytablesize = struct.unpack('<I', androidbytes)[0]

	## 4. offset of optimised data table
	androidbytes = androidfile.read(4)
	datatableoffset = struct.unpack('<I', androidbytes)[0]

	## 5. length of optimised data table
	androidbytes = androidfile.read(4)
	datatablesize = struct.unpack('<I', androidbytes)[0]

	## 6. flags
	androidbytes = androidfile.read(4)
	flags = struct.unpack('<I', androidbytes)[0]

	## 7. adler checksum of opt and deps
	androidbytes = androidfile.read(4)
	optdepschecksum = struct.unpack('<I', androidbytes)[0]
	androidfile.close()

	## sanity checks for the ODEX header
	## 1. header offset + length of Dex should be < offset of dependency table
	if (dexoffset + dexlength) > dependencytableoffset:
		return newtags

	## 2. offset of dependency table + size of dependency table should be < offset of optimised data table
	if (dependencytableoffset + dependencytablesize) > datatableoffset:
		return newtags
	## 3. offset of data table + length of data table == length of ODEX file
	if not (datatableoffset + datatablesize) == os.stat(filename).st_size:
		return newtags

	## check the Adler32 checksum for opts + deps
	androidfile = open(filename, 'rb')
	androidfile.seek(dependencytableoffset)
	checksumdata = androidfile.read()
	androidfile.close()

	if zlib.adler32(checksumdata) & 0xffffffff != optdepschecksum:
		return newtags

	## Then perform a few checks on the Dex file included in the Odex file, but
	## disable checksum verification.
	if verifyAndroidDexGeneric(filename, dexlength, dexoffset, verifychecksum=False) != []:
		newtags.append('dalvik')
		newtags.append('odex')
	return newtags

## verify if this is a GNU message catalog. First check if the name of the
## file ends in '.po', plus check the first few bytes of the file
## If it is a GNU message catalog, mark it as a 'resource' file
def verifyMessageCatalog(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not filename.endswith('.mo'):
		return newtags
	## now read the first four bytes
	catalogfile = open(filename, 'rb')
	catbytes = catalogfile.read(4)
	catalogfile.close()
	if catbytes == '\xde\x12\x04\x95' or catbytes == '\x95\x04\x12\xde':
		## now check if it is a valid file by running msgunfmt
		p = subprocess.Popen(['msgunfmt', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return newtags
		## this is a valid GNU message catalog, so tag it as such
		newtags.append('messagecatalog')
		newtags.append('resource')
	return newtags

## Simple verifier for SQLite 3 files
## See http://sqlite.org/fileformat.html
def verifySqlite3(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not offsets.has_key('sqlite3'):
		return newtags
	if not 0 in offsets['sqlite3']:
		return newtags
	## check first if the file size is even
	filesize = os.stat(filename).st_size
	## header is already 100 bytes
	if filesize < 100:
		return newtags
	if filesize%2 != 0:
		return newtags

	## get and check the page size, verify if the sizes are correct
	sqlitefile = open(filename, 'rb')
	sqlitefile.seek(16)
	sqlitebytes = sqlitefile.read(2)
	sqlitefile.seek(28)
	pagebytes = sqlitefile.read(4)
	sqlitefile.close()
	pagesize = struct.unpack('>H', sqlitebytes)[0]
	if filesize%pagesize != 0:
		return newtags
	amountofpages = struct.unpack('>I', pagebytes)[0]
	if filesize/pagesize != amountofpages:
		return newtags
	newtags.append('sqlite3')
	return newtags

## Extremely simple verifier for Ogg files.
## This will not tag all Ogg files, but it will be good enough
## for the common cases.
## Note: some Ogg files on some Android devices are "created by a
## buggy encoder" according to ogginfo
def verifyOgg(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not filename.endswith('.ogg'):
		return newtags
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not 'ogg' in offsets:
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
def verifyMP4(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags or 'audio' in tags:
		return newtags
	if not offsets.has_key('mp4'):
		return newtags
	if len(offsets['mp4']) == 0:
		return newtags
	if not offsets['mp4'][0] == 4:
		return newtags
	## now check if it is a valid file by running mp4dump
	p = subprocess.Popen(['mp4dump', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	if "invalid atom size" in stanout:
		return newtags
	newtags.append('mp4')
	return newtags

## very simplistic verifier for some Web Open Font Format
## http://people.mozilla.com/~jkew/woff/
def verifyWOFF(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	## a WOFF file starts with 'wOFF'
	ttffile = open(filename, 'rb')
	ttfbytes = ttffile.read(4)
	if ttfbytes != 'wOFF':
		ttffile.close()
		return newtags
	ttfbytes = ttffile.read(8)
	ttffile.close()
	if struct.unpack('>L', ttfbytes[4:8])[0] == os.stat(filename).st_size:
		newtags.append('woff')
		newtags.append('font')
		newtags.append('resource')
	return newtags

## very simplistic verifier for OpenType fonts
def verifyOTF(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not offsets.has_key('otf'):
		return newtags
	if not 0 in offsets['otf']:
		return newtags

	## sanity check: list the tables and see if offset + length
	## matches the file length
	filesize = os.stat(filename).st_size
	p = subprocess.Popen(['ttx', '-l', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return newtags
	lengthmatch = False
	for l in stanout.strip().split('\n')[3:]:
		ttfsplits = l.strip().split()
		try:
			ttflength = int(ttfsplits[2])
			ttfoffset = int(ttfsplits[3])
			if ttflength + ttfoffset == filesize:
				lengthmatch = True
				break
		except:
			return newtags
	if not lengthmatch:
		return newtags

	## run mkeot first. If it fails (mkeot might not be able to handle
	## all OTF fonts) use ttx to dump fonts
	p = subprocess.Popen(['mkeot', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		## first create a temporary directory where ttx can write its temporary files
		fontdir = tempfile.mkdtemp(dir=unpacktempdir)
		## now check if it is a valid file by running ttx
		p = subprocess.Popen(['ttx', '-d', fontdir, '-i', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			## cleanup
			## TODO: sanity checks
			rmfiles = os.listdir(fontdir)
			for r in rmfiles:
				os.unlink(os.path.join(fontdir, r))
			os.rmdir(fontdir)
			return newtags
		else:
			## TODO: process output of ttx, since it might return 0 even though the font file is corrupted
			pass
		## cleanup
		## TODO: sanity checks
		rmfiles = os.listdir(fontdir)
		for r in rmfiles:
			os.unlink(os.path.join(fontdir, r))
		os.rmdir(fontdir)
	newtags.append('otf')
	newtags.append('font')
	newtags.append('resource')
	return newtags

## very simplistic verifier for some Windows icon files
## https://en.wikipedia.org/wiki/ICO_%28file_format%29
def verifyIco(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not (filename.lower().endswith('.ico') or filename.lower().endswith('.cur')):
		return newtags
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	## check the first four bytes
	icofile = open(filename, 'rb')
	icobytes = icofile.read(4)
	icofile.close()
	## only allow icon files and cursor files
	if icobytes == '\x00\x00\x01\x00':
		filetype = 'ico'
	elif icobytes == '\x00\x00\x02\x00':
		filetype = 'cur'
	else:
		return newtags
	## now check how many images there are in the file
	## actually unpack the ico files
	icofile = open(filename, 'rb')
	icofile.seek(4)
	icobytes = icofile.read(2)
	icocount = struct.unpack('<H', icobytes)[0]
	icofile.close()

	if icocount == 0:
		return newtags

	icofilesize = os.stat(filename).st_size
	icofile = open(filename, 'rb')
	icofile.seek(6)
	for i in xrange(0,icocount):
		icoheader = icofile.read(16)
		if len(icoheader) != 16:
			icofile.close()
			return newtags
		## now parse the header
		## fourth byte should be 0 according to specification
		## although according to wikipedia a value of '\xff' is
		## written by .NET
		if not (icoheader[3] == '\x00' or icoheader[3] == '\xff'):
			icofile.close()
			return newtags
		icosize = struct.unpack('<I', icoheader[8:12])[0]
		icooffset = struct.unpack('<I', icoheader[12:16])[0]
		if icosize > icofilesize:
			icofile.close()
			return newtags
		if icooffset > icofilesize:
			icofile.close()
			return newtags
		if icooffset + icosize > icofilesize:
			icofile.close()
			return newtags
		## TODO: extra sanity check to see if each image is either PNG or BMP
		#oldoffset = icofile.tell()
		#icofile.seek(icooffset)
		#icobytes = icofile.read(icosize)
		#icofile.seek(oldoffset)
	icofile.close()

	## then check each individual image in the file
	icodir = tempfile.mkdtemp(dir=unpacktempdir)
	p = subprocess.Popen(['icotool', '-x', '-o', icodir, filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()

	if p.returncode != 0 or "no images matched" in stanerr:
		pass
	else:
		if filetype == 'ico':
			newtags.append('ico')
		else:
			newtags.append('cursor')
		newtags.append('resource')
	shutil.rmtree(icodir)
	return newtags

## very simplistic verifier for some TrueType fonts
def verifyTTF(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
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
	## run mkeot to verify it is a TTF font
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
## TODO: move out to a separate module
def verifyELF(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
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

	## don't rely on output of readelf as it does not take localized systems into account
	## Instead, use specification found here: http://en.wikipedia.org/wiki/Executable_and_Linkable_Format
	elffile = open(filename, 'rb')
	elfbytes = elffile.read()
	elffile.close()

	## just set some default values: little endian, 32 bit
	littleendian = True
	bit32 = True

	## first check if this is a 32 bit or 64 bit binary
	if struct.unpack('>B', elfbytes[4])[0] != 1:
		bit32 = False
	## then check if this is a little endian or big endian binary
	if struct.unpack('>B', elfbytes[5])[0] != 1:
		littleendian = False

	## check the type
	if littleendian:
		elftypebyte = struct.unpack('<H', elfbytes[0x10:0x10+2])[0]
	else:
		elftypebyte = struct.unpack('>H', elfbytes[0x10:0x10+2])[0]
	if elftypebyte == 0:
		elftype = 'elfnone'
	elif elftypebyte == 1:
		elftype = 'elfrelocatable'
	elif elftypebyte == 2:
		elftype = 'elfexecutable'
	elif elftypebyte == 3:
		elftype = 'elfdynamic'
	elif elftypebyte == 4:
		elftype = 'elfcore'
	newtags.append(elftype)

	## the size of the ELF header
	if bit32:
		elfunpackbytes = elfbytes[0x28:0x28+2]
	else:
		elfunpackbytes = elfbytes[0x34:0x34+2]
	if littleendian:
		thisheadersize = struct.unpack('<H', elfunpackbytes)[0]
	else:
		thisheadersize = struct.unpack('>H', elfunpackbytes)[0]

	## the size of the program headers
	if bit32:
		elfunpackbytes = elfbytes[0x2A:0x2A+2]
	else:
		elfunpackbytes = elfbytes[0x36:0x36+2]
	if littleendian:
		programheadersize = struct.unpack('<H', elfunpackbytes)[0]
	else:
		programheadersize = struct.unpack('>H', elfunpackbytes)[0]

	## the amount of program headers
	if bit32:
		elfunpackbytes = elfbytes[0x2C:0x2C+2]
	else:
		elfunpackbytes = elfbytes[0x38:0x38+2]
	if littleendian:
		numberprogramheaders = struct.unpack('<H', elfunpackbytes)[0]
	else:
		numberprogramheaders = struct.unpack('>H', elfunpackbytes)[0]

	## the size of the section headers
	if bit32:
		elfunpackbytes = elfbytes[0x2E:0x2E+2]
	else:
		elfunpackbytes = elfbytes[0x3A:0x3A+2]
	if littleendian:
		sectionheadersize = struct.unpack('<H', elfunpackbytes)[0]
	else:
		sectionheadersize = struct.unpack('>H', elfunpackbytes)[0]

	## the amount of section headers
	if bit32:
		elfunpackbytes = elfbytes[0x30:0x30+2]
	else:
		elfunpackbytes = elfbytes[0x3C:0x3C+2]
	if littleendian:
		numbersectionheaders = struct.unpack('<H', elfunpackbytes)[0]
	else:
		numbersectionheaders = struct.unpack('>H', elfunpackbytes)[0]

	## the start of section headers
	if bit32:
		elfunpackbytes = elfbytes[0x20:0x20+4]
	else:
		elfunpackbytes = elfbytes[0x28:0x28+8]
	if littleendian:
		if bit32:
			startsectionheader = struct.unpack('<I', elfunpackbytes)[0]
		else:
			startsectionheader = struct.unpack('<Q', elfunpackbytes)[0]
	else:
		if bit32:
			startsectionheader = struct.unpack('>I', elfunpackbytes)[0]
		else:
			startsectionheader = struct.unpack('>Q', elfunpackbytes)[0]

	if startsectionheader > len(elfbytes):
		return []

	## the start of program headers
	if bit32:
		elfunpackbytes = elfbytes[0x1C:0x1C+4]
	else:
		elfunpackbytes = elfbytes[0x20:0x20+8]
	if littleendian:
		if bit32:
			startprogramheader = struct.unpack('<I', elfunpackbytes)[0]
		else:
			startprogramheader = struct.unpack('<Q', elfunpackbytes)[0]
	else:
		if bit32:
			startprogramheader = struct.unpack('>I', elfunpackbytes)[0]
		else:
			startprogramheader = struct.unpack('>Q', elfunpackbytes)[0]

	## the start of section header index
	if bit32:
		elfunpackbytes = elfbytes[0x32:0x32+2]
	else:
		elfunpackbytes = elfbytes[0x3E:0x3E+2]
	if littleendian:
		sectionheaderindex = struct.unpack('<H', elfunpackbytes)[0]
	else:
		sectionheaderindex = struct.unpack('>H', elfunpackbytes)[0]

	dynamic = False

	## first find the table with the names of the sections
	## then grab the list of sections
	## TODO

	## process the section headers
	offset = 0
	dynamiccount = 0
	for i in xrange(0,numbersectionheaders):
		sectionheader = elfbytes[startsectionheader+offset:startsectionheader+sectionheadersize+offset]
		if (startsectionheader + offset) > len(elfbytes):
			return []
		if (startsectionheader + sectionheadersize + offset) > len(elfbytes):
			return []
		if littleendian:
			sh_name = struct.unpack('<I', sectionheader[0:4])[0]
		else:
			sh_name = struct.unpack('>I', sectionheader[0:4])[0]
		if littleendian:
			sh_type = struct.unpack('<I', sectionheader[4:8])[0]
		else:
			sh_type = struct.unpack('>I', sectionheader[4:8])[0]
		if sh_type == 6:
			dynamiccount += 1
		offset += sectionheadersize

	## dynamic count cannot be larger than 1
	if dynamiccount == 1:
		dynamic = True

	## This does not work well for some Linux kernel modules as well as other files
	## (architecture dependent?)
	## One architecture where this sometimes seems to happen is ARM.
	totalsize = startsectionheader + sectionheadersize * numbersectionheaders
	if totalsize == os.stat(filename).st_size:
		newtags.append("elf")
	else:
		## If it is a signed kernel module then the key is appended to the ELF data
		elffile = open(filename, 'rb')
		elffile.seek(-28, os.SEEK_END)
		elfbytes = elffile.read()
		if elfbytes == "~Module signature appended~\n":
			## The metadata of the signing data can be found in 12 bytes
			## preceding the 'magic'
			## According to 'scripts/sign-file' in the Linux kernel
			## the last 4 bytes are the size of the signature data
			## three bytes before that are 0x00
			## The byte before that is the length of the key identifier
			## The byte before that is the length of the "signer's name"
			elffile.seek(-40, os.SEEK_END)
			totalsiglength = 40
			elfbytes = elffile.read(12)
			signaturelength = struct.unpack('>I', elfbytes[-4:])[0]
			totalsiglength += signaturelength
			keyidentifierlen = ord(elfbytes[4])
			signernamelen = ord(elfbytes[3])
			totalsiglength += keyidentifierlen
			totalsiglength += signernamelen
			if totalsiglength + totalsize == os.stat(filename).st_size:
				newtags.append("elf")
		elffile.close()

	if not "elf" in newtags:
		## on some architectures it is necessary to look at the maximum of the starting
		## address of all sections, plus the size of the section to see if
		## (offset of section + size of section) == file size
		p = subprocess.Popen(['readelf', '-t', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return newtags
		st = stanout.strip().split("\n")
		for s in st:
			if "Addr" in s:
				continue
			if ':' in s:
				continue
			spl = s.split()
			if len(spl) == 8:
				try:
					totalsize = int(spl[2], 16) + int(spl[3], 16)
				except:
					continue
				if totalsize == os.stat(filename).st_size:
					newtags.append("elf")
					break

	## TODO: better research this
	if not "elf" in newtags:
		return []
	if not dynamic:
		newtags.append("static")
	else:
		newtags.append("dynamic")
	#if not "elf" in newtags:
		#newtags.append("elf")

	## check whether or not it might be a Linux kernel file or module
	p = subprocess.Popen(['readelf', '-SW', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if "There are no sections in this file." in stanout:
		pass
	else:
		st = stanout.strip().split("\n")
		for s in st[3:]:
			if "__ksymtab_strings" in s:
				newtags.append('linuxkernel')
				break
			if "oat_patches" in s:
				## Android
				newtags.append('oat')
				newtags.append('android')
				break
	return newtags

## simple helper method to verify if a file is a valid Java class file
def verifyJavaClass(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not offsets.has_key('java'):
		return newtags
	if offsets['java'] == []:
		return newtags
	if offsets['java'][0] != 0:
		return newtags
	if not filename.lower().endswith('.class'):
		return newtags
	## There could be multiple class files included. There are situations where there are
	## multiple Java class headers in a file and the file *is* valid. These are files
	## from Java compilers that need to read or write Java class files.
	if len(offsets['java']) > 1:
		tmpfile = tempfile.mkstemp()
		os.fdopen(tmpfile[0]).close()

		## test for each offset found. If the Java class parser thinks it's a valid class
		## file there are multiple class files embedded in this file and then this file
		## cannot be tagged as an individual Java class file.
		origclassfile = open(filename)
		for i in offsets['java']:
			tmpclassfile = open(tmpfile[1], 'wb')
			origclassfile.seek(i)
			data = origclassfile.read()
			tmpclassfile.write(data)
			tmpclassfile.close()
			javares = javacheck.parseJava(filename)
			if javares != None:
				origclassfile.close()
				os.unlink(tmpfile[1])
				return newtags

		origclassfile.close()
		os.unlink(tmpfile[1])
		javares = javacheck.parseJava(filename)
		if javares == None:
			return newtags
		newtags.append('java')
	else:
		## The following will only work if the file has either one or multiple valid class
		## files, starting with a valid class file and ending with a valid class file, or
		## class files followed by random garbage, but no partial class file.
		## The only case that might slip through here is if there is a class file with random
		## garbage following the class file
		javares = javacheck.parseJava(filename)
		if javares == None:
			return newtags
		## TODO: add more checks
		newtags.append('java')
	return newtags

## Method to verify if a Windows executable is a valid 7z file
def verifyExe(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not offsets.has_key('pe'):
		return newtags
	## a PE file *has* to start with the identifier 'MZ'
	if offsets['pe'][0] != 0:
		return newtags
	if not filename.lower().endswith('.exe'):
		return newtags
	datafile = open(filename, 'rb')
	databuffer = datafile.read(100000)
	datafile.close()
	## the string 'PE\0\0' has to appear fairly early in the file
	if not 'PE\0\0' in databuffer:
		return newtags
	## this is a dead giveaway. Ignore DOS executables for now
	if not "This program cannot be run in DOS mode." in databuffer:
		return newtags
	## run 7z l on the file and see if the file size matches 'Physical Size' in the output of 7z
	return newtags

def verifyVimSwap(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if filename.endswith('.swp'):
		datafile = open(filename, 'rb')
		databuffer = datafile.read(6)
		datafile.close()
		if databuffer == 'b0VIM\x20':
			newtags.append('vimswap')
	return newtags

def verifyTZ(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if "zoneinfo" in filename:
		datafile = open(filename, 'rb')
		databuffer = datafile.read(4)
		datafile.close()
		if databuffer == 'TZif':
			## simplistic check for timezone data. This should be enough for
			## most Linux based machines to filter the majority of the
			## timezone files without any extra checks.
			newtags.append('timezone')
			newtags.append('resource')
	return newtags

## verify Apple's AppleDouble encoded files (resource forks)
## http://tools.ietf.org/html/rfc1740 -- Appendix A & B -- Appendix A & B -- Appendix A & B -- Appendix A & B -- Appendix A & B
def verifyResourceFork(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if not 'appledouble' in offsets:
		return newtags
	if not 0 in offsets['appledouble']:
		return newtags

	filesize = os.stat(filename).st_size
	## files are always a multiple of 4
	if filesize%4 != 0:
		return newtags

	datafile = open(filename, 'rb')
	## 4 bytes magic, 4 bytes verson, 16 bytes filler
	datafile.seek(24)
	databuffer = datafile.read(2)
	numberofentries = struct.unpack('>H', databuffer)[0]
	if numberofentries == 0:
		datafile.close()
		return newtags

	## walk all the entries to see if they are valid
	validsize = False
	for i in range(0, numberofentries):
		databuffer = datafile.read(4)
		entry = struct.unpack('>I', databuffer)[0]
		if entry == 0:
			datafile.close()
			return newtags
		databuffer = datafile.read(4)
		offset = struct.unpack('>I', databuffer)[0]
		databuffer = datafile.read(4)
		length = struct.unpack('>I', databuffer)[0]
		if offset + length > filesize:
			datafile.close()
			return newtags
		if offset + length == filesize:
			validsize = True
	datafile.close()

	if not validsize:
		return newtags

	newtags.append('appledouble')
	newtags.append('resourcefork')
	newtags.append('resource')

	return newtags

def verifyRSACertificate(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if not os.path.basename(filename) == 'CERT.RSA':
		return newtags
	p = subprocess.Popen(["openssl", "asn1parse", "-inform", "DER", "-in", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode == 0:
		newtags.append("rsa")
		newtags.append("certificate")
		newtags.append('resource')
	return newtags

## simple check for certificates that you can find in Windows software
## and that could lead to false positives later in the scanning process.
def verifyCertificate(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []

	## a list of known certificates observed in the wild in various
	## installers for Windows software.
	## These certificates are likely in DER format but it is
	## a bit hard to find out which flavour so they can be verified
	## with openssl
	knowncerts = ['042f81e050c384566c1d10dd329712013e1265181196d976b6c75eb244b7f334',
		      'b2ae0c8d9885670d40dae35edc286b6617f1836053e42ffb1d83281f8a6354e6',
		      'dde6c511b2798af5a89fdeeaf176204df3f2c562c79a843d80b68f32a0fbccae',
		      'fdb72f2b5e7cbc57f196e37a7c96f71529124e1c1a7477c63df8e28dc2910c8b',
		     ]

	if os.path.basename(filename) == 'CERTIFICATE':
		certfile = open(filename, 'rb')
		h = hashlib.new('sha256')
		h.update(certfile.read())
		certfile.close()
		if h.hexdigest() in knowncerts:
			newtags.append('certificate')
	return newtags

'''
## stubs for very crude check for HTML files
def verifyHTML(filename, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	extensions = ['htm', 'html']
	if not os.path.basename(filename).lower().rsplit('.', 1)[-1] in extensions:
		return newtags
	htmlfile = open(filename, 'rb')
	htmldata = htmlfile.read()
	htmlfile.close()
	htmlparser = HTMLParser.HTMLParser()
	try:
		htmlparser.feed(htmldata)
	except:
		htmlparser.close()
		return newtags
	htmlparser.close()
	return newtags
'''
