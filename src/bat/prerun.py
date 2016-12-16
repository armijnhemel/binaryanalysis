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

import sys, os, subprocess, os.path, shutil, stat, struct, zlib, binascii
import tempfile, re, magic, hashlib, HTMLParser, math
import fsmagic, extractor, javacheck, elfcheck

## method to search for all the markers in magicscans
## Although it is in this method it is actually not a pre-run scan, so perhaps
## it should be moved to bruteforcescan.py instead.
## This method returns a tuple with three results:
## * offsets :: a dictionary with offsets per marker
## * offsettokeys :: a dictionary that maps an offset to a marker
## * isascii :: a flag to indicate that the data found was ASCII
## data only or not
def genericMarkerSearch(filename, magicscans, optmagicscans, offset=0, length=0, debug=False):
	datafile = open(filename, 'rb')
	databuffer = []

	## dictionary with offsets per marker
	offsets = {}

	## mapping of offset to keys
	offsettokeys = {}

	## flag that indicates if the data is ASCII
	isascii = True

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
		if not key in fsmagic.fsmagic:
			continue
		bufkeys.append((key,fsmagic.fsmagic[key]))

	## don't read the file if there are no keys to process
	if bufkeys == []:
		datafile.close()
		return (offsets, offsettokeys, isascii)

	datafile2 = open(filename, 'rb')
	while databuffer != '':
		if isascii:
			if not extractor.isPrintables(databuffer):
				isascii = False
		for bkey in bufkeys:
			(key, bufkey) = bkey
			if not bufkey in databuffer:
				continue
			res = databuffer.find(bufkey)
			while res != -1:
				## hardcode a few checks to avoid possibly passing
				## around many offsets to many methods
				if key == 'jpeg':
					datafile2.seek(offset+res+2)
					checkkey = datafile2.read(1)
					if len(checkkey) == 1:
						if checkkey == '\xff':
							offsets[key].add(offset + res)
				elif key == 'compress':
					datafile2.seek(offset+res+2)
					compressdata = datafile2.read(1)
					if len(compressdata) == 1:
						compressbits = ord(compressdata) & 0x1f
						if compressbits >= 9 and compressbits <= 16:
							offsets[key].add(offset + res)
				elif key == 'ttf':
					datafile2.seek(offset+res+4)
					fontbytes = datafile2.read(2)
					if len(fontbytes) == 2:
						numberoftables = struct.unpack('>H', fontbytes)[0]
						if numberoftables != 0:
							## followed by searchrange
							fontbytes = datafile2.read(2)
							if len(fontbytes) == 2:
								searchrange = struct.unpack('>H', fontbytes)[0]
								## sanity check, see specification
								if pow(2, int(math.log(numberoftables, 2)+4)) == searchrange:
									offsets[key].add(offset + res)
				else:
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
	datafile2.close()
	datafile.close()

	for key in marker_keys:
		offsets[key] = list(offsets[key])
		## offsets are expected to be sorted.
		offsets[key].sort()
		for offset in offsets[key]:
			if offset in offsettokeys:
				offsettokeys[offset].append(key)
			else:
				offsettokeys[offset] = [key]
	return (offsets, offsettokeys, isascii)

## Verify a file is an XML file using xmllint.
## Actually this *could* be done with xml.dom.minidom (although some parser settings should be set
## to deal with unresolved entities) to avoid launching another process
def searchXML(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	datafile = open(filename, 'rb')

	## first check if the file starts with a byte order mark for a UTF-8 file
	## https://en.wikipedia.org/wiki/Byte_order_mark
	offset = 0
	bommarks = datafile.read(3)
	if bommarks == '\xef\xbb\xbf':
		offset = 3
	datafile.seek(offset)
	firstchar = datafile.read(1)
	## xmllint expects a file to start either with whitespace,
	## or a < character.
	while True:
		if firstchar not in ['\n', '\r', '\t', ' ', '\v', '<']:
			datafile.close()
			return newtags
		if firstchar == '<':
			databytes = datafile.read(4)
			datafile.close()
			try:
				if databytes.lower() != '?xml':
					return newtags
				break
			except:
				return newtags
		else:
			firstchar = datafile.read(1)
	p = subprocess.Popen(['xmllint','--noout', "--nonet", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode == 0:
		newtags.append("xml")
	return newtags

## Verify a file only contains text. This depends on the settings of the
## Python installation.
## The default encoding in Python 2 is 'ascii'. It cannot be guaranteed
## that it has been set by the user to another encoding.
## Since other encodings also contain ASCII it should not be much of an issue.
##
## Interesting link with background info:
## * http://fedoraproject.org/wiki/Features/PythonEncodingUsesSystemLocale
def verifyText(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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

## verify WAV files
## http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
## https://sites.google.com/site/musicgapi/technical-documents/wav-file-format
def verifyWav(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	## some chunks observed in the wild. 'LGWV' and 'bext' seem to be extensions
	validchunks = ['fmt ', 'fact', 'data', 'cue ', 'list', 'plst', 'labl', 'ltxt', 'note', 'smpl', 'inst', 'bext', 'LGWV']
	## the next four characters should be 'WAVE'
	fourcc = 'WAVE'
	newtags = verifyRiff(filename, validchunks, fourcc, tempdir, tags, offsets, scanenv, debug, unpacktempdir)
	if newtags != []:
		newtags.append('wav')
		newtags.append('audio')
	return newtags

## verify WebP files
## https://developers.google.com/speed/webp/docs/riff_container
def verifyWebP(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	validchunks = ['VP8 ', 'VP8L', 'VP8X', 'ANIM', 'ANMF', 'ALPH', 'ICCP', 'EXIF', 'XMP ']
	## the next four characters should be 'WEBP'
	fourcc = 'WEBP'
	newtags = verifyRiff(filename, validchunks, fourcc, tempdir, tags, offsets, scanenv, debug, unpacktempdir)
	if newtags != []:
		newtags.append('webp')
		newtags.append('graphics')
	return newtags

## generic method to verify RIFF files, such as WebP or WAV
def verifyRiff(filename, validchunks, fourcc, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None):
	newtags = []
	if "text" in tags or "compressed" in tags or "audio" in tags or "graphics" in tags:
		return newtags
	if not 'riff' in offsets:
		return newtags
	if not 0 in offsets['riff']:
		return newtags
	filesize = os.stat(filename).st_size

	## there should at least be a valid header
	if filesize < 12:
		return newtags
	rifffile = open(filename, 'rb')
	rifffile.seek(4)
	## size of bytes following the size field
	rifffilesize = struct.unpack('<I', rifffile.read(4))[0]

	if not rifffilesize + 8 == filesize:
		rifffile.close()
		return newtags
	fourcc_read = rifffile.read(4)

	if fourcc_read != fourcc:
		rifffile.close()
		return newtags

	## then depending on the file format different
	## content will follow.
	## There are different chunks that can follow eachother
	## in the file.
	while rifffile.tell() != filesize:
		chunkheaderbytes = rifffile.read(4)
		if len(chunkheaderbytes) != 4:
			rifffile.close()
			return newtags
		if not chunkheaderbytes in validchunks:
			rifffile.close()
			return newtags

		## then read the size of the chunk
		chunksizebytes = rifffile.read(4)
		if len(chunksizebytes) != 4:
			rifffile.close()
			return newtags
		chunksizebytes = struct.unpack('<I', chunksizebytes)[0]
		curoffset = rifffile.tell()
		if curoffset + chunksizebytes > filesize:
			rifffile.close()
			return newtags
		rifffile.seek(curoffset + chunksizebytes)

	rifffile.close()
	newtags.append('riff')
	return newtags

## generic method to verify AIFF and AIFF-C. This is very similar to RIFF
## but has different endianness and several other restrictions.
## https://en.wikipedia.org/wiki/Audio_Interchange_File_Format
def verifyAIFF(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if "text" in tags or "compressed" in tags or "audio" in tags or "graphics" in tags:
		return newtags
	if not 'aiff' in offsets:
		return newtags
	if not 0 in offsets['aiff']:
		return newtags
	filesize = os.stat(filename).st_size

	## there should at least be a valid header
	if filesize < 12:
		return newtags

	bigendian = True

	aifffile = open(filename, 'rb')
	aifffile.seek(4)

	## size of bytes following the size field. This field
	## should be filesize - 8 if the whole file is AIFF
	formsizebytes = aifffile.read(4)

	formsize = struct.unpack('>I', formsizebytes)[0]

	if formsize + 8 != filesize:
		aifffile.close()
		return newtags

	## then check if it is little endian or big endian
	## this is not used, but could be useful in the future
	endianbytes = aifffile.read(4)

	if endianbytes == 'AIFC':
		bigendian = False
	elif endianbytes == 'AIFF':
		bigendian = True
	else:
		aifffile.close()
		return newtags

	## then depending on the file format different
	## content will follow.
	## There are different chunks that can follow eachother
	## in the file.
	seenchunkids = set()
	while aifffile.tell() != filesize:
		chunkheaderbytes = aifffile.read(4)
		if len(chunkheaderbytes) != 4:
			aifffile.close()
			return newtags
		seenchunkids.add(chunkheaderbytes)

		## then read the size of the chunk
		chunksizebytes = aifffile.read(4)
		if len(chunksizebytes) != 4:
			aifffile.close()
			return newtags
		chunksizebytes = struct.unpack('>I', chunksizebytes)[0]
		curoffset = aifffile.tell()
		if curoffset + chunksizebytes > filesize:
			aifffile.close()
			return newtags
		aifffile.seek(curoffset + chunksizebytes)
	aifffile.close()

	## AIFF files have two mandatory chunks
	if not ('COMM' in seenchunkids and 'SSND' in seenchunkids):
		return newtags

	newtags.append('aiff')
	newtags.append('audio')

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
def verifyAndroidResource(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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
	if not len(androidbytes) == 8:
		return newtags
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
def verifyChromePak(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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
			resourcebytes = pakfileread(2)
			if len(resourcebytes) != 2:
				pakfile.close()
				return newtags
			resourceid = struct.unpack('<H', resourcebytes)[0]
			resourcebytes = pakfileread(4)
			if len(resourcebytes) != 4:
				pakfile.close()
				return newtags
			resourceoffset = struct.unpack('<I', resourcebytes)[0]
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
def verifyAndroidXML(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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
def verifyAndroidDex(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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
def verifyAndroidOdex(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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
def verifyMessageCatalog(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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
def verifySqlite3(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	if not 'sqlite3' in offsets:
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

## extremely simple verifier for MP4 to reduce false positives
def verifyMP4(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags or 'audio' in tags:
		return newtags
	if not 'mp4' in offsets:
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

## very simplistic verifier for some Windows icon files
## https://en.wikipedia.org/wiki/ICO_%28file_format%29
def verifyIco(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	knownicoextensions = ['cur', 'ico', 'hdb']
	filesplit = filename.lower().rsplit('.', 1)
	if len(filesplit) != 2:
		return newtags

	extension = filesplit[1]
	if not extension in knownicoextensions:
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
	icofile = open(filename, 'rb')
	icofile.seek(4)
	icobytes = icofile.read(2)
	icofile.close()
	if len(icobytes) != 2:
		return newtags
	icocount = struct.unpack('<H', icobytes)[0]

	if icocount == 0:
		return newtags

	icofilesize = os.stat(filename).st_size
	icofile = open(filename, 'rb')
	icofile.seek(6)

	oldoffset = 0
	## the ICO format first has all the headers, then the image data
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

		## grab the size of the icon, plus the offset where it can
		## be found in the file
		icosize = struct.unpack('<I', icoheader[8:12])[0]
		icooffset = struct.unpack('<I', icoheader[12:16])[0]

		## the declared size of the icon cannot be larger than
		## the icon file
		if icosize > icofilesize:
			icofile.close()
			return newtags
		## the declared offset of the icon cannot be beyond the
		## end of the icon file
		if icooffset > icofilesize:
			icofile.close()
			return newtags
		## the data of the icon cannot be outside of the file
		if icooffset + icosize > icofilesize:
			icofile.close()
			return newtags
		## the icon cannot start before the end of the
		## previous icon (if any)
		if not icooffset >= oldoffset:
			return newtags
		oldoffset = icooffset + icosize
		## TODO: extra sanity check to see if each image
		## is actually a valid image.
		#oldoffset = icofile.tell()
		#icofile.seek(icooffset)
		#icobytes = icofile.read(icosize)
		#icofile.seek(oldoffset)
	icofile.close()

	## the size of all icons together has to be the file size
	if not oldoffset == icofilesize:
		return newtags

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

def verifyBFLT(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if not 'bflt' in offsets:
		return newtags
	if not 0 in offsets['bflt']:
		return newtags
	filesize = os.stat(filename).st_size
	if filesize < 64:
		return newtags
	bfltfile = open(filename, 'rb')
	bfltfile.seek(4)
	bfltbytes = bfltfile.read(4)
	version = struct.unpack('>I', bfltbytes)[0]
	## only support version 4 for now
	if version != 4:
		bfltfile.close()
		return newtags

	bfltbytes = bfltfile.read(4)
	firstinsoffset = struct.unpack('>I', bfltbytes)[0]
	if firstinsoffset > filesize:
		bfltfile.close()
		return newtags
	
	bfltbytes = bfltfile.read(4)
	data_start_offset = struct.unpack('>I', bfltbytes)[0]
	if data_start_offset > filesize:
		bfltfile.close()
		return newtags

	bfltbytes = bfltfile.read(4)
	data_end_offset = struct.unpack('>I', bfltbytes)[0]
	if data_end_offset > filesize:
		bfltfile.close()
		return newtags

	bfltbytes = bfltfile.read(4)
	bss_end_offset = struct.unpack('>I', bfltbytes)[0]

	bfltbytes = bfltfile.read(4)
	stacksize = struct.unpack('>I', bfltbytes)[0]

	bfltbytes = bfltfile.read(4)
	reloc_start_offset = struct.unpack('>I', bfltbytes)[0]
	if reloc_start_offset > filesize:
		bfltfile.close()
		return newtags

	bfltbytes = bfltfile.read(4)
	reloc_count = struct.unpack('>I', bfltbytes)[0]

	bfltbytes = bfltfile.read(4)
	flags = struct.unpack('>I', bfltbytes)[0]

	## should be all null, but isn't always the case.
	filler = bfltfile.read(24)
	bfltfile.close()

	if (reloc_count * 4) + reloc_start_offset == filesize:
		newtags.append('bflt')
	return newtags

## simplistic method to verify if a file is an ELF file
## This might not work for all ELF files and it is a conservative verification, only used to
## reduce false positives of LZMA scans.
## This does for sure not work for Linux kernel modules on some devices.
def verifyELF(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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
	newtags = elfcheck.verifyELF(filename, tempdir, tags, offsets, scanenv, debug, unpacktempdir)
	return newtags

## Method to verify if a Windows executable is a valid 7z file
def verifyExe(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if not 'pe' in offsets:
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

## Check if a file is a Vim swap file
def verifyVimSwap(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if filename.endswith('.swp'):
		datafile = open(filename, 'rb')
		databuffer = datafile.read(6)
		datafile.close()
		if databuffer == 'b0VIM\x20':
			newtags.append('vimswap')
	return newtags

## Check for timezone files.
## documentation: man 5 tzfile
def verifyTZ(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	filesize = os.stat(filename).st_size

	## header is 44 bytes
	if filesize < 44:
		return newtags

	datafile = open(filename, 'rb')
	databuffer = datafile.read(4)
	if databuffer != 'TZif':
		datafile.close()
		return newtags
	## the version of the file
	databytes = datafile.read(1)
	if not databytes in ['\x00', '\x32', '\x33']:
		datafile.close()
		return newtags
	if databytes == '\x00':
		version = 0
	elif databytes == '\x32':
		version = 2
	elif databytes == '\x33':
		version = 3
	## then 15 null bytes
	databytes = datafile.read(15)
	if len(databytes) != 15:
		datafile.close()
		return newtags
	if set(databytes) != set(['\x00']):
		datafile.close()
		return newtags

	## number of utc/local indicators
	databytes = datafile.read(4)
	utcindicators = struct.unpack('>I', databytes)[0]

	## number of standard indicators
	databytes = datafile.read(4)
	standardindicators = struct.unpack('>I', databytes)[0]

	## number of leap seconds
	databytes = datafile.read(4)
	leapseconds = struct.unpack('>I', databytes)[0]

	## number of transition times
	databytes = datafile.read(4)
	transitiontimes = struct.unpack('>I', databytes)[0]
	
	## number of local time types
	databytes = datafile.read(4)
	localtimetypes = struct.unpack('>I', databytes)[0]

	if localtimetypes == 0:
		datafile.close()
		return newtags

	## number of characters in the timezone abbrevation strings
	databytes = datafile.read(4)
	timezoneabbreviationchars = struct.unpack('>I', databytes)[0]

	for i in xrange(0,transitiontimes):
		databytes = datafile.read(4)
		if len(databytes) != 4:
			datafile.close()
			return newtags
	for i in xrange(0,transitiontimes):
		databytes = datafile.read(1)
		if len(databytes) != 1:
			datafile.close()
			return newtags

	for i in xrange(0, localtimetypes):
		databytes = datafile.read(6)
		if len(databytes) != 6:
			datafile.close()
			return newtags

	databytes = datafile.read(timezoneabbreviationchars)
	if len(databytes) != timezoneabbreviationchars:
		datafile.close()
		return newtags

	for i in xrange(0, leapseconds):
		databytes = datafile.read(8)
		if len(databytes) != 8:
			datafile.close()
			return newtags

	for i in xrange(0, standardindicators):
		databytes = datafile.read(1)
		if len(databytes) != 1:
			datafile.close()
			return newtags

	for i in xrange(0, utcindicators):
		databytes = datafile.read(1)
		if len(databytes) != 1:
			datafile.close()
			return newtags

	## if the end of the file is reached, then this
	## is a valid time zone file
	if datafile.tell() == filesize:
		newtags.append('timezone')
		newtags.append('resource')
		datafile.close()
		return newtags
	if version == 0:
		## version 0 does not have an extra header
		datafile.close()
		return newtags

	## for version 2 and version 3 there can be extra data
	## header is 44 bytes
	if filesize - datafile.tell() < 44:
		datafile.close()
		return newtags

	databytes = datafile.read(4)
	if databytes != 'TZif':
		datafile.close()
		return newtags

	## the version of the file, has to be the same as
	## in the first header
	databytes = datafile.read(1)
	if not databytes in ['\x32', '\x33']:
		datafile.close()
		return newtags

	if databytes == '\x32':
		if version != 2:
			datafile.close()
			return newtags
	elif databytes == '\x33':
		if version != 3:
			datafile.close()
			return newtags

	## then again 15 null bytes
	databytes = datafile.read(15)
	if set(databytes) != set(['\x00']):
		datafile.close()
		return newtags

	## and then all the same data again
	## number of utc/local indicators
	databytes = datafile.read(4)
	utcindicators = struct.unpack('>I', databytes)[0]

	## number of standard indicators
	databytes = datafile.read(4)
	standardindicators = struct.unpack('>I', databytes)[0]

	## number of leap seconds
	databytes = datafile.read(4)
	leapseconds = struct.unpack('>I', databytes)[0]

	## number of transition times
	databytes = datafile.read(4)
	transitiontimes = struct.unpack('>I', databytes)[0]
	
	## number of local time types
	databytes = datafile.read(4)
	localtimetypes = struct.unpack('>I', databytes)[0]

	if localtimetypes == 0:
		datafile.close()
		return newtags

	## number of characters in the timezone abbrevation strings
	databytes = datafile.read(4)
	timezoneabbreviationchars = struct.unpack('>I', databytes)[0]

	for i in xrange(0,transitiontimes):
		databytes = datafile.read(8)
		if len(databytes) != 8:
			datafile.close()
			return newtags
	for i in xrange(0,transitiontimes):
		databytes = datafile.read(1)
		if len(databytes) != 1:
			datafile.close()
			return newtags

	for i in xrange(0, localtimetypes):
		databytes = datafile.read(6)
		if len(databytes) != 6:
			datafile.close()
			return newtags

	databytes = datafile.read(timezoneabbreviationchars)
	if len(databytes) != timezoneabbreviationchars:
		datafile.close()
		return newtags

	for i in xrange(0, leapseconds):
		databytes = datafile.read(12)
		if len(databytes) != 12:
			datafile.close()
			return newtags

	for i in xrange(0, standardindicators):
		databytes = datafile.read(1)
		if len(databytes) != 1:
			datafile.close()
			return newtags

	for i in xrange(0, utcindicators):
		databytes = datafile.read(1)
		if len(databytes) != 1:
			datafile.close()
			return newtags

	## if the end of the file is reached, then this
	## is a valid time zone file
	if datafile.tell() == filesize:
		newtags.append('timezone')
		newtags.append('resource')
		datafile.close()
		return newtags

	## on to the third header, which is a (possibly empty)
	## tzset string (man 3 tzset) in between two newlines
	databytes = datafile.read(1)
	if databytes != '\n':
		datafile.close()
		return newtags

	## there have to be at two newlines, so this cannot be
	## the last byte of the file
	if datafile.tell() == filesize:
		datafile.close()
		return newtags

	## check if the file ends with a newline
	curoffset = datafile.tell()
	datafile.seek(filesize-1)
	databytes = datafile.read(1)
	if databytes != '\n':
		datafile.close()
		return newtags
	datafile.seek(curoffset)

	## TODO: better check if the tzset string is valid
	validtzchars = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ<>:+-.,/")
	while True:
		databytes = datafile.read(1)
		if datafile.tell() == filesize:
			datafile.close()
			break
		if not databytes in validtzchars:
			datafile.close()
			return newtags

	datafile.close()
	newtags.append('timezone')
	newtags.append('resource')
	return newtags

## verify if a file is in Intel HEX format and tag it is as such.
## This will only be done if the *entire* file is in Intel HEX format.
## comments (starting with #) are allowed though.
def verifyIHex(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if not 'text' in tags:
		return newtags

	## https://en.wikipedia.org/wiki/Intel_HEX
	datafile = open(filename, 'r')
	validfile = True
	for d in datafile:
		d = d.strip()
		if not d.startswith(':'):
			if not d.startswith('#'):
				validfile = False
				break
		if len(d)%2 != 1:
			validfile = False
			break
		try:
			databytes = binascii.unhexlify(d[1:])
		except TypeError, e:
			validfile = False
			break
		if len(databytes) == 0:
			validfile = False
			break
		if reduce(lambda x, y: x + y, map(lambda x: ord(x), databytes)) % 256 != 0:
			validfile = False
			break
	datafile.close()
	if validfile:
		newtags.append('ihex')
	return newtags

## verify Apple's AppleDouble encoded files (resource forks)
## http://tools.ietf.org/html/rfc1740 -- Appendix A & B
def verifyResourceFork(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if not 'appledouble' in offsets:
		return newtags
	if not 0 in offsets['appledouble']:
		return newtags

	filesize = os.stat(filename).st_size

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

## Tag and check some RSA certificates as found for example on Android
def verifyRSACertificate(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if not os.path.basename(filename).endswith('.RSA'):
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
def verifyCertificate(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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

## check compiled terminfo files
## man 5 term
## does not check the ncurses extensions
def verifyTerminfo(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
	newtags = []
	if not 'binary' in tags:
		return newtags
	if 'compressed' in tags or 'graphics' in tags or 'xml' in tags:
		return newtags
	terminfofile = open(filename, 'rb')
	databytes = terminfofile.read(2)
	if databytes != '\x1a\x01':
		terminfofile.close()
		return newtags
	filesize = os.stat(filename).st_size
	## keep a fictional offset, starting directly after the header
	offset = 12
	## next two bytes is the size in bytes in the names section
	databytes = terminfofile.read(2)
	if len(databytes) != 2:
		terminfofile.close()
		return newtags
	namesectionbytes = struct.unpack('<H', databytes)[0]
	if offset + namesectionbytes > filesize:
		terminfofile.close()
		return newtags
	offset += namesectionbytes
	## then next two bytes is the size in bytes in the boolean section
	databytes = terminfofile.read(2)
	if len(databytes) != 2:
		terminfofile.close()
		return newtags
	booleansectionbytes = struct.unpack('<H', databytes)[0]
	if offset + booleansectionbytes > filesize:
		terminfofile.close()
		return newtags
	if booleansectionbytes%2 != 0:
		## align bytes
		booleansectionbytes += 1
	offset += booleansectionbytes
	## then next two bytes is the size in short integers in the numbers section
	databytes = terminfofile.read(2)
	if len(databytes) != 2:
		terminfofile.close()
		return newtags
	numbersectionbytes = struct.unpack('<H', databytes)[0]
	if offset + numbersectionbytes*2 > filesize:
		terminfofile.close()
		return newtags
	offset += numbersectionbytes * 2
	## then next two bytes is the number of offsets in the string table
	databytes = terminfofile.read(2)
	if len(databytes) != 2:
		terminfofile.close()
		return newtags
	numberoffsets = struct.unpack('<H', databytes)[0]
	stringnumberoffset = offset
	if offset + numberoffsets*2 > filesize:
		terminfofile.close()
		return newtags
	offset += numberoffsets * 2
	## then next two bytes is the size of the string table
	databytes = terminfofile.read(2)
	if len(databytes) != 2:
		terminfofile.close()
		return newtags
	stringtablesize = struct.unpack('<H', databytes)[0]
	stringtableoffset = offset
	if offset + stringtablesize > filesize:
		terminfofile.close()
		return newtags
	offset += stringtablesize
	## extra sanity check, the string number offsets should be
	## valid offsets into the string table
	terminfofile.seek(stringnumberoffset)
	termbytes = terminfofile.read(numberoffsets*2)
	for t in xrange(0, len(termbytes), 2):
		if termbytes[t:t+2] == '\xff\xff':
			continue
		tableoffset = struct.unpack('<H', termbytes[t:t+2])[0]
		if stringtableoffset + tableoffset > filesize:
			terminfofile.close()
			return newtags
	if offset != filesize:
		## perhaps it uses ncurses extensions
		terminfofile.seek(offset)
		## the number of extended boolean capabilities
		databytes = terminfofile.read(2)
		if len(databytes) != 2:
			terminfofile.close()
			return newtags
		extendedboolean = struct.unpack('<H', databytes)[0]
		## the number of extended numeric capabilities
		databytes = terminfofile.read(2)
		if len(databytes) != 2:
			terminfofile.close()
			return newtags
		extendednumeric = struct.unpack('<H', databytes)[0]
		## the number of extended string capabilities
		databytes = terminfofile.read(2)
		if len(databytes) != 2:
			terminfofile.close()
			return newtags
		extendedstring = struct.unpack('<H', databytes)[0]
		## the size of extended string table
		databytes = terminfofile.read(2)
		if len(databytes) != 2:
			terminfofile.close()
			return newtags
		extendedstringtablesize = struct.unpack('<H', databytes)[0]
		## the last offset of extended string table in bytes
		databytes = terminfofile.read(2)
		if len(databytes) != 2:
			terminfofile.close()
			return newtags

		## TODO: more sanity checks
		extendedstringtablelastoffset = struct.unpack('<H', databytes)[0]
		terminfofile.close()
		return newtags
	terminfofile.close()
	newtags.append('terminfo')
	newtags.append('resource')
	return newtags
	
'''
## stubs for very crude check for HTML files
def verifyHTML(filename, cursor, conn, tempdir=None, tags=[], offsets={}, scanenv={}, debug=False, unpacktempdir=None, filehashes=None):
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
