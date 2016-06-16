#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains helper functions to unpack archives or file systems.
Most of the commands are pretty self explaining. The result of the wrapper
functions is a list of tuples, which contain the name of a temporary directory
with the unpacked contents of the archive, and the offset of the archive or
file system in the parent file.

Optionally return a range of bytes that should be excluded in same cases
to prevent other scans from (re)scanning (part of) the data.
'''

import sys, os, subprocess, os.path, shutil, stat, array, struct, binascii, json
import tempfile, bz2, re, magic, tarfile, zlib, copy, uu, hashlib, StringIO, zipfile
import fsmagic, extractor, ext2, jffs2, prerun
from collections import deque

## generic method to create temporary directories, with the correct filenames
## which is used throughout the code.
def dirsetup(tempdir, filename, marker, counter):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		try:
			tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), marker, counter)
			os.makedirs(tmpdir)
		except Exception, e:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
	return tmpdir

def unpacksetup(tempdir):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	return tmpdir

## Carve a file from a larger file, or copy a file.
def unpackFile(filename, offset, tmpfile, tmpdir, length=0, modify=False, unpacktempdir=None, blacklist=[]):
	if blacklist != []:
		if length == 0:
			lowest = extractor.lowestnextblacklist(offset, blacklist)
			if not lowest == 0:
				## if the blacklist is not empty set 'length' to
				## the first entry in the blacklist following offset,
				## but relative to offset
				length=lowest-offset

	filesize = os.stat(filename).st_size
	if filesize == length:
		length = 0

	## don't use dd for stuff that is less than 50 million bytes
	## TODO: make configurable
	unpackcutoff = 50000000

	## If the while file needs to be scanned, then either copy it, or hardlink it.
	## Hardlinking is only possible if the file resides on the same file system
	## and if the file is not modified in a way.
	if offset == 0 and length == 0:
		## use copy if tmpfile is expected to be *modified*. If not
		## the original could be modified, which would confuse other
		## scans.
		## just use mkstemp() to get the name of a temporary file
		templink = tempfile.mkstemp(dir=tmpdir)
		os.fdopen(templink[0]).close()
		os.unlink(templink[1])
		if not modify:
			try:
				os.link(filename, templink[1])
			except OSError, e:
				## if filename and tmpdir are on different devices it is
				## not possible to use hardlinks
				shutil.copy(filename, templink[1])
		else:
			shutil.copy(filename, templink[1])
		shutil.move(templink[1], tmpfile)
	else:
		if length == 0:
			if unpackcutoff < filesize and (filesize - offset) < unpackcutoff:
				srcfile = open(filename, 'rb')
				dstfile = open(tmpfile, 'wb')
				srcfile.seek(offset)
				dstfile.write(srcfile.read(length))
				dstfile.flush()
				dstfile.close()
				srcfile.close()
				return
			## The tail end of the file is needed and the first bytes (indicated by 'offset') need
			## to be ignored, while the rest needs to be copied. If the offset is small, it is
			## faster to use 'tail' instead of 'dd', especially for big files.
			if offset < 128:
				tmptmpfile = open(tmpfile, 'wb')
				p = subprocess.Popen(['tail', filename, '-c', "%d" % (filesize - offset)], stdout=tmptmpfile, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				tmptmpfile.close()
			else:
				p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile,), 'bs=%s' % (offset,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				os.chmod(tmpfile, stat.S_IRWXU)
		else:
			if unpackcutoff < filesize and length < unpackcutoff:
				srcfile = open(filename, 'rb')
				dstfile = open(tmpfile, 'wb')
				srcfile.seek(offset)
				dstfile.write(srcfile.read(length))
				dstfile.flush()
				dstfile.close()
				srcfile.close()
				return
			if offset == 0:
				## sometimes there are some issues with dd and maximum file size
				## see for example https://bugzilla.redhat.com/show_bug.cgi?id=612839
				if (length+offset) >= 2147479552:
					shutil.copy(filename, tmpfile)
					truncfile = open(tmpfile, 'a+b')
					truncfile.seek(length+offset)
					truncfile.truncate()
					truncfile.close()
				else:
					## bytes need be removed only from the end of the file
					p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile,), 'bs=%s' % (length,), 'count=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
					(stanout, stanerr) = p.communicate()
					os.chmod(tmpfile, stat.S_IRWXU)
			else:
				## bytes need to be removed on both sides of the file, so possibly
				## use a two way pass
				## First determine which side to cut first before cutting
				if offset > (filesize - length):
					p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile,), 'bs=%s' % (offset,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
					(stanout, stanerr) = p.communicate()
					os.chmod(tmpfile, stat.S_IRWXU)
					tmptmpfile = open(tmpfile, 'a+b')
					tmptmpfile.seek(length)
					tmptmpfile.truncate()
					tmptmpfile.close()
				else:
					tmptmpfile = tempfile.mkstemp(dir=tmpdir)
					os.fdopen(tmptmpfile[0]).close()

					## sometimes there are some issues with dd and maximum file size
					## see for example https://bugzilla.redhat.com/show_bug.cgi?id=612839
					if (length+offset) >= 2147479552:
						shutil.copy(filename, tmptmpfile[1])
						os.chmod(tmptmpfile[1], stat.S_IRWXU)
						truncfile = open(tmptmpfile[1], 'a+b')
						truncfile.seek(length+offset)
						truncfile.truncate()
						truncfile.close()
					else:
						## first copy bytes from the front of the file up to a certain length
						p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmptmpfile[1],), 'bs=%s' % (length+offset,), 'count=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
						(stanout, stanerr) = p.communicate()
						os.chmod(tmptmpfile[1], stat.S_IRWXU)

					## then copy bytes from the temporary file, but skip 'offset' bytes at the front
					p = subprocess.Popen(['dd', 'if=%s' % (tmptmpfile[1],), 'of=%s' % (tmpfile,), 'bs=%s' % (offset,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
					(stanout, stanerr) = p.communicate()
					os.chmod(tmpfile, stat.S_IRWXU)
					os.unlink(tmptmpfile[1])

## There are certain routers that have all bytes swapped, because they use 16
## bytes NOR flash instead of 8 bytes SPI flash. This is an ugly hack to first
## rearrange the data. This is mostly for Realtek RTL8196C based routers.
def searchUnpackByteSwap(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	## can't byteswap if there is not an even amount of bytes in the file
	filesize = os.stat(filename).st_size
	if filesize % 2 != 0:
		return ([], blacklist, [], hints)
	datafile = open(filename, 'rb')
	offset = 0
	datafile.seek(offset)
	swapped = False
	databuffer = datafile.read(100000)
	## look for "Uncompressing Linux..."
	while databuffer != '':
		datafile.seek(offset + 99950)
		if "nUocpmerssni giLun.x.." in databuffer:
			swapped = True
			break
		databuffer = datafile.read(100000)
		if len(databuffer) >= 50:
			offset = offset + 99950
		else:
			offset = offset + len(databuffer)

	if swapped:
		tmpdir = dirsetup(tempdir, filename, "byteswap", 1)
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		## reset pointer into file
		datafile.seek(0)
		databuffer = datafile.read(1000000)
		while databuffer != '':
			tmparray = array.array('H')
			tmparray.fromstring(databuffer)
			tmparray.byteswap()
			os.write(tmpfile[0], tmparray.tostring())
			databuffer = datafile.read(1000000)
		blacklist.append((0, filesize))
		datafile.close()
		os.fdopen(tmpfile[0]).close()
		return ([(tmpdir, 0, filesize)], blacklist, [], hints)
	return ([], blacklist, [], hints)

## unpack UU encoded files
def searchUnpackUU(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not offsets.has_key('text'):
		return ([], blacklist, [], hints)
	pass

## unpack base64 files
def searchUnpackBase64(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	counter = 1
	diroffsets = []
	template = None
	if 'TEMPLATE' in scanenv:
		template = scanenv['TEMPLATE']
	tmpdir = dirsetup(tempdir, filename, "base64", counter)
	p = subprocess.Popen(['base64', '-d', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.rmdir(tmpdir)
		return ([], blacklist, [], hints)
	else:
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		os.write(tmpfile[0], stanout)
		os.fdopen(tmpfile[0]).close()
		if template != None:
			mvpath = os.path.join(tmpdir, template)
			if not os.path.exists(mvpath):
				try:
					shutil.move(tmpfile[1], mvpath)
				except:
					pass
		## the whole file is blacklisted
		filesize = os.stat(filename).st_size
		blacklist.append((0, filesize))
		diroffsets.append((tmpdir, 0, filesize))
		return (diroffsets, blacklist, [], hints)

## decompress executables that have been compressed with UPX.
def searchUnpackUPX(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'upx' in offsets:
		return ([], blacklist, [], hints)
	if offsets['upx'] == []:
		return ([], blacklist, [], hints)
	p = subprocess.Popen(['upx', '-t', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return ([], blacklist, [], hints)
	tags = []
	counter = 1
	diroffsets = []
	tmpdir = dirsetup(tempdir, filename, "upx", counter)
	p = subprocess.Popen(['upx', '-d', filename, '-o', os.path.basename(filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.rmdir(tmpdir)
		return ([], blacklist, tags, hints)
	else:
		## the whole file is blacklisted
		filesize = os.stat(filename).st_size
		blacklist.append((0, filesize))
		tags.append("compressed")
		tags.append("upx")
		diroffsets.append((tmpdir, 0, filesize))
	return (diroffsets, blacklist, tags, hints)

## carve Java serialized data from a larger file by verifying content
## A specification can be found here:
## https://docs.oracle.com/javase/7/docs/platform/serialization/spec/protocol.html
##
## At the moment it works only well for blockdata, which is what is encountered
## the most in the wild (example: data in some Android apps)
def searchUnpackJavaSerialized(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'java_serialized' in offsets:
		return ([], blacklist, [], hints)
	if offsets['java_serialized'] == []:
		return ([], blacklist, [], hints)

	## file has to be at least 5 bytes long
	filesize = os.stat(filename).st_size
	if filesize < 5:
		return ([], blacklist, [], hints)

	tags = []
	counter = 1
	diroffsets = []
	tc_bytes = ['\x70', '\x71', '\x72', '\x73', '\x74', '\x75', '\x76', '\x77', '\x78', '\x79', '\x7a', '\x7b', '\x7c', '\x7d', '\x7e']
	for offset in offsets['java_serialized']:
		## check if the offset found is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## extra sanity check to see if STREAM_VERSION is set to 5
		serialized_file = open(filename, 'rb')
		serialized_file.seek(offset+2)
		bytes_read = 2
		serialized_bytes = serialized_file.read(2)
		bytes_read += 2
		stream_version = struct.unpack('>H', serialized_bytes)[0]
		if stream_version != 5:
			serialized_file.close()
			continue

		## The next bytes always have to be in range 0x70 - 0x7e
		try:
			tc_byte = serialized_file.read(1)
			if len(tc_byte) != 1:
				serialized_file.close()
				continue
		except:
			serialized_file.close()
			continue
		bytes_read += 1
		if tc_byte not in tc_bytes:
			serialized_file.close()
			continue

		## now verify for each of the bytes if it is a valid Java serialized file
		## At the moment only supports NULL, STRING, BLOCKDATA, RESET, BLOCKDATA_LONG.
		## TODO: use a proper state machine to verify all of the data
		while True:
			# 0x70 == NULL
			if tc_byte == '\x70':
				## nothing happens here, so continue
				pass
			# 0x73 == OBJECT
			elif tc_byte == '\x73':
				pass
			# 0x74 == STRING
			elif tc_byte == '\x74':
				try:
					## followed by size, then the data
					serialized_bytes = serialized_file.read(2)
					bytes_read += 2
					size = struct.unpack('>H', serialized_bytes)[0]
					serialized_bytes = serialized_file.seek(offset+bytes_read+size)
					bytes_read += size
				except:
					serialized_file.close()
					break
			# 0x77 == BLOCKDATA
			elif tc_byte == '\x77':
				## start with a byte that indicates the size.
				try:
					serialized_bytes = serialized_file.read(1)
					bytes_read += 1
					size = struct.unpack('>B', serialized_bytes)[0]
					if offset + bytes_read+size > filesize:
						serialized_file.close()
						break
					serialized_bytes = serialized_file.seek(offset+bytes_read+size)
					bytes_read += size
				except:
					serialized_file.close()
					break
			# 0x79 == RESET
			elif tc_byte == '\x79':
				## nothing happens here, so continue
				pass
			# 0x7a == BLOCKDATA_LONG
			elif tc_byte == '\x7a':
				## start with an int that indicates the size.
				try:
					serialized_bytes = serialized_file.read(4)
					bytes_read += 4
					size = struct.unpack('>I', serialized_bytes)[0]
					if offset + bytes_read+size > filesize:
						serialized_file.close()
						break
					serialized_bytes = serialized_file.seek(offset+bytes_read+size)
					bytes_read += size
				except:
					serialized_file.close()
					break
			# 0x7e == ENUM
			elif tc_byte == '\x7e':
				## first a class descriptor, then a newHandle, then enumConstName
				pass
			else:
				serialized_file.close()
				break
			if offset + bytes_read == filesize:
				## currently only grab files that are at the end
				## of the file.
				if offset == 0:
					serialized_file.close()
					## the whole file is serialized Java, so tag it as such
					blacklist.append((0,filesize))
					return (diroffsets, blacklist, ['serializedjava', 'binary'], hints)

				## write the data out to a file and tag it as serializedjava
				tmpdir = dirsetup(tempdir, filename, "java_serialized", counter)
				tempname = "deserialize"
				tmpfilename = os.path.join(tmpdir, tempname)
				hints[tmpfilename] = {}
				hints[tmpfilename]['tags'] = ['serializedjava', 'binary']
				hints[tmpfilename]['scanned'] = True
				serialized_file.seek(offset)
				serialized_tmpfile = open(tmpfilename, 'wb')
				serialized_tmpfile.write(serialized_file.read(bytes_read))
				serialized_tmpfile.close()
				counter = counter + 1
				serialized_file.close()
				blacklist.append((offset,offset+bytes_read))
				diroffsets.append((tmpdir, offset, bytes_read))
				break
			try:
				tc_byte = serialized_file.read(1)
				if len(tc_byte) != 1:
					serialized_file.close()
					break
				bytes_read += 1
			except:
				serialized_file.close()
				break

	return (diroffsets, blacklist, tags, hints)

## Unpack SWF files that are zlib compressed. Not all SWF files
## are compressed but some are. For now it is assumed that the whole
## file is a complete  SWF file.
def searchUnpackSwf(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'swf' in offsets:
		return ([], blacklist, [], hints)
	if offsets['swf'] == []:
		return ([], blacklist, [], hints)

	newtags = []
	counter = 1
	diroffsets = []
	readsize = 1000000
	for offset in offsets['swf']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		unzswfobj = zlib.decompressobj()
		swffile = open(filename, 'rb')
		swffile.seek(offset+8)
		unzswfdata = swffile.read(readsize)
		unzswf = ''
		bytesread = 8
		try:
			while unzswfdata != '':
				unzswf += unzswfobj.decompress(unzswfdata)
				deflatesize = len(unzswfdata) - len(unzswfobj.unused_data)
				bytesread += len(unzswfdata) - len(unzswfobj.unused_data)
				if len(unzswfobj.unused_data) != 0:
					break
				unzswfdata = swffile.read(readsize)
		except Exception, e:
			swffile.close()
			continue
		swffile.close()

		tmpdir = dirsetup(tempdir, filename, "swf", counter)
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		os.write(tmpfile[0], unzswf)
		os.fdopen(tmpfile[0]).close()

		diroffsets.append((tmpdir, offset, bytesread))
		blacklist.append((offset, offset + bytesread))
		if offset == 0 and bytesread == os.stat(filename).st_size:
			newtags.append('swf')
		counter += 1
	return (diroffsets, blacklist, newtags, hints)

def searchUnpackJffs2(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	filesize = os.stat(filename).st_size
	if filesize < 8:
		return ([], blacklist, [], hints)

	if not 'jffs2_le' in offsets and not 'jffs2_be' in offsets:
		return ([], blacklist, [], hints)
	if offsets['jffs2_le'] == [] and offsets['jffs2_be'] == []:
		return ([], blacklist, [], hints)

	if not 'jffs2_be' in offsets:
		be_offsets = set()
	else:
		be_offsets = set(offsets['jffs2_be'])

	counter = 1
	jffs2offsets = copy.deepcopy(offsets['jffs2_le']) + copy.deepcopy(offsets['jffs2_be'])
	diroffsets = []
	newtags = []
	jffs2offsets.sort()

	jffs2_tmpdir = scanenv.get('UNPACK_TEMPDIR', None)

	crccache = {}

	jffs2file = open(filename, 'rb')
	for offset in jffs2offsets:
		## at least 8 bytes are needed for a JFFS2 file system
		if filesize - offset < 8:
			break
		## check if the offset found is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		bigendian = False
		if offset in be_offsets:
			bigendian = True
		## first a simple sanity check. Read bytes 4-8 from the inode, which
		## represent the total node of the inode. If the total length of the
		## inode is bigger than the total size of the file it is not a valid
		## JFFS2 file system, so return.
		## If offset + size of the JFFS2 inode is blacklisted it is also not
		## a valid JFFS2 file system
		jffs2file.seek(offset+4)
		jffs2buffer = jffs2file.read(4)

		if not bigendian:
			jffs2inodesize = struct.unpack('<I', jffs2buffer)[0]
		else:
			jffs2inodesize = struct.unpack('>I', jffs2buffer)[0]
		if (offset + jffs2inodesize) > filesize:
			continue
		blacklistoffset = extractor.inblacklist(offset + jffs2inodesize, blacklist)
		if blacklistoffset != None:
			continue

		## another sanity check, this time for the header_crc
		## The first 8 bytes of a node are used to compute a CRC32 checksum that
		## is then compared with a CRC32 checksum stored in bytes 9-12
		## The checksum varies slightly from the one in the zlib/binascii modules
		## as explained here:
		##
		## http://www.infradead.org/pipermail/linux-mtd/2003-February/006910.html
		jffs2file.seek(offset)
		jffs2buffer = jffs2file.read(12)
		if len(jffs2buffer) < 12:
			continue
		if not bigendian:
			jffs2_hdr_crc = struct.unpack('<I', jffs2buffer[-4:])[0]
		else:
			jffs2_hdr_crc = struct.unpack('>I', jffs2buffer[-4:])[0]

		## specific implementation for computing checksum grabbed from MIT licensed script found
		## at:
		## https://github.com/sviehb/jefferson/blob/master/src/scripts/jefferson
		## It follows the algorithm explained at:
		##
		## http://www.infradead.org/pipermail/linux-mtd/2003-February/006910.html
		if jffs2buffer[:-4] in crccache:
			jffs2crc = crccache[jffs2buffer[:-4]]
		else:
			jffs2crc = (binascii.crc32(jffs2buffer[:-4], -1) ^ -1) & 0xffffffff
			crccache[jffs2buffer[:-4]] = jffs2crc
		if not jffs2_hdr_crc == jffs2crc:
			continue

		tmpdir = dirsetup(tempdir, filename, "jffs2", counter)
		res = unpackJffs2(filename, offset, filesize, tmpdir, bigendian, jffs2_tmpdir, blacklist)
		if res != None:
			(jffs2dir, jffs2size) = res
			## jffs2 nodes are all 4 byte aligned according to
			## http://www.sourceware.org/jffs2/jffs2-html/node3.html
			jffs2rest = 4 - jffs2size%4
			if offset == 0 and jffs2size + jffs2rest == filesize:
				newtags.append('jffs2')
				jffs2size = filesize
			diroffsets.append((jffs2dir, offset, jffs2size))
			blacklist.append((offset, offset + jffs2size))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
	jffs2file.close()
	return (diroffsets, blacklist, newtags, hints)

def unpackJffs2(filename, offset, filesize, tempdir=None, bigendian=False, jffs2_tmpdir=None, blacklist=[]):
	tmpdir = unpacksetup(tempdir)

	if jffs2_tmpdir != None:
		tmpfile = tempfile.mkstemp(dir=jffs2_tmpdir)
		os.fdopen(tmpfile[0]).close()
		unpackFile(filename, offset, tmpfile[1], jffs2_tmpdir, blacklist=blacklist)
	else:
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		os.fdopen(tmpfile[0]).close()
		unpackFile(filename, offset, tmpfile[1], tmpdir, blacklist=blacklist)

	res = jffs2.unpackJFFS2(tmpfile[1], tmpdir, bigendian)
	os.unlink(tmpfile[1])
	if tempdir == None:
		os.rmdir(tmpdir)
	return res

def searchUnpackAr(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'ar' in offsets:
		return ([], blacklist, [], hints)
	if offsets['ar'] == []:
		return ([], blacklist, [], hints)
	filesize = os.stat(filename).st_size
	## extra sanity check for size of the header
	if filesize < 64:
		return ([], blacklist, [], hints)
	counter = 1
	diroffsets = []
	newtags = []
	for offset in offsets['ar']:
		## check if the offset found is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## extra sanity check, the byte following the magic is always '\x0a'
		localoffset = offset + 7
		arfile = open(filename, 'rb')
		arfile.seek(localoffset)
		archeckbyte = arfile.read(1)
		localoffset += 1
		if archeckbyte != '\x0a':
			arfile.close()
			continue

		## the magic bytes are followed by a header which has 0x60 0x0a
		## at the end.
		## see, for example, https://en.wikipedia.org/wiki/Ar_%28Unix%29
		localoffset += 58
		arfile.seek(localoffset)
		archeckbytes = arfile.read(2)
		arfile.close()
		if not archeckbytes == '\x60\x0a':
			continue

		tmpdir = dirsetup(tempdir, filename, "ar", counter)
		res = unpackAr(filename, offset, tmpdir, blacklist)
		if res != None:
			(ardir, size) = res
			if size == filesize:
				newtags.append("ar")
			diroffsets.append((ardir, offset, size))
			blacklist.append((offset, offset + size))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, newtags, hints)

def unpackAr(filename, offset, tempdir=None, blacklist=[]):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, blacklist=blacklist)

	p = subprocess.Popen(['ar', 'tv', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	## ar only works on complete files, so the size can be set to length of the file
	p = subprocess.Popen(['ar', 'x', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.unlink(tmpfile[1])
	if tempdir == None:
		os.rmdir(tmpdir)
	return (tmpdir, os.stat(filename).st_size)

## 1. search ISO9660 file system
## 2. mount it using FUSE
## 3. copy the contents
## 4. make sure all permissions are correct (so use chmod)
## 5. unmount file system
def searchUnpackISO9660(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'iso9660' in offsets:
		return ([], blacklist, [], hints)
	if offsets['iso9660'] == []:
		return ([], blacklist, [], hints)
	diroffsets = []
	counter = 1
	for offset in offsets['iso9660']:
		## according to /usr/share/magic the magic header starts at 0x8001
		if offset < 32769:
			continue
		## check if the offset found is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "iso9660", counter)
		res = unpackISO9660(filename, offset - 32769, blacklist, tmpdir)
		if res != None:
			(isooffset, size) = res
			diroffsets.append((isooffset, offset - 32769, size))
			blacklist.append((offset - 32769, offset + size))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

def unpackISO9660(filename, offset, blacklist, tempdir=None, unpacktempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, blacklist=blacklist)

	## create a mountpoint
	mountdir = tempfile.mkdtemp(dir=unpacktempdir)
	p = subprocess.Popen(['fuseiso', tmpfile[1], mountdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.rmdir(mountdir)
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	## first create *another* temporary directory, because of the behaviour of shutil.copytree()
	tmpdir2 = tempfile.mkdtemp(dir=unpacktempdir)
	## then copy the contents to a subdir, and don't follow symlinks
	shutil.copytree(mountdir, tmpdir2 + "/bla", symlinks=True)
	## then change all the permissions
	osgen = os.walk(tmpdir2 + "/bla")
	try:
		while True:
			i = osgen.next()
			os.chmod(i[0], stat.S_IRWXU)
			if os.path.islink(i[0]):
				continue
			if not os.path.isdir(i[0]):
				continue
			for p in i[2]:
				if os.path.islink(os.path.join(i[0], p)):
					continue
				if os.path.isfile(os.path.join(i[0], p)):
					continue
				os.chmod("%s/%s" % (i[0], p), stat.S_IRWXU)
	except Exception, e:
		pass
	## then move all the contents using shutil.move()
	mvfiles = os.listdir(os.path.join(tmpdir2, "bla"))
	for f in mvfiles:
		shutil.move(os.path.join(tmpdir2, "bla", f), tmpdir)
	## then cleanup the temporary dir
	shutil.rmtree(tmpdir2)
	
	## determine size. It might not be accurate.
	p = subprocess.Popen(['du', '-scb', mountdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		## this should not happen
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	size = int(stanout.strip().split("\n")[-1].split()[0])
	## unmount the ISO image using fusermount
	p = subprocess.Popen(['fusermount', "-u", mountdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	## TODO: check exit codes
	os.rmdir(mountdir)
	os.unlink(tmpfile[1])
	return (tmpdir, size)

## unpacking POSIX or GNU tar archives. This does not work yet for the V7 tar format
def searchUnpackTar(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	taroffsets = []
	for marker in fsmagic.tar:
		taroffsets = taroffsets + offsets[marker]
	if taroffsets == []:
		return ([], blacklist, [], hints)
	taroffsets.sort()

	tar_tmpdir = scanenv.get('UNPACK_TEMPDIR', None)

	diroffsets = []
	counter = 1
	for offset in taroffsets:
		## according to /usr/share/magic the magic header starts at 0x101
		if offset < 0x101:
			continue

		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue

		tmpdir = dirsetup(tempdir, filename, "tar", counter)
		(res, tarsize) = unpackTar(filename, offset, tmpdir, tar_tmpdir)
		if res != None:
			diroffsets.append((res, offset - 0x101, tarsize))
			counter = counter + 1
			blacklist.append((offset - 0x101, offset - 0x101 + tarsize))
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

def unpackTar(filename, offset, tempdir=None, tar_tmpdir=None):
	tmpdir = unpacksetup(tempdir)
	if tar_tmpdir != None:
		tmpfile = tempfile.mkstemp(dir=tar_tmpdir)
		testtar = tempfile.mkstemp(dir=tar_tmpdir)
		os.fdopen(testtar[0]).close()
	else:
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		testtar = tempfile.mkstemp(dir=tmpdir)
		os.fdopen(testtar[0]).close()

	## first read about 1MB from the tar file and do a very simple rough check to
	## filter out false positives
	if os.stat(filename).st_size > 1024*1024:
		tartest = open(testtar[1], 'wb')
		testtarfile = open(filename, 'r')
		testtarfile.seek(offset - 0x101)
		testtarbuffer = testtarfile.read(1024*1024)
		testtarfile.close()
		tartest.write(testtarbuffer)
		tartest.close()
		if not tarfile.is_tarfile(tartest.name):
			os.unlink(testtar[1])
			## not a tar file, so clean up
			os.fdopen(tmpfile[0]).close()
			os.unlink(tmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return (None, None)
	os.unlink(testtar[1])

	if offset != 0x101:
		p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile[1],), 'bs=%s' % (offset - 0x101,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	else:
		templink = tempfile.mkstemp(dir=tmpdir)
		os.fdopen(templink[0]).close()
		os.unlink(templink[1])
		try:
			os.link(filename, templink[1])
		except OSError, e:
			## if filename and tmpdir are on different devices it is
			## not possible to use hardlinks
			shutil.copy(filename, templink[1])
		shutil.move(templink[1], tmpfile[1])

	tarsize = 0
	if not tarfile.is_tarfile(tmpfile[1]):
		## not a tar file, so clean up
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)

	try:
		## tmpfile[1] cannot be a closed file for some reason. Strange.
		tar = tarfile.open(tmpfile[1], 'r')
		tarmembers = tar.getmembers()
		## assume that the last member is also the last in the file
		tarsize = tarmembers[-1].offset_data + tarmembers[-1].size
		for i in tarmembers:
			if not i.isdev():
				tar.extract(i, path=tmpdir)
			if i.isdir():
				os.chmod(os.path.join(tmpdir,i.name), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
		tar.close()
	except Exception, e:
		## not a tar file, so clean up
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (tmpdir, tarsize)

## yaffs2 is used frequently in Android and various mediaplayers based on
## Realtek chipsets (RTD1261/1262/1073/etc.)
## yaffs2 does not have a magic header, so it is really hard to recognize.
## However, there are a few standard patterns that occur frequently
def searchUnpackYaffs2(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	diroffsets = []
	scanoffsets = []
	wholefile = True
	newtags = []
	candidates = {}

	## smallest possible file system supported by unpacker is 512 bytes if taking inband
	## tags into account
	filesize = os.stat(filename).st_size
	if filesize < 512:
		return (diroffsets, blacklist, newtags, hints)

	## A file could have various YAFFS2 file systems, without padding.
	## The 'magic' that is searched for is not necessarily accurate
	## but present in most cases.

	haveyaffsoffsets = False
	if 'yaffs2' in offsets:
		if offsets['yaffs2'] != []:
			haveyaffsoffsets = True
	
	counter = 1
	if not haveyaffsoffsets:
		offset = 0
		if 'u-boot' in offsets:
			if not offsets['u-boot'] == []:
				if len(offsets['u-boot']) == 1 and offsets['u-boot'][0] == 0:
					offset = 64
					## smallest possible file system supported by unpacker is 512 bytes
					if filesize < 578:
						return (diroffsets, blacklist, newtags, hints)
		
		tmpdir = dirsetup(tempdir, filename, "yaffs2", counter)
		yaffsres = unpackYaffs(filename, offset, tmpdir)
		if yaffsres != None:
			(res, bytesread) = yaffsres
			blacklist.append((offset, offset + bytesread))
			diroffsets.append((tmpdir, offset, bytesread))
			newtags = ['yaffs2', 'filesystem']
		else:
			os.rmdir(tmpdir)
	else:
		for offset in offsets['yaffs2']:
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				continue
			tmpdir = dirsetup(tempdir, filename, "yaffs2", counter)
			yaffsres = unpackYaffs(filename, offset, tmpdir)
			if yaffsres != None:
				(res, bytesread) = yaffsres
				blacklist.append((offset, offset+bytesread))
				diroffsets.append((tmpdir, offset, bytesread))
				counter += 1
			else:
				os.rmdir(tmpdir)
	return (diroffsets, blacklist, newtags, hints)

def unpackYaffs(filename, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)

	p = subprocess.Popen(['bat-unyaffs', '-b', filename, '-d', tmpdir, '-j', '-n', '%d' % offset], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return

	bytesread = 0
	try:
		res = json.loads(stanout)
		if 'bytesread' in res:
			bytesread = res['bytesread']
	except:
		pass

	## check if there was actually any data unpacked.
	if os.listdir(tmpdir) == []:
		return
	return (tmpdir, bytesread)

## Windows executables can be unpacked in many ways.
## We should try various methods:
## * 7z
## * unshield
## * cabextract
## * unrar
## * unzip
## Sometimes one or both will give results.
## We should probably blacklist the whole file after one method has been successful.
## Some Windows executables can only be unpacked interactively using Wine :-(
def searchUnpackExe(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	## first determine if this is a MS Windows executable
	## TODO: replace this with a better check for PE checking and use tags
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	try:
		mstype = ms.file(filename)
	except:
		## first copy the file to a temporary location
		tmpmagic = tempfile.mkstemp()
		os.fdopen(tmpmagic[0]).close()
		shutil.copy(filename, tmpmagic[1])
		mstype = ms.file(tmpmagic[1])
		os.unlink(tmpmagic[1])
	ms.close()
	newtags = []

	if mstype == None:
		return ([], blacklist, newtags, hints)
	if not 'PE32 executable for MS Windows' in mstype and not "PE32+ executable for MS Windows" in mstype and not "PE32 executable (GUI) Intel 80386, for MS Windows" in mstype:
		return ([], blacklist, newtags, hints)

	## apparently it is a MS Windows executable, so continue
	diroffsets = []
	counter = 1
	assemblies = []
	if 'windowsassemblyheader' in offsets and 'windowsassemblytrailer' in offsets:
		if len(offsets['windowsassemblyheader']) != 0:
			if len(offsets['windowsassemblytrailer']) != 0:
				assemblies = extractor.searchAssemblyAttrs(filename, offsets['windowsassemblyheader'], offsets['windowsassemblytrailer'])
	## if we were able to extract the assembly XML file we could get some useful
	## information from it. Although there are some vanity entries that we can
	## easily skip (and just bruteforce) there are a few that we really need to
	## recognize. TODO: refactor
	if assemblies != []:
		for assembly in assemblies:
			## we are pretty much out of luck with this one.
			if assembly['name'] == "NOSMicrosystems.iNOSSO":
				return ([], blacklist, [], hints)
			## if we see this we can probably directly go to unrar
			elif assembly['name'] == "WinRAR SFX":
				pass
			elif assembly['name'] == "WinZipComputing.WinZip.WZSEPE32":
				pass
			elif assembly['name'] == "WinZipComputing.WinZip.WZSFX":
				pass
			elif assembly['name'] == "JR.Inno.Setup":
				pass
			elif assembly['name'] == "Nullsoft.NSIS.exehead":
				pass
			elif assembly['name'] == "7zS.sfx.exe":
				pass
			## IExpress WExtract
			elif assembly['name'] == "wextract":
				pass
			elif assembly['name'] == "InstallShield.Setup":
				pass
			## self extracting cab, use either cabextract or 7z
			elif assembly['name'] == "sfxcab":
				pass
			## Setup Factory
			elif assembly['name'] == "setup.exe":
				pass
			## dunno this one, seems to be misspelled
			elif assembly['name'] == "Squeez-SFX":
				pass
	## after all the special cases we can just bruteforce our way through
	## like before, although if we find some strings we could already skip
	## some checks. Needs refactoring.
	## first search for ZIP. Do this by searching for:
	## * PKBAC (seems to give the best results)
	## * WinZip Self-Extractor
	## 7zip gives better results than unzip
	if 'pkbac' in offsets:
		if offsets['pkbac'] != []:
			## assume only one entry now. TODO: fix if multiple exe files
			## were concatenated.
			offset = offsets['pkbac'][0]
			tmpdir = dirsetup(tempdir, filename, "exe", counter)
			tmpres = unpack7z(filename, 0, tmpdir, blacklist)
			if tmpres != None:
				(size7z, res) = tmpres
				diroffsets.append((res, 0, size7z))
				blacklist.append((0, size7z))
				newtags.append('exe')
				return (diroffsets, blacklist, newtags, hints)
			else:
				os.rmdir(tmpdir)
	## then search for WinRAR and extract with unrar
	if 'winrar' in offsets:
		if offsets['winrar'] != []:
			## assume only one entry now. TODO: fix if multiple exe files
			## were concatenated.
			offset = offsets['winrar'][0]
			tmpdir = dirsetup(tempdir, filename, "exe", counter)
			res = unpackRar(filename, 0, tmpdir)
			if res != None:
				(endofarchive, rardir) = res
				filesize = os.stat(filename).st_size
				diroffsets.append((rardir, 0, filesize))
				## add the whole binary to the blacklist
				blacklist.append((0, filesize))
				counter = counter + 1
				newtags.append('exe')
				newtags.append('winrar')
				return (diroffsets, blacklist, newtags, hints)
			else:
				os.rmdir(tmpdir)
	## else try other methods
	## 7zip gives better results than cabextract
	## Ideally we should also do something with innounp
	## As a last resort try 7-zip
	tmpdir = dirsetup(tempdir, filename, "exe", counter)
	tmpres = unpack7z(filename, 0, tmpdir, blacklist)
	if tmpres != None:
		(size7z, res) = tmpres
		diroffsets.append((res, 0, size7z))
		blacklist.append((0, size7z))
		## TODO: research if size7z == filesize
		newtags.append('exe')
		return (diroffsets, blacklist, newtags, hints)
	else:
		os.rmdir(tmpdir)
	return (diroffsets, blacklist, newtags, hints)

## unpacker for Microsoft InstallShield
## We're using unshield for this. Unfortunately the released version of
## unshield (0.6) does not support newer versions of InstallShield files, so we
## can only unpack a (shrinking) subset of files.
##
## Patches for support of newer versions have been posted at:
## http://sourceforge.net/tracker/?func=detail&aid=3163039&group_id=30550&atid=399603
## but unfortunately there has not been a new release yet.
def searchUnpackInstallShield(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if offsets['installshield'] == []:
		return ([], blacklist, [], hints)
	diroffsets = []
	counter = 1
	## To successfully unpack we need:
	## * installshield cabinet (.cab)
	## * header file (.hdr)
	## * possibly (if available) <filename>2.cab
	##
	## To successfully unpack the filenames need to be formatted as <filename>1.<extension>
	## so we will only consider files that end in "1.cab"
	if offsets['installshield'][0] != 0:
		return ([], blacklist, [], hints)
	## Check the filenames first, if we don't have <filename>1.cab, or <filename>1.hdr we return
	## This should prevent that data2.cab is scanned.
	if not filename.endswith("1.cab"):
		return ([], blacklist, [], hints)
	try:
		os.stat(filename[:-4] + ".hdr")
	except Exception, e:
		return ([], blacklist, [], hints)
	blacklistoffset = extractor.inblacklist(0, blacklist)
	if blacklistoffset != None:
		return ([], blacklist, [], hints)
	tmpdir = dirsetup(tempdir, filename, "installshield", counter)

	p = subprocess.Popen(['unshield', 'x', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		shutil.rmtree(tmpdir)
	else:
		## Ideally we add data1.cab, data1.hdr and (if present) data2.cab to the blacklist.
		## For this we need to be able to supply more information to the parent process
		diroffsets.append((tmpdir, 0, 0))
	return (diroffsets, blacklist, [], hints)

## unpacker for Microsoft Cabinet Archive files.
def searchUnpackCab(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'cab' in offsets:
		return ([], blacklist, [], hints)
	newtags = []
	if offsets['cab'] == []:
		return ([], blacklist, newtags, hints)
	diroffsets = []
	counter = 1
	for offset in offsets['cab']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "cab", counter)
		res = unpackCab(filename, offset, tmpdir, blacklist)
		if res != None:
			(cabdir, cabsize) = res
			diroffsets.append((cabdir, offset, cabsize))
			blacklist.append((offset, offset + cabsize))
			counter = counter + 1
			if offset == 0 and cabsize == os.stat(filename).st_size:
				newtags.append('cab')
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, newtags, hints)

## This method will not work when the CAB is embedded in a bigger file, such as
## a MINIX file system. We need to use more data from the metadata and perhaps
## adjust for certificates.
def unpackCab(filename, offset, tempdir=None, blacklist=[]):
	cab = file(filename, "r")
	cab.seek(offset)
	cabbuffer = cab.read(12)
	cab.close()

	if len(cabbuffer) != 12:
		return

	filesize = os.stat(filename).st_size

	cabsize = struct.unpack('<I', cabbuffer[8:])[0]
	if filesize < cabsize:
		return

	if filesize < cabsize + offset:
		return

	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, blacklist=blacklist, length=cabsize)

	p = subprocess.Popen(['cabextract', '-d', tmpdir, tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		## files might have been written, but possibly not correct, so
		## remove them
		rmfiles = os.listdir(tmpdir)
		if rmfiles != []:
			## TODO: This does not yet correctly process symlinks links
			for rmfile in rmfiles:
				try:
					shutil.rmtree(os.path.join(tmpdir, rmfile))
				except:
					os.remove(os.path.join(tmpdir, rmfile))
		if tempdir == None:
			os.rmdir(tmpdir)
		return None

	os.unlink(tmpfile[1])
	return (tmpdir, cabsize)

def searchUnpack7z(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not '7z' in offsets:
		return ([], blacklist, [], hints)
	if offsets['7z'] == []:
		return ([], blacklist, [], hints)

	counter = 1
	diroffsets = []
	tags = []
	for offset in offsets['7z']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "7z", counter)
		res = unpack7z(filename, offset, tmpdir, blacklist)
		if res != None:
			(size7s, resdir) = res
			diroffsets.append((resdir, offset, size7s))
			counter = counter + 1
			if offset == 0 and size7s == os.stat(filename).st_size:
				tags.append("compressed")
				tags.append("7z")
			blacklist.append((offset, offset+size7s))
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, tags, hints)

def unpack7z(filename, offset, tempdir=None, blacklist=[]):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that 7z is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, blacklist=blacklist)

	param = "-o%s" % tmpdir
	p = subprocess.Popen(['7z', param, '-l', '-y', 'x', tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		## 7z might have exited, but perhaps left some files behind, so remove them
		tmpfiles = os.listdir(tmpdir)
		if tmpfiles != []:
			## TODO: This does not yet correctly process symlinks links
			for f in tmpfiles:
				try:
					shutil.rmtree(os.path.join(tmpdir, f))
				except:
					os.remove(os.path.join(tmpdir, f))
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.unlink(tmpfile[1])
	sizeres = re.search("Compressed:\s+(\d+)", stanout)
	if sizeres != None:
		size7s = int(sizeres.groups()[0])
	else:
		size7s = 0
	return (size7s, tmpdir)

## unpack lzip archives.
def searchUnpackLzip(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'lzip' in offsets:
		return ([], blacklist, [], hints)
	if offsets['lzip'] == []:
		return ([], blacklist, [], hints)
	filesize = os.stat(filename).st_size
	if filesize < 5:
		return ([], blacklist, [], hints)
	diroffsets = []
	tags = []
	counter = 1
	for offset in offsets['lzip']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## sanity check, only versions 0 or 1 are supported
		lzipfile = open(filename, 'rb')
		lzipfile.seek(offset+4)
		lzipversion = lzipfile.read(1)
		lzipfile.close()
		if struct.unpack('<B', lzipversion)[0] > 1:
			continue
		tmpdir = dirsetup(tempdir, filename, "lzip", counter)
		(res, lzipsize) = unpackLzip(filename, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset, lzipsize))
			blacklist.append((offset, offset+lzipsize))
			counter = counter + 1
			if offset == 0 and lzipsize == filesize:
				tags.append("compressed")
				tags.append("lzip")
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, tags, hints)

def unpackLzip(filename, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzip is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir)

	p = subprocess.Popen(['lzip', "-d", "-c", tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanout)
	os.fsync(outtmpfile[0])
	os.fdopen(outtmpfile[0]).close()
	if os.stat(outtmpfile[1]).st_size == 0:
		os.unlink(outtmpfile[1])
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)

	## Sanity checks
	## http://www.nongnu.org/lzip/manual/lzip_manual.html
	## * first compute the CRC32 value of the file that was unpacked.
	## * search the original file for the CRC32 value followed by the size
	##  of the unpacked data
	## * verify using lzip that it is actually the right offset
	## * report the size of the compressed data

	## compute the crc32 of the unpacked data and pack it
	crc32 = struct.pack('<I', gzipcrc32(outtmpfile[1]))
	## pack the size of the unpacked data into a string
	packedsize = struct.pack('<Q', os.stat(outtmpfile[1]).st_size)
	## concatenate crc32 and packedsize so it can be searched
	crc32packedsize = crc32+packedsize

	## search the compressed data for the crc32 and uncompressed data size
	datafile = open(tmpfile[1], 'rb')
	datafile.seek(0)
	## read 1 million bytes
	lzipdataread = 1000000
	lzipbytes = datafile.read(lzipdataread)
	lzipcrc32offset = 0
	totalread = lzipdataread
	lzdata = ''

	lzipsize = 0
	while lzipbytes != '':
		lzdata += lzipbytes
		res = lzdata.find(crc32packedsize, lzipcrc32offset)
		if res != -1:
			devnull = open(os.devnull, 'w')
			p = subprocess.Popen(['lzip'], stdin=subprocess.PIPE, stdout=devnull, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate(lzdata[:res+20])
			devnull.close()
			if p.returncode != 0:
				continue
			crc32match = True
			endoflzip = res + 12
			datafile.close()
			lzipsize = struct.unpack('<Q', lzdata[res+12:res+20])[0]
			break
		lzipbytes = datafile.read(lzipdataread)
		lzipcrc32offset = totalread - 50
		totalread += lzipdataread
	datafile.close()

	## clean up
	os.unlink(tmpfile[1])
	return (tmpdir, lzipsize)

## unpack lzo archives.
def searchUnpackLzo(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'lzo' in offsets:
		return ([], blacklist, [], hints)
	if offsets['lzo'] == []:
		return ([], blacklist, [], hints)
	diroffsets = []
	tags = []
	counter = 1
	for offset in offsets['lzo']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue

		## do a quick check for the version, which is either
		## 0, 1 or 2 right now.
		lzopfile = open(filename, 'rb')
		lzopfile.seek(offset+9)
		lzopversionbyte = ord(lzopfile.read(1)) & 0xf0
		if not lzopversionbyte in [0x00, 0x10, 0x20]:
			lzopfile.close()
			continue

		## extra sanity check: according to /usr/share/magic
		## byte 15 has to be 1, 2 or 3
		lzopfile.seek(offset+15)
		lzopversionbyte = lzopfile.read(1)
		lzopfile.close()
		if not ord(lzopversionbyte) in [1,2,3]:
			continue
		
		tmpdir = dirsetup(tempdir, filename, "lzo", counter)
		(res, lzosize) = unpackLzo(filename, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset, lzosize))
			blacklist.append((offset, offset+lzosize))
			if offset == 0 and lzosize == os.stat(filename).st_size:
				tags.append("compressed")
				tags.append("lzo")
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, tags, hints)

def unpackLzo(filename, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzop is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir)

	p = subprocess.Popen(['lzop', "-d", "-P", "-p%s" % (tmpdir,), tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)
	## determine the size of the archive we unpacked, so we can skip a lot in future scans
	p = subprocess.Popen(['lzop', '-t', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	## file could be two lzop files concatenated, which would unpack just fine
	## but which would give a returncode != 0 when tested. This will do for now though.
	if p.returncode != 0:
		lzopsize = 0
	else:
		## the whole file is the lzop archive
		lzopsize = os.stat(filename).st_size
	os.unlink(tmpfile[1])
	return (tmpdir, lzopsize)

## To unpack XZ a header and a footer and footer need to be found
## http://tukaani.org/xz/xz-file-format.txt
def searchUnpackXZ(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'xz' in offsets:
		return ([], blacklist, [], hints)
	if not 'xztrailer' in offsets:
		return ([], blacklist, [], hints)
	if offsets['xz'] == []:
		return ([], blacklist, [], hints)
	if offsets['xztrailer'] == []:
		return ([], blacklist, [], hints)

	dotest = True
	## check version of XZ, as older versions do not support -l
	p = subprocess.Popen(['xz', '-V'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return ([], blacklist, [], hints)

	if '4.999.9beta' in stanout:
		dotest = False

	diroffsets = []
	newtags = []
	counter = 1
	datafile = open(filename, 'rb')
	template = None
	if 'TEMPLATE' in scanenv:
		template = scanenv['TEMPLATE']
	## If there only is one header, it makes more sense to work backwards
	## since most archives are probably complete files.
	if len(offsets['xz']) == 1:
		offsets['xztrailer'] = sorted(offsets['xztrailer'], reverse=True)
	for offset in offsets['xz']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## bytes 7 and 8 in the stream are "streamflags"
		datafile.seek(offset)
		data = datafile.read(8)
		streamflags = data[6:8]
		for trail in offsets['xztrailer']:
			## check if the trailer is in the blacklist
			blacklistoffset = extractor.inblacklist(trail, blacklist)
			if blacklistoffset != None:
				continue
			## only check offsets that make sense
			if trail < offset:
				continue
			## The "streamflag" bytes should also be present just before the
			## trailer according to the XZ file format documentation.
			datafile.seek(trail-2)
			data = datafile.read(2)
			if data != streamflags:
				continue

			xzsize = trail+2 - offset
			datafile.seek(offset)
			data = datafile.read(xzsize)
			## TODO: the two bytes before that are the so called "backward size"

			tmpdir = dirsetup(tempdir, filename, "xz", counter)
			res = unpackXZ(filename, offset, xzsize, template, dotest, tmpdir)
			if res != None:
				diroffsets.append((res, offset, xzsize))
				blacklist.append((offset, trail+2))
				if offset == 0 and trail+2 == os.stat(filename).st_size:
					datafile.close()
					newtags.append('compressed')
					newtags.append('xz')
					return (diroffsets, blacklist, newtags, hints)
				counter = counter + 1
				break
			else:
				## cleanup
				os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, newtags, hints)

def unpackXZ(filename, offset, xzsize, template, dotest, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, length=xzsize)

	if dotest:
		## test integrity of the file
		p = subprocess.Popen(['xz', '-l', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.unlink(tmpfile[1])
			return None
	## unpack
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	p = subprocess.Popen(['xzcat', tmpfile[1]], stdout=outtmpfile[0], stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	os.fsync(outtmpfile[0])
	os.fdopen(outtmpfile[0]).close()
	if os.stat(outtmpfile[1]).st_size == 0:
		os.unlink(outtmpfile[1])
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.unlink(tmpfile[1])

	wholefile = False
	if offset == 0 and offset+xzsize == os.stat(filename).st_size:
		if filename.lower().endswith('.xz'):
			wholefile = True

	if wholefile:
		filenamenoext = os.path.basename(filename)[:-3]
		if len(filenamenoext) > 0:
			if not os.path.exists(os.path.join(tmpdir, filenamenoext)):
				try:
					shutil.move(outtmpfile[1], os.path.join(tmpdir, filenamenoext))
				except Exception, e:
					pass
	else:
		if template != None:
			if not os.path.exists(os.path.join(tmpdir, template)):
				try:
					shutil.move(outtmpfile[1], os.path.join(tmpdir, template))
				except Exception, e:
					pass
	return tmpdir

## Not sure how cpio works if we have a cpio archive within a cpio archive
## especially with regards to locating the proper cpio trailer.
def searchUnpackCpio(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'cpiotrailer' in offsets:
		return ([], blacklist, [], hints)
	cpiooffsets = []
	for marker in fsmagic.cpio:
		cpiooffsets = cpiooffsets + offsets[marker]
	if cpiooffsets == []:
		return ([], blacklist, [], hints)
	if offsets['cpiotrailer'] == []:
		return ([], blacklist, [], hints)

	cpiooffsets.sort()

	diroffsets = []
	counter = 1
	newcpiooffsets = []
	for offset in cpiooffsets:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## first some sanity checks for the different CPIO flavours
		datafile = open(filename, 'rb')
		datafile.seek(offset)
		cpiomagic = datafile.read(6)
		## man 5 cpio. At the moment only the ASCII cpio archive
		## formats are supported, not the old obsolete binary format
		if cpiomagic == '070701' or cpiomagic == '070702':
			datafile.seek(offset)
			cpiodata = datafile.read(110)
			## all characters in cpiodata need to be digits
			cpiores = re.match('[\w\d]{110}', cpiodata)
			if cpiores != None:
				newcpiooffsets.append(offset)
		elif cpiomagic == '070707':
			datafile.seek(offset)
			cpiodata = datafile.read(76)
			## all characters in cpiodata need to be digits
			cpiores = re.match('[\w\d]{76}', cpiodata)
			if cpiores != None:
				newcpiooffsets.append(offset)
		else:
			newcpiooffsets.append(offset)
		datafile.close()

	if newcpiooffsets == []:
		return ([], blacklist, [], hints)
	datafile = open(filename, 'rb')
	for offset in newcpiooffsets:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		for trailer in offsets['cpiotrailer']:
			if trailer < offset:
				continue
			blacklistoffset = extractor.inblacklist(trailer, blacklist)
			if blacklistoffset != None:
				continue
			datafile.seek(offset)
			tmpdir = dirsetup(tempdir, filename, "cpio", counter)
			## length of 'TRAILER!!!' plus 1 to include the whole trailer
			## Also, cpio archives are always rounded to blocks of 512 bytes
			data = datafile.read(trailer + 10 - offset)
			trailercorrection = 512 - len(data)%512
			data += datafile.read(trailercorrection)
			res = unpackCpio(data, tmpdir)
			if res != None:
				diroffsets.append((res, offset, 0))
				blacklist.append((offset, trailer + 10 + trailercorrection))
				counter = counter + 1
				## success with unpacking, no need to continue with
				## the next trailer for this offset
				break
			else:
				## cleanup
				os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, [], hints)

## tries to unpack stuff using cpio. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
## This one needs to stay separate, since it is also used by RPM unpacking
def unpackCpio(data, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	p = subprocess.Popen(['cpio', '-t'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tmpdir)
	(stanout, stanerr) = p.communicate(data)
	if p.returncode != 0:
		## we don't have a valid archive according to cpio -t
		if tempdir == None:
			os.rmdir(tmpdir)
		return
	p = subprocess.Popen(['cpio', '-i', '-d', '--no-absolute-filenames'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tmpdir)
	(stanout, stanerr) = p.communicate(data)
	return tmpdir

def searchUnpackRomfs(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'romfs' in offsets:
		return ([], blacklist, [], hints)
	if offsets['romfs'] == []:
		return ([], blacklist, [], hints)
	diroffsets = []
	counter = 1
	for offset in offsets['romfs']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "romfs", counter)
		res = unpackRomfs(filename, offset, tmpdir, blacklist=blacklist)
		if res != None:
			(romfsdir, size) = res
			diroffsets.append((romfsdir, offset, size))
			blacklist.append((offset, offset + size))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
        return (diroffsets, blacklist, [], hints)

def unpackRomfs(filename, offset, tempdir=None, unpacktempdir=None, blacklist=[]):
	## First check the size of the header. If it has some
	## bizarre value (like bigger than the file it can unpack)
	## it is not a valid romfs file system
	romfsfile = open(filename)
	romfsfile.seek(offset)
	romfsdata = romfsfile.read(12)
	romfsfile.close()
	if len(romfsdata) < 12:
		return None
	romfssize = struct.unpack('>L', romfsdata[8:12])[0]

	if romfssize > os.stat(filename).st_size:
		return None
	## a valid romfs cannot be empty
	if romfssize == 0:
		return None

	## It could be a valid romfs, so unpack
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, blacklist=blacklist)

	## Compare the value of the header again, but now with the
	## unpacked file.
	if romfssize > os.stat(tmpfile[1]).st_size:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None

	## temporary dir to unpack stuff in
	tmpdir2 = tempfile.mkdtemp(dir=unpacktempdir)

	p = subprocess.Popen(['bat-romfsck', '-d', tmpdir2, '-b', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		shutil.rmtree(tmpdir2)
		return None
	## then move all the contents using shutil.move()
	mvfiles = os.listdir(tmpdir2)
	for f in mvfiles:
		shutil.move(os.path.join(tmpdir2, f), tmpdir)
	## then cleanup the temporary dir
	shutil.rmtree(tmpdir2)

	## determine the size and cleanup
	datafile = open(tmpfile[1])
	datafile.seek(8)
	## TODO: replace with romfssize??
	sizedata = datafile.read(4)
	size = struct.unpack('>I', sizedata)[0]
	datafile.close()
	os.unlink(tmpfile[1])
	return (tmpdir, size)

## unpacking cramfs file systems. This will fail on file systems from some
## devices most notably from Sigma Designs, since they seem to have tweaked
## the file system.
def searchUnpackCramfs(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'cramfs_le' in offsets and not 'cramfs_be' in offsets:
		return ([], blacklist, [], hints)
	if 'cramfs_le' in offsets:
		le_offsets = copy.deepcopy(offsets['cramfs_le'])
	else:
		le_offsets = []
	if 'cramfs_be' in offsets:
		be_offsets = copy.deepcopy(offsets['cramfs_be'])
	else:
		be_offsets = []
	if le_offsets == [] and be_offsets == []:
		return ([], blacklist, [], hints)
	counter = 1
	cramfsoffsets = le_offsets + be_offsets
	diroffsets = []
	cramfsoffsets.sort()

	if not 'cramfs_be' in offsets:
		be_offsets = set()
	else:
		be_offsets = set(offsets['cramfs_be'])

	for offset in cramfsoffsets:
		bigendian = False
		if offset in be_offsets:
			bigendian = True
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		cramfsfile = open(filename)
		cramfsfile.seek(offset)
		tmpbytes = cramfsfile.read(64)
		cramfsfile.close()
		if not "Compressed ROMFS" in tmpbytes:
			continue

		tmpdir = dirsetup(tempdir, filename, "cramfs", counter)
		retval = unpackCramfs(filename, offset, tmpdir, bigendian=bigendian, blacklist=blacklist)
		if retval != None:
			(res, cramfssize) = retval
			if cramfssize != 0:
				blacklist.append((offset,offset+cramfssize))
			diroffsets.append((res, offset, cramfssize))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

## tries to unpack stuff using fsck.cramfs. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackCramfs(filename, offset, tempdir=None, unpacktempdir=None, bigendian=False, blacklist=[]):
	sizetmpfile = open(filename)
	sizetmpfile.seek(offset+4)
	tmpbytes = sizetmpfile.read(4)
	sizetmpfile.close()

	if len(tmpbytes) < 4:
		return
	if bigendian:
		cramfslen = struct.unpack('>I', tmpbytes)[0]
	else:
		cramfslen = struct.unpack('<I', tmpbytes)[0]

	versiontmpfile = open(filename)
	versiontmpfile.seek(offset+8)
	tmpbytes = versiontmpfile.read(4)
	versiontmpfile.close()

	if bigendian:
		cramfsversion = struct.unpack('>I', tmpbytes)[0]
	else:
		cramfsversion = struct.unpack('<I', tmpbytes)[0]
	if cramfsversion != 0:
		if cramfslen > os.stat(filename).st_size:
			return
	else:
		## this is an old cramfs version, so length
		## field does not mean anything
		cramfslen = os.stat(filename).st_size

	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, length=cramfslen, unpacktempdir=unpacktempdir, blacklist=blacklist)

	## directory to avoid name clashes
        tmpdir2 = tempfile.mkdtemp(dir=unpacktempdir)

	## right now this is a path to a specially adapted fsck.cramfs that ignores special inodes
	## We actually need to create a new subdirectory inside tmpdir, otherwise the tool will complain
	p = subprocess.Popen(['bat-fsck.cramfs', '-x', os.path.join(tmpdir2, "cramfs"), tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		shutil.rmtree(tmpdir2)
		return
	else:
		## first copy all the contents from the temporary dir to tmpdir
		mvfiles = os.listdir(os.path.join(tmpdir2, "cramfs"))
		for f in mvfiles:
			## skip symbolic links for now
			if os.path.islink(os.path.join(tmpdir2, 'cramfs', f)):
				continue
			shutil.move(os.path.join(tmpdir2, "cramfs", f), tmpdir)
		## determine if the whole file actually is the cramfs file. Do this by running bat-fsck.cramfs again with -v and check stderr.
		## If there is no warning or error on stderr, we know that the entire file is the cramfs file and it can be blacklisted.
		p = subprocess.Popen(['bat-fsck.cramfs', '-v', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if len(stanerr) != 0:
			cramfssize = 0
		else:
			cramfssize = os.stat(tmpfile[1]).st_size
		os.unlink(tmpfile[1])
		shutil.rmtree(tmpdir2)
		return (tmpdir, cramfssize)

## Search and unpack a squashfs file system. Since there are so many flavours
## of squashfs available we have to do some extra work here, and possibly have
## some extra tools (squashfs variants) installed.
def searchUnpackSquashfs(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	newtags = []
	squashoffsets = []
	for marker in fsmagic.squashtypes:
		if marker in offsets:
			squashoffsets = squashoffsets + offsets[marker]
	if squashoffsets == []:
		if 'squashfs7' in offsets:
			if offsets['squashfs7'] == []:
				return ([], blacklist, newtags, hints)
		else:
			return ([], blacklist, newtags, hints)

	squashoffsets.sort()

	diroffsets = []
	counter = 1
	for offset in squashoffsets:
		## check if the offset we find is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## determine the type of squashfs magic we have, plus
		## do some extra sanity checks
		squashes = filter(lambda x: offset in offsets[x], offsets)
		if len(squashes) != 1:
			continue
		if squashes[0] not in fsmagic.squashtypes:
			continue
		## determine the size of the file for the blacklist. The size can sometimes be extracted
		## from the header, but it depends on the endianness and the major version of squashfs
		## used. In some of the cases this data might not be relevant.
		sqshfile = open(filename, 'rb')
		sqshfile.seek(offset)
		sqshheader = sqshfile.read(4)
		bigendian = False
		if sqshheader in ['sqsh', 'qshs', 'tqsh']:
			bigendian = True
		## get the version from the header
		sqshfile.seek(offset+28)
		versionbytes = sqshfile.read(2)
		if bigendian:
			majorversion = struct.unpack('>H', versionbytes)[0]
		else:
			majorversion = struct.unpack('<H', versionbytes)[0]

		if majorversion > 5 or majorversion == 0:
			continue

		## first read the first 80 bytes from the file system to see if
		## the string '7zip' can be found. If so, then the inodes have been
		## compressed with a variant of squashfs that uses 7zip compression
		## and might cause crashes in some of the variants below.
		sqshfile = open(filename)
		sqshfile.seek(offset)
		sqshbuffer = sqshfile.read(80)
		sqshfile.close()

		sevenzipcompression = False
		if "7zip" in sqshbuffer:
			sevenzipcompression = True

		tmpdir = dirsetup(tempdir, filename, "squashfs", counter)
		retval = unpackSquashfsWrapper(filename, offset, squashes[0], sevenzipcompression, majorversion, bigendian, tmpdir)
		if retval != None:
			(res, squashsize, squashtype) = retval
			diroffsets.append((res, offset, squashsize))
			blacklist.append((offset,offset+squashsize))
			counter = counter + 1
			newtags.append(squashtype)
		else:
			## cleanup
			os.rmdir(tmpdir)
	## squashfs7 is different, we first need to rewrite the binary
	## to replace the identifier 'sqlz' with 'sqsh', then we can unpack
	## it with unsquashfsRealtekLZMA
	## TODO: see if it is possible to remove some duplicate code that is
	## shared with the above code.
	if 'squashfs7' in offsets:
		if offsets['squashfs7'] != []:
			for offset in offsets['squashfs7']:
				blacklistoffset = extractor.inblacklist(offset, blacklist)
				if blacklistoffset != None:
					continue
				tmpdir = dirsetup(tempdir, filename, "squashfs", counter)

				sqshtmpdir = unpacksetup(tmpdir)
				tmpfile = tempfile.mkstemp(dir=sqshtmpdir)
				os.fdopen(tmpfile[0]).close()

				## unpack the file
				unpackFile(filename, offset, tmpfile[1], tmpdir)

				## open the file and replace the header
				sqshf = open(tmpfile[1], 'r+b')
				sqshf.seek(0)
				sqshf.write('sqsh')
				sqshf.close()

				retval = unpackSquashfsRealtekLZMA(tmpfile[1], offset, tmpdir)
				os.unlink(tmpfile[1])
				if retval != None:
					(res, squashsize) = retval
					diroffsets.append((res, offset, squashsize))
					blacklist.append((offset,offset+squashsize))
					counter = counter + 1
					newtags.append('squashfsrealteklzma')
				else:
					os.rmdir(tmpdir)
	return (diroffsets, blacklist, newtags, hints)

## wrapper around all the different squashfs types
def unpackSquashfsWrapper(filename, offset, squashtype, sevenzipcompression, majorversion, bigendian, tempdir=None):
	## determine the size of the file for the blacklist. The size can sometimes be extracted
	## from the header, but it depends on the endianness and the major version of squashfs
	## used. In some of the cases this data might not be relevant.
	sqshfile = open(filename, 'rb')
	sqshfile.seek(offset)

	filesize = os.stat(filename).st_size

	squashsize = 0

	if majorversion == 4:
		sqshfile.seek(offset+40)
		squashdata = sqshfile.read(8)
		if bigendian:
			squashsize = struct.unpack('>Q', squashdata)[0]
		else:
			squashsize = struct.unpack('<Q', squashdata)[0]
	elif majorversion == 3:
		sqshfile.seek(offset+63)
		squashdata = sqshfile.read(8)
		if bigendian:
			squashsize = struct.unpack('>Q', squashdata)[0]
		else:
			squashsize = struct.unpack('<Q', squashdata)[0]
	elif majorversion == 2:
		sqshfile.seek(offset+8)
		squashdata = sqshfile.read(4)
		if bigendian:
			squashsize = struct.unpack('>I', squashdata)[0]
		else:
			squashsize = struct.unpack('<I', squashdata)[0]
	else:
		squashsize = 1
	sqshfile.close()

	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpdir = unpacksetup(tempdir)

	tmpoffset = 0

	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	## DD-WRT variant uses special magic
	if squashtype == 'squashfs5' or squashtype == 'squashfs6':
		if squashsize > filesize:
			os.unlink(tmpfile[1])
			return None
		unpackFile(filename, offset, tmpfile[1], tmpdir, length=squashsize)
		retval = unpackSquashfsDDWRTLZMA(tmpfile[1],tmpoffset,tmpdir)
		if retval != None:
			os.unlink(tmpfile[1])
			return retval + (squashsize, 'squashfs-ddwrt',)
		## since no other squashfs unpacker uses the same squash header
		## it is safe to return here
		os.unlink(tmpfile[1])
		return None

	## try normal Squashfs unpacking first
	if squashtype == 'squashfs1' or squashtype == 'squashfs2':
		if squashsize > filesize:
			os.unlink(tmpfile[1])
			return None
		unpackFile(filename, offset, tmpfile[1], tmpdir, length=squashsize)
		retval = unpackSquashfs(tmpfile[1], tmpoffset, tmpdir)
		if retval != None:
			os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			os.unlink(tmpfile[1])
			return retval + (squashsize, 'squashfs')

		## then try other flavours
		## first SquashFS 4.2
		retval = unpackSquashfs42(tmpfile[1],tmpoffset,tmpdir)
		if retval != None:
			os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			os.unlink(tmpfile[1])
			return retval + (squashsize, 'squashfs42')

		### Atheros2 variant
		if majorversion == 3:
			retval = unpackSquashfsAtheros2LZMA(tmpfile[1],tmpoffset,tmpdir)
			if retval != None:
				os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
				os.unlink(tmpfile[1])
				return retval + (squashsize, 'squashfsatheros2lzma')

	## OpenWrt variant
	if majorversion == 3:
		if squashsize > filesize:
			os.unlink(tmpfile[1])
			return None
		unpackFile(filename, offset, tmpfile[1], tmpdir, length=squashsize)
		retval = unpackSquashfsOpenWrtLZMA(tmpfile[1],tmpoffset,tmpdir)
		if retval != None:
			os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			os.unlink(tmpfile[1])
			return retval + (squashsize, 'squashfsopenwrtlzma')

	## unpack the file once (again)
	unpackFile(filename, offset, tmpfile[1], tmpdir)

	## Realtek variant
	retval = unpackSquashfsRealtekLZMA(tmpfile[1],tmpoffset,tmpdir)
	if retval != None:
		os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
		os.unlink(tmpfile[1])
		return retval + ('squashfsrealteklzma',)

	## Broadcom variant
	if majorversion == 2 or majorversion == 3:
		if squashsize > filesize:
			os.unlink(tmpfile[1])
			return None
		retval = unpackSquashfsBroadcom(tmpfile[1],tmpoffset,tmpdir)
		if retval != None:
			os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			os.unlink(tmpfile[1])
			return retval + (squashsize, 'squashfsbroadcomlzma')

	if not sevenzipcompression:
		if squashsize > filesize:
			os.unlink(tmpfile[1])
			return None
		retval = unpackSquashfsAtherosLZMA(tmpfile[1],tmpoffset,tmpdir)
		if retval != None:
			os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			os.unlink(tmpfile[1])
			return retval + (squashsize, 'squashfsatheroslzma')

	## another Atheros variant
	retval = unpackSquashfsAtheros40LZMA(tmpfile[1],tmpoffset,tmpdir)
	if retval != None:
		os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
		os.unlink(tmpfile[1])
		return retval + ('squashfsatheros40lzma',)

	## Ralink variant
	if not sevenzipcompression:
		if majorversion == 2 or majorversion == 3:
			if squashsize > filesize:
				os.unlink(tmpfile[1])
				return None
			retval = unpackSquashfsRalinkLZMA(tmpfile[1],tmpoffset,tmpdir)
			if retval != None:
				os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
				os.unlink(tmpfile[1])
				return retval + (squashsize, 'squashfsralinklzma',)

	## another Broadcom variant
	retval = unpackSquashfsBroadcom40LZMA(tmpfile[1],tmpoffset,tmpdir)
	if retval != None:
		os.chmod(tmpdir, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
		os.unlink(tmpfile[1])
		return retval + (squashsize, 'squashfsbroadcom40lzma',)

	os.unlink(tmpfile[1])
	if tempdir == None:
		os.rmdir(tmpdir)
	return None

## tries to unpack stuff using 'normal' unsquashfs. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackSquashfs(filename, offset, tmpdir):
	## squashfs is not always in the same path:
	## Fedora uses /usr/sbin, Ubuntu uses /usr/bin
	## Just to be sure we add /usr/sbin to the path and set the environment

	unpackenv = os.environ.copy()
	unpackenv['PATH'] = unpackenv['PATH'] + ":/usr/sbin"

	p = subprocess.Popen(['unsquashfs', '-d', tmpdir, '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=unpackenv)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return None
	else:
		if "gzip uncompress failed with error code " in stanerr:
			return None
		return (tmpdir,)

## squashfs variant from DD-WRT, with LZMA
def unpackSquashfsDDWRTLZMA(filename, offset, tmpdir, unpacktempdir=None):
	## squashfs 1.0 with lzma from DDWRT can't unpack to an existing directory
	## so use a workaround using an extra temporary directory
	tmpdir2 = tempfile.mkdtemp(dir=unpacktempdir)

	p = subprocess.Popen(['bat-unsquashfs-ddwrt', '-dest', tmpdir2 + "/squashfs-root", '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	## Return code is not reliable enough, since even after successful unpacking the return code could be 16 (related to creating inodes as non-root)
	## we need to filter out messages about creating inodes. Right now we do that by counting how many
	## error lines we have for creating inodes and comparing them with the total number of lines in stderr
	## If they match we know all errors are for creating inodes, so we can safely ignore them.
	stanerrlines = stanerr.strip().split("\n")
	inode_error = 0
	for stline in stanerrlines:
		if "create_inode: could not create" in stline:
			inode_error = inode_error + 1
	if stanerr != "" and len(stanerrlines) != inode_error:
		shutil.rmtree(tmpdir2)
		return None
	else:
		## move all the contents using shutil.move()
		mvfiles = os.listdir(os.path.join(tmpdir2, "squashfs-root"))
		for f in mvfiles:
			mvpath = os.path.join(tmpdir2, "squashfs-root", f)
			if os.path.islink(mvpath):
				os.symlink(os.readlink(mvpath), os.path.join(tmpdir, f))
				continue
			try:
				shutil.move(mvpath, tmpdir)
			except Exception, e:
				pass
		## then cleanup the temporary dir
		shutil.rmtree(tmpdir2)
		return (tmpdir,)

## squashfs variant from Atheros, with LZMA, looks a lot like OpenWrt variant
## TODO: merge with OpenWrt variant
def unpackSquashfsAtheros2LZMA(filename, offset, tmpdir, unpacktempdir=None):
	## squashfs 1.0 with lzma from OpenWrt can't unpack to an existing directory
	## so we use a workaround using an extra temporary directory
	tmpdir2 = tempfile.mkdtemp(dir=unpacktempdir)

	p = subprocess.Popen(['bat-unsquashfs-atheros2', '-dest', tmpdir2 + "/squashfs-root", '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if "gzip uncompress failed with error code " in stanerr:
		shutil.rmtree(tmpdir2)
		return None
	if p.returncode == -11:
		## core dump, seen in Trendnet TEW-639GR_672GR_mixed_v1.0.9.161.bin
		shutil.rmtree(tmpdir2)
		return None
	## Return code is not reliable enough, since even after successful unpacking the return code could be 16 (related to creating inodes as non-root)
	## we need to filter out messages about creating inodes. Right now we do that by counting how many
	## error lines we have for creating inodes and comparing them with the total number of lines in stderr
	## If they match we know all errors are for creating inodes, so we can safely ignore them.
	if p.returncode != 0:
		stanerrlines = stanerr.strip().split("\n")
		inode_error = 0
		for stline in stanerrlines:
			if "create_inode: could not create" in stline:
				inode_error = inode_error + 1
		if stanerr != "" and len(stanerrlines) != inode_error:
			shutil.rmtree(tmpdir2)
			return None
	if "uncompress failed, unknown error -3" in stanerr:
		## files might have been written, but possibly not correct, so
		## remove them
		rmfiles = os.listdir(tmpdir)
		if rmfiles != []:
			## TODO: This does not yet correctly process symlinks links
			for rmfile in rmfiles:
				if os.path.join(tmpdir, rmfile) == filename:	
					continue
				try:
					shutil.rmtree(os.path.join(tmpdir, rmfile))
				except:
					os.remove(os.path.join(tmpdir, rmfile))
		shutil.rmtree(tmpdir2)
		return None
	## move all the contents using shutil.move()
	mvfiles = os.listdir(os.path.join(tmpdir2, "squashfs-root"))
	for f in mvfiles:
		mvpath = os.path.join(tmpdir2, "squashfs-root", f)
		if os.path.islink(mvpath):
			os.symlink(os.readlink(mvpath), os.path.join(tmpdir, f))
			continue
		try:
			shutil.move(mvpath, tmpdir)
		except Exception, e:
			## TODO: find out how to treat this properly
			pass
	## then we cleanup the temporary dir
	shutil.rmtree(tmpdir2)
	return (tmpdir,)

## squashfs variant from OpenWrt, with LZMA
def unpackSquashfsOpenWrtLZMA(filename, offset, tmpdir, unpacktempdir=None):
	## squashfs 1.0 with lzma from OpenWrt can't unpack to an existing directory
	## so use a workaround using an extra temporary directory
	tmpdir2 = tempfile.mkdtemp(dir=unpacktempdir)

	p = subprocess.Popen(['bat-unsquashfs-openwrt', '-dest', tmpdir2 + "/squashfs-root", '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if "gzip uncompress failed with error code " in stanerr:
		shutil.rmtree(tmpdir2)
		return None
	if p.returncode == -11:
		## core dump, seen in Trendnet TEW-639GR_672GR_mixed_v1.0.9.161.bin
		shutil.rmtree(tmpdir2)
		return None
	## Return code is not reliable enough, since even after successful unpacking the return code
	## could be 16 (related to creating inodes as non-root) so filter out messages about creating
	## inodes. Right now this is done by counting how many error lines for creating inodes there are
	## and comparing them with the total number of lines in stderr
	## If they match all errors are for creating inodes, so they can be safely ignored.
	stanerrlines = stanerr.strip().split("\n")
	inode_error = 0
	for stline in stanerrlines:
		if "create_inode: could not create" in stline:
			inode_error = inode_error + 1
	if stanerr != "" and len(stanerrlines) != inode_error:
		shutil.rmtree(tmpdir2)
		return None
	else:
		## move all the contents using shutil.move()
		mvfiles = os.listdir(os.path.join(tmpdir2, "squashfs-root"))
		for f in mvfiles:
			mvpath = os.path.join(tmpdir2, "squashfs-root", f)
			if os.path.islink(mvpath):
				os.symlink(os.readlink(mvpath), os.path.join(tmpdir, f))
				continue
			try:
				shutil.move(mvpath, tmpdir)
			except Exception, e:
				pass
		## then cleanup the temporary dir
		shutil.rmtree(tmpdir2)
		return (tmpdir,)

## squashfs 4.2, various compression methods
def unpackSquashfs42(filename, offset, tmpdir):
	p = subprocess.Popen(['bat-unsquashfs42', '-d', tmpdir, '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return None
	else:
		if "gzip uncompress failed with error code " in stanerr:
			return None
		return (tmpdir,)

## generic function for all kinds of squashfs+lzma variants that were copied
## from slax.org and then adapted and that are slightly different, but not that
## much.
def unpackSquashfsWithLZMA(filename, offset, command, tmpdir):
	p = subprocess.Popen([command, '-d', tmpdir, '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return None
	return (tmpdir,)

## squashfs variant from Atheros, with LZMA
## This one can unpack squashfs file systems with regular magic,
## as well as with 'lzma magic' (see bat-extratools source code)
def unpackSquashfsAtherosLZMA(filename, offset, tmpdir):
	p = subprocess.Popen(["bat-unsquashfs-atheros", '-d', tmpdir, '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return None
	else:
		return (tmpdir,)

## squashfs variant from Broadcom, with LZMA
def unpackSquashfsBroadcom40LZMA(filename, offset, tmpdir):
	return unpackSquashfsWithLZMA(filename, offset, "bat-unsquashfs-broadcom40", tmpdir)

## squashfs variant from Ralink, with LZMA
def unpackSquashfsRalinkLZMA(filename, offset, tmpdir):
	return unpackSquashfsWithLZMA(filename, offset, "bat-unsquashfs-ralink", tmpdir)

## squashfs variant from Atheros, with LZMA
def unpackSquashfsAtheros40LZMA(filename, offset, tmpdir):
	p = subprocess.Popen(['bat-unsquashfs-atheros40', '-d', tmpdir, '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return None
	if "uncompress failed, unknown error -3" in stanerr:
		## files might have been written, but possibly not correct, so
		## remove them
		rmfiles = os.listdir(tmpdir)
		if rmfiles != []:
			## TODO: This does not yet correctly process symlinks links
			for rmfile in rmfiles:
				if os.path.join(tmpdir, rmfile) == filename:	
					continue
				try:
					shutil.rmtree(os.path.join(tmpdir, rmfile))
				except:
					os.remove(os.path.join(tmpdir, rmfile))
		return None
	## like with 'normal' squashfs we can use 'file' to determine the size
	squashsize = 0
	p = subprocess.Popen(['file', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()

	if p.returncode != 0:
		return None
	else:
		squashsize = int(re.search(", (\d+) bytes", stanout).groups()[0])
	return (tmpdir, squashsize)

## squashfs variant from Broadcom, with zlib and LZMA
def unpackSquashfsBroadcom(filename, offset, tmpdir):
	p = subprocess.Popen(['bat-unsquashfs-broadcom', '-d', tmpdir, '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return None
	else:
		## we first need to check the contents of stderr to see if uncompression actually worked
		## This could lead to duplicate scanning with gzip or LZMA, so we might need to implement
		## a top level "pruning" script :-(
		if "LzmaUncompress: error" in stanerr:
			return None
		if "zlib::uncompress failed, unknown error -3" in stanerr:
			return None
		return (tmpdir,)

## squashfs variant from Realtek, with LZMA
## explicitely use only one processor, because otherwise unpacking
## might fail if multiple CPUs are used.
def unpackSquashfsRealtekLZMA(filename, offset, tmpdir):
	p = subprocess.Popen(['bat-unsquashfs-realtek', '-p', '1', '-d', tmpdir, '-f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return None
	else:
		if "gzip uncompress failed with error code " in stanerr:
			return None
		## unlike with 'normal' squashfs we can't always use 'file' to determine the size
		squashsize = 1
		return (tmpdir, squashsize)

'''
def searchUnpackFAT(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'fat12' in offsets and not 'fat16' in offsets:
		return ([], blacklist, [], hints)
	if offsets['fat12'] == [] and offsets['fat16'] == []:
		return ([], blacklist, [], hints)

	fattypes = []
	if offsets['fat12'] != []:
		fattypes.append('fat12')
	if offsets['fat16'] != []:
		fattypes.append('fat16')
	sys.stdout.flush()
	diroffsets = []
	counter = 1
	for t in fattypes:
		for offset in offsets[t]:
			## FAT12 and FAT16 headers have at least 54 bytes
			if offset < 54:
				continue
			## check if the offset we find is in a blacklist
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				continue
			tmpdir = dirsetup(tempdir, filename, "fat", counter)
			## we should actually scan the data starting from offset - 54
			res = unpackFAT(filename, offset - 54, t, tmpdir)
			if res != None:
				(fattmpdir, fatsize) = res
				diroffsets.append((fattmpdir, offset - 54, fatsize))
				blacklist.append((offset - 54, offset - 54 + fatsize))
				counter = counter + 1
			else:
				os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

## http://www.win.tue.nl/~aeb/linux/fs/fat/fat-1.html
def unpackFAT(filename, offset, fattype, tempdir=None, unpackenv={}):
	## first analyse the data a bit
	fatfile = open(filename, 'rb')
	fatfile.seek(offset)
	fatbytes = fatfile.read(3)
	## first some sanity checks
	if fatbytes[0] != '\xeb':
		fatfile.close()
		return None
	if fatbytes[2] != '\x90':
		fatfile.close()
		return None
	## the OEM identifier
	oemidentifier = fatfile.read(8)
	## on to "bytes per sector"
	fatbytes = fatfile.read(2)
	bytespersector = struct.unpack('<H', fatbytes)[0]
	## then "sectors per cluster"
	fatbytes = fatfile.read(1)
	sectorspercluster = ord(fatbytes)
	## then reserved sectors
	fatbytes = fatfile.read(2)
	reservedsectors = struct.unpack('<H', fatbytes)[0]
	## then "number of fat tables"
	fatbytes = fatfile.read(1)
	fattables = ord(fatbytes)
	## then number of directory entries
	fatbytes = fatfile.read(2)
	directoryentries = struct.unpack('<H', fatbytes)[0]
	## then sectors in logical volume. If this is 0 then it has special meaning
	fatbytes = fatfile.read(2)
	sectorsinlogicalvolume = struct.unpack('<H', fatbytes)[0]
	## then media descriptor type
	fatbytes = fatfile.read(1)
	mediadescriptortype = ord(fatbytes)
	## then sectors per FAT
	fatbytes = fatfile.read(2)
	sectorsperfat = struct.unpack('<H', fatbytes)[0]
	## then sectors per track
	fatbytes = fatfile.read(2)
	sectorspertrack = struct.unpack('<H', fatbytes)[0]
	## then number of heads
	fatbytes = fatfile.read(2)
	numberofheads = struct.unpack('<H', fatbytes)[0]

	if fattype == 'fat16':
		## then number of hidden sectors
		fatbytes = fatfile.read(4)
		hiddensectors = struct.unpack('<I', fatbytes)[0]
		if sectorsinlogicalvolume == 0:
			fatbytes = fatfile.read(4)
			totalnumberofsectors = struct.unpack('<I', fatbytes)[0]
		else:
			totalnumberofsectors = sectorsinlogicalvolume
	fatfile.close()
	totalsize = totalnumberofsectors * bytespersector
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, length=totalsize)
	return (tmpdir, totalsize)
'''

def searchUnpackMinix(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'minix' in offsets:
		return ([], blacklist, [], hints)
	if offsets['minix'] == []:
		return ([], blacklist, [], hints)
	## right now just allow file systems that are only Minix
	if not 0x410 in offsets['minix']:
		return ([], blacklist, [], hints)
	diroffsets = []
	counter = 1
	for offset in offsets['minix']:
		## according to /usr/share/magic the magic header starts at 0x410
		if offset < 0x410:
			continue
		## check if the offset we find is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "minix", counter)
		## we should actually scan the data starting from offset - 0x410
		res = unpackMinix(filename, offset - 0x410, tmpdir)
		if res != None:
			(minixtmpdir, minixsize) = res
			diroffsets.append((minixtmpdir, offset - 0x410, minixsize))
			blacklist.append((offset - 0x410, offset - 0x410 + minixsize))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

## Unpack an minix v1 file system using bat-minix. Needs hints for size of minix file system
def unpackMinix(filename, offset, tempdir=None, unpackenv={}, unpacktempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir)

	## create an extra temporary directory
	tmpdir2 = tempfile.mkdtemp(dir=unpacktempdir)

	p = subprocess.Popen(['bat-minix', '-i', tmpfile[1], '-o', tmpdir2], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		shutil.rmtree(tmpdir2)
		return None
	else:
		minixsize = int(stanout.strip())
	## then we move all the contents using shutil.move()
	mvfiles = os.listdir(tmpdir2)
	for f in mvfiles:
		shutil.move(os.path.join(tmpdir2, f), tmpdir)
	## then we cleanup the temporary dir
	shutil.rmtree(tmpdir2)
	os.unlink(tmpfile[1])
	return (tmpdir, minixsize)

## Search and unpack ext2/3/4
def searchUnpackExt2fs(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'ext2' in offsets:
		return ([], blacklist, [], hints)
	if offsets['ext2'] == []:
		return ([], blacklist, [], hints)
	datafile = open(filename, 'rb')
	diroffsets = []
	counter = 1

	## set path for Debian
	unpackenv = os.environ.copy()
	unpackenv['PATH'] = unpackenv['PATH'] + ":/sbin"

	filesize = os.stat(filename).st_size

	for offset in offsets['ext2']:
		## according to /usr/share/magic the magic header starts at 0x438
		if offset < 0x438:
			continue
		## check if the offset is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue

		## only revisions 0 and 1 have ever been made, so ignore the rest
		datafile.seek(offset - 0x438 + 0x44c)
		revision = datafile.read(1)
		if len(revision) < 1:
			continue
		if not (revision == '\x01' or revision == '\x00'):
			continue

		## for a quick sanity check only a tiny bit of data is needed.
		## Use tune2fs for this.
		datafile.seek(offset - 0x438)
		ext2checkdata = datafile.read(8192)
		if len(ext2checkdata) != 8192:
			continue

		tmpfile = tempfile.mkstemp()
		os.write(tmpfile[0], ext2checkdata)
		os.fdopen(tmpfile[0]).close()
		## perform a sanity check
		p = subprocess.Popen(['tune2fs', '-l', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=unpackenv)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.unlink(tmpfile[1])
			continue
		if len(stanerr) == 0:
			## grab the superblock, which starts at offset + 1024
			## the block count will be at bytes 4 - 8
			## the block size can be computed using the data at bytes 24 - 28
			## http://www.nongnu.org/ext2-doc/ext2.html
			blockcount = struct.unpack('<I', ext2checkdata[1028:1032])[0]
			blocksize = 1024 << struct.unpack('<I', ext2checkdata[1048:1052])[0]
			ext2checksize = blockcount * blocksize
		else:
			ext2checksize = 0
		os.unlink(tmpfile[1])

		## it doesn't make sense if the size of the file system is
		## larger than the actual file size
		if ext2checksize > filesize:
			continue

		## it also does not make sense if the declared size of the file system
		## extends beyond the file
		if ext2checksize + offset - 0x438 > filesize:
			continue

		tmpdir = dirsetup(tempdir, filename, "ext2", counter)
		res = unpackExt2fs(filename, offset - 0x438, ext2checksize, tmpdir, unpackenv=unpackenv, blacklist=blacklist)
		if res != None:
			(ext2tmpdir, ext2size) = res
			diroffsets.append((ext2tmpdir, offset - 0x438, ext2size))
			blacklist.append((offset - 0x438, offset - 0x438 + ext2size))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, [], hints)

## Unpack an ext2 file system using e2tools and some custom written code from BAT's own ext2 module
def unpackExt2fs(filename, offset, ext2length, tempdir=None, unpackenv={}, blacklist=[]):
	## first unpack things, write data to a file and return
	## the directory if the file is not empty
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir,length=ext2length, blacklist=blacklist)

	res = ext2.copyext2fs(tmpfile[1], tmpdir)
	if res == None:
		os.unlink(tmpfile[1])
		return

	## determine size, if ext2length is set to 0 (only Android sparse files),
	## else just return ext2length
	if ext2length == 0:
		p = subprocess.Popen(['tune2fs', '-l', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=unpackenv)
		(stanout, stanerr) = p.communicate()
		if p.returncode == 0:
			if len(stanerr) != 0:
				## do something here
				pass
			else:
				datafile = open(tmpfile[1], 'rb')
				datafile.seek(0)
				ext2checkdata = datafile.read(8192)
				## grab the superblock, which starts at offset + 1024
				## the block count will be at bytes 4 - 8
				## the block size can be computed using the data at bytes 24 - 28
				## http://www.nongnu.org/ext2-doc/ext2.html
				blockcount = struct.unpack('<I', ext2checkdata[1028:1032])[0]
				blocksize = 1024 << struct.unpack('<I', ext2checkdata[1048:1052])[0]
				ext2size = blockcount * blocksize
		else:
			## do something here
			pass
	else:
		ext2size = ext2length
	os.unlink(tmpfile[1])
	return (tmpdir, ext2size)

## Compute the CRC32 for gzip uncompressed data.
def gzipcrc32(filename):
	datafile = open(filename, 'rb')
	datafile.seek(0)
	databuffer = datafile.read(10000000)
	crc32 = binascii.crc32('')
	while databuffer != '':
		crc32 = binascii.crc32(databuffer, crc32)
		databuffer = datafile.read(10000000)
	datafile.close()
	crc32 = crc32 & 0xffffffff
	return crc32

def searchUnpackKnownGzip(filename, tempdir=None, scanenv={}, debug=False):
	## first check if the file actually could be a valid gzip file
	gzipfile = open(filename, 'rb')
	gzipfile.seek(0)
	gzipheader = gzipfile.read(3)
	gzipfile.close()
	if gzipheader != fsmagic.fsmagic['gzip']:
		return ([], [], [], {})

	## then try unpacking it.
	res = searchUnpackGzip(filename, tempdir, [], {'gzip': [0]}, scanenv, debug)
	(diroffsets, blacklist, newtags, hints) = res

	failed = False
	## there were results, so check if they were successful
	if diroffsets != []:
		if len(diroffsets) != 1:
			failed = True
		else:
			(dirpath, startoffset, endoffset) = diroffsets[0]
			if startoffset != 0 or endoffset != os.stat(filename).st_size:
				failed = True

		if failed:
			for i in diroffsets:
				(dirpath, startoffset, endoffset) = i
				try:
					shutil.rmtree(dirpath)
				except:
					pass
			return ([], [], [], {})
		else:
			return (diroffsets, blacklist, newtags, hints)
	return ([], [], [], {})

def searchUnpackGzip(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'gzip' in offsets:
		return ([], blacklist, [], hints)
	if offsets['gzip'] == []:
		return ([], blacklist, [], hints)

	newtags = []
	counter = 1
	diroffsets = []
	template = None
	if 'TEMPLATE' in scanenv:
		template = scanenv['TEMPLATE']
	for offset in offsets['gzip']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue

		## some sanity checks for gzip flags:
		## multi-part gzip (continuation) is not supported
		## encrypted files are not supported
		## flags 6 and 7 are reserved and should not be set
		## (see gzip.h in gzip sources and RFC 1952)
		## 1. check if "FEXTRA" is set. If so, don't continue searching for the name
		## 2. check if "FNAME" is set. If so, it follows immediately after MTIME
		## TODO: also process if FEXTRA is set
		gzipfile = open(filename)
		gzipfile.seek(offset+3)
		gzipbyte = gzipfile.read(1)
		gzipfile.close()
		hasnameset = False
		hascrc16 = False
		hascomment = False
		if (ord(gzipbyte) >> 1 & 1) == 1:
			hascrc16 = True
		if (ord(gzipbyte) >> 2 & 1) == 1:
			## continuation
			## TODO: extra fields, deal with this properly
			continue
		if (ord(gzipbyte) >> 3 & 1) == 1:
			hasnameset = True
		if (ord(gzipbyte) >> 4 & 1) == 1:
			hascomment = True
		if (ord(gzipbyte) >> 5 & 1) == 1:
			## encrypted
			continue
		if (ord(gzipbyte) >> 6 & 1) == 1:
			## reserved
			continue
		if (ord(gzipbyte) >> 7 & 1) == 1:
			## reserved
			continue

		gzipfile = open(filename)
		localoffset = offset+10
		renamename = None
		comment = None
		if hasnameset:
			renamename = ''
			gzipfile.seek(localoffset)
			gzipbyte = gzipfile.read(1)
			localoffset += 1
			while gzipbyte != '\0':
				renamename += gzipbyte
				gzipbyte = gzipfile.read(1)
				localoffset += 1
		if hascomment:
			comment = ''
			gzipfile.seek(localoffset)
			gzipbyte = gzipfile.read(1)
			localoffset += 1
			while gzipbyte != '\0':
				comment += gzipbyte
				gzipbyte = gzipfile.read(1)
				localoffset += 1
		if hascrc16:
			localoffset += 2
		gzipfile.seek(localoffset)
		compresseddataheader = gzipfile.read(1)

		## simple check for deflate
		bfinal = (ord(compresseddataheader) >> 0 & 1)
		btype1 = (ord(compresseddataheader) >> 1 & 1)
		btype2 = (ord(compresseddataheader) >> 2 & 1)
		if btype1 == 1 and btype2 == 1:
			## according to RFC 1951 this is an error
			gzipfile.close()
			continue

		## Because gzip is a header followed by deflate data it is
		## possible to do some sanity checking by first decompressing
		## some data.
		## try to uncompress raw deflate data, first one block of
		## a bit less than 10 meg
		## http://www.zlib.net/manual.html#Advanced
		gzipfile.seek(localoffset)
		readsize = 10000000
		deflatedata = gzipfile.read(readsize)
		deflateobj = zlib.decompressobj(-zlib.MAX_WBITS)
		deflatesize = 0
		try:
			uncompresseddata = deflateobj.decompress(deflatedata)
			## check if there is some uncompressed data left. For a completely
			## uncompressed ## file there should be some data left (8 bytes, namely
			## CRC32 and file size). If there is no data left, then it means that
			## decompression is not yet complete.
			if deflateobj.unused_data != "":
				deflatesize = len(deflatedata) - len(deflateobj.unused_data)
		except:
			gzipfile.close()
			continue

		tmpdir = dirsetup(tempdir, filename, "gzip", counter)
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		os.fdopen(tmpfile[0]).close()

		outgzipfile = open(tmpfile[1], 'wb')
		outgzipfile.write(uncompresseddata)
		outgzipfile.flush()
		## The size of the *raw* deflate data is gzipsize,
		## followed by the crc32 of the uncompresed data
		## and the size
		unpackfailure = False
		if deflatesize == 0:
			while deflateobj.unused_data == "":
				localoffset += readsize
				deflatedata = gzipfile.read(readsize)
				if deflatedata == '':
					break
				try:
					uncompresseddata = deflateobj.decompress(deflatedata)
					outgzipfile.write(uncompresseddata)
					outgzipfile.flush()
				except:
					## something weird is going on
					unpackfailure = True
					break
			deflatesize = len(deflatedata) - len(deflateobj.unused_data)
		deflateobj.flush()
		outgzipfile.close()

		if unpackfailure:
			gzipfile.close()
			os.unlink(tmpfile[1])
			os.rmdir(tmpdir)
			continue

		## The trailer of a valid gzip file is the CRC32 followed by file
		## size of uncompressed data
		crc32 = gzipcrc32(tmpfile[1])

		gzipfile.seek(localoffset + deflatesize)
		gzipcrc32andsize = gzipfile.read(8)

		if len(gzipcrc32andsize) != 8:
			gzipfile.close()
			os.unlink(tmpfile[1])
			os.rmdir(tmpdir)
			continue

		if gzipcrc32andsize[0:4] != struct.pack('<I', crc32):
			gzipfile.close()
			os.unlink(tmpfile[1])
			os.rmdir(tmpdir)
			continue
		filesize = os.stat(tmpfile[1]).st_size
		if gzipcrc32andsize[4:8] != struct.pack('<I', filesize):
			gzipfile.close()
			os.unlink(tmpfile[1])
			os.rmdir(tmpdir)
			continue

		## the size of the gzip data is the size of the deflate data,
		## plus 4 bytes for crc32 and 4 bytes for file size, plus
		## the gzip header.
		gzipsize = deflatesize + 8 + (localoffset - offset)
		diroffsets.append((tmpdir, offset, gzipsize))
		blacklist.append((offset, offset + gzipsize))
		counter = counter + 1
		if hasnameset and renamename != None:
			mvname = os.path.basename(renamename)
			if not os.path.exists(os.path.join(tmpdir, mvname)):
				try:
					shutil.move(tmpfile[1], os.path.join(tmpdir, mvname))
				except Exception, e:
					## if there is an exception don't rename
					pass
		if offset == 0 and (gzipsize == os.stat(filename).st_size):
			## if the gzip file is the entire file, then tag it
			## as a compressed file and as gzip. Also check if the
			## file might be a tar file and pass that as a hint
			## to downstream unpackers.
			newtags.append('compressed')
			newtags.append('gzip')

			## if the file has not been renamed already try to see
			## if it needs to be renamed.
			if not(hasnameset and renamename != None):
				## rename the file, like gunzip does
				if filename.lower().endswith('.gz'):
					filenamenoext = os.path.basename(filename)[:-3]
					if len(filenamenoext) > 0:
						gzpath = os.path.join(tmpdir, filenamenoext)
						if not os.path.exists(gzpath):
							shutil.move(tmpfile[1], gzpath)
				elif filename.lower().endswith('.tgz'):
					filenamenoext = os.path.basename(filename)[:-4] + ".tar"
					if len(filenamenoext) > 4:
						gzpath = os.path.join(tmpdir, filenamenoext)
						if not os.path.exists(gzpath):
							shutil.move(tmpfile[1], gzpath)
		gzipfile.close()

	return (diroffsets, blacklist, newtags, hints)

def searchUnpackCompress(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'compress' in offsets:
		return ([], blacklist, [], hints)
	if offsets['compress'] == []:
		return ([], blacklist, [], hints)

	compresslimit = int(scanenv.get('COMPRESS_MINIMUM_SIZE', 1))
	compress_tmpdir = scanenv.get('UNPACK_TEMPDIR', None)

	counter = 1
	diroffsets = []
	for offset in offsets['compress']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## according to the specification the "bits per code" has
		## to be 9 <= bits per code <= 16
		## The "bits per code" field is masked with 0x1f
		compressfile = open(filename, 'rb')
		compressfile.seek(offset+2)
		compressdata = compressfile.read(1)
		compressfile.close()
		if len(compressdata) != 1:
			break
		compressbits = ord(compressdata) & 0x1f
		if compressbits < 9:
			continue
		if compressbits > 16:
			continue

		## since compress expects a stream it will decompress some
		## data, so as a first test read 1 MiB of data and then
		## try to decompress it.
		## If no data could be impressed
		compressfile = open(filename, 'rb')
		compressfile.seek(offset)
		compressdata = compressfile.read(1048576)
		compressfile.close()

		p = subprocess.Popen(['uncompress'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate(compressdata)
		if len(stanout) == 0:
			continue

		tmpdir = dirsetup(tempdir, filename, "compress", counter)
		res = unpackCompress(filename, offset, compresslimit, tmpdir, compress_tmpdir, blacklist)
		if res != None:
			## TODO: find out how to find the length of the compressed
			## data that was uncompressed so the right offsets for the
			## blacklist can be computed
			compresssize = 0
			diroffsets.append((res, offset, compresssize))
			#blacklist.append((offset, offset + compresssize))
			counter = counter + 1
			if offset == 0 and compresssize == os.stat(filename).st_size:
				newtags.append('compressed')
				newtags.append('compress')
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

def unpackCompress(filename, offset, compresslimit, tempdir=None, compress_tmpdir=None, blacklist=[]):
	tmpdir = unpacksetup(tempdir)

	## if UNPACK_TEMPDIR is set to for example a ramdisk use that instead.
	if compress_tmpdir != None:
		tmpfile = tempfile.mkstemp(dir=compress_tmpdir)
		os.fdopen(tmpfile[0]).close()
		outtmpfile = tempfile.mkstemp(dir=compress_tmpdir)
		unpackFile(filename, offset, tmpfile[1], compress_tmpdir, blacklist=blacklist)
	else:
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		os.fdopen(tmpfile[0]).close()
		outtmpfile = tempfile.mkstemp(dir=tmpdir)
		unpackFile(filename, offset, tmpfile[1], tmpdir, blacklist=blacklist)

	p = subprocess.Popen(['uncompress', '-c', tmpfile[1]], stdout=outtmpfile[0], stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	os.fdopen(outtmpfile[0]).close()
	os.unlink(tmpfile[1])
	if os.stat(outtmpfile[1]).st_size < compresslimit:
		os.unlink(outtmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	if compress_tmpdir != None:
		## create the directory and move the compressed file
		try:
			os.makedirs(tmpdir)
		except OSError, e:
			pass
		shutil.move(outtmpfile[1], tmpdir)
	return tmpdir

def searchUnpackKnownBzip2(filename, tempdir=None, scanenv={}, debug=False):
	## first check if the file actually could be a valid gzip file
	bzip2file = open(filename, 'rb')
	bzip2file.seek(0)
	bzip2header = bzip2file.read(3)
	bzip2file.close()
	if bzip2header != fsmagic.fsmagic['bz2']:
		return ([], [], [], {})

	## then try unpacking it.
	res = searchUnpackBzip2(filename, tempdir, [], {'bz2': [0]}, scanenv, debug)
	(diroffsets, blacklist, newtags, hints) = res

	failed = False
	## there were results, so check if they were successful
	if diroffsets != []:
		if len(diroffsets) != 1:
			failed = True
		else:
			(dirpath, startoffset, endoffset) = diroffsets[0]
			if startoffset != 0 or endoffset != os.stat(filename).st_size:
				failed = True

		if failed:
			for i in diroffsets:
				(dirpath, startoffset, endoffset) = i
				try:
					shutil.rmtree(dirpath)
				except:
					pass
			return ([], [], [], {})
		else:
			return (diroffsets, blacklist, newtags, hints)
	return ([], [], [], {})

## search and unpack bzip2 compressed files
def searchUnpackBzip2(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'bz2' in offsets:
		return ([], blacklist, [], hints)
	if offsets['bz2'] == []:
		return ([], blacklist, [], hints)

	diroffsets = []
	counter = 1
	newtags = []
	bzip2datasize = 10000000
	for offset in offsets['bz2']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## sanity check: block size is byte number 4 in the header
		bzfile = open(filename, 'rb')
		bzfile.seek(offset + 3)
		blocksizebyte = bzfile.read(1)
		bzfile.close()
		try:
			blocksizebyte = int(blocksizebyte)
		except:
			continue
		if blocksizebyte == 0:
			continue

		## some more sanity checks based on bzip2's decompress.c
		bzfile = open(filename, 'rb')
		bzfile.seek(offset + 4)
		blockbytes = bzfile.read(6)
		bzfile.close()

		## first check if this is a stream or a regular file
		if blockbytes[0] != '\x17':
			## not a stream, so do some more checks
			if blockbytes[0] != '\x31':
				continue
			if blockbytes[1] != '\x41':
				continue
			if blockbytes[2] != '\x59':
				continue
			if blockbytes[3] != '\x26':
				continue
			if blockbytes[4] != '\x53':
				continue
			if blockbytes[5] != '\x59':
				continue

		## extra sanity check: try to uncompress a few blocks of data
		bzfile = open(filename, 'rb')
		bzfile.seek(offset)
		bzip2data = bzfile.read(bzip2datasize)
		bzfile.close()
		bzip2decompressobj = bz2.BZ2Decompressor()
		bzip2size = 0
		try:
			uncompresseddata = bzip2decompressobj.decompress(bzip2data)
		except Exception, e:
			continue
		if bzip2decompressobj.unused_data != "":
			bzip2size = len(bzip2data) - len(bzip2decompressobj.unused_data)
		else:
			if len(uncompresseddata) != 0:
				if len(bzip2data) == os.stat(filename).st_size:
					bzip2size = len(bzip2data)

		tmpdir = dirsetup(tempdir, filename, "bzip2", counter)
		if bzip2size != 0:
			tmpfile = tempfile.mkstemp(dir=tmpdir)
			os.fdopen(tmpfile[0]).close()

			outbzip2file = open(tmpfile[1], 'wb')
			outbzip2file.write(uncompresseddata)
			outbzip2file.flush()
			outbzip2file.close()
			diroffsets.append((tmpdir, offset, bzip2size))
			blacklist.append((offset, offset + bzip2size))
			if offset == 0 and (bzip2size == os.stat(filename).st_size):
				## rename the file, like bunzip does
				if filename.lower().endswith('.bz2'):
					filenamenoext = os.path.basename(filename)[:-4]
					if len(filenamenoext) > 0:
						bz2path = os.path.join(tmpdir, filenamenoext)
						if not os.path.exists(bz2path):
							shutil.move(tmpfile[1], bz2path)
				## slightly different for tbz2
				elif filename.lower().endswith('.tbz2'):
					filenamenoext = os.path.basename(filename)[:-5] + ".tar"
					if len(filenamenoext) > 4:
						bz2path = os.path.join(tmpdir, filenamenoext)
						if not os.path.exists(bz2path):
							shutil.move(tmpfile[1], bz2path)
				newtags.append('compressed')
				newtags.append('bzip2')
			counter = counter + 1
		else:
			## try to load more data into the bzip2 decompression object
			localoffset = offset + bzip2datasize
			bzfile = open(filename, 'rb')
			bzfile.seek(localoffset)
			bzip2data = bzfile.read(bzip2datasize)
			unpackingerror = False
			bytesread = bzip2datasize
			unpackedbytessize = len(uncompresseddata)

			tmpfile = tempfile.mkstemp(dir=tmpdir)
			os.fdopen(tmpfile[0]).close()

			outbzip2file = open(tmpfile[1], 'wb')
			outbzip2file.write(uncompresseddata)
			outbzip2file.flush()
			while bzip2data != "":
				try:
					uncompresseddata = bzip2decompressobj.decompress(bzip2data)
					outbzip2file.write(uncompresseddata)
					outbzip2file.flush()
					unpackedbytessize += len(uncompresseddata)
				except Exception, e:
					unpackingerror = True
					break

				## end of the bzip2 compressed data is reached
				if bzip2decompressobj.unused_data != "":
					bytesread += len(bzip2data) - len(bzip2decompressobj.unused_data)
					break
				bytesread += len(bzip2data)
				bzip2data = bzfile.read(bzip2datasize)
			bzfile.close()
			outbzip2file.close()
			if unpackingerror:
				## cleanup
				os.unlink(tmpfile[1])
				os.rmdir(tmpdir)
			if unpackedbytessize != 0:
				diroffsets.append((tmpdir, offset, bytesread))
				blacklist.append((offset, offset + bytesread))
				if offset == 0 and (bytesread == os.stat(filename).st_size):
					## rename the file, like bunzip does
					if filename.lower().endswith('.bz2'):
						filenamenoext = os.path.basename(filename)[:-4]
						bz2path = os.path.join(tmpdir, filenamenoext)
						if not os.path.exists(bz2path):
							shutil.move(tmpfile[1], bz2path)
					## slightly different for tbz2
					elif filename.lower().endswith('.tbz2'):
						filenamenoext = os.path.basename(filename)[:-5] + ".tar"
						bz2path = os.path.join(tmpdir, filenamenoext)
						if not os.path.exists(bz2path):
							shutil.move(tmpfile[1], bz2path)
					newtags.append('compressed')
					newtags.append('bzip2')
				counter = counter + 1
			else:
				## cleanup
				os.unlink(tmpfile[1])
				os.rmdir(tmpdir)
	return (diroffsets, blacklist, newtags, hints)

def searchUnpackRZIP(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'rzip' in offsets:
		return ([], blacklist, [], hints)
	if offsets['rzip'] == []:
		return ([], blacklist, [], hints)
	if offsets['rzip'][0] != 0:
		return ([], blacklist, [], hints)
	if os.stat(filename).st_size < 10:
		return ([], blacklist, [], hints)
	diroffsets = []
	tags = []
	offset = 0

	rzipfile = open(filename, 'rb')
	rzipfile.seek(0)
	rzipdata = rzipfile.read(10)
	rzipfile.close()

	rzipsize = struct.unpack('>L', rzipdata[6:10])[0]

	blacklistoffset = extractor.inblacklist(offset, blacklist)
	if blacklistoffset != None:
		return (diroffsets, blacklist, tags, hints)

	tmpdir = dirsetup(tempdir, filename, "rzip", 1)
	res = unpackRZIP(filename, offset, rzipsize, tmpdir)
	if res != None:
		rzipdir = res
		diroffsets.append((rzipdir, offset, 0))
		#blacklist.append((offset, offset + unpackrzipsize))
		#if offset == 0:
		#	tags.append("compressed")
		#	tags.append("rzip")
	else:
		## cleanup
		os.rmdir(tmpdir)

	return (diroffsets, blacklist, tags, hints)

def unpackRZIP(filename, offset, rzipsize, tempdir=None):
	tmpdir = unpacksetup(tempdir)

	tmpfile = tempfile.mkstemp(dir=tempdir, suffix='.rz')
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir)

	p = subprocess.Popen(['rzip', '-d', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		return None
	if os.stat(tmpfile[1][:-3]).st_size == rzipsize:
		return tmpdir
	else:
		os.unlink(tmpfile[1][:-3])
		return None
	
def searchUnpackAndroidSparse(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'android-sparse' in offsets:
		return ([], blacklist, [], hints)
	if offsets['android-sparse'] == []:
		return ([], blacklist, [], hints)

	diroffsets = []
	counter = 1
	tags = []
	for offset in offsets['android-sparse']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## first see if the major version is correct
		sparsefile = open(filename)
		sparsefile.seek(offset+4)
		sparsedata = sparsefile.read(2)
		sparsefile.close()
		majorversion = struct.unpack('<H', sparsedata)[0]
		if not majorversion == 1:
			continue

		tmpdir = dirsetup(tempdir, filename, "android-sparse", counter)
		res = unpackAndroidSparse(filename, offset, tmpdir)
		if res != None:
			(sparsesize, sparsedir) = res
			diroffsets.append((sparsedir, offset, sparsesize))

			blacklist.append((offset, offset + sparsesize))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, tags, hints)

def unpackAndroidSparse(filename, offset, tempdir=None):
	## checks to find the right size
	## First check the size of the header. If it has some
	## bizarre value (like bigger than the file it can unpack)
	## it is not a valid android sparse file file system
	sparsefile = open(filename, 'rb')
	sparsefile.seek(offset)
	sparsedata = sparsefile.read(28)
	sparsefile.close()

	## from sparse_format.h, everything little endian
	## 0 - 3 : magic
	## 4 - 5 : major version
	## 6 - 7 : minor version
	## 8 - 9 : file header size
	## 10 - 11: chunk header size (should be 12 bytes)
	## 12 - 15: block size
	## 16 - 19: total blocks in original image
	## 20 - 23: total chunks
	## 24 - 27: CRC checksum
	blocksize = struct.unpack('<L', sparsedata[12:16])[0]
	chunkcount = struct.unpack('<L', sparsedata[20:24])[0]

	## now reopen the file and read each chunk header.
	sparsefile = open(filename, 'rb')

	## keep a counter to see how many bytes were read. After unpacking
	## this will indicate the size of the sparse file
	seekctr = offset + 28
	for i in xrange(0,chunkcount):
		sparsefile.seek(seekctr)
		## read the chunk header
		sparsedata = sparsefile.read(12)
		## 0 - 1 : chunk type
		## 2 - 3 : unused
		## 4 - 7 : chunk size (for raw)
		## 8 - 12 : total size
		chunktype = sparsedata[0:2]
		if chunktype == '\xc1\xca':
			## RAW
			chunksize = struct.unpack('<L', sparsedata[4:8])[0]
			datasize = chunksize * blocksize
		elif chunktype == '\xc2\xca':
			## FILL
			datasize = 4
		elif chunktype == '\xc3\xca':
			## DON'T CARE
			datasize = 0
		elif chunktype == '\xc4\xca':
			## CRC
			datasize = 4
		else:
			## dunno what's happening here, so exit
			sparsefile.close()
			return None
		seekctr = seekctr + 12 + datasize
	sparsefile.close()

	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, length=seekctr)

	## write the data out to a temporary file
	outtmpfile = tempfile.mkstemp(dir=tempdir)
	os.fdopen(outtmpfile[0]).close()

	p = subprocess.Popen(['bat-simg2img', tmpfile[1], outtmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(outtmpfile[1])
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None

	os.unlink(tmpfile[1])

	## sanity check first, some vendors add another header with a signature
	datafile = open(outtmpfile[1], 'rb')
	datafile.seek(0x438)
	databuffer = datafile.read(2)
	datafile.close()

	if databuffer != fsmagic.fsmagic['ext2']:
		## no expected marker found
		ext2offsets = prerun.genericMarkerSearch(outtmpfile[1], ['ext2'], [])['ext2']
	else:
		ext2offsets = [0]

	## set path for Debian
	unpackenv = os.environ.copy()
	unpackenv['PATH'] = unpackenv['PATH'] + ":/sbin"

	## walk the offsets that can be found. TODO: many more sanity checks in case
	## there are multiple ext4 file systems hidden in the Android sparse file system
	for ext2offset in ext2offsets:
		ext2checksize = 0
		res = unpackExt2fs(outtmpfile[1], ext2offset - 0x438, ext2checksize, tmpdir, unpackenv=unpackenv)
		if res == None:
			## TODO: more sanity checks
			os.unlink(outtmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None
		break
	os.unlink(outtmpfile[1])
	return (seekctr, tmpdir)

def searchUnpackLRZIP(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'lrzip' in offsets:
		return ([], blacklist, [], hints)
	if offsets['lrzip'] == []:
		return ([], blacklist, [], hints)

	diroffsets = []
	counter = 1
	tags = []
	lrzipmajorversions = [0]
	lrzipminorversions = [0,1,2,3,4,5,6,7,8]

	filesize = os.stat(filename).st_size

	for offset in offsets['lrzip']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue

		## read the lrzip header, which is 24 bytes
		## https://github.com/ckolivas/lrzip/blob/master/doc/magic.header.txt
		lrzipfile = open(filename, 'rb')
		lrzipfile.seek(offset)
		lrzipheader = lrzipfile.read(24)
		lrzipfile.close()

		lrzipversionbytes = lrzipheader[4:6]
		lrzipmajorversion = ord(lrzipversionbytes[0])
		if lrzipmajorversion not in lrzipmajorversions:
			continue
		lrzipminorversion = ord(lrzipversionbytes[1])
		if lrzipminorversion not in lrzipminorversions:
			continue

		## read the uncompressed size from the header
		lrzipsize = struct.unpack('<Q', lrzipheader[6:14])[0]
		if lrzipsize == 0:
			continue
		encrypted = False
		hasmd5 = False
		if lrzipminorversion == 6:
			if lrzipheader[-3] == '\x01':
				hasmd5 = True
			if lrzipheader[-2] == '\x01':
				encrypted = True
				continue
		if lrzipminorversion == 5:
			if lrzipheader[-3] == '\x01':
				hasmd5 = True

		lrzipmd5 = None
		if hasmd5:
			lrzipfile = open(filename, 'rb')
			lrzipfile.seek(-16, os.SEEK_END)
			lrzipmd5bytes = lrzipfile.read(16)
			lrzipfile.close()
			lrzipmd5 = lrzipmd5bytes.encode('hex')

		tmpdir = dirsetup(tempdir, filename, "lrzip", counter)
		res = unpackLRZIP(filename, offset, hasmd5, lrzipmd5, lrzipsize, tmpdir)
		if res != None:
			(lrzipdir, md5match, endoflrzip) = res
			diroffsets.append((lrzipdir, offset, endoflrzip))
			blacklist.append((offset, offset + endoflrzip))
			counter = counter + 1
			if offset == 0 and md5match and endoflrzip == filesize:
				tags.append("compressed")
				tags.append("lrzip")
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, tags, hints)

def unpackLRZIP(filename, offset, hasmd5, lrzipmd5, lrzipsize, tempdir=None):
	tmpdir = unpacksetup(tempdir)

	tmpfile = tempfile.mkstemp(dir=tempdir)
	os.fdopen(tmpfile[0]).close()

	outtmpfile = tempfile.mkstemp(dir=tempdir)

	unpackFile(filename, offset, tmpfile[1], tmpdir)

	p = subprocess.Popen(['lrzcat', tmpfile[1]], stdout=outtmpfile[0], stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	os.fsync(outtmpfile[0])
	os.fdopen(outtmpfile[0]).close()
	if p.returncode != 0:
		## depending on the output of lrzcat it might still be
		## valid data, that might be followed by other data
		unpackedfilesize = os.stat(outtmpfile[1]).st_size

		if not unpackedfilesize == lrzipsize:
			## if lrzip failed it might have left some things behind and
			## removed the original file, so remove any droppings
			os.unlink(outtmpfile[1])
			rmfiles = os.listdir(tmpdir)
			if rmfiles != []:
				for rmfile in rmfiles:
					os.unlink(os.path.join(tmpdir, rmfile))
			if os.path.exists(tmpfile[1]):
				os.unlink(tmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None
		h = hashlib.new('md5')
		lrzipfile = open(outtmpfile[1], 'rb')
		h.update(lrzipfile.read())
		lrzipfile.close()

		tmpmd5 = h.hexdigest()
		searchmd5 = tmpmd5.decode('hex')
		## now open the file to see if the md5 sum can be
		## found somewhere in it and then test it again
		lrzipfile = open(filename, 'rb')
		lrzipfile.seek(offset)
		## read 1 million bytes
		lrzipdataread = 1000000
		lrzipbytes = lrzipfile.read(lrzipdataread)
		lrzipmd5offset = 0
		totalread = lrzipdataread
		lrzdata = ''
		while lrzipbytes != '':
			lrzdata += lrzipbytes
			res = lrzdata.find(searchmd5, lrzipmd5offset)
			if res != -1:
				p = subprocess.Popen(['lrzcat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate(lrzdata[:res+16])
				if p.returncode != 0:
					continue
				md5match = True
				endoflrzip = offset + res + 16
				lrzipfile.close()
				return (tmpdir, md5match, endoflrzip)
			lrzipbytes = lrzipfile.read(lrzipdataread)
			lrzipmd5offset = totalread - 50
			totalread += lrzipdataread
		lrzipfile.close()
		if res == -1:
			return None
		p = subprocess.Popen(['lrzcat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate(lrzipbytes[:res+16])
		if p.returncode != 0:
			return
		md5match = True
		endoflrzip = offset + res + 16
		return (tmpdir, md5match, endoflrzip)

	## The result of lrzip is a single file (never multiple files)
	## If an empty file was unpacked it is a false positive.
	unpackedfilesize = os.stat(outtmpfile[1]).st_size
	if unpackedfilesize == 0:
		os.unlink(outtmpfile[1])
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None

	## If it is a valid lrzip file, then the file size should match
	## if not, it is a false positive
	if not unpackedfilesize == lrzipsize:
		return None

	h = hashlib.new('md5')
	lrzipfile = open(outtmpfile[1], 'rb')
	h.update(lrzipfile.read())
	lrzipfile.close()

	md5match = False
	if h.hexdigest() == lrzipmd5:
		md5match = True

	return (tmpdir, md5match, os.stat(filename).st_size)

def unpackZip(filename, offset, cutoff, endofcentraldir, commentsize, memorycutoff, tempdir=None):
	filesize = os.stat(filename).st_size

	inmemory = False
	havetmpfile = False
	if offset != 0 or cutoff != filesize:
		inmemory = True

	tmpdir = unpacksetup(tempdir)

	ziplen = cutoff - offset
	## process everything in memory if the size of the ZIP file is below
	## a certain threshold and is not a complete ZIP file (in which case
	## using 'unzip' might be faster).
	if not inmemory:
		memfile = filename
	else:
		if ziplen < memorycutoff:
			openzipfile = open(filename, 'rb')
			openzipfile.seek(offset)
			zipdata = openzipfile.read(ziplen)
			openzipfile.close()
			memfile = StringIO.StringIO(zipdata)
		else:
			tmpfile = tempfile.mkstemp(dir=tempdir)
			os.fdopen(tmpfile[0]).close()

			if cutoff != 0:
				unpackFile(filename, offset, tmpfile[1], tmpdir, length=ziplen)
			else:
				unpackFile(filename, offset, tmpfile[1], tmpdir)
			havetmpfile = True
			memfile = tmpfile[1]
	try:
		memzipfile = zipfile.ZipFile(memfile, 'r')
		infolist = memzipfile.infolist()
		## first check whether or not the file can be unpacked. There are situations
		## where ZIP files are packed in a weird format that unzip does not like:
		## https://bugzilla.redhat.com/show_bug.cgi?id=907442
		## Also check if the file contains encrypted entries.
		weirdzip = False
		weirdzipnames = set()
		for i in infolist:
			if i.file_size == 0:
				if not i.filename.endswith('/'):
					if filter(lambda x: x.filename.startswith(i.filename) and not x.filename == i.filename, infolist) != []:
						weirdzip = True
						weirdzipnames.add(i.filename)
			if i.flag_bits & 0x01 == 1:
				## data is encrypted
				memzipfile.close()
				if inmemory:
					if not havetmpfile:
						memfile.close()
					if not havetmpfile:
						## write out the data if it is not already there
						tmpdir = unpacksetup(tempdir)
						tmpfile = tempfile.mkstemp(dir=tempdir)
						os.fdopen(tmpfile[0]).close()

						datafile = open(tmpfile[1], 'wb')
						datafile.write(zipdata)
						datafile.close()

				return (tmpdir, ['encrypted'])
		if not havetmpfile:
			tmpdir = unpacksetup(tempdir)
		for i in infolist:
			if weirdzip and i.filename in weirdzipnames:
				os.mkdir(os.path.join(tmpdir, i.filename))
			else:
				memzipfile.extract(i, tmpdir)
		memzipfile.close()
		if havetmpfile:
			os.unlink(tmpfile[1])
	except Exception, e:
		if inmemory:
			if havetmpfile:
				os.unlink(tmpfile[1])
			else:
				memfile.close()
		for i in os.listdir(tmpdir):
			try:
				os.unlink(os.path.join(tmpdir, i))
				continue
			except:
				shutil.rmtree(os.path.join(tmpdir, i))
		return (None, [])
	if inmemory:
		if not havetmpfile:
			memfile.close()
	return (tmpdir, [])

def searchUnpackKnownZip(filename, tempdir=None, scanenv={}, debug=False):
	datafile = open(filename, 'rb')
	databuffer = datafile.read(4)
	datafile.close()
	if databuffer != fsmagic.fsmagic['zip']:
		return ([], [], [], {})
	filesize = os.stat(filename).st_size

	## try to find an end of central dir. A ZIP file comment can be 65535
	## characters long, so at maximum 65535 + 22 characters should be read,
	## perhaps a few more just in case
	datafile = open(filename, 'rb')
	datafile.seek(max(0,min(filesize, filesize-(65535+30))))
	offset = datafile.tell()
	databuffer = datafile.read()
	datafile.close()
	zipend = databuffer.find(fsmagic.fsmagic['zipend']) + offset
	if zipend == -1:
		return ([], [], [], {})
	## then try unpacking it.
	res = searchUnpackZip(filename, tempdir, [], {'zip': [0], 'zipend': [zipend]}, scanenv, debug)
	(diroffsets, blacklist, newtags, hints) = res

	failed = False
	## there were results, so check if they were successful
	if diroffsets != []:
		if len(diroffsets) != 1:
			failed = True
		else:
			(dirpath, startoffset, endoffset) = diroffsets[0]
			if startoffset != 0 or endoffset != filesize:
				failed = True
		if failed:
			for i in diroffsets:
				(dirpath, startoffset, endoffset) = i
				try:
					shutil.rmtree(dirpath)
				except:
					pass
			return ([], [], [], {})
		else:
			return (diroffsets, blacklist, newtags, hints)
	else:
		if 'encrypted' in newtags:
			return (diroffsets, blacklist, newtags, hints)
	return ([], [], [], {})

## Carve and unpack ZIP files
def searchUnpackZip(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'zip' in offsets:
		return ([], blacklist, [], hints)
	if not 'zipend' in offsets:
		return ([], blacklist, [], hints)
	tags = []
	if offsets['zip'] == []:
		return ([], blacklist, tags, hints)
	if offsets['zipend'] == []:
		return ([], blacklist, tags, hints)
	diroffsets = []
	counter = 1
	filesize = os.stat(filename).st_size

	## read the parameter for the maximum file size that should be read into
	## memory from the configuration. Default: 50 million bytes.
	try:
		memorycutoff = int(scanenv.get('ZIP_MEMORY_CUTOFF', 50000000))
	except:
		memorycutoff = 50000000
	zipfile = open(filename, 'rb')

	zipends = []
	## first check all the potential end of central dir offsets in the file and filter
	## out the bogus ones
	for zipendindex in xrange(0, len(offsets['zipend'])):
		zipend = offsets['zipend'][zipendindex]
		blacklistoffset = extractor.inblacklist(zipend, blacklist)
		if blacklistoffset != None:
			continue

		## first check a few things in the ZIP file, as they have to make sense
		zipfile.seek(zipend+4)
		numberofthisdisk = struct.unpack('<H', zipfile.read(2))[0]
		diskwithcentraldirectory = struct.unpack('<H', zipfile.read(2))[0]
		entriesincentraldirectorythisdisk = struct.unpack('<H', zipfile.read(2))[0]
		entriesincentraldirectory = struct.unpack('<H', zipfile.read(2))[0]

		## the size of the central directory entries. This cannot be larger than
		## the file itself
		sizeofcentraldirectory = struct.unpack('<I', zipfile.read(4))[0]
		if sizeofcentraldirectory > filesize:
			continue

		## the start of the central directory entries in the ZIP file (relative
		## to the start of the file)
		offsetofcentraldirectory = struct.unpack('<I', zipfile.read(4))[0]

		## These cannot be outside of the file (relative)
		if offsetofcentraldirectory > filesize:
			continue
		## central directory (relative) cannot follow end of central directory
		if offsetofcentraldirectory > zipend:
			continue

		## check if there is any ZIP file comment
		zipfile.seek(zipend + 20)
		commentdata = zipfile.read(2)
		commentsize = struct.unpack('<H', commentdata)[0]

		## comment cannot extend beyond the file
		if zipend + 22 + commentsize > filesize:
			continue

		cutoff = zipend + 22 + commentsize
		zipends.append((zipend, cutoff, offsetofcentraldirectory))

	## then walk all the ZIP offsets and see if anything can be unpacked
	for offset in offsets['zip']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## some more sanity checks
		zipfile.seek(offset+4)
		versionneededbytes = zipfile.read(2)
		versionneeded = struct.unpack('<H', versionneededbytes)[0]

		## https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
		## section 4.4.3.2
		## According to the specification this can go up to 62 right now
		if versionneeded > 100 or versionneeded < 10:
			continue

		## extra sanity checks: read the name of the first local file header
		## and match it with the name of the first entry of the central
		## directory.
		zipfile.seek(offset+26)
		namesize = struct.unpack('<H', zipfile.read(2))[0]
		zipfile.seek(offset+30)
		firstfilename = zipfile.read(namesize)

		for z in zipends:
			(zipend, cutoff, offsetofcentraldirectory) = z
			if offset > zipend:
				continue

			blacklistoffset = extractor.inblacklist(zipend, blacklist)
			if blacklistoffset != None:
				## continue to the next offset as this data cannot be
				## part of the ZIP file
				break

			## central directory (absolute) cannot be more than the filesize
			if offset + offsetofcentraldirectory > filesize:
				continue
			## central directory (absolute) cannot follow end of central directory
			if offset + offsetofcentraldirectory > zipend:
				continue

			## sanity check: the central directory entry should be valid
			zipfile.seek(offset+offsetofcentraldirectory)
			centraldirheader = zipfile.read(4)
			if centraldirheader != "PK\x01\x02":
				continue

			## the name of the first entry in the central directory should match
			## the name of the first entry in the local file header
			zipfile.seek(offset+offsetofcentraldirectory+28)
			filenamelengthdir = struct.unpack('<H', zipfile.read(2))[0]
			zipfile.seek(offset+offsetofcentraldirectory+46)
			if not firstfilename == zipfile.read(filenamelengthdir):
				continue

			## relative offset: assume it is 0 but not sure if this is
			## correct. TODO: find out and if needed fix.
			zipfile.seek(offset+offsetofcentraldirectory+42)
			reloffset = struct.unpack('<I', zipfile.read(4))[0]
			if reloffset != 0:
				continue

			tmpdir = dirsetup(tempdir, filename, "zip", counter)
			endofcentraldir = zipend - offset
			(res, tmptags) = unpackZip(filename, offset, cutoff, endofcentraldir, commentsize, memorycutoff, tmpdir)
			if res != None:
				blacklist.append((offset, zipend + 22 + commentsize))
				if offset == 0 and zipend + commentsize + 22 == filesize:
					tags.append('zip')
					tags.append('compressed')
					if 'encrypted' in tmptags:
						tags.append('encrypted')
						os.rmdir(tmpdir)
					else:
						diroffsets.append((res, offset, (zipend - offset) + commentsize + 22))
					break
				diroffsets.append((res, offset, (zipend - offset) + commentsize + 22))
				if 'encrypted' in tmptags:
					tmpfilename = os.path.join(res, os.listdir(res)[0])
					hints[tmpfilename] = {}
					hints[tmpfilename]['tags'] = ['zip', 'encrypted']
				counter = counter + 1

				## move to next offset
				break
			else:
				os.rmdir(tmpdir)
	zipfile.close()
	return (diroffsets, blacklist, tags, hints)

def searchUnpackPack200(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'pack200' in offsets:
		return ([], blacklist, [], hints)
	tags = []
	diroffsets = []
	if offsets['pack200'] == []:
		return ([], blacklist, tags, hints)
	if len(offsets['pack200']) != 1:
		return ([], blacklist, tags, hints)
	if offsets['pack200'][0] != 0:
		return ([], blacklist, tags, hints)
	if blacklist != []:
		return ([], blacklist, tags, hints)
	tmpdir = dirsetup(tempdir, filename, "pack200", 1)
	res = unpackPack200(filename, tmpdir)
	if res != None:
		filesize = os.stat(filename).st_size
		diroffsets.append((res, 0, filesize))
		blacklist.append((0, filesize))
	else:
		## cleanup
		os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

def unpackPack200(filename, tempdir=None):
	tmpdir = unpacksetup(tempdir)

	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, 0, tmpfile[1], tmpdir)

	packtmpfile = tempfile.mkstemp(dir=tmpdir, suffix=".jar")
	os.fdopen(packtmpfile[0]).close()

	p = subprocess.Popen(['unpack200', tmpfile[1], packtmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		os.unlink(packtmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.unlink(tmpfile[1])
	return tmpdir

def searchUnpackRar(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'rar' in offsets:
		return ([], blacklist, [], hints)
	if offsets['rar'] == []:
		return ([], blacklist, [], hints)
	havefooter = False
	if 'rarfooter' in offsets:
		if offsets['rarfooter'] != []:
			havefooter = True
	diroffsets = []
	counter = 1
	for offset in offsets['rar']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "rar", counter)
		res = unpackRar(filename, offset, tmpdir)
		## TODO: verify endofarchive and use it for blacklisting
		if res != None:
			(endofarchive, rardir) = res
			diroffsets.append((rardir, offset, 0))
			blacklist.append((offset, endofarchive))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

def unpackRar(filename, offset, tempdir=None):
	## according to various sites the marker header is
	## followed by an archive header, of which the block type is 0x73
	## http://forensicswiki.org/wiki/RAR
	## http://acritum.com/winrar/rar-format

	rarfile = open(filename, 'rb')
	rarfile.seek(offset)

	## TODO: for now assume version is 4 or lower, but fix for RAR 5
	rarbytes = rarfile.read(10)
	rarfile.close()
	if rarbytes[-1] != '\x73':
		return

	## Assumes (for now) that unrar is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir)

	# inspect the rar archive, and retrieve the end of archive
	# this way we won't waste too many resources when we don't need to
	## TODO: unrar needs vvt now to work correctly?
	p = subprocess.Popen(['unrar', 'vvt', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	#p = subprocess.Popen(['unrar', 'vt', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	rarstring = stanout.strip().split("\n")[-1]
	res = re.search("\s*\d+\s*\d+\s+(\d+)\s+\d+%", rarstring)
	if res != None:
		endofarchive = int(res.groups(0)[0]) + offset
	else:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	p = subprocess.Popen(['unrar', 'x', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	## oh the horror, we really need to check if unrar actually was successful
	#outtmpfile = tempfile.mkstemp(dir=tmpdir)
	#os.write(outtmpfile[0], stanout)
	#if os.stat(outtmpfile[1]).st_size == 0:
		#os.unlink(outtmpfile[1])
		#os.unlink(tmpfile[1])
		#return None
	os.unlink(tmpfile[1])
	return (endofarchive, tmpdir)

def searchUnpackLZMA(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	lzmaoffsets = []
	for marker in fsmagic.lzmatypes:
		lzmaoffsets = lzmaoffsets + offsets[marker]
	if lzmaoffsets == []:
		return ([], blacklist, [], hints)
	filesize = os.stat(filename).st_size
	## LZMA files should at least have a full header
	if filesize < 13:
		return ([], blacklist, [], hints)
	lzmaoffsets.sort()
	diroffsets = []
	newtags = []
	counter = 1

	template = None
	if 'TEMPLATE' in scanenv:
		template = scanenv['TEMPLATE']

	lzmalimit = int(scanenv.get('LZMA_MINIMUM_SIZE', 1))
	lzma_file = open(filename, 'rb')

	## see if LZMA_TRY_ALL is set. This option will disable the sanity checks.
	## This is not recommended.
	lzma_try = scanenv.get('LZMA_TRY_ALL', None)

	if lzma_try == 'yes':
		lzma_try_all = True
	else:
		lzma_try_all = False

	lzma_tmpdir = scanenv.get('UNPACK_TEMPDIR', None)

	for offset in lzmaoffsets:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## According to http://svn.python.org/projects/external/xz-5.0.3/doc/lzma-file-format.txt the first
		## 13 bytes of the LZMA file are the header. It consists of properties (1 byte), dictionary
		## size (4 bytes), and a field to store the size of the uncompressed data (8 bytes).
		##
		## The properties field is not fixed, but computed during compression and could be any value
		## between 0x00 and 0xe0. In practice only a handful of values are really used, 0x5d being the most
		## common one, because it is the default :-)
		##
		## The dictionary size can be any 32 bit integer, but again only a handful of values are widely
		## used. LZMA utils uses 2^n, with 16 <= n <= 25 (default 23). XZ utils uses 2^n or 2^n+2^(n-1).
		## For XZ utils n seems to be be 12 <= n <= 30 (default 23). Setting these requires tweaking
		## command line parameters which is unlikely to happen very often.
		##
		## The following checks are based on some real life data, plus some theoretical values
		## but could use refinement.
		## Values were computed based on dictionary size 2^n or 2^n+2^(n-1), with 16 <= n <= 25
		if not lzma_try_all:
			lzma_file.seek(offset + 3)
			lzmacheckbyte = lzma_file.read(2)
			if lzmacheckbyte not in ['\x01\x00', '\x02\x00', '\x03\x00', '\x04\x00', '\x06\x00', '\x08\x00', '\x10\x00', '\x20\x00', '\x30\x00', '\x40\x00', '\x60\x00', '\x80\x00', '\x80\x01', '\x0c\x00', '\x18\x00', '\x00\x00', '\x00\x01', '\x00\x02', '\x00\x03', '\x00\x04', '\xc0\x00']:
				continue

		## sanity checks if the size is set.
		lzmafile = open(filename, 'rb')
		lzmafile.seek(offset+5)
		lzmasizebytes = lzmafile.read(8)
		lzmafile.close()
		if len(lzmasizebytes) != 8:
			continue

		## A few more sanity checks: first check if the file is a stream
		## of unknown size, or if it has a file set.
		## If it has a file size set, then check if the value of the size
		## actually makes sense.
		## Then read some data and try to decompress it. Because LZMA is a
		## stream it will uncompress some data. If no data can be decompressed
		## at all, it is not a valid LZMA stream.
		lzmasizeknown = False
		if lzmasizebytes != '\xff\xff\xff\xff\xff\xff\xff\xff':
			lzmasize = struct.unpack('<Q', lzmasizebytes)[0]
			## XZ Utils rejects files with uncompressed size of 256 GiB
			if lzmasize > 274877906944:
				continue
			## if the size is 0, why even bother?
			if lzmasize == 0:
				continue
			lzmasizeknown = True

		## either read all bytes that are left in the file or a minimum
		## amount of bytes, whichever is the smallest
		minlzmadatatoread = 1000000
		lzmabytestoread = min(filesize-offset, minlzmadatatoread)

		lzmafile = open(filename, 'rb')
		lzmafile.seek(offset)
		lzmadata = lzmafile.read(lzmabytestoread)
		lzmafile.close()

		p = subprocess.Popen(['lzma', '-cd', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate(lzmadata)
		if p.returncode == 0:
			# whole stream successfully unpacked.
			tmpdir = dirsetup(tempdir, filename, "lzma", counter)
			tmpfile = tempfile.mkstemp(dir=tmpdir)
			os.write(tmpfile[0], stanout)
			os.fdopen(tmpfile[0]).close()
			diroffsets.append((tmpdir, offset, len(lzmadata)))
			blacklist.append((offset, offset+len(lzmadata)))
			counter += 1
			continue

		if len(stanout) == 0:
			## no data was successfully unpacked, so this is not
			## a valid LZMA stream
			continue

		## The data seems to be a valid LZMA stream, but not all LZMA
		## data was unpacked.

		## If there is a very big difference (thousandfold) between
		## the unpacked data and the declared size it is a false positive
		## for sure
		## TODO: make lzmacutoff configurable
		lzmacutoff = 1000
		if lzmasizeknown:
			if len(stanout) != lzmasize:
				if len(stanout) < lzmacutoff:
					if lzmasize/len(stanout) > 1000:
						continue
					else:
						## there is a very big chance that it actually
						## is a false positive
						pass
			else:
				## all data has been unpacked
				tmpdir = dirsetup(tempdir, filename, "lzma", counter)
				tmpfile = tempfile.mkstemp(dir=tmpdir)
				os.write(tmpfile[0], stanout)
				os.fdopen(tmpfile[0]).close()
				diroffsets.append((tmpdir, offset, 0))
				counter += 1
				continue
		else:
			if len(stanout) < lzmacutoff:
				if lzmabytestoread/len(stanout) > 1000:
					continue

		## TODO: check if the output consists of a single character that
		## has been repeated

		tmpdir = dirsetup(tempdir, filename, "lzma", counter)
		res = unpackLZMA(filename, offset, template, tmpdir, lzmalimit, lzma_tmpdir, blacklist)
		if res != None:
			(diroffset, wholefile) = res
			if wholefile:
				lzmasize = filesize - offset
				diroffsets.append((diroffset, offset, lzmasize))
				blacklist.append((offset, filesize))
				if offset == 0:
					newtags.append('compressed')
					newtags.append('lzma')
			else:
				diroffsets.append((diroffset, offset, 0))
			blacklist.append((offset, offset+len(lzmadata)))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	lzma_file.close()
	return (diroffsets, blacklist, newtags, hints)

## tries to unpack stuff using lzma -cd. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
## Newer versions of XZ (>= 5.0.0) have an option to test and list archives.
## Unfortunately this does not work for files with trailing data, so we can't
## use it to filter out "bad" files.
def unpackLZMA(filename, offset, template, tempdir=None, minbytesize=1, lzma_tmpdir=None, blacklist=[]):
	tmpdir = unpacksetup(tempdir)

	## if UNPACK_TEMPDIR is set to for example a ramdisk use that instead.
	if lzma_tmpdir != None:
		tmpfile = tempfile.mkstemp(dir=lzma_tmpdir)
		os.fdopen(tmpfile[0]).close()
		outtmpfile = tempfile.mkstemp(dir=lzma_tmpdir)
		unpackFile(filename, offset, tmpfile[1], lzma_tmpdir, blacklist=blacklist)
	else:
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		os.fdopen(tmpfile[0]).close()
		outtmpfile = tempfile.mkstemp(dir=tmpdir)
		unpackFile(filename, offset, tmpfile[1], tmpdir, blacklist=blacklist)
	p = subprocess.Popen(['lzma', '-cd', tmpfile[1]], stdout=outtmpfile[0], stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	wholefile = False
	if p.returncode == 0:
		wholefile = True
	os.fdopen(outtmpfile[0]).close()
	os.unlink(tmpfile[1])

	## sanity checks if the size is set
	lzmafile = open(filename, 'rb')
	lzmafile.seek(offset+5)
	lzmasizebytes = lzmafile.read(8)
	lzmafile.close()

	## check if the size of the uncompressed data is recorded
	## in the binary
	if lzmasizebytes != '\xff\xff\xff\xff\xff\xff\xff\xff':
		lzmasize = struct.unpack('<Q', lzmasizebytes)[0]
		if os.stat(outtmpfile[1]).st_size != lzmasize:
			os.unlink(outtmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None

	else:
		if os.stat(outtmpfile[1]).st_size < minbytesize:
			os.unlink(outtmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None

	if lzma_tmpdir != None:
		## create the directory and move the LZMA file
		try:
			os.makedirs(tmpdir)
		except OSError, e:
			pass

		if template != None:
			mvpath = os.path.join(tmpdir, template)
			if not os.path.exists(mvpath):
				try:
					shutil.move(outtmpfile[1], mvpath)
				except Exception, e:
					pass
		else:
			shutil.move(outtmpfile[1], tmpdir)
	else:
		if template != None:
			mvpath = os.path.join(tmpdir, template)
			if not os.path.exists(mvpath):
				try:
					shutil.move(outtmpfile[1], mvpath)
				except Exception, e:
					pass
	return (tmpdir, wholefile)

## Search and unpack Ubi. Since we can't easily determine the length of the
## file system by using ubi we will have to use a different measurement to
## measure the size of ubi. A good start is the sum of the size of the
## volumes that were unpacked.
def searchUnpackUbi(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'ubi' in offsets:
		return ([], blacklist, [], hints)
	if offsets['ubi'] == []:
		return ([], blacklist, [], hints)
	datafile = open(filename, 'rb')
	## We can use the values of offset and ubisize where offset != -1
	## to determine the ranges for the blacklist.
	diroffsets = []
	counter = 1
	## TODO: big file fixes
	data = datafile.read()
	datafile.close()
	for offset in offsets['ubi']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "ubi", counter)
		res = unpackUbi(data, offset, tmpdir)
		if res != None:
			(ubitmpdir, ubisize) = res
			diroffsets.append((ubitmpdir, offset, ubisize))
			blacklist.append((offset, offset+ubisize))
			## TODO use ubisize to set the blacklist correctly
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

def unpackUbi(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp()
	os.write(tmpfile[0], data[offset:])
	## take a two step approach: first unpack the UBI images,
	## then extract the individual files from these images
	p = subprocess.Popen(['ubi_extract_images.py', '-o', tmpdir, tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()

	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		p = subprocess.Popen(['ubi_display_info.py', tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.fdopen(tmpfile[0]).close()
			os.unlink(tmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None

		stanoutlines = stanout.split('\n')
		for s in stanoutlines:
			if 'PEB Size' in s:
				blocksize = int(s.split(':')[1].strip())
        		if 'Total Block Count' in s:
				blockcount = int(s.split(':')[1].strip())

		ubisize = blocksize * blockcount

		## clean up the temporary files
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		## determine the sum of the size of the unpacked files

		## now the second stage, unpacking the images that were extracted

		ubitmpdir = os.path.join(tmpdir, os.path.basename(tmpfile[1]))
		for i in os.listdir(ubitmpdir):
			p = subprocess.Popen(['ubi_extract_files.py', '-o', tmpdir, os.path.join(ubitmpdir, i)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			os.unlink(os.path.join(ubitmpdir, i))

		os.rmdir(ubitmpdir)

		return (tmpdir, ubisize)

## unpacking for ARJ. The file format is described at:
## http://www.fileformat.info/format/arj/corion.htm
## Although there is no trailer the arj program can be used to at least give
## some information about the uncompressed size of the archive.
## Please note: these files can also be unpacked with 7z, which could be
## a little bit faster. Since 7z is "smart" and looks ahead useful information
## like the actual offset that is used for reporting and blacklisting could
## be lost.
## WARNING: this method is very costly. Since ARJ is not used on many Unix
## systems it is advised to not enable it when scanning binaries intended for
## these systems.
def searchUnpackARJ(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'arj' in offsets:
		return ([], blacklist, [], hints)
	if offsets['arj'] == []:
		return ([], blacklist, [], hints)
	diroffsets = []
	counter = 1
	for offset in offsets['arj']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "arj", counter)
		res = unpackARJ(filename, offset, tmpdir)
		if res != None:
			(arjtmpdir, arjsize) = res
			diroffsets.append((arjtmpdir, offset, arjsize))
			blacklist.append((offset, arjsize))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)

def unpackARJ(filename, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir, suffix=".arj")
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir)

	## first check archive integrity
	p = subprocess.Popen(['arj', 't', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		## this is not an ARJ archive
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		p = subprocess.Popen(['arj', 'x', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.unlink(tmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None
	## everything has been unpacked, so we can get the size.
	p = subprocess.Popen(['arj', 'v', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	stanoutlines = stanout.strip().split("\n")
	## we should do more sanity checks here
	arjsize = int(stanoutlines[-1].split()[-2])
	## always clean up the old temporary files
	os.unlink(tmpfile[1])
	return (tmpdir, arjsize)

## extraction of Windows .ICO files. The identifier for .ICO files is very
## common, so on large files this will have a rather big performance impact
## with relatively little gain.
## This scan should only be enabled if verifyIco is also enabled
def searchUnpackIco(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	diroffsets = []
	hints = {}
	counter = 1
	offset = 0
	template = None
	if 'TEMPLATE' in scanenv:
		template = scanenv['TEMPLATE']
	blacklistoffset = extractor.inblacklist(offset, blacklist)
	if blacklistoffset != None:
		return (diroffsets, blacklist, [], hints)
	tmpdir = dirsetup(tempdir, filename, "ico", counter)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	icofile = tmpfile[1]

	if template != None:
		mvpath = os.path.join(tmpdir, template)
		if not os.path.exists(mvpath):
			try:
				shutil.move(tmpfile[1], mvpath)
				icofile = mvpath
			except:
				pass

	unpackFile(filename, offset, icofile, tmpdir)

	p = subprocess.Popen(['icotool', '-x', '-o', tmpdir, icofile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()

	if p.returncode != 0 or "no images matched" in stanerr:
		os.unlink(icofile)
		os.rmdir(tmpdir)
		return (diroffsets, blacklist, [], hints)
	## clean up the temporary files
	os.unlink(icofile)
	diroffsets.append((tmpdir, offset, 0))
	return (diroffsets, blacklist, [], hints)

## Windows MSI
def searchUnpackMSI(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not filename.lower().endswith('.msi'):
		return ([], blacklist, [], hints)
	if not "msi" in offsets:
		return ([], blacklist, [], hints)
	if not 0 in offsets['msi']:
		return ([], blacklist, [], hints)
	diroffsets = []
	newtags = []
	counter = 1

	for offset in offsets['msi']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			return (diroffsets, blacklist, newtags, hints)
		tmpdir = dirsetup(tempdir, filename, "msi", counter)
		tmpres = unpack7z(filename, 0, tmpdir, blacklist)
		if tmpres != None:
			(size7z, res) = tmpres
			diroffsets.append((res, 0, size7z))
			blacklist.append((0, size7z))
			newtags.append('msi')
			return (diroffsets, blacklist, newtags, hints)
	return (diroffsets, blacklist, newtags, hints)

## Windows HtmlHelp
def searchUnpackCHM(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not filename.lower().endswith('.chm'):
		return ([], blacklist, [], hints)
	if not "chm" in offsets:
		return ([], blacklist, [], hints)
	if not 0 in offsets['chm']:
		return ([], blacklist, [], hints)
	diroffsets = []
	newtags = []
	counter = 1

	for offset in offsets['chm']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			return (diroffsets, blacklist, newtags, hints)
		tmpdir = dirsetup(tempdir, filename, "chm", counter)
		tmpres = unpack7z(filename, 0, tmpdir, blacklist)
		if tmpres != None:
			(size7z, res) = tmpres
			diroffsets.append((res, 0, size7z))
			blacklist.append((0, size7z))
			newtags.append('chm')
			return (diroffsets, blacklist, newtags, hints)
	return (diroffsets, blacklist, newtags, hints)

###
## The scans below are scans that are used to extract files from bigger binary
## blobs, but they should not be recursively applied to their own results,
## because that results in endless loops.
###

## PDFs end with %%EOF, sometimes followed by one or two extra characters
## See http://www.adobe.com/devnet/pdf/pdf_reference.html
## The structure is described in section 7.5
def searchUnpackPDF(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'pdf' in offsets:
		return ([], blacklist, [], hints)
	if not 'pdftrailer' in offsets:
		return ([], blacklist, [], hints)
	if offsets['pdf'] == []:
		return ([], blacklist, [], hints)
	if offsets['pdftrailer'] == []:
		return ([], blacklist, [], hints)
	diroffsets = []
	counter = 1
	filesize = os.stat(filename).st_size

	for offset in offsets['pdf']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## first check whether or not the file has a valid PDF version
		pdffile = open(filename, 'rb')
		pdffile.seek(offset+5)
		pdfbytes = pdffile.read(3)
		pdffile.close()
		if pdfbytes[0] != '1':
			continue
		if pdfbytes[1] != '.':
			continue
		try:
			int(pdfbytes[2])
		except:
			continue
		for trailer in offsets['pdftrailer']:
			if offset > trailer:
				continue
			blacklistoffset = extractor.inblacklist(trailer, blacklist)
			if blacklistoffset != None:
				break

			## first do some sanity checks for the trailer. According to the
			## PDF specification the word "startxref" should.
			## Read 100 bytes and see if 'startxref' is in those bytes. If not
			## it cannot be a valid PDF file.
			pdffile = open(filename, 'rb')
			pdffile.seek(trailer-100)
			pdfbytes = pdffile.read(100)
			pdffile.close()
			if not "startxref" in pdfbytes:
				continue

			## startxref is followed by whitespace and then a number indicating
			## the byte offset for a possible xref table.
			xrefres = re.search('startxref\s+(\d+)\s+', pdfbytes)
			if xrefres == None:
				continue

			xrefoffset = int(xrefres.groups()[0])

			pdffile = open(filename, 'rb')
			pdffile.seek(xrefoffset)
			pdfbytes = pdffile.read(4)
			pdffile.close()
			if pdfbytes != 'xref':
				continue

			## as a sanity check walk the xref table
			## After the line "xref" there is a line that
			## tells how many entries follow and how they are numbered
			## according to the PDF specification each xref entry is
			## 20 bytes long
			## set offset to just after 'xref\n'
			xrefoffset += 5
			pdffile = open(filename, 'rb')
			pdffile.seek(xrefoffset)
			## just read a bunch of bytes to find the first line
			bytesread = 10
			pdfbytes = pdffile.read(bytesread)

			## end of line marker can be either
			## * space followed by newline
			## * space followed by carriage return
			## * carriage return followed by newline
			nloffset = pdfbytes.find(' \n')
			if nloffset == -1:
				nloffset = pdfbytes.find(' \r')
				if nloffset == -1:
					nloffset = pdfbytes.find('\r\n')
			totalbytesread = bytesread
			while nloffset == -1:
				pdfbytes = pdffile.read(bytesread)
				nloffset = pdfbytes.find(' \n')
				if nloffset == -1:
					nloffset = pdfbytes.find(' \r')
					if nloffset == -1:
						nloffset = pdfbytes.find('\r\n')
				if nloffset != -1:
					nloffset += totalbytesread
				totalbytesread += bytesread
				if totalbytesread > filesize:
					break

			## reset the file pointer
			pdffile.seek(xrefoffset)
			subsectionline = pdffile.read(nloffset)
			try:
				subsectionlinelems = map(lambda x: int(x), subsectionline.split())
			except:
				pdffile.close()
				continue

			if len(subsectionlinelems) != 2:
				pdffile.close()
				continue

			#(subsection, subsectionelemcount)

			## adjust offset to length of subsection line plus newline
			xrefoffset += nloffset + 1

			pdffile.close()

			tmpdir = dirsetup(tempdir, filename, "pdf", counter)
			res = unpackPDF(filename, offset, trailer, tmpdir)
			if res != None:
				(pdfdir, size) = res
				if offset == 0 and (filesize - 2) <= size <= filesize:
					## the PDF is the whole file, so why bother?
					shutil.rmtree(tmpdir)
					return (diroffsets, blacklist, ['pdf'], hints)
				else:
					diroffsets.append((pdfdir, offset, size))
					blacklist.append((offset, offset + size))
				counter = counter + 1
				break
			else:
				os.rmdir(tmpdir)
		if offsets['pdftrailer'] == []:
			break
		offsets['pdftrailer'].remove(trailer)

	return (diroffsets, blacklist, [], hints)

def unpackPDF(filename, offset, trailer, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()
	filesize = os.stat(filename).st_size

	## if the data is the whole file we can just hardlink
	if offset == 0 and (trailer + 5 == filesize or trailer + 5 == filesize-1 or trailer + 5 == filesize-2):
		templink = tempfile.mkstemp(dir=tmpdir)
		os.fdopen(templink[0]).close()
		os.unlink(templink[1])

		try:
			os.link(filename, templink[1])
		except OSError, e:
			## if filename and tmpdir are on different devices it is
			## not possible to use hardlinks
			shutil.copy(filename, templink[1])
		shutil.move(templink[1], tmpfile[1])
	else:
		## first we use 'dd' or tail. Then we use truncate
		if offset < 128:
			tmptmpfile = open(tmpfile[1], 'wb')
			p = subprocess.Popen(['tail', filename, '-c', "%d" % (filesize - offset)], stdout=tmptmpfile, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			tmptmpfile.close()
		else:
			p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile[1],), 'bs=%s' % (offset,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
		pdflength = trailer + 5 - offset
		p = subprocess.Popen(['truncate', "-s", "%d" % pdflength, tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.unlink(tmpfile[1])
			return None

	p = subprocess.Popen(['pdfinfo', "%s" % (tmpfile[1],)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.unlink(tmpfile[1])
		return None
	else:
		## Is this accurate? Using "File size" from pdfinfo's output
		## surely is not.
		size = os.stat(tmpfile[1]).st_size
		return (tmpdir, size)

## http://en.wikipedia.org/wiki/Graphics_Interchange_Format
## 1. search for a GIF header
## 2. search for a GIF trailer
## 3. check the data with gifinfo
##
## gifinfo will not recognize if there is trailing data for
## a GIF file, so all data needs to be looked at, until a
## valid GIF file has been carved out (part of the file, or
## the whole file), or stop if no valid GIF file can be found.
def searchUnpackGIF(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	gifoffsets = []
	for marker in fsmagic.gif:
		## first check if the header is not blacklisted
		for m in offsets[marker]:
			blacklistoffset = extractor.inblacklist(m, blacklist)
			if blacklistoffset != None:
				continue
			gifoffsets.append(m)
	if gifoffsets == []:
		return ([], blacklist, [], hints)

	gifoffsets.sort()

	diroffsets = []
	counter = 1

	## magic header for XMP https://en.wikipedia.org/wiki/Extensible_Metadata_Platform
	xmpmagicheaderbytes = ['\x01'] + map(lambda x: chr(x), range(255,-1,-1)) + ['\x00']
	xmpmagic = "".join(xmpmagicheaderbytes)

	datafile = open(filename, 'rb')
	lendata = os.stat(filename).st_size
	for i in range(0,len(gifoffsets)):
		offset = gifoffsets[i]
		if i < len(gifoffsets) - 1:
			nextoffset = gifoffsets[i+1]
		else:
			nextoffset = lendata
		## first check if the header is not blacklisted
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue

		localoffset = offset

		## sanity check for the logical screen descriptor
		datafile.seek(offset+6)
		localoffset += 6
		## first logical screen width
		databytes = datafile.read(2)
		localoffset += 2
		logicalwidth = struct.unpack('<H', databytes)[0]
		if logicalwidth == 0:
			continue
		## then the logical screen height
		databytes = datafile.read(2)
		logicalheight = struct.unpack('<H', databytes)[0]
		if logicalheight == 0:
			continue
		localoffset += 2

		## Then check to see if there is an image control block (for a valid
		## GIF stream with actual image content there has to be at least one
		## image control block). Depending on the image there might be all kinds
		## of information in between the logical screen descriptor and the first
		## information control block, such as a global color table and XMP
		## extensions or other application specific extensions.
		packedfields = datafile.read(1)
		localoffset += 1
		globalcolortablesize = 0
		if (ord(packedfields) >> 7 & 1) == 1:
			globalcolortablesize = pow(2,(ord(packedfields)%8) + 1) * 3
		localoffset += 2
		localoffset += globalcolortablesize
		databytes = datafile.seek(localoffset)
		## then read the next byte to see if it is an extension (0x21)
		## or an image control block
		databytes = datafile.read(1)
		localoffset += 1

		## there could be various extensions before there is an image
		## control block
		while databytes == '\x21':
			## depending on the extension label a number of bytes
			## need to be skipped
			databytes = datafile.read(1)
			localoffset += 1
			if databytes == '\xf9':
				## graphic control extension, 8 bytes in total counting
				## label and extension identifier
				localoffset += 6
				datafile.seek(localoffset)
			elif databytes == '\xfe':
				## length of the comment
				databytes = datafile.read(1)
				localoffset += 1
				commentsize = ord(databytes)
				localoffset += commentsize
				datafile.seek(localoffset)
			elif databytes == '\xff':
				## application extension with all other data is 14 bytes
				## unless it is XMP, in which case it is variable
				## for details see XMP Specification part 3
				## TODO: add support for other extensions such
				## as ICC profiles
				databytes = datafile.read(1)
				if databytes != '\x0b':
					break
				localoffset += 1
				databytes = datafile.read(8)
				localoffset += 8
				if databytes == 'XMP Data':
					databytes = datafile.read(1000)
					magicoffset = databytes.find(xmpmagic)
					while magicoffset == -1:
						databuf = datafile.read(1000)
						## files with a broken XMP trailer
						## exist, so check if the end of the
						## file is reached at some point
						## TODO: check blacklists as well
						if databuf == '':
							break
						databytes += databuf
						magicoffset = databytes.find(xmpmagic)
					localoffset += magicoffset + 258
					datafile.seek(localoffset)
				else:
					localoffset += 3
					datafile.seek(localoffset)
					databytes = datafile.read(1)
					localoffset += 1
					blocksize = ord(databytes)
					localoffset += blocksize
					datafile.seek(localoffset)
			databytes = datafile.read(1)
			localoffset += 1
			if databytes == '\x00':
				databytes = datafile.read(1)
				localoffset += 1
		if databytes != '\x2c':
			continue

		## Now read data from the current offset until the next offset
		## and search for trailer bytes. If these cannot be found, then
		## move onto the next GIF offset.
		## GIF files have a trailer which according to the GIF specification
		## consists of a "block terminator" and a semi-colon. Since the trailer
		## is very generic it is best to search for it here instead of in the
		## top level identifier search which would be quite costly.
		datafile.seek(offset)

		## read around 10 meg of data
		gifchunkread = 100000000
		bytesread = 0
		giffound = False
		data = ""
		trailersearchoffset = 0
		tmpdir = dirsetup(tempdir, filename, "gif", counter)
		while bytesread <= nextoffset-offset and not giffound:
			## concatenation of data is expensive :-(
			data += datafile.read(gifchunkread)
			bytesread += gifchunkread
			traileroffsets = []
			trailer = data.find('\x00;', trailersearchoffset)
			while trailer != -1:
				## see if the trailer is actually after the next offset
				if trailer > nextoffset-offset:
					break
				## check if the trailer is not blacklisted. If so, then
				## the trailer and any trailer following it can never be
				## part of this GIF file.
				blacklistoffset = extractor.inblacklist(trailer+offset, blacklist)
				if blacklistoffset == None:
					traileroffsets.append(trailer)
				else:
					break
				trailersearchoffset = trailer + 2
				trailer = data.find('\x00;', trailersearchoffset)

			for trail in traileroffsets:
				## TODO: use templates here to make the name of the file more predictable
				## which helps with result interpretation
				p = subprocess.Popen(['gifinfo'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p.communicate(data[:trail+2])
				if p.returncode != 0:
					continue
				else:
					giffound = True
					## basically this is copy of the original image so why bother?
					if offset == 0 and trail == lendata - 2:
						blacklist.append((0, lendata))
						datafile.close()
						os.rmdir(tmpdir)
						return (diroffsets, blacklist, ['graphics', 'gif', 'binary'], hints)
					else:
						tmpfilename = os.path.join(tmpdir, 'unpack-%d.gif' % counter)
						tmpfile = open(tmpfilename, 'wb')
						tmpfile.write(data[:trail+2])
						tmpfile.close()
						diroffsets.append((tmpdir, offset, trail+2))
						hints[tmpfilename] = {}
						hints[tmpfilename]['tags'] = ['graphics', 'gif', 'binary']
						hints[tmpfilename]['scanned'] = True
						counter = counter + 1
						blacklist.append((offset, offset+trail+2))
						## go to the next header
						break
		if not giffound:
			os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, [], hints)

def searchUnpackKnownPNG(filename, tempdir=None, scanenv={}, debug=False):
	## first check if the file actually could be a valid png file
	pngfile = open(filename, 'rb')
	pngfile.seek(0)
	pngheader = pngfile.read(8)
	pngfile.close()
	if pngheader != fsmagic.fsmagic['png']:
		return ([], [], [], {})

	lendata = os.stat(filename).st_size
	pngfile = open(filename, 'rb')
	pngfile.seek(lendata - 12)
	pngtrailer = pngfile.read(12)
	pngfile.close()
	if pngtrailer != fsmagic.fsmagic['pngtrailer']:
		return ([], [], [], {})
	## only check files smaller than or equal to 10 MiB for now
	if lendata > 10485760:
		return ([], [], [], {})
	pngheaderoffsets = prerun.genericMarkerSearch(filename, ['png'], [])['png']
	if len(pngheaderoffsets) != 1:
		return ([], [], [], {})
	pngtraileroffsets = prerun.genericMarkerSearch(filename, ['pngtrailer'], [])['pngtrailer']
	if len(pngtraileroffsets) != 1:
		return ([], [], [], {})
	res = searchUnpackPNG(filename, tempdir, [], {'png': [0], 'pngtrailer': [lendata - 12]}, scanenv, debug)
	(diroffsets, blacklist, newtags, hints) = res

	failed = False
	## there were results, so check if they were successful
	if blacklist != []:
		if len(blacklist) != 1:
			failed = True
		else:
			(startoffset, endoffset) = blacklist[0]
			if startoffset != 0 or endoffset != os.stat(filename).st_size:
				failed = True

		if failed:
			return ([], [], [], {})
		else:
			return (diroffsets, blacklist, newtags, hints)
	return ([], [], [], {})

## PNG extraction is similar to GIF extraction, except there is a way better
## defined trailer.
def searchUnpackPNG(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'png' in offsets:
		return ([], blacklist, [], hints)
	if not 'pngtrailer' in offsets:
		return ([], blacklist, [], hints)
	if offsets['png'] == []:
		return ([], blacklist, [], hints)
	if offsets['pngtrailer'] == []:
		return ([], blacklist, [], hints)
	lendata = os.stat(filename).st_size
	## sanity check: minimal PNG consists of header (8 bytes), IHDR chunk (25 bytes)
	## and IEND chunk (12 bytes)
	if lendata < 45:
		return ([], blacklist, [], hints)
	diroffsets = []
	headeroffsets = offsets['png']
	traileroffsets = deque(offsets['pngtrailer'])
	counter = 1
	datafile = open(filename, 'rb')
	orig_offset = headeroffsets[0]
	lenheaderoffsets = len(headeroffsets)

	trailerpopcounter = 0

	for i in range(0,len(headeroffsets)):
		offset = headeroffsets[i]
		if i < lenheaderoffsets - 1:
			nextoffset = headeroffsets[i+1]
		else:
			nextoffset = lendata
		## first check if the offset is not blacklisted
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue

		datafile.seek(offset)

		## some sanity checks. According to http://www.w3.org/TR/PNG/
		## the first chunk in a PNG following the PNG signature is always IHDR.
		## The PNG signature is 8 bytes
		datafile.seek(offset+8)
		chunkbytes = datafile.read(4)
		## IHDR chunk size is always 13 bytes
		#chunksize = struct.unpack('>I', chunkbytes)[0]
		if chunkbytes != '\x00\x00\x00\x0d':
			continue
		chunkbytes = datafile.read(4)
		if chunkbytes != 'IHDR':
			continue

		datafile.seek(offset)

		for r in xrange(0, trailerpopcounter):
			traileroffsets.popleft()

		trailerpopcounter = 0

		tmpdir = dirsetup(tempdir, filename, "png", counter)
		pngfound = False
		for trail in traileroffsets:
			if trail <= offset:
				trailerpopcounter += 1
				continue
			if trail >= nextoffset:
				break
			## then check if the trailer is not blacklisted. If it
			## is, then the next trailers can never be valid for this
			## PNG file either.
			blacklistoffset = extractor.inblacklist(trail, blacklist)
			if blacklistoffset != None:
				break
			pngsize = trail+12-offset
			data = datafile.read(pngsize)
			p = subprocess.Popen(['webpng', '-d', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stanout, stanerr) = p.communicate(data)
			if p.returncode != 0:
				continue
			else:
				pngfound = True
				## basically we have a copy of the original
				## image here, so why bother?
				if offset == 0 and trail == lendata - 12:
					os.rmdir(tmpdir)
					blacklist.append((0,lendata))
					datafile.close()
					return (diroffsets, blacklist, ['graphics', 'png', 'binary'], hints)
				else:
					tmpfilename = os.path.join(tmpdir, 'unpack-%d.png' % counter)
					tmpfile = open(tmpfilename, 'wb')
					tmpfile.write(data)
					tmpfile.close()
					hints[tmpfilename] = {}
					hints[tmpfilename]['tags'] = ['graphics', 'png', 'binary']
					hints[tmpfilename]['scanned'] = True
					blacklist.append((offset,trail+12))
					diroffsets.append((tmpdir, offset, pngsize))
					counter = counter + 1
					trailerpopcounter += 1
					break
		if not pngfound:
			os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, [], hints)

## JFIF is the most common JPEG format
## Specifications can be found at http://www.w3.org/Graphics/JPEG/
## Extra information:
## http://www.media.mit.edu/pia/Research/deepview/exif.html
## http://www.sno.phy.queensu.ca/~phil/exiftool/TagNames/JPEG.html
def searchUnpackJPEG(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'jpeg' in offsets:
		return ([],blacklist, [], hints)
	if not 'jpegtrailer' in offsets:
		return ([],blacklist, [], hints)

	if len(offsets['jpeg']) == 0:
		return ([],blacklist, [], hints)
	if len(offsets['jpegtrailer']) == 0:
		return ([],blacklist, [], hints)

	hints = {}
	counter = 1
	diroffsets = []
	newtags = []

	lendata = os.stat(filename).st_size

	traileroffsets = offsets['jpegtrailer']
	lastseentrailer = 0

	datafile = open(filename, 'rb')
	## Start verifying the JFIF image.
	for offset in offsets['jpeg']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		localoffset = offset
		datafile.seek(offset+2)
		localoffset += 2
		jpegdata = datafile.read(2)
		localoffset += 2
		## following the JPEG "start of image" there is
		## either a APP0 (JFIF) or APP1 (Exif and XMP)
		## or APP13 (PSIR/IPTC)
		if not  jpegdata in ['\xff\xe0', '\xff\xe1', '\xff\xed']:
			continue
		validpng = True
		havexmp = False
		xmp = None
		while jpegdata in ['\xff\xe0', '\xff\xe1', '\xff\xed']:
			if not validpng:
				break
			if jpegdata == '\xff\xe0':
				## JFIF data
				## first the size of the app marker
				jpegdata = datafile.read(2)
				sizeheader = struct.unpack('>H', jpegdata)[0]
				if sizeheader > lendata:
					validpng = False
					break
				jpegdata = datafile.read(sizeheader - 2)
				localoffset += sizeheader
				if len(jpegdata) != sizeheader - 2:
					validpng = False
					break
				## check if the rest of the header starts with either
				## JFIF or JFXX
				if not (jpegdata.startswith('JFIF\x00') or jpegdata.startswith('JFXX\x00')):
					validpng = False
					break
				if jpegdata.startswith('JFIF\x00'):
					if not (jpegdata[5:7] == '\x01\x01' or jpegdata[5:7] == '\x01\x02'):
						validpng = False
						break
				jpegdata = datafile.read(2)
				localoffset += 2
			elif jpegdata == '\xff\xe1':
				## EXIF, XMP
				## first the size of the app marker
				jpegdata = datafile.read(2)
				sizeheader = struct.unpack('>H', jpegdata)[0]
				if sizeheader > lendata:
					validpng = False
					break
				jpegdata = datafile.read(sizeheader - 2)
				localoffset += sizeheader
				if len(jpegdata) != sizeheader - 2:
					validpng = False
					break
				if not (jpegdata.startswith('Exif\x00') or jpegdata.startswith('http://ns.adobe.com/xap/1.0/\x00')):
					validpng = False
					break
				if jpegdata.startswith('http://ns.adobe.com/xap/1.0/\x00'):
					xmp = jpegdata.split('\x00', 1)[1]
					havexmp = True
				jpegdata = datafile.read(2)
				localoffset += 2
			elif jpegdata == '\xff\xed':
				## PSIR/IPTC
				jpegdata = datafile.read(2)
				sizeheader = struct.unpack('>H', jpegdata)[0]
				if sizeheader > lendata:
					validpng = False
					break
				jpegdata = datafile.read(sizeheader - 2)
				localoffset += sizeheader
				if len(jpegdata) != sizeheader - 2:
					validpng = False
					break
				if not jpegdata.startswith('Photoshop 3.0\x00'):
					validpng = False
					break
				jpegdata = datafile.read(2)
				localoffset += 2
		if not validpng:
			continue

		if jpegdata[0] != '\xff':
			## catch all for non-compliant data
			continue

		'''
		## TODO: better parse the data to see if it is correct. Right now
		## it is possible that some JPEG files are not correctly unpacked
		while jpegdata[0] == '\xff':
			## individual checks to see if JPEG is valid
			if jpegdata[1] in ['\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xd4','\xda', '\xdb']:
				jpegdata = datafile.read(2)
				localoffset += 2
				markerlength = struct.unpack('>H', jpegdata)[0]
				if markerlength > lendata:
					continue
				jpegdata = datafile.read(markerlength-2)
				localoffset += markerlength-2
				jpegdata = datafile.read(2)
				localoffset += 2
		'''

		traileroffsets = traileroffsets[lastseentrailer:]

		lastseentrailer = 0
		## find the closest jpeg trailer
		for trail in traileroffsets:
			if trail <= offset:
				lastseentrailer += 1
				continue
			if trail < localoffset:
				lastseentrailer += 1
				continue
			blacklistoffset = extractor.inblacklist(trail, blacklist)
			if blacklistoffset != None:
				break
			if offset == 0 and trail+2 == lendata:
				p = subprocess.Popen(['jpegtopnm', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					validpng = False
					break
				blacklist.append((0,lendata))
				datafile.close()
				return (diroffsets, blacklist, ['graphics', 'jpeg', 'binary'], hints)
			else:
				tmpdir = dirsetup(tempdir, filename, "jpeg", counter)
				datafile.seek(offset)
				jpegtestdata = datafile.read(trail+2 - offset)
				p = subprocess.Popen(['jpegtopnm'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p.communicate(jpegtestdata)
				if p.returncode == 0:
					tmpfilename = os.path.join(tmpdir, 'unpack-%d.jpg' % counter)
					tmpfile = open(tmpfilename, 'wb')
					tmpfile.write(jpegtestdata)
					tmpfile.close()
					hints[tmpfilename] = {}
					hints[tmpfilename]['tags'] = ['graphics', 'jpeg', 'binary']
					hints[tmpfilename]['scanned'] = True
					blacklist.append((offset,trail+2))
					diroffsets.append((tmpdir, offset, trail-offset+2))
					counter = counter + 1
					lastseentrailer += 1
					break
				os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, newtags, hints)

## unpack Windows Imaging files
## Assume for now that the whole image is a WIM file
def searchUnpackWIM(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	diroffsets = []
	newtags = []
	if not 'mswim' in offsets:
		return (diroffsets, blacklist, newtags, hints)
	if offsets['mswim'] == []:
		return (diroffsets, blacklist, newtags, hints)
	if not 0 in offsets['mswim']:
		return (diroffsets, blacklist, newtags, hints)
	counter = 1
	for offset in offsets['mswim']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			return (diroffsets, blacklist, newtags, hints)
		tmpdir = dirsetup(tempdir, filename, "wim", counter)
		tmpres = unpack7z(filename, 0, tmpdir, blacklist)
		if tmpres != None:
			(size7z, res) = tmpres
			diroffsets.append((res, 0, size7z))
			blacklist.append((0, size7z))
			newtags.append('wim')
			return (diroffsets, blacklist, newtags, hints)
		os.rmdir(tmpdir)
	return (diroffsets, blacklist, newtags, hints)

## Unpack Android backup files. These are zlib compressed files.
## Unpacking is almost identical to SWF, but has a few extra sanity
## checks.
def searchUnpackAndroidBackup(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'androidbackup' in offsets:
		return ([], blacklist, [], hints)
	if offsets['androidbackup'] == []:
		return ([], blacklist, [], hints)

	newtags = []
	counter = 1
	diroffsets = []
	readsize = 1000000
	
	backupfile = open(filename, 'rb')
	for offset in offsets['androidbackup']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## first some sanity checks
		unzobj = zlib.decompressobj()
		backupfile.seek(offset+15)
		versiondata = backupfile.read(2)
		if versiondata != "1\n":
			continue
		compressiondata = backupfile.read(2)
		if compressiondata != "1\n":
			continue
		encryptiondata = backupfile.read(5)
		if encryptiondata != "none\n":
			continue
		unzswfdata = backupfile.read(readsize)
		unz = ''
		bytesread = 22 # 15 + 2 + 2 + 5
		try:
			while unzswfdata != '':
				unz += unzobj.decompress(unzswfdata)
				deflatesize = len(unzswfdata) - len(unzobj.unused_data)
				bytesread += len(unzswfdata) - len(unzobj.unused_data)
				if len(unzobj.unused_data) != 0:
					break
				unzswfdata = backupfile.read(readsize)
		except Exception, e:
			continue

		tmpdir = dirsetup(tempdir, filename, "androidbackup", counter)
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		os.write(tmpfile[0], unz)
		os.fdopen(tmpfile[0]).close()

		diroffsets.append((tmpdir, offset, bytesread))
		blacklist.append((offset, offset + bytesread))
		if offset == 0 and bytesread == os.stat(filename).st_size:
			newtags.append('androidbackup')
		counter += 1
	backupfile.close()
	return (diroffsets, blacklist, newtags, hints)

## unpack some Intel hex files
## TODO: sometimes these files can contain comments, for example:
## mulaw_main.csp.ihex and other firmware files in the Linux kernel
def searchUnpackIHex(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	tags = []
	diroffsets = []
	counter = 1
	filesize = os.stat(filename).st_size

	tmpdir = dirsetup(tempdir, filename, "ihex", counter)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	datafile = open(filename, 'r')
	foundend = False
	offset = 0
	for d in datafile:
		if foundend:
			os.fdopen(tmpfile[0]).close()
			datafile.close()
			os.rmdir(tmpdir)
			return (diroffsets, blacklist, tags, hints)
		b = d.strip()
		if len(b) < 3:
			break
		bytecount = ord(b[1:3].decode('hex'))
		address = struct.unpack('>H', b[3:7].decode('hex'))
		recordtype = ord(b[7:9].decode('hex'))
		if recordtype == 1:
			foundend = True
			break
		if recordtype != 0:
			continue
		databytes = b[9:9+bytecount*2].decode('hex')
		os.write(tmpfile[0], databytes)
	diroffsets.append((tmpdir, offset, filesize))
	blacklist.append((offset, offset + filesize))
	os.fdopen(tmpfile[0]).close()
	datafile.close()
	return (diroffsets, blacklist, tags, hints)

## sometimes Ogg audio files are embedded into binary blobs
def searchUnpackOgg(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	return ([], blacklist, [], hints)

## sometimes MP3 audio files are embedded into binary blobs
def searchUnpackMP3(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	return ([], blacklist, [], hints)

## PLF is Parrot's own file format. An incomplete description can be found here:
## http://embedded-software.blogspot.nl/2010/12/plf-file-format.html
## Parrot's own header file with slightly more information can be found here:
## https://github.com/Parrot-Developers/libARUpdater/blob/master/Sources/ARUPDATER_Plf.h
def searchUnpackPLF(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = []
	if not 'plf' in offsets:
		return ([], blacklist, [], hints)
	if offsets['plf'] == []:
		return ([], blacklist, [], hints)

	if not 0 in offsets['plf']:
		return ([], blacklist, [], hints)

	newtags = []
	counter = 1
	diroffsets = []

	plffile = open(filename, 'rb')
	for offset in offsets['plf']:
		dataunpacked = False
		## first some sanity checks for the header
		plffile.seek(offset)
		plfheader = plffile.read(0x38)

		if len(plfheader) != 0x38:
			continue

		plfsize = struct.unpack('<I', plfheader[-4:])[0]
		## right now only whole files that are PLF files are recognized
		if not plfsize == os.stat(filename).st_size:
			continue

		## parse all the fields in the header and add some sanity checks
		headerversion = struct.unpack('<I', plfheader[4:8])[0]
		headersize = struct.unpack('<I', plfheader[8:12])[0] ## should be 56
		if headersize != 0x38:
			continue

		sectionheadersize = struct.unpack('<I', plfheader[12:16])[0] ## should be 20
		if sectionheadersize != 0x14:
			continue

		filetype = struct.unpack('<I', plfheader[16:20])[0]
		entrypoint = struct.unpack('<I', plfheader[20:24])[0]
		targetplatform = struct.unpack('<I', plfheader[24:28])[0]
		targetapplication = struct.unpack('<I', plfheader[28:32])[0]
		hardware = struct.unpack('<I', plfheader[32:36])[0]
		fwversion = struct.unpack('<I', plfheader[36:40])[0]
		fwedition = struct.unpack('<I', plfheader[40:44])[0]
		fwextension = struct.unpack('<I', plfheader[44:48])[0]
		language_zone = struct.unpack('<I', plfheader[48:52])[0]

		## skip past the header
		localoffset = offset+0x38
		plffile.seek(localoffset)
		plfentryheader = plffile.read(sectionheadersize)
		newfs = False
		newdir = False
		tmpdir = dirsetup(tempdir, filename, "plf", counter)
		while plfentryheader != '':
			if newdir:
				## this is a superugly hack :-(
				tmpdir = dirsetup(tempdir, filename, "plf", counter)
				newdir = False
			entrytype = struct.unpack('<I', plfentryheader[:4])[0]
			entrysize = struct.unpack('<I', plfentryheader[4:8])[0]
			entrycrc32 = struct.unpack('<I', plfentryheader[8:12])[0]
			entryuncompressedsize = struct.unpack('<I', plfentryheader[16:])[0]

			plffile.seek(localoffset+sectionheadersize)
			plfname = ""
			lenplfname = 0
			compressed = False
			if entryuncompressedsize != 0:
				compressed = True

			plfbuf = plffile.read(entrysize)
			## first check if the entry is gzip compressed. If so, decompress
			if compressed:
				plfbuf = zlib.decompress(plfbuf, zlib.MAX_WBITS | 16)

			if entrytype == 4 or entrytype == 9:
				## then try to get the name of the file
				plfnameend = plfbuf.find('\x00')
				if plfnameend != -1:
					plfname = plfbuf[0:plfnameend]
					lenplfname = len(plfname) + 1
					plfname = os.path.normpath(plfname)
					if plfname.startswith('/'):
						plfname = plfname[1:]

			## process files
			if entrytype == 9:
				fileentry = plfbuf[lenplfname:lenplfname+12]
				fileflags = struct.unpack('<I', fileentry[0:4])[0]
				if (fileflags >> 12) == 0x04:
					if len(plfname) + 1 + len(fileentry) == entrysize:
						os.mkdir(os.path.join(tmpdir, plfname))
						dataunpacked = True
				elif (fileflags >> 12) == 0x08:
					tmpfile = tempfile.mkstemp(dir=tmpdir)
					os.write(tmpfile[0], plfbuf[lenplfname+len(fileentry):])
					os.fdopen(tmpfile[0]).close()
					if plfname != '':
						try:
							os.makedirs(os.path.dirname(os.path.join(tmpdir, plfname)))
						except:
							pass
						shutil.move(tmpfile[1], os.path.join(tmpdir, plfname))
					else:
						pass
					dataunpacked = True
				elif (fileflags >> 12) == 0x0a:
					plfbuf = plfbuf[len(plfname) + 1 + len(fileentry):]
					symlinknameend = plfbuf.find('\x00')
					if symlinknameend != -1:
						dataunpacked = True
						pass
			elif entrytype == 4:
				tmpfile = tempfile.mkstemp(dir=tmpdir)
				os.write(tmpfile[0], plfbuf[lenplfname:])
				os.fdopen(tmpfile[0]).close()
				if plfname != '':
					try:
						os.makedirs(os.path.dirname(os.path.join(tmpdir, plfname)))
					except Exception, e:
						pass
					shutil.move(tmpfile[1], os.path.join(tmpdir, plfname))
				else:
					pass
				dataunpacked = True
			else:
				## unsure what to do with the other PLF data, so
				## just write it to a file and make it available
				## for further analysis
				tmpfile = tempfile.mkstemp(dir=tmpdir)
				os.write(tmpfile[0], plfbuf)
				os.fdopen(tmpfile[0]).close()
				dataunpacked = True
				newdir = True
				## the offsets are actually incorrect. TODO: fix this
				blacklist.append((offset, localoffset))
				diroffsets.append((tmpdir, offset, localoffset-offset))
				counter += 1

			localoffset += entrysize + sectionheadersize
			if (localoffset -offset) % 4 != 0:
				correction = 4 - (localoffset -offset) % 4
				localoffset += correction
			plffile.seek(localoffset)
			plfentryheader = plffile.read(sectionheadersize)

		if dataunpacked:
			blacklist.append((offset, localoffset))
			diroffsets.append((tmpdir, offset, localoffset-offset))
			counter += 1
		else:
			os.rmdir(tmpdir)
	plffile.close()

	return (diroffsets, blacklist, newtags, hints)
