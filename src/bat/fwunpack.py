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

import sys, os, subprocess, os.path, shutil, stat, array, struct, binascii, json, math
import tempfile, bz2, re, magic, tarfile, zlib, copy, uu, hashlib, StringIO, zipfile
import fsmagic, extractor, ext2, jffs2, prerun, javacheck, elfcheck
from collections import deque
import xml.dom

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

## a convenience method to set up a temporary directory if necessary
def unpacksetup(tempdir):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	return tmpdir

## Carve a file from a larger file, or simply copy or hardlink the file.
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

	## If the whole file needs to be scanned, then either copy it, or hardlink it.
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
	if not 'text' in offsets:
		return ([], blacklist, [], hints)
	pass

## unpack base64 files
## There are quite a few false positives, for example ld.so.conf on
## Linux systems
def searchUnpackBase64(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if os.path.basename(filename) == 'ld.so.conf':
		if '/etc/ld.so.conf' in filename:
			## just ignore ld.so.conf
			return ([], blacklist, [], hints)

	## open the file, read a line and see if there is anything in there
	## that is not [a-zA-Z0-9=\n] because then it is not a valid base64
	## file.
	base64indexes = set('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=\n')
	base64file = open(filename, 'rw')
	base64data = base64file.readline()
	while base64data != '':
		if filter(lambda x: x not in base64indexes, base64data) != '':
			base64file.close()
			return ([], blacklist, [], hints)
		base64data = base64file.readline()
	base64file.close()
	
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
## are compressed but some are.
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
		## represent the total length of the inode. If the total length of the
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

def searchUnpackKnownAr(filename, tempdir=None, scanenv={}, debug=False):
	## first check if the file actually could be a valid ar file
	arfile = open(filename, 'rb')
	arfile.seek(0)
	arheader = arfile.read(7)
	arfile.close()
	if arheader != fsmagic.fsmagic['ar']:
		return ([], [], [], {})

	## then try unpacking it.
	res = searchUnpackAr(filename, tempdir, [], {'ar': [0]}, scanenv, debug)
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
	arfile = open(filename, 'rb')
	for offset in offsets['ar']:
		dataunpacked = False
		## check if the offset found is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## extra sanity check, the byte following the magic is always '\x0a'
		localoffset = offset + 7
		arfile.seek(localoffset)
		archeckbyte = arfile.read(1)
		localoffset += 1
		if archeckbyte != '\x0a':
			continue

		tmpdir = dirsetup(tempdir, filename, "ar", counter)

		filenamecount = {}

		## Then the content of the archive follows. Each entry consists of a
		## file, followed by the actual data.
		## The file header is 60 bytes long and has 0x60 0x0a
		## at the end.
		## https://en.wikipedia.org/wiki/Ar_%28Unix%29
		## http://www.freebsd.org/cgi/man.cgi?query=ar&sektion=5
		## TODO: filenames could occur multiple times
		filenames = deque()
		longfilenames = False
		while localoffset + 60 <= filesize:
			arfile.seek(localoffset)
			arbytes = arfile.read(60)
			if not arbytes[-2:] == '\x60\x0a':
				break
			## first read the ar file size
			try:
				entrysize = int(arbytes[48:58].rstrip())
			except:
				break
			if localoffset + 60 + entrysize > filesize:
				break
			entryfilename = arbytes[0:16]
			if '//' in entryfilename:
				## System V/GNU long filenames, all filenames stored in
				## a special section
				longfilenames = True
				arbytes = arfile.read(entrysize)
				for fn in arbytes.split('\n'):
					 filenames.append(fn.split('/', 1)[0])
				localoffset += 60 + entrysize
				if localoffset % 2 != 0:
					localoffset += 1
				continue
			elif '#1/' in entryfilename:
				## BSD ar, filenames with spaces, or too long for ar header
				pass
			elif '/' in entryfilename:
				if entryfilename.startswith('/'):
					if longfilenames:
						entryfilename = filenames.popleft()
					else:
						localoffset += 60 + entrysize
						if localoffset % 2 != 0:
							localoffset += 1
						continue
				else:
					## space in the filename
					entryfilename = entryfilename.split('/', 1)[0]
			else:
				## regular short filename
				entryfilename = entryfilename.rstrip()

			## now write the data
			outfilename = os.path.join(tmpdir, entryfilename)

			## this is an ugly hack for now to deal with
			## archives created for Windows in COFF format. TODO
			try:
				os.path.exists(outfilename)
			except:
				break

			## if there are files with the same name included, modify
			## the name first and then copy the contents
			if os.path.exists(outfilename):
				if outfilename in filenamecount:
					filenamecount[outfilename] += 1
				else:
					filenamecount[outfilename] = 1
				outfilename = outfilename + "-copy-%d" % filenamecount[outfilename]
			arentry = open(outfilename, 'wb')
			arentry.write(arfile.read(entrysize))
			arentry.close()
			dataunpacked = True

			localoffset += 60 + entrysize
			if localoffset % 2 != 0:
				localoffset += 1

		if dataunpacked:
			if offset == 0 and localoffset == filesize:
				newtags.append("ar")
			diroffsets.append((tmpdir, offset, localoffset - offset))
			blacklist.append((offset, localoffset))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
	arfile.close()
	return (diroffsets, blacklist, newtags, hints)

## Unpack ISO 9660 file systems. Currently supports plain ISO9660, Rock Ridge and zisofs.
## TODO: Joliet
## https://en.wikipedia.org/wiki/ISO_9660
## http://wiki.osdev.org/ISO_9660
## http://libburnia-project.org/wiki/zisofs
## http://pismotec.com/cfs/jolspec.html
##
## For zisofs systems the assumption is made that they were created by (for example)
## running mkisofs with the rock ridge and -z options.
def searchUnpackISO9660(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'iso9660' in offsets:
		return ([], blacklist, [], hints)
	if offsets['iso9660'] == []:
		return ([], blacklist, [], hints)

	userockridge = True
	newtags = []

	## disable Rock Ridge on request
	if 'ISO9660_NO_ROCKRIDGE' in scanenv:
		userockridge = False

	## SUSP entries, used by Rock Ridge
	suspentries = ['CE', 'PD', 'SP', 'ST', 'ER', 'ES']

	## Rock Ridge system use entries
	rockridgeentries = ['PX', 'PN', 'SL', 'NM', 'CL', 'PL', 'RE', 'TF', 'SF', 'RR']

	## other extensions, such as zisofs
	customentries = ['ZF']

	diroffsets = []
	counter = 1
	isofile = open(filename, 'rb')
	filesize = os.stat(filename).st_size

	## set a few variables that need to be (re)set for each ISO image
	## contained in the file
	primaryvolumedescripterseen = False
	havebootrecord = False
	haveextensions = False
	havejoliet = False
	primaryoffset = None
	validiso = True
	previousoffset = offsets['iso9660'][0]

	## walk all of the offsets. A valid ISO image will have at least two of these:
	## primary volume descriptor and terminator
	for offset in offsets['iso9660']:
		## according to /usr/share/magic the magic header can be found at start of ISO9660 + 0x8001
		if offset < 32769:
			continue

		## a volume descriptor should be 2048 bytes
		if offset-1+2048 > filesize:
			break

		## volume descriptors have to be continuous
		if not primaryoffset == None:
			if offset - previousoffset != 2048:
				primaryvolumedescripterseen = False
				havebootrecord = False
				haveextensions = False
				havejoliet = False
				primaryoffset = None
				continue

		## check if the offset found is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue

		## version byte, should be 1 according to ECMA-119/ISO9660
		isofile.seek(offset+5)
		isobyte = isofile.read(1)
		if isobyte != '\x01':
			continue
		## the volume descriptor type precedes the magic marker
		isofile.seek(offset-1)
		isobyte = isofile.read(1)

		if isobyte == '\x00':
			## record the boot record. This is important to detect bootable CDs that might use isolinux
			## but not relevant for storing the CD's content.
			havebootrecord = True
			isofile.seek(offset -1 + 7)
			bootsystemidentifier = isofile.read(32)
			bootidentifier = isofile.read(32)
		elif isobyte == '\x01':
			## process the primary volume descriptor
			## read the volume space size
			isofile.seek(offset-1+80)
			isobytes = isofile.read(8)

			## a lot of the data is stored in little endian and big endian
			## format and often needs to match
			if struct.unpack('<I', isobytes[0:4])[0] != struct.unpack('>I', isobytes[4:8])[0]:
				continue

			volumespacesize = struct.unpack('<I', isobytes[0:4])[0]
		
			## read the logical block size. This will almost always be 2048, but
			## could be different.
			isofile.seek(offset-1+128)
			isobytes = isofile.read(4)
			if struct.unpack('<H', isobytes[0:2])[0] != struct.unpack('>H', isobytes[2:4])[0]:
				continue
			logicalblocksize = struct.unpack('<H', isobytes[0:2])[0]

			## the total length of the file system is defined
			## as volumespacesize * logicalblocksize
			fslength = volumespacesize * logicalblocksize
			if fslength + offset - 32769 > filesize:
				continue

			## logical block size is followed by the path table size
			isobytes = isofile.read(8)
			if struct.unpack('<I', isobytes[0:4])[0] != struct.unpack('>I', isobytes[4:8])[0]:
				continue
			pathtablesize = struct.unpack('<I', isobytes[0:4])[0]
			if pathtablesize + offset - 32769 > filesize:
				continue

			## followed by the LBA location of the "L-path table"
			## mpath and lpath are typically not used by Linux
			isobytes = isofile.read(4)
			lpathlocation = struct.unpack('<I', isobytes)[0]
			#if (lpathlocation * logicalblocksize) + offset - 32769 > filesize:
			#	continue

			## and the LBA location of the "M-path table"
			isobytes = isofile.read(4)
			mpathlocation = struct.unpack('>I', isobytes)[0]
			#if (mpathlocation * logicalblocksize) + offset - 32769 > filesize:
			#	continue

			## There is a root directory entry (34 bytes) at offset - 1 + 156
			isofile.seek(offset-1+156)
			isobytes = isofile.read(34)
			## the directory entry should always have length 34
			if ord(isobytes[0]) != 34:
				continue

			## the length of the extended attribute record cannot
			## exceed the length of the file
			extendedattributerecordlength = ord(isobytes[1])
			if extendedattributerecordlength + offset - 32769 > filesize:
				continue

			## then the location of the extent, recorded as the block number,
			## so multiply with logicalblocksize
			if struct.unpack('<I', isobytes[2:6])[0] != struct.unpack('>I', isobytes[6:10])[0]:
				continue
			rootextentlocation = struct.unpack('<I', isobytes[2:6])[0]
			## extent cannot be located outside of the file
			if (rootextentlocation * logicalblocksize) + offset - 32769 > filesize:
				continue

			## then the extent size
			if struct.unpack('<I', isobytes[10:14])[0] != struct.unpack('>I', isobytes[14:18])[0]:
				continue
			rootextentsize = struct.unpack('<I', isobytes[10:14])[0]

			## extent cannot be located outside of the file
			if rootextentsize + (rootextentlocation * logicalblocksize) + offset - 32769 >  filesize:
				continue

			## then the date, ignore for now
			extentdate = isobytes[18:25]

			extentfileflags = isobytes[25]
			## check if the root entry is actually a directory
			if (ord(extentfileflags) >> 1 & 1) != 1:
				continue

			## filename size, should be 1 for the root
			extentfilenamesize = ord(isobytes[32])
			if extentfilenamesize != 1:
				continue

			primaryvolumedescripterseen = True
			primaryoffset = offset
		elif isobyte == '\x02':
			## extensions, such as joliet. If so, then it might be possible
			## or necessary to translate the file names using the information
			## in this section.
			isofile.seek(offset-1+88)
			isobytes = isofile.read(3)
			if isobytes in ['\x25\x2f\x40', '\x25\x2f\x43', '\x25\x2f\x45']:
				havejoliet = True
		elif isobyte == '\xff':
			## volume descriptor set terminator. If it is just a standalone
			## terminator then it makes no sense to continue.
			if not primaryvolumedescripterseen:
				continue

			if primaryoffset == None:
				continue

			tmpdir = dirsetup(tempdir, filename, "iso9660", counter)

			## keep track of information for relocated directories
			## logical block address of extent -> extent name
			extenttoname = {}

			## keep a list of translated names in case of deep directories
			translatednames = {}

			## keep a list of directories that need to be relocated (deep directories)
			toberelocated = {}

			## CL entries (deep directories)
			clentries = {}

			extenttoparent = {}

			## keep a list of extents to parent directories (deep directories)
			relocatedextenttoparent = {}

			## keep a list of relocated directories to parents (PL field) (deep directories)
			relocatedtoparent = {}

			## populate the queue with the first entry
			extentqueue = deque([(rootextentlocation, rootextentsize, "", True)])
			dotdot = rootextentlocation

			while len(extentqueue) != 0:
				if not validiso:
					break
				(thisextentlocation, thisextentsize, parentdirname, inroot) = extentqueue.popleft()
				## jump to the extent for the root of the file system and walk it, fill up a queue
				## with files that need to be looked at.
				isofile.seek((thisextentlocation * logicalblocksize) + primaryoffset - 32769)
				isobytes = isofile.read(thisextentsize)

				directoryentryoffset = 0
				lenisobytes = len(isobytes)
				while directoryentryoffset < lenisobytes:
					if not validiso:
						break
					diroffsetlen = ord(isobytes[directoryentryoffset])
					if diroffsetlen == 0:
						if 2048 - directoryentryoffset%2048 < 255:
							directoryentryoffset += (2048 - directoryentryoffset%2048)
							continue
						else:
							## according to the specification unused
							## positions after the last byte record are set to 0
							break
					## the length of the extended attribute record cannot
					## exceed the length of the file
					extendedattributerecordlength = ord(isobytes[directoryentryoffset+1])
					if extendedattributerecordlength + primaryoffset - 32769 > filesize:
						validiso = False
						break

					## then the location of the extent with the actual content, recorded as the block number
					if struct.unpack('<I', isobytes[directoryentryoffset+2:directoryentryoffset+6])[0] != struct.unpack('>I', isobytes[directoryentryoffset+6:directoryentryoffset+10])[0]:
						validiso = False
						break
					extentlocation = struct.unpack('<I', isobytes[directoryentryoffset+2:directoryentryoffset+6])[0]
					## extent cannot be located outside of the file
					if (extentlocation * logicalblocksize) + primaryoffset - 32769 > filesize:
						validiso = False
						break

					## then the extent size
					if struct.unpack('<I', isobytes[directoryentryoffset+10:directoryentryoffset+14])[0] != struct.unpack('>I', isobytes[directoryentryoffset+14:directoryentryoffset+18])[0]:
						validiso = False
						break
					extentsize = struct.unpack('<I', isobytes[directoryentryoffset+10:directoryentryoffset+14])[0]

					## extent cannot be located outside of the file
					if extentsize + (extentlocation * logicalblocksize) + primaryoffset - 32769 >  filesize:
						validiso = False
						break

					## then the date, ignore for now
					extentdate = isobytes[directoryentryoffset+18:directoryentryoffset+25]

					extentfileflags = isobytes[directoryentryoffset+25]

					## filename size, should be 1 for the root
					extentfilenamesize = ord(isobytes[directoryentryoffset+32])

					extentfilename = isobytes[directoryentryoffset+33:directoryentryoffset+33+extentfilenamesize]
					ishidden = False
					isdirectory = False
					isassociatedfile = False
					isfinaldirectory = True
					if (ord(extentfileflags) & 1) == 1:
						ishidden = True
					if (ord(extentfileflags) >> 1 & 1) == 1:
						isdirectory = True
					if (ord(extentfileflags) >> 2 & 1) == 1:
						isassociatedfile = True
					if (ord(extentfileflags) >> 3 & 1) == 1:
						pass
					if (ord(extentfileflags) >> 4 & 1) == 1:
						pass
					if (ord(extentfileflags) >> 7 & 1) == 1:
						isfinaldirectory = False

					if not isdirectory:
						pass ## TODO, as in case of relocated files it does not
						## always work correctly
						## check for the file name
						#if extentfilename[-2] != ';':
							#pass
							#break

					## now check the "system use" field in the directory record to
					## see if Rock Ridge is used by checking for the 'SP' record (defined
					## in SUSP), but only for the root of the file system
					if extentfilename == '\x00':
						if userockridge:
							if inroot:
								if diroffsetlen > 33+extentfilenamesize+2:
									## grab the first two bytes from the system use field to see if they are 'SP'
									if isobytes[directoryentryoffset+33+extentfilenamesize:directoryentryoffset+33+extentfilenamesize+2] == 'SP':
										if haveextensions:
											validiso = False
											break
										haveextensions = True
										## record how many bytes to skip in the system use field
										## to get to the rock ridge information
										rockridgeskip = ord(isobytes[directoryentryoffset+33+extentfilenamesize+9])
					elif extentfilename == '\x01':
						## check the '..' link. In case of "deep directories" this
						## information is important.
						if not inroot:
							## extentlocation points to '..'
							extenttoparent[thisextentlocation] = extentlocation
							dotdot = extentlocation
							if haveextensions:
								localoffset = directoryentryoffset+33+extentfilenamesize
								if localoffset % 2 != 0:
									localoffset += 1
								while localoffset < directoryentryoffset + diroffsetlen:
									extension = isobytes[localoffset:localoffset+2]
									if not (extension in rockridgeentries or extension in customentries or extension in suspentries):
										break
									rrlen = ord(isobytes[localoffset+2])
									if directoryentryoffset + rrlen > lenisobytes:
										validiso = False
										break
									if extension == 'PL':
										## PL is needed ## for relocating directories
										if not struct.unpack('<I', isobytes[localoffset+4:localoffset+8])[0] == struct.unpack('>I', isobytes[localoffset+8:localoffset+12])[0]:
											validiso = False
											break
										originalparentlocation = struct.unpack('<I', isobytes[localoffset+4:localoffset+8])[0]
										relocatedtoparent[thisextentlocation] = originalparentlocation
									localoffset += rrlen
					else:
						## now look at everything that is not '.' or '..'
						islink = False
						iszisofs = False
						localoffset = directoryentryoffset+33+extentfilenamesize
						dontwrite = False
						isrelocated = False
						alternatename = ""
						if localoffset % 2 != 0:
							localoffset += 1
						if haveextensions:
							symlinktargetname = ""
							continuelinkname = False
							islinkpx = False
							delayeddirectorycheck = False
							while localoffset < directoryentryoffset + diroffsetlen:
								extension = isobytes[localoffset:localoffset+2]
								if not (extension in rockridgeentries or extension in customentries or extension in suspentries):
									break
								rrlen = ord(isobytes[localoffset+2])
								if directoryentryoffset + rrlen > lenisobytes:
									validiso = False
									break
								if extension == 'ZF':
									iszisofs = True
								elif extension == 'PX':
									pxversion = ord(isobytes[localoffset+3])
									if pxversion != 1:
										validiso = False
										break
									if rrlen < 12:
										validiso = False
										break
									if not struct.unpack('<I', isobytes[localoffset+4:localoffset+8])[0] == struct.unpack('>I', isobytes[localoffset+8:localoffset+12])[0]:
										validiso = False
										break
									posixfilemode = struct.unpack('<I', isobytes[localoffset+4:localoffset+8])[0]
									## filter pipes, sockets, etc. and sanity check directories, symlinks and files
									if posixfilemode >= 0140000:
										## no need for sockets
										break
									if posixfilemode >= 0120000:
										## store if the file is a symlink
										islinkpx = True
									else:
										if posixfilemode < 0040000:
											## pipe, FIFO, character device
											break
										if posixfilemode >= 0060000:
											## regular file or block device
											if posixfilemode < 0100000:
												break
											## it should be a regular file. Sanity check to see
											## if the ISO9660 information says it is a directory
											if isdirectory:
												validiso = False
												break
										else:
											## check if the directory is really a directory.
											## If there are relocations this will not work.
											if not isdirectory:
												delayeddirectorycheck = True
								elif extension == 'PN':
									## skip over the PN field, as block and character devices
									## are not interesting
									pass
								elif extension == 'SL':
									islink = True
									## look at the SL component flags
									componentflags = isobytes[localoffset+5]
									if (ord(componentflags) >> 6 & 1) == 1:
										validiso = False
										break
									if (ord(componentflags) >> 7 & 1) == 1:
										validiso = False
										break
									if (ord(componentflags) & 1) == 1:
										continuelinkname = True
									elif (ord(componentflags) >> 1 & 1) == 1:
										if continuelinkname:
											validiso = False
											break
										else:
											symlinktargetname = '.'
									elif (ord(componentflags) >> 2 & 1) == 1:
										if continuelinkname:
											validiso = False
											break
										else:
											if inroot:
												symlinktargetname = '.'
											else:
												symlinktargetname = '..'
									elif (ord(componentflags) >> 3 & 1) == 1:
										if continuelinkname:
											validiso = False
											break
										else:
											symlinktargetname = '/'
									else:
										symlinktargetlength = ord(isobytes[localoffset+6])
										if directoryentryoffset + symlinktargetlength > lenisobytes:
											validiso = False
											break
										symlinktargetname += isobytes[localoffset+7:localoffset+7+symlinktargetlength]
								elif extension == 'NM':
									## there can be multiple 'NM' entries to make
									## longer names possible.
									alternatename += isobytes[localoffset+5:localoffset+rrlen]
								elif extension == 'CL':
									## The CL field is needed for relocating directories
									delayeddirectorycheck = False
									if not struct.unpack('<I', isobytes[localoffset+4:localoffset+8])[0] == struct.unpack('>I', isobytes[localoffset+8:localoffset+12])[0]:
										validiso = False
										break
									childlocation = struct.unpack('<I', isobytes[localoffset+4:localoffset+8])[0]
									## record the parent of the child location
									clentries[childlocation] = thisextentlocation
									## an empty file with the same name will be written, but
									## this is not really needed.
									dontwrite = True
								elif extension == 'RE':
									## record the name of the RE field. This is needed
									## for identifiying directories that were relocated.
									isrelocated = True
								elif extension == 'TF':
									## skip over the TF field as time information
									## is not interesting
									pass
								elif extension == 'SF':
									## skip over the SF field for now. Sparse files
									## are rare
									pass
								localoffset += rrlen

							## now process the result of the delayed directory
							## check if any.
							if delayeddirectorycheck:
								validiso = False
								break

						if not isdirectory:
							if islink:
								origoutfilename = extentfilename.rsplit(';', 1)[0]
								while os.path.isabs(origoutfilename):
									origoutfilename = origoutfilename[1:]
								if alternatename != '':
									outfilename = alternatename
								else:
									outfilename = origoutfilename
								while os.path.isabs(outfilename):
									outfilename = outfilename[1:]
								oldcwd = os.getcwd()
								os.chdir(os.path.join(tmpdir, parentdirname))
								os.symlink(symlinktargetname, alternatename)
								os.chdir(oldcwd)
							else:
								if dontwrite:
									## this is for a CL entry, so record the parent
									relocatedextenttoparent[extentlocation] = thisextentlocation
								else:
									## regular file, so grab contents and write them
									## to a file.
									origoutfilename = extentfilename.rsplit(';', 1)[0]
									while os.path.isabs(origoutfilename):
										origoutfilename = origoutfilename[1:]
									if alternatename != '':
										outfilename = alternatename
									else:
										outfilename = origoutfilename
									while os.path.isabs(outfilename):
										outfilename = outfilename[1:]
									oldoffset = isofile.tell()
									isofile.seek(extentlocation * logicalblocksize + primaryoffset - 32769)
									curfilename = os.path.join(tmpdir, parentdirname, outfilename)
									outfile = open(curfilename, 'wb')
									if not iszisofs:
										## regular files, also in zisofs file
										## systems if they were not compressed.
										outfile.write(isofile.read(extentsize))
									else:
										## first zisofs magic header
										isodata = isofile.read(8)
										if not isodata == '\x37\xe4\x53\x96\xc9\xdb\xd6\x07':
											validiso = False
											break

										## followed by the original size
										isodata = isofile.read(4)
										if not len(isodata) == 4:
											validiso = False
											break
										uncompressed_size = struct.unpack('<I', isodata)[0]
										isodata = isofile.read(1)
										if not len(isodata) == 1:
											validiso = False
											break
										header_size = ord(isodata)
										if header_size != 4:
											validiso = False
											break
										real_header_size = header_size << 2

										isodata = isofile.read(1)
										if not len(isodata) == 1:
											validiso = False
											break
										block_size_byte = ord(isodata)
										if not block_size_byte in [15,16,17]:
											validiso = False
											break
										block_size = pow(2,block_size_byte)

										numberofblocks = int(math.ceil(uncompressed_size/block_size)) + 1
										## then seek past the header to process
										## the meta information about each compressed
										## block. The list contains one final pointer
										## that is indicates the start of the
										## non-zlib data.
										isofile.seek(extentlocation * logicalblocksize + primaryoffset - 32769 + real_header_size)
										blockpointers = []
										for bl in xrange(0,numberofblocks+1):
											blpointerbytes = isofile.read(4)
											if len(blpointerbytes) != 4:
												validiso = False
												break
											blpointer = struct.unpack('<I', blpointerbytes)[0]
											blockpointers.append(blpointer)
										blockswritten = 0
										for bl in xrange(0, len(blockpointers)-1):
											if (blockpointers[bl] + extentlocation * logicalblocksize + primaryoffset - 32769) > filesize:
												validiso = False
												break
											if (blockpointers[bl+1] + extentlocation * logicalblocksize + primaryoffset - 32769) > filesize:
												validiso = False
												break
											isofile.seek(extentlocation * logicalblocksize + primaryoffset - 32769 + blockpointers[bl])
											isodata = isofile.read(blockpointers[bl+1] - blockpointers[bl])
											deflateobj = zlib.decompressobj()
											uncompresseddata = deflateobj.decompress(isodata)
											outfile.write(uncompresseddata)
											blockswritten += 1
										if not validiso:
											outfile.close()
											os.unlink(curfilename)
											break
									outfile.close()
									isofile.seek(oldoffset)
						else:
							## create directories
							if alternatename != '':
								curdirfilename = os.path.join(parentdirname, alternatename)
							else:
								curdirfilename = os.path.join(parentdirname, extentfilename)
							while os.path.isabs(curdirfilename):
								curdirfilename = curdirfilename[1:]
							origcurdirfilename = curdirfilename
							extenttoname[extentlocation] = origcurdirfilename

							## it could be that there are relocated directories with the
							## same alternate name. In that case create a temporary directory
							## and record the name somewhere so it can be changed later.
							if os.path.exists((os.path.join(tmpdir, curdirfilename))):
								while True:
									try:
										tempdirname = tempfile.mkdtemp(dir=os.path.join(tmpdir, parentdirname))
										curdirfilename = os.path.join(parentdirname, os.path.basename(tempdirname))
										translatednames[curdirfilename] = origcurdirfilename
										break
									except Exception, e:
										pass
							else:
								os.mkdir(os.path.join(tmpdir, curdirfilename))

							## record the parent for each directory that will be visited
							relocatedextenttoparent[extentlocation] = thisextentlocation

							## queue the extent so it can be visited.
							extentqueue.append((extentlocation, extentsize, curdirfilename, False))
							if isrelocated:
								if extentfilename in toberelocated:
									toberelocated[curdirfilename].append({'parent': thisextentlocation, 'self': extentlocation})
								else:
									toberelocated[curdirfilename] = [{'parent': thisextentlocation, 'self': extentlocation}]

					## finally go to the next directory record
					directoryentryoffset += diroffsetlen
					if directoryentryoffset % 2 != 0:
						break

			## now move any replaced directories into the right place
			for relocentry in toberelocated:
				## walk the RE entries. The 'self' field has to
				## correspond to the key of a 'CL' entry (child location).
				lenrelocentry = len(relocentry)
				if relocentry in translatednames:
					translatedlenrelocentry = len(translatednames[relocentry])
				for reloc in toberelocated[relocentry]:
					if not reloc['self'] in clentries:
						continue
					if not reloc['self'] in relocatedtoparent:
						continue
					## The entry of PL should correspond to the parent of the
					## CL value, which was recorded in clentries
					cl = clentries[reloc['self']]
					if not cl in relocatedextenttoparent:
						continue
					if not cl == relocatedtoparent[reloc['self']]:
						continue
					shutil.move(os.path.join(tmpdir, relocentry), os.path.join(tmpdir, extenttoname[cl]))
					if relocentry in translatednames:
						oldcwd = os.getcwd()
						os.chdir(os.path.join(tmpdir, extenttoname[cl]))
						shutil.move(os.path.basename(relocentry), os.path.basename(translatednames[relocentry]))
						os.chdir(oldcwd)
						translatename = os.path.join(extenttoname[cl], os.path.basename(translatednames[relocentry]))
					else:
						translatename = os.path.join(extenttoname[cl], os.path.basename(relocentry))

					## now fix every other instance too
					for ex in extenttoname:
						if extenttoname[ex] == relocentry:
							if relocentry in translatednames:
								extenttoname[ex] = translatename
						if extenttoname[ex].startswith(relocentry):
							newextentname = extenttoname[ex][lenrelocentry:]
							while os.path.isabs(newextentname):
								newextentname = newextentname[1:]
							extenttoname[ex] = os.path.join(translatename, newextentname)

			## Add the results to the result list and the black list and continue
			## with the next image.
			diroffsets.append((tmpdir, primaryoffset - 32769, fslength))
			blacklist.append((primaryoffset - 32769, primaryoffset - 32769 + fslength))
			counter = counter + 1
			if primaryoffset - 32769 == 0 and fslength == os.stat(filename).st_size:
				## whole file, so return right away
				isofile.close()
				newtags.append('iso9660')
				return (diroffsets, blacklist, newtags, hints)
			primaryvolumedescripterseen = False
			havebootrecord = False
			haveextensions = False
			havejoliet = False
			primaryoffset = None
			validiso = True

		if not primaryoffset == None:
			previousoffset = offset
	isofile.close()
	return (diroffsets, blacklist, newtags, hints)

## unpacking xar archives
## https://github.com/mackyle/xar/wiki/xarformat
def searchUnpackXar(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'xar' in offsets:
		return ([], blacklist, [], hints)
	if offsets['xar'] == []:
		return ([], blacklist, [], hints)

	newtags = []
	counter = 1
	diroffsets = []
	filesize = os.stat(filename).st_size
	xarfile = open(filename, 'rb')
	for offset in offsets['xar']:
		xarfile.seek(offset+4)
		dataunpacked = False

		## sanity checks first for the header, the compression, etc.
		## First the size of the header
		xarbytes = xarfile.read(2)
		if len(xarbytes) != 2:
			break
		headerlength = struct.unpack('>H', xarbytes)[0]
		if headerlength + offset > filesize:
			continue

		## Then the number. So far only 1 has been used
		xarbytes = xarfile.read(2)
		if len(xarbytes) != 2:
			break
		if struct.unpack('>H', xarbytes)[0] != 1:
			continue

		## Then the length of the table of contents (compressed)
		xarbytes = xarfile.read(8)
		if len(xarbytes) != 8:
			break
		toccompressedlength = struct.unpack('>Q', xarbytes)[0]
		if toccompressedlength + offset > filesize:
			continue

		## Then the length of the table of contents (uncompressed)
		## Use this for sanity check after decompression of TOC
		xarbytes = xarfile.read(8)
		if len(xarbytes) != 8:
			break
		tocuncompressedlength = struct.unpack('>Q', xarbytes)[0]

		## Then the checksum algorithm. Only support 'none', MD5 or SHA1
		## for now.
		xarbytes = xarfile.read(4)
		if len(xarbytes) != 4:
			break
		checksumalgorithm = struct.unpack('>I', xarbytes)[0]
		if not checksumalgorithm in [0,1,2]:
			continue

		## offsets in the TOC are relative to after end of the compressed TOC
		localoffset = offset + toccompressedlength + headerlength

		## now read the TOC
		xarbytes = xarfile.read(toccompressedlength)
		toc = zlib.decompress(xarbytes)
		if len(toc) != tocuncompressedlength:
			continue
		try:
			dom = xml.dom.minidom.parseString(toc)
		except:
			continue

		## now walk the DOM file to get information about the files
		## Verify that the XML file is actually correct
		if not dom.documentElement.tagName == 'xar':
			continue

		rootchildnodes = dom.documentElement.childNodes
		havetoc = False
		for r in rootchildnodes:
			if r.nodeType == xml.dom.Node.ELEMENT_NODE:
				if r.tagName == 'toc':
					if havetoc:
						## there should only be one instance of toc
						havetoc = False
						break
					havetoc = True
					tocnode = r
		if not havetoc:
			continue

		## now create the directory
		tmpdir = dirsetup(tempdir, filename, "xar", counter)

		## elements inside toc can be 'checksum', 'file', 'x-signature'
		## 'creation-time' and 'signature'. 'file' elements can be nested
		## to create a directory structure.
		nodes = deque(map(lambda x: (x, tmpdir), tocnode.childNodes))
		brokentoc = False
		maxoffset = localoffset
		while len(nodes) != 0:
			if brokentoc:
				break
			(ch, curdir) = nodes.popleft()
			if ch.nodeType == xml.dom.Node.ELEMENT_NODE:
				if ch.tagName == 'file':
					filenodes = ch.childNodes
					childname = ''
					childtype = ''
					childdata = None
					newchildnodes = []
					for fch in filenodes:
						if fch.nodeType == xml.dom.Node.ELEMENT_NODE:
							if fch.tagName == 'name':
								for n in fch.childNodes:
									if n.nodeType == xml.dom.Node.TEXT_NODE:
										childname = n.data.strip()
							elif fch.tagName == 'type':
								for n in fch.childNodes:
									if n.nodeType == xml.dom.Node.TEXT_NODE:
										if n.data in ['file', 'directory']:
											childtype = n.data.strip()
							elif fch.tagName == 'data':
								childdata = fch
							elif fch.tagName == 'file':
								newchildnodes.append(fch)

					if childname != '' and childtype != '':
						if childtype == 'directory':
							childdirname = os.path.join(curdir, childname)
							os.mkdir(childdirname)
							dataunpacked = True
							for n in newchildnodes:
								nodes.append((n, childdirname))
						elif childtype == 'file':
							if childdata == None:
								## empty file
								childfile = open(os.path.join(curdir, childname), 'wb')
								childfile.close()
								## and reset for the next file
								childname = ''
								childtype = ''
								childdata = None
								continue

							## first extract the right data from the childdata node
							dataoffset = 0
							datasize = 0
							datalength = 0
							extractedchecksum = ''
							checksumtype = None
							compression = None
							childdatanodes = childdata.childNodes
							for childdatanode in childdatanodes:
								if childdatanode.nodeType == xml.dom.Node.ELEMENT_NODE:
									if childdatanode.tagName == 'offset':
										for n in childdatanode.childNodes:
											if n.nodeType == xml.dom.Node.TEXT_NODE:
												try:
													dataoffset = int(n.data.strip())
												except Exception, e:
													brokentoc = True
													break
									if childdatanode.tagName == 'size':
										for n in childdatanode.childNodes:
											if n.nodeType == xml.dom.Node.TEXT_NODE:
												try:
													datasize = int(n.data.strip())
												except Exception, e:
													brokentoc = True
													break
									if childdatanode.tagName == 'length':
										for n in childdatanode.childNodes:
											if n.nodeType == xml.dom.Node.TEXT_NODE:
												try:
													datalength = int(n.data.strip())
												except Exception, e:
													brokentoc = True
													break
									if childdatanode.tagName == 'extracted-checksum':
										for n in childdatanode.childNodes:
											if n.nodeType == xml.dom.Node.TEXT_NODE:
												extractedchecksum = n.data.strip()
										checksumstyle = childdatanode.getAttribute('style')
										if checksumstyle != '':
											if checksumstyle.lower() in ['md5', 'sha1']:
												checksumtype = checksumstyle
									if childdatanode.tagName == 'encoding':
										for n in childdatanode.childNodes:
											if n.nodeType == xml.dom.Node.TEXT_NODE:
												datachecksum = n.data.strip()
										compressionstyle = childdatanode.getAttribute('style')
										if compressionstyle != '':
											if compressionstyle.lower() == 'application/x-gzip':
												compression = 'gzip'
											elif compressionstyle.lower() == 'application/x-bzip2':
												compression = 'bzip2'
									if brokentoc:
										break
							if brokentoc:
								break

							if dataoffset != 0 and datalength != 0 and checksumtype != None:
								oldoffset = xarfile.tell()
								xarfile.seek(localoffset + dataoffset)
								childfilename = os.path.join(curdir, childname)
								childfile = open(childfilename, 'wb')
								databytes = xarfile.read(datalength)
								if compression == None:
									childfile.write(databytes)
									dataunpacked = True
								elif compression == 'bzip2':
									bzip2decompressobj = bz2.BZ2Decompressor()
									try:
										uncompresseddata = bzip2decompressobj.decompress(databytes)
										if bzip2decompressobj.unused_data != "":
											brokentoc = True
										else:
											childfile.write(uncompresseddata)
											dataunpacked = True
									except Exception, e:
										brokentoc = True
								elif compression == 'gzip':
									deflateobj = zlib.decompressobj()
									try:
										uncompresseddata = deflateobj.decompress(databytes)
										if deflateobj.unused_data != "":
											brokentoc = True
										else:
											childfile.write(uncompresseddata)
											dataunpacked = True
									except Exception, e:
										brokentoc = True
								childfile.close()
								xarfile.seek(oldoffset)
								if brokentoc:
									os.unlink(childfilename)
								else:
									if datasize != os.stat(childfilename).st_size:
										brokentoc = True
										os.unlink(childfilename)
								if localoffset + dataoffset + datalength > maxoffset:
									maxoffset = localoffset + dataoffset + datalength
							
						## and reset for the next file
						childname = ''
						childtype = ''
						childdata = None
		if brokentoc:
			if not dataunpacked:
				os.rmdir(tmpdir)
			continue
		counter += 1
		diroffsets.append((tmpdir, offset, maxoffset - offset))
		blacklist.append((offset, maxoffset))

	xarfile.close()

	return (diroffsets, blacklist, newtags, hints)

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
			shutil.rmtree(tmpdir)
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
		testtarfile = open(filename, 'rb')
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
		tarseen = set()
		for i in tarmembers:
			if i.name in tarseen:
				## skip double entries. TODO: some more checks
				continue
			tarseen.add(i.name)
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
			shutil.rmtree(tmpdir)
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

## unpack lzop archives.
def searchUnpackLzop(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'lzop' in offsets:
		return ([], blacklist, [], hints)
	if offsets['lzop'] == []:
		return ([], blacklist, [], hints)
	diroffsets = []
	tags = []
	counter = 1
	for offset in offsets['lzop']:
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
		if not ord(lzopversionbyte) in [1,2,3]:
			lzopfile.close()
			continue

		## extra sanity check: LZOP version that is needed.
		## the latest lzop version is 0x1030
		## if the version_needed field is larger than this
		## then it won't work
		## LZOP 1030 generates output files for 0940
		## which is very old, so this should not be a problem.
		lzopfile.seek(offset+13)
		lzopversionneeded = lzopfile.read(2)
		lzopfile.close()
		if struct.unpack('>H', lzopversionneeded)[0] > 0x1030:
			continue

		tmpdir = dirsetup(tempdir, filename, "lzop", counter)
		(res, lzopsize) = unpackLzop(filename, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset, lzopsize))
			blacklist.append((offset, offset+lzopsize))
			if offset == 0 and lzopsize == os.stat(filename).st_size:
				tags.append("compressed")
				tags.append("lzop")
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, tags, hints)

def unpackLzop(filename, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzop is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir, suffix='.lzo')
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir)

	p = subprocess.Popen(['lzop', "-d", "-P", "-p%s" % (tmpdir,), tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0 and p.returncode != 2:
		rmfiles = os.listdir(tmpdir)
		for r in rmfiles:
			rmfile = os.path.join(tmpdir, r)
			os.unlink(rmfile)
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

## To unpack XZ a header and a footer need to be found
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
	newtags = []
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
		return ([], blacklist, newtags, hints)
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
				diroffsets.append((res, offset, len(data)))
				if offset == 0 and len(data) == os.stat(filename).st_size:
					newtags.append('cpio')
				blacklist.append((offset, trailer + 10 + trailercorrection))
				counter = counter + 1
				## success with unpacking, no need to continue with
				## the next trailer for this offset
				break
			else:
				## cleanup
				os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, newtags, hints)

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
	newtags = []
	counter = 1
	for offset in offsets['romfs']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "romfs", counter)
		res = unpackRomfs(filename, offset, tmpdir, blacklist=blacklist)
		if res != None:
			(romfsdir, size) = res
			filesize = os.stat(filename).st_size
			if offset == 0 and size == filesize:
				newtags.append("romfs")
			diroffsets.append((romfsdir, offset, size))
			blacklist.append((offset, offset + size))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
        return (diroffsets, blacklist, newtags, hints)

def unpackRomfs(filename, offset, tempdir=None, unpacktempdir=None, blacklist=[]):
	## First check the size of the header. If it has some
	## bizarre value (like bigger than the file it can unpack)
	## it is not a valid romfs file system
	romfsfile = open(filename, 'rb')
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
	os.unlink(tmpfile[1])
	## then move all the contents using shutil.move()
	mvfiles = os.listdir(tmpdir2)
	for f in mvfiles:
		pathtomove = os.path.join(os.path.join(tmpdir2, f))
		if os.path.islink(pathtomove):
			if os.path.exists(pathtomove):
				shutil.move(pathtomove, tmpdir)
			else:
				linktarget = os.readlink(pathtomove)
				oldcwd = os.getcwd()
				os.chdir(tmpdir)
				os.symlink(linktarget, f)
				os.chdir(oldcwd)
				continue
		shutil.move(pathtomove, tmpdir)
	## then cleanup the temporary dir
	shutil.rmtree(tmpdir2)

	## determine the size and cleanup
	## Correct if romfssize%1024 == 0?
	romfssizecorrection = 1024 - romfssize%1024
	return (tmpdir, romfssize + romfssizecorrection)

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

	filesize = os.stat(filename).st_size
	counter = 1
	cramfsoffsets = le_offsets + be_offsets
	diroffsets = []
	newtags = []
	cramfsoffsets.sort()

	if not 'cramfs_be' in offsets:
		be_offsets = set()
	else:
		be_offsets = set(offsets['cramfs_be'])

	cramfsfile = open(filename, 'rb')
	for offset in cramfsoffsets:
		bigendian = False
		if offset in be_offsets:
			bigendian = True
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		cramfsfile.seek(offset)
		tmpbytes = cramfsfile.read(64)
		if len(tmpbytes) != 64:
			break
		if not tmpbytes[16:32] == "Compressed ROMFS":
			continue

		if bigendian:
			cramfslen = struct.unpack('>I', tmpbytes[4:8])[0]
		else:
			cramfslen = struct.unpack('<I', tmpbytes[4:8])[0]

		if bigendian:
			cramfsversion = struct.unpack('>I', tmpbytes[8:12])[0] & 1
		else:
			cramfsversion = struct.unpack('<I', tmpbytes[8:12])[0] & 1

		oldcramfs = False
		## check if the length of the cramfslen field does not
		## exceed the actual size of the file. This does not work
		## for cramfs versions that are version 0.
		validcramfs = True
		if cramfsversion != 0:
			if cramfslen > filesize - offset:
				continue

			## find out the amount of files, which includes the root inode
			## as well
			if bigendian:
				amountoffiles = struct.unpack('>I', tmpbytes[44:48])[0]
			else:
				amountoffiles = struct.unpack('<I', tmpbytes[44:48])[0]
			cramfsfile.seek(offset+64)

			## Then walk the inodes. 6 bits are for the name length, the
			## other 26 bits for the offset. Depending on whether or not the
			## file system is big endian or little endian some tricks have to
			## be performed to get the correct data out of the inode.
			## first the root node
			tmpbytes = cramfsfile.read(12)
			if len(tmpbytes) != 12:
				continue
			if bigendian:
				namelenoffset = struct.unpack('>I', tmpbytes[8:12])[0]
				namelength = (namelenoffset & 4227858432) >> 26
				entryoffset = (namelenoffset & 67108863)
			else:
				namelenoffset = struct.unpack('<I', tmpbytes[8:12])[0]
				namelength = namelenoffset & 63
				entryoffset = (namelenoffset & 4294967232) >> 6
				if entryoffset*4 > filesize - offset:
					validcramfs = False
					continue
			for a in range(1,amountoffiles):
				## first read the data of a cramfs_inode
				tmpbytes = cramfsfile.read(12)
				if len(tmpbytes) != 12:
					validcramfs = False
					break
				if bigendian:
					namelenoffset = struct.unpack('>I', tmpbytes[8:12])[0]
					namelength = (namelenoffset & 4227858432) >> 26
					entryoffset = (namelenoffset & 67108863)
				else:
					namelenoffset = struct.unpack('<I', tmpbytes[8:12])[0]
					namelength = namelenoffset & 63
					entryoffset = (namelenoffset & 4294967232) >> 6
				if namelength == 0:
					validcramfs = False
					break
				if entryoffset*4 > filesize - offset:
					validcramfs = False
					break
				## followed by the file name
				tmpbytes = cramfsfile.read(namelength*4)
				if len(tmpbytes) != namelength*4:
					validcramfs = False
					break
				filenameentry = tmpbytes.split('\x00', 1)[0]
		else:
			oldcramfs = True
			## this is an old cramfs version, so length
			## field does not mean anything, so just set it
			## to the entire file.
			cramfslen = filesize

		if not validcramfs:
			continue

		tmpdir = dirsetup(tempdir, filename, "cramfs", counter)
		retval = unpackCramfs(filename, offset, bigendian, cramfslen, oldcramfs, tmpdir, blacklist=blacklist)
		if retval != None:
			(res, cramfssize) = retval
			if cramfssize != 0:
				blacklist.append((offset,offset+cramfssize))
			if cramfssize == filesize:
				newtags.append("cramfs")
			diroffsets.append((res, offset, cramfssize))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	cramfsfile.close()
	return (diroffsets, blacklist, newtags, hints)

## unpack a cramfs file system
def unpackCramfs(filename, offset, bigendian, cramfslen, oldcramfs, tempdir=None, unpacktempdir=None, blacklist=[]):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, length=cramfslen, unpacktempdir=unpacktempdir, blacklist=blacklist)

	## A new subdirectory inside tmpdir has to be created to unpack the
	## files into, otherwise the tool will complain.
        tmpdir2 = tempfile.mkdtemp(dir=unpacktempdir)

	## right now this is a path to a specially adapted fsck.cramfs that ignores special inodes
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

		## then remove the temporary directory
		shutil.rmtree(tmpdir2)

		## Since for old cramfs (version 0) the length field does not mean
		## anyting ## determine if the whole file actually is the cramfs file
		## by running bat-fsck.cramfs again with -v and check stderr for any
		## errors.
		## If there is no warning or error on stderr the entire file is the
		## cramfs file and it can be blacklisted.
		if oldcramfs:
			p = subprocess.Popen(['bat-fsck.cramfs', '-v', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
			(stanout, stanerr) = p.communicate()
			if len(stanerr) != 0:
				cramfslen = 0
		os.unlink(tmpfile[1])
		return (tmpdir, cramfslen)

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
		sqshfile = open(filename, 'rb')
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
	rmfiles = os.listdir(tmpdir)
	for r in rmfiles:
		rmfile = os.path.join(tmpdir, r)
		if not os.path.isdir(rmfile):
			os.unlink(rmfile)
		elif os.path.islink(rmfile):
			os.unlink(rmfile)
		else:
			shutil.rmtree(rmfile)

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
	newtags = []
	counter = 1
	filesize = os.stat(filename).st_size
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
			if (offset - 0x410) == 0 and minixsize == filesize:
				newtags.append('minix')
				newtags.append('filesystem')
		else:
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, newtags, hints)

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
	newtags = []

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
		revisionbytes = datafile.read(4)
		if len(revisionbytes) < 4:
			continue
		revision = struct.unpack('<I', revisionbytes)[0]
		if not (revision == 1 or revision == 0):
			continue

		## for a quick sanity check only a tiny bit of data is needed.
		## Use tune2fs for this.
		datafile.seek(offset - 0x438)
		ext2checkdata = datafile.read(8192)
		if len(ext2checkdata) != 8192:
			continue

		## check for RO_COMPAT_SPARSE_SUPER
		datafile.seek(offset - 0x438 + 0x464)
		featureflagbytes = datafile.read(4)
		if len(featureflagbytes) < 4:
			continue
		featureflags = struct.unpack('<I', featureflagbytes)[0]
		sparse_super = False
		if featureflags & 0x01:
			sparse_super = True

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

		## blocks per group
		datafile.seek(offset - 0x438 + 0x420)
		ext2bytes = datafile.read(4)
		if len(ext2bytes) < 4:
			continue
		blockspergroup = struct.unpack('<I', ext2bytes)[0]

		## sanity check: see if there are backup superblocks at
		## the correct locations
		validext2 = True
		for i in xrange(0, blockcount, blockspergroup):
			if not validext2:
				break
			if i == 0:
				continue
			groupnumber = i/blockspergroup
			if sparse_super:
				for p in [3,5,7]:
					if pow(p, int(math.log(groupnumber, p))) == groupnumber:
						if blocksize == 1024:
							datafile.seek(offset - 0x438 + 0x400 + groupnumber*blocksize*blockspergroup)
						else:
							datafile.seek(offset - 0x438 + groupnumber*blocksize*blockspergroup)
						ext2bytes = datafile.read(1024)
						if len(ext2bytes) != 1024:
							validext2 = False
							break
						if ext2bytes[0x38:0x3a] != '\x53\xef':
							validext2 = False
							break
						break
			else:
				if blocksize == 1024:
					datafile.seek(offset - 0x438 + 0x400 + groupnumber*blocksize*blockspergroup)
				else:
					datafile.seek(offset - 0x438 + groupnumber*blocksize*blockspergroup)
				ext2bytes = datafile.read(1024)
				if len(ext2bytes) != 1024:
					validext2 = False
					break
				if ext2bytes[0x38:0x3a] != '\x53\xef':
					validext2 = False
					break
		if not validext2:
			continue

		## it doesn't make sense if the size of the file system is
		## larger than the actual file size
		if ext2checksize + offset - 0x438 > filesize:
			continue

		tmpdir = dirsetup(tempdir, filename, "ext2", counter)
		res = unpackExt2fs(filename, offset - 0x438, ext2checksize, tmpdir, unpackenv=unpackenv, blacklist=blacklist)
		if res != None:
			(ext2tmpdir, ext2size) = res
			diroffsets.append((ext2tmpdir, offset - 0x438, ext2size))
			blacklist.append((offset - 0x438, offset - 0x438 + ext2size))
			counter = counter + 1
			if offset - 0x438 == 0 and ext2size == filesize:
				newtags.append('ext2')
				newtags.append('filesystem')
		else:
			os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, newtags, hints)

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
		gzipfile = open(filename, 'rb')
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

		gzipfile = open(filename, 'rb')
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
		filesize = os.stat(tmpfile[1]).st_size % pow(2,32)
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
	compressfile = open(filename, 'rb')
	for offset in offsets['compress']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## according to the specification the "bits per code" has
		## to be 9 <= bits per code <= 16
		## The "bits per code" field is masked with 0x1f
		compressfile.seek(offset+2)
		compressdata = compressfile.read(1)
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
		## If no data could be uncompressed return
		compressfile.seek(offset)
		compressdata = compressfile.read(1048576)

		p = subprocess.Popen(['uncompress'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
	compressfile.close()
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
		sparsefile = open(filename, 'rb')
		sparsefile.seek(offset+4)
		sparsedata = sparsefile.read(2)
		sparsefile.close()
		if len(sparsedata) != 2:
			break
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

	if len(sparsedata) != 28:
		return

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
		ext2offsetsres = prerun.genericMarkerSearch(outtmpfile[1], ['ext2'], [])
		(ext2offsets, offsettokeys, isascii) = ext2offsetsres
		ext2offsets = ext2offsets['ext2']
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

## This is for Android update files that are sparse, since Android 5.something
## See for example:
## https://android.googlesource.com/platform/bootable/recovery/+/android-5.1.1_r1/updater/blockimg.c
##
## Files observed in the wild are: system.new.dat
def searchUnpackAndroidSparseDataImage(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not filename.endswith('.new.dat'):
		return ([], blacklist, [], hints)
	listdir = os.listdir(os.path.dirname(filename))
	systemtransferfiles = filter(lambda x: x.endswith(".transfer.list"), listdir)
	if systemtransferfiles == []:
		return ([], blacklist, [], hints)
	transferfile = None
	for i in systemtransferfiles:
		if i.startswith(os.path.basename(filename)[:-8]):
			transferfile = i
			break
	if transferfile == None:
		return ([], blacklist, [], hints)
	## now read the transferlist
	transferfilelines = open(os.path.join(os.path.dirname(filename), transferfile), 'rb').readlines()
	if transferfilelines == []:
		return ([], blacklist, [], hints)
	## first line is the version number:
	lineindexnumber = 0
	try:
		version = int(transferfilelines[lineindexnumber].strip())
		lineindexnumber += 1
	except:
		return ([], blacklist, [], hints)
	try:
		blockstowrite = int(transferfilelines[lineindexnumber].strip())
		lineindexnumber += 1
	except:
		return ([], blacklist, [], hints)
	if version >= 2:
		try:
			stash_entries_needed = int(transferfilelines[lineindexnumber].strip())
			lineindexnumber += 1
		except:
			return ([], blacklist, [], hints)
		try:
			max_stash_blocks = int(transferfilelines[lineindexnumber].strip())
			lineindexnumber += 1
		except:
			return ([], blacklist, [], hints)

	## hardcoded in the Android source code
	blocksize = 4096
	filesize = os.stat(filename).st_size

	## now process all the commands
	## The lines should be structured as:
	## "command rangeset"
	## where rangeset is separated by colons
	tmpdir = dirsetup(tempdir, filename, "java-sparse-data-image", 1)
	outfile = open(os.path.join(tmpdir, os.path.basename(filename)[:-8] + '.img'), 'wb')
	infile = open(filename, 'rb')
	unsupported = False
	for i in range(lineindexnumber, len(transferfilelines)):
		if unsupported:
			outfile.close()
			infile.close()
			os.unlink(outfile)
			os.rmdir(tmpdir)
			return ([], blacklist, [], hints)
		try:
			splitline = transferfilelines[i].rstrip().split(' ', 1)
			if len(splitline) != 2:
				outfile.close()
				infile.close()
				os.unlink(outfile)
				os.rmdir(tmpdir)
				return ([], blacklist, [], hints)
			(command, rangeset) = splitline
			rangesetitems = map(lambda x: int(x), filter(lambda x: x != '', rangeset.split(',')))
			if len(rangesetitems) - 1 != rangesetitems[0]:
				outfile.close()
				infile.close()
				os.unlink(outfile)
				os.rmdir(tmpdir)
				return ([], blacklist, [], hints)
			if command == "erase":
				for r in xrange(1,len(rangesetitems), 2):
					blockstoerase = rangesetitems[r+1] - rangesetitems[r]
					if rangesetitems[r] == 0:
						## seek to a position beyond the file size
						## and then write one character. Because
						## the file is in write mode the old data
						## is truncated first. The end result is
						## a file with just \x00.
						outfile.seek(blockstoerase*blocksize-1)
						outfile.write('\x00')
					else:
						unsupported = True
					outfile.flush()
			elif command == "new":
				infile.seek(0)
				for r in xrange(1,len(rangesetitems), 2):
					## TODO: sanity checks. The range should not
					## extend beyond the target file.
					blockstoread = rangesetitems[r+1] - rangesetitems[r]
					outfile.seek(rangesetitems[r]*blocksize)
					outfile.write(infile.read(blockstoread*blocksize))
					outfile.flush()
		except Exception, e:
			outfile.close()
			infile.close()
			os.unlink(outfile)
			os.rmdir(tmpdir)
			return ([], blacklist, [], hints)
	outfile.close()
	infile.close()
	diroffsets = []
	diroffsets.append((tmpdir, 0, filesize))
	blacklist.append((0, filesize))
	return (diroffsets, blacklist, [], hints)

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
	counter = 1
	if offsets['pack200'] == []:
		return ([], blacklist, tags, hints)
	lenheaderoffsets = len(offsets['pack200'])
	filesize = os.stat(filename).st_size
	for i in xrange(0,lenheaderoffsets):
		offset = offsets['pack200'][i]
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		if i < lenheaderoffsets - 1:
			nextoffset = offsets['pack200'][i+1]
		else:
			nextoffset = filesize
		blacklistoffset = extractor.inblacklist(nextoffset, blacklist)
		if blacklistoffset != None:
			break
		pack200length = nextoffset - offset
		tmpdir = dirsetup(tempdir, filename, "pack200", counter)
		res = unpackPack200(filename, offset, pack200length, tmpdir)
		if res != None:
			diroffsets.append((res, offset, pack200length))
			blacklist.append((offset, nextoffset))
			counter += 1
			if offset == 0 and pack200length == filesize:
				tags.append('pack200')
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, tags, hints)

def unpackPack200(filename, offset, pack200length, tempdir=None):
	tmpdir = unpacksetup(tempdir)

	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir, length=pack200length)

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

## unpack LZMA compressed data. Uncompressing LZMA is difficult,
## as it is a stream without a fixed header and theoretically millions
## and millions of possible variations. In practice only a few seem
## to be used.
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
		if filesize - offset < 13:
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

		## sanity checks to see if the size is set.
		lzmafile = open(filename, 'rb')
		lzmafile.seek(offset+5)
		lzmasizebytes = lzmafile.read(8)
		lzmafile.close()
		if len(lzmasizebytes) != 8:
			continue

		## A few more sanity checks: first check if the file is a stream
		## of unknown size, or if it has a file size set (for the
		## uncompressed file).
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
		minlzmadatatoread = 10000000
		lzmabytestoread = min(filesize-offset, minlzmadatatoread)

		lzmafile = open(filename, 'rb')
		lzmafile.seek(offset)
		lzmadata = lzmafile.read(lzmabytestoread)
		if len(lzmadata) < 14:
			lzmafile.close()
			continue

		lzma_extra_strict = False

		if not lzma_try_all:
			## quite a few LZMA streams have '\x00' at byte 14, but not all
			if not lzmadata[14] == '\x00' and lzma_extra_strict:
				lzmafile.close()
				continue

		p = subprocess.Popen(['lzma', '-cd', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate(lzmadata)
		if p.returncode == 0:
			lzmafile.close()
			## whole stream successfully unpacked and there was
			## no trailing data
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
			lzmafile.close()
			continue

		## The data seems to be a valid LZMA stream, but not all LZMA
		## data was unpacked.
		if lzmafile.tell() == filesize:
			## dunno what to do in this case
			pass

		lzmafile.close()
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
	blacklistoffset = extractor.inblacklist(offset, blacklist)
	if blacklistoffset != None:
		return (diroffsets, blacklist, [], hints)

	## now check how many images there are in the file
	icofile = open(filename, 'rb')
	icofile.seek(4)
	icobytes = icofile.read(2)
	icocount = struct.unpack('<H', icobytes)[0]

	## the ICO format first has all the headers, then the image data
	for i in xrange(0,icocount):
		tmpdir = dirsetup(tempdir, filename, "ico", counter)
		icoheader = icofile.read(16)
		## grab the size of the icon, plus the offset where it can
		## be found in the file
		icosize = struct.unpack('<I', icoheader[8:12])[0]
		icooffset = struct.unpack('<I', icoheader[12:16])[0]

		ispng = False
		oldoffset = icofile.tell()
		icofile.seek(icooffset)
		icobytes = icofile.read(icosize)
		if len(icobytes) > 45:
			if icobytes[:8] == fsmagic.fsmagic['png']:
				ispng = True
		if ispng:
			tmpfile = os.path.join(tmpdir, "unpack-%d.png" % counter)
		else:
			tmpfile = os.path.join(tmpdir, "unpack-%d.bmp" % counter)
		icooutput = open(tmpfile, 'wb')
		if not ispng:
			## it is a BMP. This means that the BMP header needs to be
			## reconstructed first. According to the specification on
			## wikipedia the bitmap data in the ICO file isn't
			## regular bitmap data (because of a XOR mask), so skip
			## for now.
			pass
			'''
			if icobytes[:4] == '\x28\x00\x00\x00':
				icooutput.write('BM')
				## BMP magic, header is 14 long
				bmpsize = len(icobytes) + 14
				## BMP size
				icooutput.write(struct.pack('<I', bmpsize))
				## BMP header reserved fields
				icooutput.write('\x00\x00\x00\x00')
				## BMP header offset of pixel array
				## first there is the BMP file header,
				## which is 14 bytes, then the DIB
				## header, in total 54 bytes
				pixelarrayoffset = 54
				## Then there is an optional color table
				bitsperpixel = struct.unpack('<H', icobytes[14:16])[0]
				rawimagesize = struct.unpack('<I', icobytes[20:24])[0]
				colorsinpalette = struct.unpack('<I', icobytes[32:36])[0]

				pixelarrayoffset += pow(2,bitsperpixel)
				if colorsinpalette == 0:
					print pow(2, bitsperpixel), filename, counter
				icooutput.write(struct.pack('<I', pixelarrayoffset))
			else:
				pass
			'''
		icooutput.write(icobytes)
		icooutput.close()
		
		icofile.seek(oldoffset)
		counter += 1
		diroffsets.append((tmpdir, icooffset, icosize))
	
	icofile.close()

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
		## then walk the trailers. Additional information can follow in the
		## form of updates so the first trailer is not always the last
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

def searchUnpackBMP(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'bmp' in offsets:
		return ([], blacklist, [], hints)
	if offsets['bmp'] == []:
		return ([], blacklist, [], hints)
	filesize = os.stat(filename).st_size
	diroffsets = []
	newtags = []
	counter = 1

	datafile = open(filename, 'rb')

	for offset in offsets['bmp']:
		## first check if the offset is not blacklisted
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		datafile.seek(offset+2)
		sizebytes = datafile.read(4)
		if len(sizebytes) != 4:
			break
		bmpsize = struct.unpack('<I', sizebytes)[0]
		if bmpsize + offset > filesize:
			break
		## read 8 bytes more data. The first 4 bytes are for
		## reserved fields, the last 
		bmpdata = datafile.read(8)
		bmpoffset = struct.unpack('<I', bmpdata[4:])[0]
		if bmpoffset + offset > filesize:
			break
		## offset for BMP cannot be less than the current
		## file pointer
		if bmpoffset + offset < datafile.tell():
			break
		## reset the file pointer and read all needed data
		datafile.seek(offset)
		bmpdata = datafile.read(bmpsize)
		if len(bmpdata) != bmpsize:
			break
		p = subprocess.Popen(['bmptopnm'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stanout, stanerr) = p.communicate(bmpdata)
		if p.returncode != 0:
			continue
		## basically we have a copy of the original
		## image here, so why bother?
		if offset == 0 and bmpsize == filesize:
			blacklist.append((0,bmpsize))
			datafile.close()
			return (diroffsets, blacklist, ['graphics', 'bmp', 'binary'], hints)

		## not the whole file, so carve
		tmpdir = dirsetup(tempdir, filename, "bmp", counter)
		tmpfilename = os.path.join(tmpdir, 'unpack-%d.bmp' % counter)
		tmpfile = open(tmpfilename, 'wb')
		tmpfile.write(bmpdata)
		tmpfile.close()
		hints[tmpfilename] = {}
		hints[tmpfilename]['tags'] = ['graphics', 'bmp', 'binary']
		hints[tmpfilename]['scanned'] = True
		blacklist.append((offset,offset + bmpsize))
		diroffsets.append((tmpdir, offset, bmpsize))
		counter = counter + 1
	datafile.close()

	return (diroffsets, blacklist, newtags, hints)

## http://en.wikipedia.org/wiki/Graphics_Interchange_Format
## https://www.w3.org/Graphics/GIF/spec-gif89a.txt
## 1. search for a GIF header
## 2. parse the GIF file and look for a trailer
## 3. check the data with gifinfo
##
## gifinfo will not recognize if there is trailing data for
## a GIF file, so all data needs to be looked at, until a
## valid GIF file has been carved out (part of the file, or
## the whole file), or stop if no valid GIF file can be found.
## TODO: remove call to gifinfo after running more tests
def searchUnpackGIF(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	newtags = []
	gifoffsets = []
	for marker in fsmagic.gif:
		## first check if the header is not blacklisted
		for m in offsets[marker]:
			blacklistoffset = extractor.inblacklist(m, blacklist)
			if blacklistoffset != None:
				continue
			gifoffsets.append(m)
	if gifoffsets == []:
		return ([], blacklist, newtags, hints)

	gifoffsets.sort()

	diroffsets = []
	counter = 1

	## magic header for XMP:
	## https://en.wikipedia.org/wiki/Extensible_Metadata_Platform
	## http://www.adobe.com/content/dam/Adobe/en/devnet/xmp/pdfs/XMPSpecificationPart3.pdf
	xmpmagicheaderbytes = ['\x01'] + map(lambda x: chr(x), range(255,-1,-1)) + ['\x00']
	xmpmagic = "".join(xmpmagicheaderbytes)

	## broken XMP headers exist.
	brokenxmpheaders = []

	## In one of them the value 0x3b is 0x00 instead.
	brokenxmpmagicheaderbytes1 = ['\x01'] + map(lambda x: chr(x), range(255,-1,-1)[:196]) + ['\x00'] + map(lambda x: chr(x), range(58,-1,-1)) + ['\x00']
	brokenxmpmagic1 = "".join(brokenxmpmagicheaderbytes1)
	brokenxmpheaders.append(brokenxmpmagic1)

	## In another one 0xdc is missing and 0x07 is duplicated
	brokenxmpmagicheaderbytes2 = ['\x01'] + map(lambda x: chr(x), range(255,-1,-1)[:35]) + map(lambda x: chr(x), range(219,-1,-1))[:-7] + ['\x07', '\x06', '\x05', '\x04', '\x03', '\x02', '\x01', '\x00', '\x00']
	brokenxmpmagic2 = "".join(brokenxmpmagicheaderbytes2)
	brokenxmpheaders.append(brokenxmpmagic2)

	datafile = open(filename, 'rb')
	filesize = os.stat(filename).st_size
	for i in range(0,len(gifoffsets)):
		offset = gifoffsets[i]
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

		validgif = True
		## there could be various extensions before there is an image
		## control block
		endofimage = -1
		xmpdata = ''
		brokenxmp = False
		while True:
			if databytes == '\x3b':
				## end of image
				endofimage = datafile.tell()
				break
			elif databytes == '\x21':
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
						validgif = False
						break
					localoffset += 1
					databytes = datafile.read(8)
					localoffset += 8
					if databytes == 'XMP Data':
						databytes = datafile.read(1000)
						if not databytes.startswith('XMP'):
							validgif = False
							break
						magicoffset = databytes.find(xmpmagic)
						while magicoffset == -1:
							## files with a broken XMP trailer
							## exist.
							for br in brokenxmpheaders:
								magicoffset = databytes.find(br)
								if magicoffset != -1:
									brokenxmp = True
									break
							if magicoffset == -1:
								databuf = datafile.read(1000)
								if databuf == '':
									validgif = False
									break
								databytes += databuf
								magicoffset = databytes.find(xmpmagic)
						datafile.seek(localoffset)
						xmpdata = datafile.read(magicoffset)[3:]
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
			elif databytes == '\x2c':
				## According to section 20 of the GIF89a specification first there
				## is the image descriptor (10 bytes, starting with 0x2c), then an
				## optional local color table and then the image data followed by
				## a block terminator.
				datafile.seek(localoffset)
				imagedescriptor = datafile.read(9)
				if len(imagedescriptor) != 9 and firstimagedescriptor:
					validgif = False
					break

				localoffset = datafile.tell()

				firstimagedescriptor = False

				## test if there is a local color table defined
				localcolortablesize = 0
				if ord(imagedescriptor[-1]) & 128 == 1:
					localcolortablepow = ord(imagedescriptor[-1]) & 7
					if localcolortablepow != 0:
						localcolortablesize = pow(2,localcolortablepow+1)

				if (localoffset -offset + localcolortablesize) > filesize:
					validgif = False
					break

				## skip over the local color table
				localoffset += localcolortablesize
				datafile.seek(localoffset)
				lzwcodesize = datafile.read(1)
				if len(lzwcodesize) != 1:
					validgif = False
					break
				localoffset = datafile.tell()
				## then the datablocks follow
				## the first byte of each datablock indicates how many bytes follow
				while True:
					lzwdatasizebyte = datafile.read(1)
					if len(lzwdatasizebyte) != 1:
						validgif = False
						break
					localoffset = datafile.tell()
					if lzwdatasizebyte == '\x00':
						## end of data block
						databytes = datafile.read(1)
						localoffset = datafile.tell()
						break
					lzwdatasize = ord(lzwdatasizebyte)
					if (localoffset - offset + lzwdatasize) > filesize:
						validgif = False
						break
					localoffset += lzwdatasize
					datafile.seek(localoffset)
			else:
				validgif = False
				break
			if not validgif:
				break
		if not validgif:
			continue

		if endofimage == -1:
			continue

		if offset == 0 and endofimage == filesize:
			## basically this is copy of the original image so why bother?
			blacklist.append((0, filesize))
			datafile.close()
			newtags = ['graphics', 'gif', 'binary']
			if brokenxmp:
				newtags.append('brokenxmp')
			return (diroffsets, blacklist, newtags, hints)
		else:
			## not the whole file, so carve
			datafile.seek(offset)
			data = datafile.read(endofimage - offset)
			tmpdir = dirsetup(tempdir, filename, "gif", counter)
			tmpfilename = os.path.join(tmpdir, 'unpack-%d.gif' % counter)
			tmpfile = open(tmpfilename, 'wb')
			tmpfile.write(data)
			tmpfile.close()
			diroffsets.append((tmpdir, offset, endofimage - offset))
			hints[tmpfilename] = {}
			newtags = ['graphics', 'gif', 'binary']
			if brokenxmp:
				newtags.append('brokenxmp')
			hints[tmpfilename]['tags'] = newtags
			hints[tmpfilename]['scanned'] = True
			counter = counter + 1
			blacklist.append((offset, endofimage))
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
	pngheaderoffsetsres = prerun.genericMarkerSearch(filename, ['png'], [])
	(pngheaderoffsets, offsettokeys, isascii) = pngheaderoffsetsres
	pngheaderoffsets = pngheaderoffsets['png']
	if len(pngheaderoffsets) != 1:
		return ([], [], [], {})
	pngtraileroffsetsres = prerun.genericMarkerSearch(filename, ['pngtrailer'], [])
	(pngtraileroffsets, offsettokeys, isascii) = pngtraileroffsetsres
	pngtraileroffsets = pngtraileroffsets['pngtrailer']
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

			## Now walk the PNG to see if it actually is a valid
			## file. Do this by looking at the length and the chunk
			## of the file and stepping through the file
			localoffset = offset + 8
			trailerseen = False
			while localoffset <= trail and not trailerseen:
				datafile.seek(localoffset)
				pngbytes = datafile.read(8)
				if len(pngbytes) != 8:
					break
				localoffset += 8

				chunksize = struct.unpack('>I', pngbytes[:4])[0]
				chunktype = pngbytes[4:]
				## TODO: extract XMP data
				if chunktype == 'IEND':
					## trailer reached
					trailerseen = True
				## now add the length to the localoffset, plus add four
				## bytes for the CRC, then seek to that offset.
				localoffset += chunksize + 4
			if not trailerseen:
				break
			if not trail + 12 == localoffset:
				break

			## now walk the image data again to compute the CRCs
			localoffset = offset + 8
			crccorrect = True
			while localoffset <= trail:
				datafile.seek(localoffset)

				## grab the size
				pngbytes = datafile.read(4)
				localoffset += 4

				chunksize = struct.unpack('>I', pngbytes)[0]
				databytes = datafile.read(chunksize + 4)
				pngcrc = datafile.read(4)
				computedcrc = binascii.crc32(databytes) & 0xffffffff
				if pngcrc != struct.pack('>I', computedcrc):
					crccorrect = False
					break
				## now add the length to the localoffset, plus add four
				## bytes for the CRC and four for the chunk, then seek to
				## that offset.
				localoffset += chunksize + 8
			if not crccorrect:
				break

			## basically we have a copy of the original
			## image here, so why bother reading and
			## copying the data again?
			if offset == 0 and trail == lendata - 12:
				os.rmdir(tmpdir)
				blacklist.append((0,lendata))
				datafile.close()
				return (diroffsets, blacklist, ['graphics', 'png', 'binary'], hints)

			## carve the image data from the file and write it to disk
			datafile.seek(offset)
			pngsize = trail+12-offset
			data = datafile.read(pngsize)
			pngfound = True
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

	## check if there could be at least one valid image
	if not offsets['jpeg'][0] < offsets['jpegtrailer'][-1]:
		return ([],blacklist, [], hints)

	hints = {}
	counter = 1
	diroffsets = []
	newtags = []
	filesize = os.stat(filename).st_size

	## list of JPEG segment markers
	jpegmarkers = ['\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6',
                       '\xc7', '\xc8', '\xc9', '\xca', '\xcb', '\xcc', '\xcd',
                       '\xce', '\xcf', '\xda', '\xdb', '\xdc', '\xdd', '\xde', '\xdf']

	framemarkers = ['\xc0', '\xc1', '\xc2', '\xc3', '\xc5', '\xc6', '\xc7',
                        '\xc8', '\xc9', '\xca', '\xcb', '\xcd', '\xce', '\xcf']

	## APP and COM
	jpegappmarkers = ['\xe0', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5',
                          '\xe6', '\xe7', '\xe8', '\xe9', '\xea', '\xeb',
                          '\xec', '\xed', '\xee', '\xfe']

	## stand alone markers, have no length field
	standalonemarkers = ['\x01', '\xd0', '\xd1', '\xd2', '\xd3', '\xd4',
                             '\xd5', '\xd6', '\xd7', '\xd8', '\xd9']

	traileroffsets = deque(offsets['jpegtrailer'])
	trailerpopcounter = 0

	## This is just a hack in case to make sure not too much data is read
	## in case there is an invalid JPEG that is hard to detect (example:
	## Android sparse data images where pieces of the ext4 file system
	## with NUL bytes have been removed. The alternative would be to do
	## a full decoding of the JPEG data in the SOS section which is not
	## trivial to implement.
	## By default set this to 100 MiB.
	jpegmaxsize = 104857600
	if 'JPEG_MAXIMUM' in scanenv:
		try:
			jpegmaxsize = int(scanenv['JPEG_MAXIMUM'])
		except:
			pass

	datafile = open(filename, 'rb')
	## Start verifying the JFIF image.
	for offset in offsets['jpeg']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		localoffset = offset
		datafile.seek(offset+2)
		localoffset += 2
		jpegmarker = datafile.read(2)
		if not len(jpegmarker) == 2:
			continue
		if not jpegmarker[0] == '\xff':
			## SOI is always followed by a segment
			continue
		## some values are not valid
		if jpegmarker[1] == '\xff' or jpegmarker[1] == '\x00':
			continue
		## only one SOI
		if jpegmarker[1] == '\xd8':
			continue
		## useless to have EOI immediately following SOI
		if jpegmarker[1] == '\xd9':
			continue
		if not (jpegmarker[1] in standalonemarkers or jpegmarker[1] in jpegmarkers or jpegmarker[1] in jpegappmarkers):
			continue
		localoffset += 2
		## following the JPEG "start of image" there could be
		## a APP0 (JFIF), APP1 (Exif and XMP), APP11 (Ducky)
		## APP2 (ICC), APP13 (PSIR/IPTC) or APP14 (Adobe)
		## or COM.
		## There are probably more (see lists of APP markers mentioned
		## above) but these have been observed in the wild.
		validpng = True
		havexmp = False
		xmp = None
		havecomment = False
		seenstartofframe = False
		while jpegmarker[0] == '\xff' and jpegmarker[1] in jpegappmarkers:
			if not validpng:
				break
			## first the size of the app marker
			jpegsize = datafile.read(2)
			if not len(jpegsize) == 2:
				validpng = False
				break
			sizeheader = struct.unpack('>H', jpegsize)[0]
			if sizeheader == 0:
				validpng = False
				break
			if offset + sizeheader > filesize:
				validpng = False
				break
			jpegdata = datafile.read(sizeheader - 2)
			localoffset += sizeheader
			if len(jpegdata) != sizeheader - 2:
				validpng = False
				break
			if jpegmarker == '\xff\xe0':
				## check if the rest of the header starts with either
				## JFIF or JFXX
				if not (jpegdata.startswith('JFIF\x00') or jpegdata.startswith('JFXX\x00')):
					validpng = False
					break
				if jpegdata.startswith('JFIF\x00'):
					if not (jpegdata[5:7] == '\x01\x01' or jpegdata[5:7] == '\x01\x02'):
						validpng = False
						break
			elif jpegmarker == '\xff\xe1':
				## EXIF, XMP
				if not (jpegdata.startswith('Exif\x00') or jpegdata.startswith('http://ns.adobe.com/xap/1.0/\x00')):
					validpng = False
					break
				if jpegdata.startswith('http://ns.adobe.com/xap/1.0/\x00'):
					xmp = jpegdata.split('\x00', 1)[1]
					havexmp = True
			elif jpegmarker == '\xff\xe2':
				## ICC http://www.color.org/specification/ICC1v43_2010-12.pdf
				if not jpegdata.startswith('ICC_PROFILE\x00'):
					validpng = False
					break
			elif jpegmarker == '\xff\xec':
				## Ducky, used by Photoshop
				if not jpegdata.startswith('Ducky\x00'):
					validpng = False
					break
			elif jpegmarker == '\xff\xed':
				## PSIR/IPTC
				if not (jpegdata.startswith('Photoshop 3.0\x00') or jpegdata.startswith('Adobe_CM\x00')):
					validpng = False
					break
			elif jpegmarker == '\xff\xee':
				## Adobe
				if not jpegdata.startswith('Adobe\x00'):
					validpng = False
					break
			elif jpegmarker == '\xff\xfe':
				## COM
				havecomment = True
			else:
				## TODO: add more
				validpng = False
				break
			jpegmarker = datafile.read(2)
			localoffset += 2
			if len(jpegmarker) != 2:
				validpng = False
				break
		if not validpng:
			continue

		if jpegmarker[0] != '\xff':
			## catch all for non-compliant data
			continue

		## look at individual JPEG segments that have not already been
		## looked at before (like APP)
		seenscanheader = False
		seenendofimage = False
		endofimage = None
		while jpegmarker[0] == '\xff':
			if jpegmarker[1] == '\xd8':
				## there can be only one SOI
				validpng = False
				break
			if jpegmarker[1] == '\xd9':
				endofimage = datafile.tell() - 2
				seenendofimage = True
				break
			## individual checks to see if JPEG is valid
			if jpegmarker[1] in standalonemarkers:
				jpegmarker = datafile.read(2)
				if len(jpegmarker) != 2:
					break
				localoffset += 2
			elif jpegmarker[1] in jpegmarkers or jpegmarker[1] in jpegappmarkers:
				jpeglength = datafile.read(2)
				if len(jpeglength) != 2:
					validpng = False
					break
				localoffset += 2
				markerlength = struct.unpack('>H', jpeglength)[0]
				if markerlength == 0:
					validpng = False
					break
				if offset + markerlength > filesize:
					continue
				if jpegmarker[1] in framemarkers:
					seenstartofframe = True
				if jpegmarker[1] == '\xda':
					## no start of scan without a frame
					if not seenstartofframe:
						validpng = False
						break
					numberofcomponents = ord(datafile.read(1))
					if not numberofcomponents in [1,2,3,4]:
						validpng = False
						break
					if not markerlength == 6+2*numberofcomponents:
						validpng = False
						break
					localoffset += 1
					seenscanheader = True
					break
				## do individual checks here if needed
				if jpegmarker[1] == '\xdb':
					pass
				localoffset += markerlength-2
				datafile.seek(localoffset)
				jpegmarker = datafile.read(2)
				localoffset += 2
				if len(jpegmarker) != 2:
					validpng = False
					break
			else:
				validpng = False
				break

		## no frame without a scan header
		if seenstartofframe:
			if not seenscanheader:
				validpng = False
		else:
			## Abbreviated format should always be
			## correctly formatted with just application
			## data, and various headers, but never
			## any image data.
			if not seenendofimage:
				validpng = False
		if not validpng:
			continue

		minendofimage = datafile.tell()

		for r in xrange(0, trailerpopcounter):
			traileroffsets.popleft()

		trailerpopcounter = 0
		## find the closest jpeg trailer
		for trail in traileroffsets:
			if trail <= offset:
				trailerpopcounter += 1
				continue
			if trail < localoffset:
				trailerpopcounter += 1
				continue
			blacklistoffset = extractor.inblacklist(trail, blacklist)
			if blacklistoffset != None:
				break
			## there is a valid end of image, so only consider
			## this trailer
			if seenendofimage:
				if trail > endofimage:
					break
				if trail != endofimage:
					continue
			else:
				## no valid end of image was seen before
				## the data segment was seen, so it has to
				## come after the data that was already
				## looked at.
				if trail < minendofimage:
					continue
			if offset == 0 and trail+2 == filesize:
				p = subprocess.Popen(['jpegtopnm', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					validpng = False
					break
				blacklist.append((0,filesize))
				datafile.close()
				return (diroffsets, blacklist, ['graphics', 'jpeg', 'binary'], hints)
			else:
				if trail+2 - offset > jpegmaxsize:
					break
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
					trailerpopcounter += 1
					break
				os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, newtags, hints)

## carve ELF files from a bigger file
def searchUnpackELF(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	diroffsets = []
	newtags = []
	if not 'elf' in offsets:
		return (diroffsets, blacklist, newtags, hints)
	if offsets['elf'] == []:
		return (diroffsets, blacklist, newtags, hints)

	counter = 1
	elffile = open(filename, 'rb')
	for offset in offsets['elf']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			return (diroffsets, blacklist, newtags, hints)
		tmpdir = dirsetup(tempdir, filename, "elf", counter)
		(totalelf, elfres) = elfcheck.parseELF(filename, offset)
		if totalelf:
			elffile.close()
			os.rmdir(tmpdir)
			newtags.append('elf')
			return (diroffsets, blacklist, newtags, hints)
		if elfres != None:
			if elfres['size'] == 0:
				os.rmdir(tmpdir)
			else:
				## TODO: in case SONAME is defined use that
				## as the name for the file instead
				tmpfilename = os.path.join(tmpdir, 'unpack-%d.elf' % counter)
				tmpfile = open(tmpfilename, 'wb')
				elffile.seek(offset)
				tmpfile.write(elffile.read(elfres['size']))
				tmpfile.close()
				hints[tmpfilename] = {}
				hints[tmpfilename]['tags'] = ['elf', 'binary']
				hints[tmpfilename]['tags'].append(elfres['elftype'])
				blacklist.append((offset,offset + elfres['size']))
				diroffsets.append((tmpdir, offset, elfres['size']))
				counter = counter + 1
		else:
			os.rmdir(tmpdir)
	elffile.close()
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
		if not b.startswith(':'):
			if not b.startswith('#'):
				break
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
	os.fdopen(tmpfile[0]).close()
	datafile.close()
	diroffsets.append((tmpdir, offset, filesize))
	blacklist.append((offset, offset + filesize))
	return (diroffsets, blacklist, tags, hints)

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

## carve WOFF fonts from a file and tag them
## https://www.w3.org/TR/WOFF/
def searchUnpackWOFF(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'woff' in offsets:
		return ([], blacklist, [], hints)
	if offsets['woff'] == []:
		return ([], blacklist, [], hints)

	newtags = []
	counter = 1
	diroffsets = []

	filesize = os.stat(filename).st_size
	wofffile = open(filename, 'rb')
	for offset in offsets['woff']:
		## first check if the offset is not blacklisted
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		wofffile.seek(offset)

		## First walk the header
		## a WOFF file starts with 'wOFF'
		woffbytes = wofffile.read(4)
		if woffbytes != 'wOFF':
			continue

		## the next 4 bytes are the "flavour"
		## followed by the length of the file (4 bytes)
		woffbytes = wofffile.read(8)
		if len(woffbytes) != 8:
			continue

		wofflength = struct.unpack('>L', woffbytes[4:8])[0]

		## font cannot be bigger than the file
		if wofflength + offset > filesize:
			continue

		## followed by the number of font tables
		woffbytes = wofffile.read(2)
		if len(woffbytes) != 2:
			continue

		numtables = struct.unpack('>H', woffbytes)[0]

		## followed by a reserved number that has to be zero
		woffbytes = wofffile.read(2)
		if len(woffbytes) != 2:
			continue
		reserved = struct.unpack('>H', woffbytes)[0]
		if reserved != 0:
			continue

		## followed by the size of the uncompressed data
		## which MUST be a multiple of four
		woffbytes = wofffile.read(4)
		if len(woffbytes) != 4:
			continue
		totalsfntsize = struct.unpack('>I', woffbytes)[0]
		if totalsfntsize%4 != 0:
			continue

		## followed by the major version and minor version
		woffbytes = wofffile.read(2)
		if len(woffbytes) != 2:
			continue
		majorversion = struct.unpack('>H', woffbytes)[0]

		woffbytes = wofffile.read(2)
		if len(woffbytes) != 2:
			continue
		minorversion = struct.unpack('>H', woffbytes)[0]

		## followed by the offset of the metadata
		woffbytes = wofffile.read(4)
		if len(woffbytes) != 4:
			continue
		metadataoffset = struct.unpack('>I', woffbytes)[0]

		## meta data offset MUST start on a 4 byte boundary
		## according to the specification (section 7)
		if metadataoffset%4 != 0:
			continue

		## meta data offset cannot be outside of the file
		if metadataoffset + offset > filesize:
			continue

		## followed by the length of the metadata
		woffbytes = wofffile.read(4)
		if len(woffbytes) != 4:
			continue
		metadatalength = struct.unpack('>I', woffbytes)[0]

		## meta data length cannot be larger than the file
		if metadatalength + offset > filesize:
			continue

		## meta data length cannot be larger than the file
		if metadatalength + metadataoffset + offset > filesize:
			continue

		## followed by the length of the metadata
		woffbytes = wofffile.read(4)
		if len(woffbytes) != 4:
			continue
		metadataoriglength = struct.unpack('>I', woffbytes)[0]

		## followed by the offset of the private data
		woffbytes = wofffile.read(4)
		if len(woffbytes) != 4:
			continue
		privatedataoffset = struct.unpack('>I', woffbytes)[0]

		## private data offset MUST start on a 4 byte boundary
		## according to the specification (section 8)
		if privatedataoffset%4 != 0:
			continue

		## private data offset cannot be outside of the file
		if privatedataoffset + offset > filesize:
			continue

		## followed by the length of the private data
		woffbytes = wofffile.read(4)
		if len(woffbytes) != 4:
			continue
		privatedatalength = struct.unpack('>I', woffbytes)[0]

		## private data length cannot be larger than the file
		if privatedatalength + offset > filesize:
			continue

		## private data length cannot be larger than the file
		if privatedatalength + privatedataoffset + offset > filesize:
			continue

		failtounpack = False
		fontblacklist = []
		## now parse the individual tables
		for i in xrange(0, numtables):
			## first a header
			woffbytes = wofffile.read(4)
			if len(woffbytes) != 4:
				failtounpack = True
				break
			tabletag = struct.unpack('>I', woffbytes)[0]

			## then the offset of the data
			woffbytes = wofffile.read(4)
			if len(woffbytes) != 4:
				failtounpack = True
				break
			tableoffset = struct.unpack('>I', woffbytes)[0]
			## table offset has to start on a 4 byte boundary
			## according to section 5 of the specification
			if tableoffset%4 != 0:
				failtounpack = True
				break
			if tableoffset + offset > filesize:
				failtounpack = True
				break

			## followed by the length of the compressed data (excl. padding)
			woffbytes = wofffile.read(4)
			if len(woffbytes) != 4:
				failtounpack = True
				break
			complength = struct.unpack('>I', woffbytes)[0]
			if complength + offset > filesize:
				failtounpack = True
				break
			if tableoffset + complength + offset > filesize:
				failtounpack = True
				break

			## check if there are any overlaps by checking the blacklist
			blacklistoffset = extractor.inblacklist(tableoffset, fontblacklist)
			if blacklistoffset != None:
				failtounpack = True
				break
			blacklistlistoffset = extractor.inblacklist(tableoffset + complength, fontblacklist)
			if blacklistoffset != None:
				failtounpack = True
				break

			## followed by the length of the uncompressed data (excl. padding)
			woffbytes = wofffile.read(4)
			if len(woffbytes) != 4:
				failtounpack = True
				break
			uncomplength = struct.unpack('>I', woffbytes)[0]

			## followed by the checksum of the uncompressed data
			woffbytes = wofffile.read(4)
			if len(woffbytes) != 4:
				failtounpack = True
				break
			tablechecksum = struct.unpack('>I', woffbytes)[0]
			fontblacklist.append((tableoffset, tableoffset + complength))

			## sanity check for the compressed tables, if any
			if complength < uncomplength:
				oldoffset = wofffile.tell()
				wofffile.seek(tableoffset + offset )
				compbytes = wofffile.read(complength)
				if len(compbytes) != complength:
					failtounpack = True
					break
				try:
					unzobj = zlib.decompressobj()
					uncompresseddata = unzobj.decompress(compbytes)
					if len(uncompresseddata) != uncomplength:
						failtounpack = True
						break
				except Exception, e:
					failtounpack = True
					break
				wofffile.seek(oldoffset)

			## TODO: calculate checksums
		if failtounpack:
			continue

		## basically we have a copy of the original
		## image here, so why bother?
		if offset == 0 and wofflength == filesize:
			blacklist.append((0,wofflength))
			wofffile.close()
			return (diroffsets, blacklist, ['woff', 'font', 'resource', 'binary'], hints)

		## not the whole file, so carve
		tmpdir = dirsetup(tempdir, filename, "woff", counter)
		tmpfilename = os.path.join(tmpdir, 'unpack-%d.woff' % counter)
		tmpfile = open(tmpfilename, 'wb')
		wofffile.seek(offset)
		tmpfile.write(wofffile.read(wofflength))
		tmpfile.close()
		hints[tmpfilename] = {}
		hints[tmpfilename]['tags'] = ['woff', 'font', 'resource', 'binary']
		hints[tmpfilename]['scanned'] = True
		blacklist.append((offset,offset + wofflength))
		diroffsets.append((tmpdir, offset, wofflength))
		counter = counter + 1
	wofffile.close()
	return (diroffsets, blacklist, newtags, hints)

## verifier for OpenType fonts
## https://www.microsoft.com/typography/otspec/otff.htm
def searchUnpackOTF(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	if not 'otf' in offsets:
		return ([], blacklist, [], hints)
	if offsets['otf'] == []:
		return ([], blacklist, [], hints)

	requiredtablenames = set(['cmap', 'head', 'hhea', 'hmtx', 'maxp', 'name', 'OS/2', 'post'])
	reporttag = 'otf'
	extension = 'otf'
	return searchUnpackFont(filename, tempdir, blacklist, offsets['otf'], requiredtablenames, reporttag, extension)

## verifier for TTF fonts. It is very similar to OTF, except for a few required
## tables, the magic header and the extension.
## https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6.html
def searchUnpackTTF(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	if not 'ttf' in offsets:
		return ([], blacklist, [], hints)
	if offsets['ttf'] == []:
		return ([], blacklist, [], hints)

	requiredtablenames = set(['cmap', 'glyf', 'head', 'hhea', 'hmtx', 'loca', 'maxp', 'name', 'post'])
	reporttag = 'ttf'
	extension = 'ttf'
	return searchUnpackFont(filename, tempdir, blacklist, offsets['ttf'], requiredtablenames, reporttag, extension)

def searchUnpackFont(filename, tempdir, blacklist, offsets, requiredtablenames, reporttag, extension):
	hints = {}
	newtags = []
	counter = 1
	diroffsets = []

	filesize = os.stat(filename).st_size
	fontfile = open(filename, 'rb')
	for offset in offsets:
		## first check if the offset is not blacklisted
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## walk the file structure
		fontfile.seek(offset)
		fontsize = 0

		## first the magic header, already checked
		fontbytes = fontfile.read(4)

		## then the number of tables
		fontbytes = fontfile.read(2)
		if len(fontbytes) != 2:
			break
		numberoftables = struct.unpack('>H', fontbytes)[0]
		if numberoftables == 0:
			continue

		## followed by searchrange
		fontbytes = fontfile.read(2)
		if len(fontbytes) != 2:
			break
		searchrange = struct.unpack('>H', fontbytes)[0]

		## sanity check, see specification
		if pow(2, int(math.log(numberoftables, 2)+4)) != searchrange:
			continue

		## followed by entryselector
		fontbytes = fontfile.read(2)
		if len(fontbytes) != 2:
			break
		entryselector = struct.unpack('>H', fontbytes)[0]

		## sanity check, see specification
		if int(math.log(numberoftables, 2)) != entryselector:
			continue

		## followed by rangeshift
		fontbytes = fontfile.read(2)
		if len(fontbytes) != 2:
			break

		rangeshift = struct.unpack('>H', fontbytes)[0]

		## sanity check, see specification
		if rangeshift != numberoftables*16 - searchrange:
			continue

		tablenames = set()
		headchecklocation = 0
		checksumadjustment = 0
		## proces the tables
		validfont = True
		fontsizepadding = 0
		for i in xrange(0,numberoftables):
			## first the tag
			fontbytes = fontfile.read(4)
			if len(fontbytes) != 4:
				validfont = False
				break
			tabletag = fontbytes

			## each table should only appear once
			if tabletag in tablenames:
				validfont = False
				break
			tablenames.add(tabletag)

			## then the checksum
			fontbytes = fontfile.read(4)
			if len(fontbytes) != 4:
				validfont = False
				break
			checksum = fontbytes

			## then the offset
			fontbytes = fontfile.read(4)
			if len(fontbytes) != 4:
				validfont = False
				break
			tableoffset = struct.unpack('>L', fontbytes)[0]
			if tableoffset > filesize:
				validfont = False
				break
			if tabletag == 'head':
				headchecklocation = tableoffset

			## finally the length
			fontbytes = fontfile.read(4)
			if len(fontbytes) != 4:
				validfont = False
				break
			tablelength = struct.unpack('>L', fontbytes)[0]
			if tablelength > filesize:
				validfont = False
				break
			if tablelength + tableoffset > filesize:
				validfont = False
				break
			fontsize = max(fontsize, tablelength + tableoffset)
			if fontsize%4 != 0:
				fontsizepadding = (4 - fontsize%4)
				fontsize += (4 - fontsize%4)

			## now calculate the checksum.
			oldoffset = fontfile.tell()
			fontfile.seek(offset+tableoffset)
			fontbytes = fontfile.read(tablelength)
			if len(fontbytes) != tablelength:
				validfont = False
				break
			computedchecksum = 0
			pad = 0
			if tablelength % 4 != 0:
				pad = 4 - tablelength % 4
				fontbytes += '\x00'*pad

			## the checksum has to fit in 4 bytes (long)
			for r in xrange(0, len(fontbytes)/4):
				computedchecksum += struct.unpack('>L', fontbytes[r*4:r*4+4])[0]
			computedchecksum = computedchecksum%pow(2,32)

			## the checksum for the 'head' section will be different
			## according to the specification.
			if not struct.pack('>L', computedchecksum) == checksum:
				if tabletag != 'head':
					validfont = False
					break
			## store the checksumadjustment
			if tabletag == 'head':
				fontfile.seek(offset+tableoffset+8)
				fontbytes = fontfile.read(4)
				if len(fontbytes) != 4:
					validfont = False
					break
				checksumadjustment = struct.unpack('>L', fontbytes)[0]

			fontfile.seek(oldoffset)

		if not validfont:
			continue

		## sanity check for required table names
		requiredtablenames = set(['cmap', 'head', 'hhea', 'hmtx', 'maxp', 'name', 'OS/2', 'post'])
		if tablenames.intersection(requiredtablenames) != requiredtablenames:
			continue

		## compute checksumadjustment and compare it to
		## the stored checksumadjustment in the head table
		## If the offset of the last table in the font
		## (offset wise, not alphabetically) plus its size
		## are not 4 byte aligned, then padding bytes need
		## to be added, if only as to not read beyond
		## where the font ends.
		## See https://lists.w3.org/Archives/Public/public-webfonts-wg/2010Jun/0063.html
		## However, checksums in some fonts are then no longer
		## properly computed.
		## Example: Font4_Luminous_Sans.ttf in some phones
		fontfile.seek(offset)
		computedchecksum = 0
		fontbytes = fontfile.read(fontsize - fontsizepadding)
		if len(fontbytes) % 4 != 0:
			pad = 4 - len(fontbytes) % 4
			fontbytes += '\x00'*pad
		for r in xrange(0, fontsize/4):
			if r*4 == headchecklocation+8:
				## skip the value for checksumadjustment in the 'head' table
				computedchecksum += 0
			else:
				computedchecksum += struct.unpack('>L', fontbytes[r*4:r*4+4])[0]
			computedchecksum = computedchecksum%pow(2,32)

		if (0xB1B0AFBA - computedchecksum)%pow(2,32) != checksumadjustment:
			continue

		## basically we have a copy of the original
		## image here, so why bother?
		if offset == 0 and fontsize == filesize:
			hints[filename] = {}
			hints[filename]['scanned'] = True
			hints[filename]['blacklistignorescans'] = set()
			hints[filename]['blacklistignorescans'].add('png')
			blacklist.append((0,fontsize))
			fontfile.close()
			return (diroffsets, blacklist, [reporttag, 'font', 'resource', 'binary'], hints)

		## not the whole file, so carve
		tmpdir = dirsetup(tempdir, filename, extension, counter)
		tmpfilename = os.path.join(tmpdir, 'unpack-%d.%s' % (counter, extension))
		tmpfile = open(tmpfilename, 'wb')
		fontfile.seek(offset)
		tmpfile.write(fontfile.read(fontsize))
		tmpfile.close()
		hints[tmpfilename] = {}
		hints[tmpfilename]['tags'] = [reporttag, 'font', 'resource', 'binary']
		hints[tmpfilename]['scanned'] = True
		hints[tmpfilename]['blacklistignorescans'] = set()
		hints[tmpfilename]['blacklistignorescans'].add('png')
		blacklist.append((offset,offset + fontsize))
		diroffsets.append((tmpdir, offset, fontsize))
		counter = counter + 1

	fontfile.close()
	return (diroffsets, blacklist, newtags, hints)

## Search Ogg files in and unpack from a larger file. Since Ogg
## bitstreams can be multiplexed and chained it is difficult to
## separate Ogg files if they have been concatenated.
## http://www.ietf.org/rfc/rfc3533.txt
## Note: some Ogg files on some Android devices are "created by a
## buggy encoder" according to ogginfo
def searchUnpackOgg(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'ogg' in offsets:
		return ([], blacklist, [], hints)
	if offsets['ogg'] == []:
		return ([], blacklist, [], hints)

	filesize = os.stat(filename).st_size

	newtags = []
	counter = 1
	diroffsets = []

	oggfile = open(filename, 'rb')

	## Ogg files can be multiplexed and chained so some data
	## needs to be juggled.

	## oggcontinue is a flag to indicate whether or not the
	## processed page should be considered part of the same
	## bitstream (or part of the same file) or not.
	oggcontinue = True

	## writeoggdata is a flag to indicate whether or not
	## data was previously written. This is used to do proper
	## bookkeeping (writing data, creating temporary
	## directories, etc.)
	writeoggdata = False

	## a mapping per file that maps bitstreams to page numbers
	## to detect if pages are out of order.
	bitstreams = {}

	## first set up a directory and temporary file to write data to
	tmpdir = dirsetup(tempdir, filename, "ogg", counter)
	tmpfilename = os.path.join(tmpdir, 'unpack-%d.ogg' % counter)
	tmpfile = open(tmpfilename, 'wb')
	totalwritten = 0
	oldoffset = 0
	for offset in offsets['ogg']:
		blacklisted = False
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			blacklisted = True
			oggcontinue = False

		if offset != oggfile.tell():
			oggcontinue = False

		## first check if this is a new stream or not
		## and if it is a new stream reset everything
		if not oggcontinue:
			if writeoggdata:
				## data was written, so first close the old file
				tmpfile.close()
				## now check if it is a valid file by running ogginfo
				p = subprocess.Popen(['ogginfo', tmpfilename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					os.unlink(tmpfilename)
				else:
					if os.stat(tmpfilename).st_size == filesize:
						blacklist.append((0, filesize))
						os.unlink(tmpfilename)
						shutil.rmtree(tmpdir)
						return (diroffsets, blacklist, ['ogg', 'audio', 'binary'], hints)
						
					## valid file, so do some more bookkeeping
					hints[tmpfilename] = {}
					hints[tmpfilename]['tags'] = ['ogg', 'audio', 'binary']
					hints[tmpfilename]['scanned'] = True
					blacklist.append((oldoffset,oldoffset + oggdatatoread))
					diroffsets.append((tmpdir, oldoffset, oggdatatoread))
					counter += 1
					tmpdir = dirsetup(tempdir, filename, "ogg", counter)
				tmpfilename = os.path.join(tmpdir, 'unpack-%d.ogg' % counter)
				tmpfile = open(tmpfilename, 'wb')
			## then reset data for the new file
			writeoggdata = False
			oggcontinue = True
			bitstreams = {}

		## if the current offset is blacklisted, then continue
		if blacklisted:
			continue

		## version field has to be zero
		oggfile.seek(offset+4)
		version = oggfile.read(1)
		if version != '\x00':
			oggcontinue = False
			continue

		streamtype = oggfile.read(1)
		## TODO: checks with streamtypes

		oggbytes = oggfile.read(8)
		if len(oggbytes) != 8:
			writeoggdata = False
			break
		granuleposition = oggbytes

		oggbytes = oggfile.read(4)
		if len(oggbytes) != 4:
			writeoggdata = False
			break
		bitstreamserialnumber = struct.unpack('<L', oggbytes)[0]

		oggbytes = oggfile.read(4)
		if len(oggbytes) != 4:
			writeoggdata = False
			break
		pagesequencenumber = struct.unpack('<L', oggbytes)[0]

		if bitstreamserialnumber in bitstreams:
			## pages have to be ordered per bitstream
			if bitstreams[bitstreamserialnumber] > pagesequencenumber:
				oggcontinue = False
				continue
		else:
			bitstreams[bitstreamserialnumber] = pagesequencenumber

		oggbytes = oggfile.read(4)
		if len(oggbytes) != 4:
			writeoggdata = False
			break
		oggchecksum = struct.unpack('<L', oggbytes)[0]

		oggbytes = oggfile.read(1)
		if len(oggbytes) != 1:
			writeoggdata = False
			break
		pagesegments = struct.unpack('<B', oggbytes)[0]
		segmenttotalsize = 0
		for p in xrange(0, pagesegments):
			oggbytes = oggfile.read(1)
			segmentsize = struct.unpack('<B', oggbytes)[0]
			segmenttotalsize += segmentsize

		'''
		## compute the checksum. The standard crc32 methods in
		## Python (binascii and zlib) use reverse polynomial
		## representation, whereas Ogg uses normal
		## TODO: compute checksum, then remove the calls to
		## ogginfo
		oggdataforchecksum = oggfile.tell() - offset + segmentsize
		oggfile.seek(offset)
		oggbytes = oggfile.read(oggdataforchecksum)
		newoggbytes = oggbytes[:20]
		newoggbytes += '\x00\x00\x00\x00'
		newoggbytes += oggbytes[24:]
		crc = 0
		computedchecksum = binascii.crc32(oggbytes)
		'''

		writeoggdata = True
		oggdatatoread = oggfile.tell() - offset + segmenttotalsize
		oggfile.seek(offset)
		tmpfile.write(oggfile.read(oggdatatoread))
		totalwritten += oggdatatoread
		oldoffset = offset

	tmpfile.close()
	oggfile.close()

	if writeoggdata:
		## now check if it is a valid file by running ogginfo
		p = subprocess.Popen(['ogginfo', tmpfilename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.unlink(tmpfilename)
			shutil.rmtree(tmpdir)
		else:
			if os.stat(tmpfilename).st_size == filesize:
				blacklist.append((0, filesize))
				os.unlink(tmpfilename)
				shutil.rmtree(tmpdir)
				return (diroffsets, blacklist, ['ogg', 'audio', 'binary'], hints)
			hints[tmpfilename] = {}
			hints[tmpfilename]['tags'] = ['ogg', 'audio', 'binary']
			hints[tmpfilename]['scanned'] = True
			blacklist.append((oldoffset,oldoffset + oggdatatoread))
			diroffsets.append((tmpdir, oldoffset, oggdatatoread))
	else:
		## remove the empty dir
		shutil.rmtree(tmpdir)

	return (diroffsets, blacklist, newtags, hints)

## ICS color profiles
## http://www.color.org/specification/ICC1v43_2010-12.pdf
## http://www.color.org/icc_specs2.xalter
def searchUnpackICS(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'ics' in offsets:
		return ([], blacklist, [], hints)
	if offsets['ics'] == []:
		return ([], blacklist, [], hints)

	filesize = os.stat(filename).st_size
	if filesize < 128:
		return ([], blacklist, [], hints)

	newtags = []
	counter = 1
	diroffsets = []

	icsfile = open(filename, 'rb')
	for offset in offsets['ics']:
		blacklistoffset = extractor.inblacklist(offset-36, blacklist)
		if blacklistoffset != None:
			continue
		icsfile.seek(offset-36)
		## first the profile header
		databytes = icsfile.read(128)
		if len(databytes) != 128:
			break
		## first check the size
		profilesize = struct.unpack('>I', databytes[:4])[0]
		if profilesize + offset - 36 > filesize:
			continue
		## then add a few more checks, such as profile class
		profileclass = databytes[12:16]
		if not profileclass in ['scnr', 'mntr', 'prtr', 'link', 'spac', 'abst', 'nmcl']:
			continue
		## and the primary platform field
		primaryplatform = databytes[40:44]
		if not primaryplatform in ['APPL', 'MSFT', 'SGI ', 'SUNW', '\x00\x00\x00\x00']:
			continue

		## now read the tag table
		icsfile.seek(offset-36+128)

		## first find the amount of tags
		databytes = icsfile.read(4)
		if len(databytes) != 4:
			break
		tagcount = struct.unpack('>I', databytes)[0]

		brokenics = False
		maxoffset = 0
		## then for each tag read the signature, offset and size
		for n in xrange(0,tagcount):
			## then the tag signature
			## TODO: add some extra sanity checks
			databytes = icsfile.read(4)
			if len(databytes) != 4:
				brokenics = True
				break
			## then the offset
			databytes = icsfile.read(4)
			if len(databytes) != 4:
				brokenics = True
				break
			tagoffset = struct.unpack('>I', databytes)[0]
			if tagoffset + offset - 36 > filesize:
				brokenics = True
				break
			## and finally the size
			databytes = icsfile.read(4)
			if len(databytes) != 4:
				brokenics = True
				break
			tagsize = struct.unpack('>I', databytes)[0]
			if tagoffset + tagsize + offset - 36 > filesize:
				brokenics = True
				break
			if tagoffset + tagsize + offset - 36 > maxoffset:
				maxoffset = tagoffset + tagsize + offset - 36


		if (maxoffset - (offset - 36)) % 4 != 0:
			maxoffset += (4 - (maxoffset - (offset - 36)) % 4)
		if maxoffset - (offset - 36) != profilesize:
			brokenics = True
		if brokenics:
			continue

		if profilesize == filesize:
			icsfile.close()
			blacklist.append((0, filesize))
			return (diroffsets, blacklist, ['ics', 'resource', 'binary'], hints)

		## set up a directory and temporary file to write data to
		tmpdir = dirsetup(tempdir, filename, "ics", counter)
		tmpfilename = os.path.join(tmpdir, 'unpack-%d.ics' % counter)
		tmpfile = open(tmpfilename, 'wb')
		icsfile.seek(offset-36)
		tmpfile.write(icsfile.read(profilesize))

		hints[tmpfilename] = {}
		hints[tmpfilename]['tags'] = ['ics', 'resource', 'binary']
		hints[tmpfilename]['scanned'] = True
		blacklist.append((offset - 36, offset - 36 + profilesize))
		diroffsets.append((tmpdir, offset - 36, profilesize))
		counter += 1

	icsfile.close()

	return (diroffsets, blacklist, newtags, hints)

## carve Java classes from files
def searchUnpackJavaClass(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'java' in offsets:
		return ([], blacklist, [], hints)
	if offsets['java'] == []:
		return ([], blacklist, [], hints)

	filesize = os.stat(filename).st_size

	newtags = []
	counter = 1
	diroffsets = []

	javafile = open(filename, 'rb')
	for offset in offsets['java']:
		javares = javacheck.parseJava(filename, offset)
		if javares != None:
			if javares['size'] != 0:
				if offset == 0 and javares['size'] == filesize:
					#blacklist.append((0, filesize))
					javafile.close()
					return (diroffsets, blacklist, ['java', 'binary'], hints)
			## set up a directory and temporary file to write data to
			tmpdir = dirsetup(tempdir, filename, "java", counter)
			if javares['classname'] != '':
				if not javares['classname'].endswith('.class'):
					tmpfilename = os.path.join(tmpdir, os.path.basename(javares['classname']) + '.class')
				else:
					tmpfilename = os.path.join(tmpdir, os.path.basename(javares['classname']))
			else:
				tmpfilename = os.path.join(tmpdir, 'unpack-%d.class' % counter)
			tmpfile = open(tmpfilename, 'wb')
			javafile.seek(offset)
			tmpfile.write(javafile.read(javares['size']))

			hints[tmpfilename] = {}
			hints[tmpfilename]['tags'] = ['java', 'binary']
			hints[tmpfilename]['scanned'] = True
			blacklist.append((offset, offset + javares['size']))
			diroffsets.append((tmpdir, offset, javares['size']))
			counter += 1

	javafile.close()
	return (diroffsets, blacklist, newtags, hints)
