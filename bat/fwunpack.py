#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains helper functions to unpack archives or file systems.
Most of the commands are pretty self explaining. The result of the wrapper
functions is a list of tuples, which contain the name of a temporary directory
with the unpacked contents of the archive, and the offset of the archive or
file system in the parent file.

Optionally, we should return a range of bytes that should be excluded.

TODO: merge many of the searchUnpack and unpack methods, so we only have to
suck in the data once in the unpack part.
'''

import sys, os, subprocess
import tempfile, bz2, re, magic, tarfile
import fsmagic, fssearch, extractor
import rpm

## convenience method to check if the offset we find is in a blacklist
## Blacklists are composed of tuples (lower, upper) which mark a region
## in the parent file(!) as a no go area.
## This method returns the upperbound from the tuple for which
## lower <= offset <= upper is True
def inblacklist(offset, blacklist):
	return extractor.inblacklist(offset, blacklist)

## TODO: rewrite this to like how we do other searches: first
## look for markers, then unpack.
## This method should return a blacklist.
def searchUnpackTar(filename, tempdir=None, blacklist=[]):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(filename)
	ms.close()

	tarmagic = ['POSIX tar archive (GNU)'
		   , 'tar archive'
		   ]

	## search for first magic marker that matches
	for tm in tarmagic:
		if tm in type:
			tarsize = 0
        		if tempdir == None:
        		       	tmpdir = tempfile.mkdtemp()
			else:
				tmpdir = tempdir
			tar = tarfile.open(filename, 'r')
                	tartmpdir = tempfile.mkdtemp(dir=tmpdir)
			tar.extractall(path=tartmpdir)
			for t in tar:
				tarsize = tarsize + t.size
			tar.close()
			blacklist.append((0,tarsize))
			return [(tartmpdir, 0), blacklist]
	return []

def searchUnpackCab(filename, tempdir=None, blacklist=[]):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(filename)
	ms.close()

	exemagic = ['Microsoft Cabinet archive data'
		   ]

	for exe in exemagic:
		if exe in type:
        		if tempdir == None:
        		       	tmpdir = tempfile.mkdtemp()
			else:
				tmpdir = tempdir
                	cabtmpdir = tempfile.mkdtemp(dir=tmpdir)
			p = subprocess.Popen(['cabextract', '-d', cabtmpdir, filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanuit, stanerr) = p.communicate()
			if p.returncode != 0:
				try:
					os.rmdir(cabtmpdir)
				except:
					pass
				continue
			return [(cabtmpdir, 0), blacklist]
	return []

def searchUnpack7z(filename, tempdir=None, blacklist=[]):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(filename)
	ms.close()

	exemagic = ['PE32 executable for MS Windows'
		   ]

	for exe in exemagic:
		if exe in type:
        		if tempdir == None:
        		       	tmpdir = tempfile.mkdtemp()
			else:
				tmpdir = tempdir
                	zztmpdir = tempfile.mkdtemp(dir=tmpdir)
			param = "-o%s" % zztmpdir
			p = subprocess.Popen(['7z', param, '-l', '-y', 'x', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanuit, stanerr) = p.communicate()
			if p.returncode != 0:
				try:
					os.rmdir(zztmpdir)
				except:
					pass
				continue
			return [(zztmpdir, 0), blacklist]
	return []

## This method should return a blacklist.
def searchUnpackCpio(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findCpio(data)
	if offset == -1:
		return []
	else:
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		diroffsets = []
		trailer = fssearch.findCpioTrailer(data)
		while(offset != -1):
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findCpio(data, offset+blacklistoffset)
			if offset == -1:
				break
			res = unpackCpio(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				blacklist.append((offset, trailer))
			offset = fssearch.findCpio(data, offset+1)
			while offset < trailer and offset != -1:
				offset = fssearch.findCpio(data, offset+1)
			trailer = fssearch.findCpioTrailer(data, offset)
		diroffsets.append(blacklist)
		return diroffsets

## tries to unpack stuff using cpio. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackCpio(data, offset, tempdir=None):
        if tempdir == None:
                tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	## write data to a temporary location first so we can check
	## the magic.
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(tmpfile[1])
	ms.close()
	if 'cpio' not in type:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	p = subprocess.Popen(['cpio', '-i', '-d', '--no-absolute-filenames'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanuit, stanerr) = p.communicate(data[offset:])
	return tmpdir

## This method should return a blacklist.
def searchUnpackCramfs(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findCramfs(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1):
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findCramfs(data, offset+blacklistoffset)
			if offset == -1:
				break
			res = unpackCramfs(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findCramfs(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		diroffsets.append(blacklist)
		return diroffsets

## tries to unpack stuff using fsck.cramfs. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackCramfs(data, offset, tempdir=None):
        if tempdir == None:
                tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	## fsck.cramfs needs to unpack in a separate directory. So, create a new temporary
	## directory to avoid name clashes
        tmpdir2 = tempfile.mkdtemp()
	## since fsck.cramfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	## right now this is a path to a specially adapted fsck.cramfs that ignores special inodes
	## create a new path to unpack all stuff
	p = subprocess.Popen(['/tmp/fsck.cramfs', '-x', tmpdir2 + "/cramfs", tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanuit, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
			os.rmdir(tmpdir2)
		return
	else:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		os.rmdir(tmpdir)
		return tmpdir2

## Search and unpack a squashfs file system. Since there are so many flavours
## of squashfs available we have to do some extra work here, and possibly have
## some extra tools (squashfs variants) installed.
## We don't return a blacklist here, but we could use unsquashfs -s to get
## statistics and possibly speed up the scanning a bit.
def searchUnpackSquashfs(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	(offset, squashtype) = fssearch.findSquashfs(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1):
			## check if the offset we find is in a blacklist
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				(offset, squashtype) = fssearch.findSquashfs(data, offset+blacklistoffset)
			if offset == -1:
				break
			res = unpackSquashfs(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			(offset, squashtype) = fssearch.findSquashfs(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		diroffsets.append(blacklist)
		return diroffsets

## tries to unpack stuff using unsquashfs. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackSquashfs(data, offset, tempdir=None):
        if tempdir == None:
                tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	## squashfs is not always in the same path, so we need to make a few different invocations
	## Fedora uses /usr/sbin, Ubuntu users /usr/bin
	## Below there is an extremely ugly hack to differentiate between the two
	try:
		os.stat('/usr/sbin/unsquashfs')
		distro = 'sbin'
	except:
		try:
			os.stat('/usr/bin/unsquashfs')
			distro = 'bin'
		except:
			return

	if distro == 'sbin':
		p = subprocess.Popen(['/usr/sbin/unsquashfs', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	elif distro == 'bin':
		p = subprocess.Popen(['/usr/bin/unsquashfs', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanuit, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return
	else:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return tmpdir

## We use tune2fs to get the size of the file system so we know what to
## blacklist.
## TODO: unpack, plus use tune2fs on the right offset
## This method should return a blacklist.
def searchUnpackExt2fs(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findExt2fs(data)
	if offset == -1:
		return blacklist
	## according to /usr/share/magic the magic header starts at 0x438
	if offset < 0x438:
		return blacklist
	else:
		diroffsets = []
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1 and offset >= 0x438):
			## check if the offset we find is in a blacklist
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findExt2fs(data, offset+blacklistoffset)
			if offset == -1:
				break
			## unpack data here
			## we should actually scan the data starting from offset - 0x438
			p = subprocess.Popen(['tune2fs', '-l', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode == 0:
				if len(stanerr) == 0:
					blockcount = 0
					blocksize = 0
					## we want block count and block size
					for line in stanout.split("\n"):
						if 'Block count' in line:
							blockcount = int(line.split(":")[1].strip())
						if 'Block size' in line:
							blocksize = int(line.split(":")[1].strip())
					blacklist.append((offset - 0x438, offset - 0x438 + blockcount * blocksize))
			offset = fssearch.findExt2fs(data, offset+1)
	return blacklist

## ideally we would have some code in Python that would analyse and
## unpack a file system, without having to mount it. This code does
## not exist as of now. We could use programs from e2tools:
## http://freshmeat.net/projects/e2tools/
## but these are very very basic and might be more hassle than we think.
def unpackExt2fs(data, offset, tempdir=None):
	pass

## tries to unpack stuff using zcat. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackGzip(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that zcat is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['zcat', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanuit, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanuit)
	#os.fdopen(outtmpfile[0]).flush()
	os.fsync(outtmpfile[0])
	if os.stat(outtmpfile[1]).st_size == 0:
		os.fdopen(outtmpfile[0]).close()
		os.unlink(outtmpfile[1])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.fdopen(outtmpfile[0]).close()
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

def searchUnpackGzip(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findGzip(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1):
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findGzip(data, offset+blacklistoffset)
			if offset == -1:
				break
			res = unpackGzip(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findGzip(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		diroffsets.append(blacklist)
		return diroffsets

## tries to unpack stuff using bzcat. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
## We use bzcat instead of the bz2 module because that can't handle trailing
## data very well.
def unpackBzip2(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that bzcat is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['bzcat', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanuit, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanuit)
	#os.fdopen(outtmpfile[0]).flush()
	os.fsync(outtmpfile[0])
	if os.stat(outtmpfile[1]).st_size == 0:
		os.fdopen(outtmpfile[0]).close()
		os.unlink(outtmpfile[1])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.fdopen(outtmpfile[0]).close()
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

def searchUnpackBzip2(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findBzip2(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
		if tempdir == None:
			tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1):
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findBzip2(data, offset+blacklistoffset)
			if offset == -1:
				break
			res = unpackBzip2(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findBzip2(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		diroffsets.append(blacklist)
		return diroffsets

def unpackZip(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that zipinfo and unzip are in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	## Use information from zipinfo -v to extract the right offsets (or at least the end offset
	p = subprocess.Popen(['zipinfo', '-v', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanuit, stanerr) = p.communicate()
	res = re.search("Actual[\w\s]*end-(?:of-)?cent(?:ral)?-dir record[\w\s]*:\s*(\d+) \(", stanuit)
	if res != None:
		endofcentraldir = int(res.groups(0)[0])
	else:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)
	p = subprocess.Popen(['unzip', '-o', tmpfile[1], '-d', tmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanuit, stanerr) = p.communicate()
	if p.returncode != 0 and p.returncode != 1:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (endofcentraldir, tmpdir)

def searchUnpackZip(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findZip(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		endofcentraldir = 0
		while(offset != -1):
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findZip(data, offset+blacklistoffset)
			if offset == -1:
				break
			(endofcentraldir, res) = unpackZip(data, offset, tmpdir)
			#print "orig:", datafile, "offset:", offset, "res:", res, "endofcentraldir", endofcentraldir
			if res != None:
				diroffsets.append((res, offset))
			if endofcentraldir == None:
				offset = fssearch.findZip(data, offset+1)
			else:
				offset = fssearch.findZip(data, endofcentraldir+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		diroffsets.append(blacklist)
		return diroffsets

def searchUnpackRar(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findRar(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1):
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findRar(data, offset+blacklistoffset)
			if offset == -1:
				break
			(endofarchive, res) = unpackRar(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			if endofarchive == None:
				offset = fssearch.findRar(data, offset+1)
			else:
				offset = fssearch.findRar(data, endofarchive)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		diroffsets.append(blacklist)
		return diroffsets

def unpackRar(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that unrar is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	# inspect the rar archive, and retrieve the end of archive
	# this way we won't waste too many resources when we don't need to
	p = subprocess.Popen(['unrar', 'vt', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanuit, stanerr) = p.communicate()
	rarstring = stanuit.strip().split("\n")[-1]
	res = re.search("\s*\d+\s*\d+\s+(\d+)\s+\d+%", rarstring)
	if res != None:
		endofarchive = int(res.groups(0)[0])
	else:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (-1, None)
	p = subprocess.Popen(['unrar', 'x', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanuit, stanerr) = p.communicate()
	## oh the horror, we really need to check if unzip actually was successful
	#outtmpfile = tempfile.mkstemp(dir=tmpdir)
	#os.write(outtmpfile[0], stanuit)
	#if os.stat(outtmpfile[1]).st_size == 0:
		#os.unlink(outtmpfile[1])
		#os.unlink(tmpfile[1])
		#return None
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (endofarchive, tmpdir)

def searchUnpackLZMA(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findLZMA(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1):
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findLZMA(data, offset+blacklistoffset)
			if offset == -1:
				break
			res = unpackLZMA(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findLZMA(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		diroffsets.append(blacklist)
		return diroffsets

## tries to unpack stuff using lzma -cd. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackLZMA(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzma is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['lzma', '-cd', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanuit, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanuit)
        if os.stat(outtmpfile[1]).st_size == 0:
                os.fdopen(outtmpfile[0]).close()
                os.unlink(outtmpfile[1])
                os.fdopen(tmpfile[0]).close()
                os.unlink(tmpfile[1])
		if tempdir == None:
                	os.rmdir(tmpdir)
                return None
	os.fdopen(outtmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

def unpackRPM(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that rpm2cpio is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	## first use rpm2cpio to unpack the rpm data
	p = subprocess.Popen(['rpm2cpio', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanuit, stanerr) = p.communicate()
	if len(stanuit) != 0:
		## cleanup first
                os.fdopen(tmpfile[0]).close()
                os.unlink(tmpfile[1])
		if tempdir == None:
                	os.rmdir(tmpdir)
		## then use unpackCpio() to unpack the RPM
		return unpackCpio(stanuit, 0, tempdir)
	else:
                os.fdopen(tmpfile[0]).close()
                os.unlink(tmpfile[1])
		if tempdir == None:
                	os.rmdir(tmpdir)
		return None

## RPM is basically a header, plus some compressed files, so we are getting
## duplicates at the moment. We can defeat this easily by setting the blacklist
## upperbound to the start of compression.
## This method should return a blacklist.
def searchUnpackRPM(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findRPM(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1):
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findRPM(data, offset+blacklistoffset)
			if offset == -1:
				break
			res = unpackRPM(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				## determine which compression is used, so we can
				## find the right offset. Code from the RPM examples
				tset = rpm.TransactionSet()
        			fdno = os.open(filename, os.O_RDONLY)
        			header = tset.hdrFromFdno(fdno)
        			os.close(fdno)
				## first some sanity checks. payload format should
				## always be 'cpio' according to LSB 3
				if header[rpm.RPMTAG_PAYLOADFORMAT] == 'cpio':
					## compression should always be 'gzip' according to LSB 3
					if header[rpm.RPMTAG_PAYLOADCOMPRESSOR] == 'gzip':
						payloadoffset = fssearch.findGzip(data, offset)
						blacklist.append((offset, payloadoffset))
			offset = fssearch.findRPM(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		diroffsets.append(blacklist)
		return diroffsets

## Search and unpack Ubifs. Since we can't easily determine the length of the
## file system by using ubifs we will have to use a different measurement to
## measure the size of ubifs. A good start is the sum of the size of the
## volumes that were unpacked.
## This method should return a blacklist.
def searchUnpackUbifs(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	## We can use the values of offset and ubisize where offset != -1
	## to determine the ranges for the blacklist.
	offset = fssearch.findUbifs(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1):
			blacklistoffset = inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findUbifs(data, offset+blacklistoffset)
			if offset == -1:
				break
			res = unpackUbifs(data, offset, tmpdir)
			if res != None:
				(ubitmpdir, ubisize) = res
				diroffsets.append((ubitmpdir, offset))
			offset = fssearch.findUbifs(data, offset+ubisize)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		diroffsets.append(blacklist)
		return diroffsets

def unpackUbifs(data, offset, tempdir=None):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		## since volumes might be called the same we need another
		## layer of tempdirs
		tmpdir = tempfile.mkdtemp(dir=tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	## use unubi to unpack the data
	p = subprocess.Popen(['unubi', '-d', tmpdir, tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanuit, stanerr) = p.communicate()

	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		## clean up the temporary files
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		## determine the sum of the size of the unpacked files
		osgen = os.walk(tempdir)
		ubisize = 0
		try:
			while True:
				i = osgen.next()
				for p in i[2]:
					ubisize = ubisize + os.stat("%s/%s" % (i[0], p)).st_size
        	except StopIteration:
                	pass
		return (tmpdir, ubisize)
