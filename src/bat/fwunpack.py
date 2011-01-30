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
'''

import sys, os, subprocess
import tempfile, bz2, re, magic, tarfile
import fsmagic, fssearch

def searchUnpackTar(filename, tempdir=None):
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
        		if tempdir == None:
        		       	tmpdir = tempfile.mkdtemp()
			else:
				tmpdir = tempdir
			tar = tarfile.open(filename, 'r')
                	tartmpdir = tempfile.mkdtemp(dir=tmpdir)
			tar.extractall(path=tartmpdir)
			tar.close()
			return [(tartmpdir, 0)]
	return []

def searchUnpackCab(filename, tempdir=None):
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
			return [(cabtmpdir, 0)]
	return []

def searchUnpack7z(filename, tempdir=None):
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
			return [(zztmpdir, 0)]
	return []

def searchUnpackCpio(filename, tempdir=None):
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
			res = unpackCpio(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findCpio(data, offset+1)
			while offset < trailer and offset != -1:
				offset = fssearch.findCpio(data, offset+1)
			trailer = fssearch.findCpioTrailer(data, offset)
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

def searchUnpackCramfs(filename, tempdir=None):
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
			res = unpackCramfs(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findCramfs(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
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
def searchUnpackSquashfs(filename, tempdir=None):
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
			res = unpackSquashfs(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			(offset, squashtype) = fssearch.findSquashfs(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
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

## ideally we would have some code in Python that would analyse and
## unpack a file system, without having to mount it. This code does
## not exist as of now. So, we'll just use programs from e2tools:
## http://freshmeat.net/projects/e2tools/
def unpackExt2fs(data, offset):
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

def searchUnpackGzip(filename, tempdir=None):
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
			res = unpackGzip(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findGzip(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
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

def searchUnpackBzip2(filename, tempdir=None):
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
			res = unpackBzip2(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findBzip2(data, offset+1)
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

def searchUnpackZip(filename, tempdir=None):
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
		return diroffsets

def searchUnpackRar(filename, tempdir=None):
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
			(endofarchive, res) = unpackRar(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			if endofarchive == None:
				offset = fssearch.findRar(data, offset+1)
			else:
				offset = fssearch.findRar(data, endofarchive)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
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

def searchUnpackLZMA(filename, tempdir=None):
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
			res = unpackLZMA(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findLZMA(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
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
## duplicates at the moment. We can defeat this by setting the blacklist
## to start of compression + 1. This should be fairly easy to do according to
## the documentation rpm.org.
def searchUnpackRPM(filename, tempdir=None):
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
			res = unpackRPM(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findRPM(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		return diroffsets

## search and unpack Ubifs. Since we can't easily determine the length of the
## file system by using ubifs we will have to use a different measurement to
## measure the size of ubifs. A good start is the size of the volumes that were
## unpacked. TODO.
def searchUnpackUbifs(filename, tempdir=None):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
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
			res = unpackUbifs(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findUbifs(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		return diroffsets

def unpackUbifs(data, offset, tempdir=None):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
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
		return tmpdir
