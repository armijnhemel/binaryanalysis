#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains helper functions to unpack archives or file systems.
Most of the commands are pretty self explaining. The result of the wrapper
functions is a list of tuples, which contain the name of a temporary directory
with the unpacked contents of the archive, and the offset of the archive or
file system in the parent file.
'''

import sys, os, subprocess
import tempfile, bz2, re, magic, tarfile
import fsmagic, fssearch

def searchUnpackTar(filename):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(filename)
	ms.close()

	tarmagic = ['POSIX tar archive (GNU)'
		   , 'tar archive'
		   ]

	for tm in tarmagic:
		if tm in type:
			tar = tarfile.open(filename, 'r')
                	tmpdir = tempfile.mkdtemp()
			tar.extractall(path=tmpdir)
			tar.close()
			return [(tmpdir, 0)]
	return []

def searchUnpackCab(filename):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(filename)
	ms.close()

	exemagic = ['Microsoft Cabinet archive data'
		   ]

	for exe in exemagic:
		if exe in type:
                	tmpdir = tempfile.mkdtemp()
			p = subprocess.Popen(['cabextract', '-d', tmpdir, filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanuit, stanerr) = p.communicate()
			if p.returncode != 0:
				try:
					os.rmdir(tmpdir)
				except:
					pass
				continue
			return [(tmpdir, 0)]
	return []

def searchUnpack7z(filename):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(filename)
	ms.close()

	exemagic = ['PE32 executable for MS Windows'
		   ]

	for exe in exemagic:
		if exe in type:
                	tmpdir = tempfile.mkdtemp()
			param = "-o%s" % tmpdir
			p = subprocess.Popen(['7z', param, '-l', '-y', 'x', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanuit, stanerr) = p.communicate()
			if p.returncode != 0:
				try:
					os.rmdir(tmpdir)
				except:
					pass
				continue
			return [(tmpdir, 0)]
	return []

def searchUnpackCpio(filename):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findCpio(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
		trailer = fssearch.findCpioTrailer(data)
		while(offset != -1):
			res = unpackCpio(data, offset)
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
	p = subprocess.Popen(['cpio', '-i', '--no-absolute-filenames'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanuit, stanerr) = p.communicate(data[offset:])
	return tmpdir

def searchUnpackCramfs(filename):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findCramfs(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
		while(offset != -1):
			res = unpackCramfs(data, offset)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findCramfs(data, offset+1)
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

def searchUnpackSquashfs(filename):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findSquashfs(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
		while(offset != -1):
			res = unpackSquashfs(data, offset)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findSquashfs(data, offset+1)
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

	p = subprocess.Popen(['/usr/sbin/unsquashfs', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
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

def searchUnpackGzip(filename):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findGzip(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
		while(offset != -1):
			res = unpackGzip(data, offset)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findGzip(data, offset+1)
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

def searchUnpackZip(filename):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findZip(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
		endofcentraldir = 0
		while(offset != -1):
			(endofcentraldir, res) = unpackZip(data, offset)
			#print "orig:", datafile, "offset:", offset, "res:", res, "endofcentraldir", endofcentraldir
			if res != None:
				diroffsets.append((res, offset))
			if endofcentraldir == None:
				offset = fssearch.findZip(data, offset+1)
			else:
				offset = fssearch.findZip(data, endofcentraldir+1)
		return diroffsets

def searchUnpackRar(filename):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findRar(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
		while(offset != -1):
			(endofarchive, res) = unpackRar(data, offset)
			if res != None:
				diroffsets.append((res, offset))
			if endofarchive == None:
				offset = fssearch.findRar(data, offset+1)
			else:
				offset = fssearch.findRar(data, endofarchive)
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

def searchUnpackLZMA(filename):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findLZMA(data)
	if offset == -1:
		return []
	else:
		diroffsets = []
		while(offset != -1):
			res = unpackLZMA(data, offset)
			if res != None:
				diroffsets.append((res, offset))
			offset = fssearch.findLZMA(data, offset+1)
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
