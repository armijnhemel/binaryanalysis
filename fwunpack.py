#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, subprocess
import tempfile
import fsmagic
import fssearch
import bz2
import tarfile

def searchUnpackSquashfs(filename):
        datafile = open(filename, 'rb')
        data = datafile.read()
        datafile.close()
	offset = fssearch.findSquashfs(data)
	if offset == -1:
		return None
	else:
		tmpdir = tempfile.mkdtemp()
		while(offset != -1):
			res = unpackSquashfs(data, offset, tmpdir)
			if res != None:
				return tmpdir
			offset = fssearch.findSquashfs(data, offset+1)
		return None

## tries to unpack stuff using unsquashfs. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackSquashfs(data, offset, tmpdir=None):
        if tmpdir == None:
                tmpdir = tempfile.mkdtemp()
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	p = subprocess.Popen(['/usr/sbin/unsquashfs', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanuit, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
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
def unpackGzip(data, offset, tmpdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that zcat is in the path
	if tmpdir == None:
		tmpdir = tempfile.mkdtemp()
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['zcat', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanuit, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanuit)
	if os.stat(outtmpfile[1]).st_size == 0:
		os.fdopen(outtmpfile[0]).close()
		os.unlink(outtmpfile[1])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
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
		return None
	else:
		tmpdir = tempfile.mkdtemp()
		while(offset != -1):
			res = unpackGzip(data, offset, tmpdir)
			if res != None:
				return tmpdir
			offset = fssearch.findGzip(data, offset+1)
		return None

def searchUnpackLZMA(filename):
        datafile = open(filename, 'rb')
        data = datafile.read()
        datafile.close()
	offset = fssearch.findLZMA(data)
	if offset == -1:
		return None
	else:
		tmpdir = tempfile.mkdtemp()
		while(offset != -1):
			res = unpackLZMA(data, offset, tmpdir)
			if res != None:
				return tmpdir
			offset = fssearch.findLZMA(data, offset+1)
		return None

## tries to unpack stuff using lzma -cd. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackLZMA(data, offset, tmpdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzma is in the path
	if tmpdir == None:
		tmpdir = tempfile.mkdtemp()
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['lzma', '-cd', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanuit, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanuit)
	os.unlink(tmpfile[1])
	return tmpdir
