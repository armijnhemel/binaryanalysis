#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains helper functions that are run before any of the other
scans.
'''

import sys, os, subprocess, os.path, shutil, stat
import tempfile, re, magic
import fsmagic, fssearch, extractor

## method to search for all the markers in magicscans
def genericMarkerSearch(filename, magicscans, envvars=None):
	datafile = open(filename, 'rb')
	databuffer = []
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
		## move the offset 99950
		datafile.seek(offset + 99950)
		## read 100000 bytes with a 50 bytes overlap
		## overlap with the previous read
		databuffer = datafile.read(100000)
		if len(databuffer) >= 50:
			offset = offset + 99950
		else:
			offset = offset + len(databuffer)
	datafile.close()
	return offsets

## XML files actually only need to be verified and tagged so other scans can decide to ignore it
def searchXML(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	tags = []
	p = subprocess.Popen(['xmllint','--noout', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode == 0:
		tags.append("xml")
	return ([], blacklist, tags)

## method to verify if a file only contains text
## Since the default encoding in Python 2 is 'ascii' and we can't guarantee
## that it has been set by the user to something else this will not work
## on UTF-8 encoded files, unless we ask the user to set the encoding in
## site.py which we can't.
##
## Interesting link with background info:
## * http://fedoraproject.org/wiki/Features/PythonEncodingUsesSystemLocale
def verifyText(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	tags = []
	datafile = open(filename, 'rb')
	databuffer = []
	offset = 0
	datafile.seek(offset)
	databuffer = datafile.read(100000)
	while databuffer != '':
		if not extractor.isPrintables(databuffer):
			datafile.close()
			tags.append("binary")
			return ([], blacklist, tags)
		## move the offset 100000
		datafile.seek(offset + 100000)
		databuffer = datafile.read(100000)
		offset = offset + len(databuffer)
	tags.append("text")
	datafile.close()
	return ([], blacklist, tags)

## quick check to verify if a file is a graphics file.
def verifyGraphics(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	tags = []
	tags = verifyPNG(filename, tempdir, blacklist, offsets, envvars)[2]
	if tags == []:
		tags = verifyBMP(filename, tempdir, blacklist, offsets, envvars)[2]
	return ([], blacklist, tags)

def verifyBMP(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	tags = []
	p = subprocess.Popen(['bmptopnm', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0 or "warning" in stanerr:
		return ([], blacklist, tags)
	tags.append("bmp")
	tags.append("graphics")
	return ([], blacklist, tags)

def verifyPNG(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	tags = []
	p = subprocess.Popen(['jpegtopnm', '-multiple', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return ([], blacklist, tags)
	## multiple jpegs in this file, so we need to unpack
	if len(stanerr.strip().split("\n")) > 1:
		return ([], blacklist, tags)
	tags.append("jpeg")
	tags.append("graphics")
	return ([], blacklist, tags)

def verifyGzip(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	tags = []
	p = subprocess.Popen(['gunzip', '-t', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return ([], blacklist, tags)
	## possibly multiple gzips in this file, or bzip2 with trailing data
	if "trailing garbage ignored" in stanerr:
		return ([], blacklist, tags)
	## the file contains one or more gzip archives
	tags.append("gzip")
	tags.append("compressed")
	return ([], blacklist, tags)

def verifyBZ2(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	tags = []
	p = subprocess.Popen(['bunzip2', '-tvv', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return ([], blacklist, tags)
	## possibly multiple bzip2 in this file, or bzip2 with trailing data
	if len(stanerr.strip().split("\n")) > 1:
		if "trailing garbage after EOF ignored" in stanerr:
			return ([], blacklist, tags)
		else:
			## output would look like:
			## $ bunzip2 -tvv foo.bz2 
			##  foo.bz2: 
			##    [1: huff+mtf rt+rld]
			##    ok
			## so splitting it on "\n" would give us a list of length 3
			## (because we strip) if there is just one bzip2 file, otherwise more.
			if len(stanerr.strip().split("\n")) > 3:
				return ([], blacklist, tags)
	tags.append("bz2")
	tags.append("compressed")
	return ([], blacklist, tags)
