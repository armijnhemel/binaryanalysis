#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os
import tempfile
import fsmagic

# Find a squashfs file system, starting at a certain offset.
# Returns the offset of the file system nearest file system.
def findSquashfs(data, offset=0):
	marker = -1
	squashtype = None
	for t in fsmagic.squashtypes:
		sqshmarker = findMarker2(fsmagic.fsmagic[t], data, offset)
		if sqshmarker == -1:
			continue
		if marker == -1:
			marker = sqshmarker
		else:
			marker = min(marker, sqshmarker)
	return marker

def findMarker(marker, data, offset=0):
	return data.find(marker, offset)

## version of findMarker that uses seek() and read()
## which should come in handy for big files
def findMarker2(marker, datafile, offset=0):
	databuffer = []
	datafile.seek(offset)
	databuffer = datafile.read(100000)
	while databuffer != '':
		res = databuffer.find(marker)
		if res != -1:
			datafile.seek(0)
			return offset + res
		else:
			## move the offset 50
			datafile.seek(offset + 99950)
			## read 100000 bytes from oldoffset + 50, so there is 50 bytes
			## overlap with the previous read
			databuffer = datafile.read(100000)
			if len(databuffer) >= 50:
				offset = offset + 99950
			else:
				offset = offset + len(databuffer)
	datafile.seek(0)
	return -1

def findType(type, data, offset=0):
	res = findMarker2(fsmagic.fsmagic[type], data, offset)
	return res

def findCpio(data, offset=0):
	cpiomarker = -1
	for marker in fsmagic.cpio:
		res = findMarker2(fsmagic.fsmagic[marker], data, offset)
		if res != -1 and cpiomarker == -1:
			cpiomarker = res
		elif res != -1:
			cpiomarker = min(cpiomarker, res)
	return cpiomarker

def findXZTrailer(data, offset=0):
	return findType('xztrailer', data, offset)

def findCpioTrailer(data, offset=0):
	return findType('cpiotrailer', data, offset)

def findExt2fs(data, offset=0):
	return findType('ext2', data, offset)

def findRPM(data, offset=0):
	return findType('rpm', data, offset)

def findGzip(data, offset=0):
	return findType('gzip', data, offset)

def findZip(data, offset=0):
	return findType('zip', data, offset)

def findCramfs(data, offset=0):
	return findType('cramfs', data, offset)

def findUbifs(data, offset=0):
	return findType('ubifs', data, offset)

def findRar(data, offset=0):
	return findType('rar', data, offset)

## not reliable according to comments in /usr/share/magic
def findLZMA(data, offset=0):
	return findType('lzma_alone', data, offset)

def findXZ(data, offset=0):
	return findType('xz', data, offset)

def findLzip(data, offset=0):
	return findType('lzip', data, offset)

def findLzo(data, offset=0):
	return findType('lzo', data, offset)

def findBzip2(data, offset=0):
	return findType('bz2', data, offset)

def findARJ(data, offset=0):
	return findType('arj', data, offset)

def findCab(data, offset=0):
	return findType('cab', data, offset)

def findPNG(data, offset=0):
	return findType('png', data, offset)

## http://www.w3.org/TR/PNG-Chunks.html
def findPNGTrailer(data, offset=0):
	return findType('pngtrailer', data, offset)

def findJFIF(data, offset=0):
	jfifmarker = findType('jfif', data, offset)
	if jfifmarker < 6:
		return -1
	else:
		return jfifmarker - 6

def findGIF(data, offset=0):
	gifmarker = -1
	for marker in fsmagic.gif:
		res = findMarker2(fsmagic.fsmagic[marker], data, offset)
		if res != -1 and gifmarker == -1:
			gifmarker = res
		elif res != -1:
			gifmarker = min(gifmarker, res)
	return gifmarker

def markerSearch(data):
	offsets = []
	marker_keys = fsmagic.marker.keys()
	for key in marker_keys:
		res = data.find(fsmagic.marker[key])
		while res != -1:
			offsets.append((res, key))
			res = data.find(fsmagic.marker[key], res+1)
	offsets.sort()
	for i in offsets:
		print hex(i[0]), i[1], i[0]%8

def bruteForceSearch(data):
	offsets = []
	fsmagic_keys = fsmagic.fsmagic.keys()
	for key in fsmagic_keys:
		res = data.find(fsmagic.fsmagic[key])
		while res != -1:
			offsets.append((res, key))
			res = data.find(fsmagic.fsmagic[key], res+1)
	offsets.sort()
	for i in offsets:
		print hex(i[0]), i[1], i[0]%8
