#!/usr/bin/python

import sys, os
import tempfile
import fsmagic
import bz2

def findSquashfs(data, offset=0):
	marker = -1
	marker = findType('squashfs-le', data,offset)
	if marker == -1:
		return findType('squashfs-be', data, offset)
	else:
		marker2 = findType('squashfs-be', data, offset)
		if marker2 != -1:
			return min(marker, marker2)
		else:
			return marker2

def findMarker(marker, data, offset=0):
	return data.find(fsmagic.marker[marker], offset)

def findType(type, data, offset=0):
	return data.find(fsmagic.fsmagic[type], offset)

def findGzip(data, offset=0):
	return findType('gzip', data, offset)

## not reliable according to comments in /usr/share/magic
def findLZMA(data, offset=0):
	return findType('lzma_alone', data, offset)

def findBzip2(data, offset=0):
	return findType('bz2', data, offset)

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

def findLinuxKernel(data):
	marker = findMarker('Linux kernel (ARM)', data)
	return findGzip(data, marker)

# search for a known marker for the Linux kernel for a certain arch
# next find the first occurance of a certain header
def findLinuxKernelX86(data, architecture):
	## there are various compression methods in use on x86
	marker = findMarker('Linux kernel (x86)', data)
	res = findGzip(data, marker)
	if res == -1:
		res = findBzip2(data, marker)
	return res
