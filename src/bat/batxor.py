#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Sometimes some files like firmwares are encrypted. The level of encryption
varies with keys and verifying signatures at boot time to very simple
"encryption" by simply XORing with a byte string.

The code here scans binary files for certain known XOR parameters and applies
them, but only if no other scan succeeds.

For this we need to keep some state, possibly even delete the file only later,
by tagging it as 'temporary' and removing it later on.
'''

import sys, os, os.path, tempfile, mmap
import fwunpack

## some of the signatures we know about:
## * Splashtop (fast boot environment)
## * Bococom router series (2.6.21, Ralink chipset)
## * Sitecom WL-340 and WL-342

## Finding new signatures is done by hand. A good helper tool can be found in
## the bat-visualisation directory in bat-extratools

## The signatures of various known XOR "encrypted" firmwares.
signatures = { 'splashtop': ['\x51', '\x57', '\x45', '\x52']
             , 'bococom':   ['\x3a', '\x93', '\xa2', '\x95', '\xc3', '\x63', '\x48', '\x45', '\x58', '\x09', '\x12', '\x03', '\x08', '\xc8', '\x3c']
             , 'sitecom':   ['\x78', '\x3c', '\x9e', '\xcf', '\x67', '\xb3', '\x59', '\xac']
             }

def unpackXOR(filename, sig, tempdir=None):
	tmpdir = fwunpack.unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	fwunpack.unpackFile(filename, 0, tmpfile[1], tmpdir, modify=True)
	datafile = open(filename)
	datafile.seek(0)
	data = datafile.read(1000000)

	## read data, XOR, write data out again
	f2 = open(tmpfile[1], 'w')
	counter = 0
	while data != '':
		for i in data:
			f2.write(chr(ord(i) ^ ord(signatures[sig][counter])))
			counter = (counter+1)%len(signatures[sig])
		data = datafile.read(1000000)
	f2.close()
	datafile.close()
	return tmpdir

def searchUnpackXOR(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = []
	diroffsets = []

	## If something else already unpacked (parts) of the file we're not
	## going to continue.
	if 'BAT_UNPACKED' in scanenv:
		if scanenv['BAT_UNPACKED'] == 'True':
			return (diroffsets, blacklist, [], hints)

	if 'XOR_MINIMUM' in scanenv:
		xor_minimum = int(scanenv['XOR_MINIMUM'])
	else:
		xor_minimum = 0
	## only continue if no other scan has succeeded
	if blacklist != []:
		return (diroffsets, blacklist, [], hints)
	counter = 1

	## only continue if we actually have signatures
	if signatures == {}:
		return (diroffsets, blacklist, [], hints)

	## open the file, so we can search for signatures
	## TODO: use the identifier search we have elsewhere.
	datafile = os.open(filename, os.O_RDONLY)
	datamm = mmap.mmap(datafile, 0, access=mmap.ACCESS_READ)

	tmpdir = fwunpack.dirsetup(tempdir, filename, "xor", counter)
	res = None
	for s in signatures:
		bs = reduce(lambda x, y: x + y, signatures[s])
		## find all instances of the signature. We might want to tweak
		## this a bit.
		bsres = datamm.find(bs)
		if bsres == -1:
			continue
		siginstances = [bsres]
		while bsres != -1:
			bsres = datamm.find(bs, bsres +1)
			if bsres != -1:
				siginstances.append(bsres)
		if len(siginstances) > 0:
			if len(siginstances) < xor_minimum:
				continue
			res = unpackXOR(filename, s, tmpdir)
			if res != None:
				diroffsets.append((res, 0, os.stat(filename).st_size))
				## blacklist the whole file
				blacklist.append((0, os.stat(filename).st_size))
				break
	datamm.close()
	os.close(datafile)
	if res == None:
		os.rmdir(tmpdir)
		return (diroffsets, blacklist, [], hints)
	return (diroffsets, blacklist, ['temporary'], hints)
