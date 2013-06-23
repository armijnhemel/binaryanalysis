#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
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

import sys, os, os.path, tempfile, re
import fwunpack

## some of the signatures we know about:
## * Splashtop (fast boot environment)
## * Bococom router series (2.6.21, Ralink chipset)

## Finding new signatures is done by hand. A good helper tool can be found in
## the bat-visualisation directory in bat-extratools

## The signatures of various known XOR "encrypted" firmwares.
signatures = { 'splashtop': ['\x51', '\x57', '\x45', '\x52']
             , 'bococom':   ['\x3a', '\x93', '\xa2', '\x95', '\xc3', '\x63', '\x48', '\x45', '\x58', '\x09', '\x12', '\x03', '\x08', '\xc8', '\x3c']
             }

## Ooooh, this is so inefficient...
def unpackXOR(filename, sig, tempdir=None):
	tmpdir = fwunpack.unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	fwunpack.unpackFile(filename, 0, tmpfile[1], tmpdir, modify=True)
	data = open(filename).read()

	## read data, XOR, write data out again
	f2 = open(tmpfile[1], 'w')
	counter = 0
	for i in data:
		f2.write(chr(ord(i) ^ ord(signatures[sig][counter])))
		counter = (counter+1)%len(signatures[sig])
	f2.close()
	return tmpdir

def searchUnpackXOR(filename, tempdir=None, blacklist=[], offsets={}, debug=False, envvars=None):
	diroffsets = []
	scanenv = os.environ.copy()

	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	## If something else already unpacked (parts) of the file we're not
	## going to continue.
	if scanenv['BAT_UNPACKED'] == 'True':
		return (diroffsets, blacklist, [])

	## only continue if no other scan has succeeded
	if blacklist != []:
		return (diroffsets, blacklist, [])
	counter = 1

	## only continue if we actually have signatures
	if signatures == {}:
		return (diroffsets, blacklist, [])

	## open the file, so we can search for signatures
	## TODO: use the identifier search we have elsewhere.
	data = open(filename).read()

	tmpdir = fwunpack.dirsetup(tempdir, filename, "xor", counter)
	res = None
	for s in signatures:
		bs = reduce(lambda x, y: x + y, signatures[s])
		## find all instances of the signature. We might want to tweak
		## this a bit.
		bsres = re.findall(bs, data)
		if len(bsres) > 0:
			res = unpackXOR(filename, s, tmpdir)
			if res != None:
				diroffsets.append((res, 0, os.stat(filename).st_size))
				## blacklist the whole file
				blacklist.append((0, os.stat(filename).st_size))
	if res == None:
		os.rmdir(tmpdir)
		return (diroffsets, blacklist, [])
	return (diroffsets, blacklist, ['temporary'])
