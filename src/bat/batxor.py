#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
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

import sys, os, os.path, tempfile
import fwunpack

## some of the signatures we know about:
## * Splashtop (fast boot environment)
## * Bococom router series (2.6.21, Ralink chipset)

## Finding new signatures is done by hand. A good helper tool can be found in
## the bat-visualisation directory in bat-extratools

### WARNING: unfinished code ###

signatures = { 'splashtop': ['\x51', '\x57', '\x45', '\x52']
             , 'bococom':   ['\x3a', '\x93', '\xa2', '\x95', '\xc3', '\x63', '\x48', '\x45', '\x58', '\x09', '\x12', '\x03', '\x08', '\xc8', '\x3c']
             }

def unpackXOR(filename, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()

	unpackFile(filename, offset, tmpfile[1], tmpdir)

	## suck in file, do XOR, write out again
	# counter = 0
	#for i in buf:
	#	f2.write(chr(ord(i) ^ ord(hexs[counter])))
	#	counter = (counter+1)%len(hexs)
	#return None

def searchUnpackXOR(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	counter = 1
	diroffsets = []

	## find signatures, run unpackXOR if any of the signatures were found,
	## preferably multiple times close to eachother
	return (diroffsets, blacklist, ['temporary'])
