#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains a few methods that can be useful for security scanning.
'''

import os, sys, sqlite3, zipfile, subprocess

'''
## This method extracts the CRC32 checksums from the entries of the encrypted zip file and checks
## whether or not there are any files in the database with the same CRC32. If so, a known plaintext
## attack is possible to decrypt the archive and extract the key. The return value will be the file
## or checksum in the database to ...
def scanEncryptedZip(path, tags, blacklist=[], scandebug=False, envvars=None, unpacktempdir=None):
	if not 'zip' in tags and not 'encrypted' in tags:
		return
	encryptedzip = zipfile.ZipFile(path, 'r')
	encryptedinfos = encryptedzip.infolist()
	for e in encryptedinfos:
		crc = e.CRC
		if crc == 0:
			continue
	return
	return (['encryptedzip-attack'], True)
'''

## experimental clamscan feature
## Always run freshclam before scanning to get the latest
## virus signatures!
def scanVirus(path, tags, blacklist=[], scandebug=False, envvars=None, unpacktempdir=None):
	p = subprocess.Popen(['clamscan', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	print >>sys.stderr, "scanning", path, p.returncode
	if p.returncode == 0:
               	return
	else:
		## Oooh, virus found!
		viruslines = stanout.split("\n")
		## first line contains the report:
		virusname = viruslines[0].strip()[len(path) + 2:-6]
		return (['virus'], virusname)
