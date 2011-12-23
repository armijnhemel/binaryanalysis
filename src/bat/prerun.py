#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains helper functions that are run before any of the other
scans.
'''

import sys, os, subprocess, os.path, shutil, stat
import tempfile, re, magic
import fsmagic, fssearch, extractor

## method to search for all the markers we have in fsmagic
def genericMarkerSearch(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	datafile = open(filename, 'rb')
	databuffer = []
	offsets = {}
	offset = 0
	datafile.seek(offset)
	databuffer = datafile.read(100000)
        marker_keys = fsmagic.fsmagic.keys()
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
	return ([], blacklist, offsets)

## XML files actually only need to be verified and blacklisted so other scans
## don't waste time on it
## TODO: rewrite as a prerun scan and tag files as 'xml'
def searchXML(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	p = subprocess.Popen(['xmllint',filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode == 0:
		## valid XML, so blacklist
		blacklist.append((0, os.stat(filename).st_size))
	return ([], blacklist, offsets)
