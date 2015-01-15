#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys

'''
This aggregate scan traverses the unpackreports and reports all duplicate
files.
'''

def findduplicates(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):
	filehashes = {}
	for r in unpackreports.keys():
		if unpackreports[r].has_key('sha256'):
			if filehashes.has_key(unpackreports[r]['sha256']):
				filehashes[unpackreports[r]['sha256']].append(r)
			else:
				filehashes[unpackreports[r]['sha256']] = [r]
	duplicates = []
	for h in filehashes:
		if len(filehashes[h]) > 1:
			duplicates.append(filehashes[h])
	if duplicates != []:
		return {'duplicates': duplicates}
