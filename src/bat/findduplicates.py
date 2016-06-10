#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys

'''
This aggregate scan traverses the unpackreports and reports all duplicate
files as a list of lists of identical files.
'''

def findduplicates(unpackreports, scantempdir, topleveldir, processors, scanenv, batcursors, batcons, scandebug=False, unpacktempdir=None):
	filehashes = {}
	for r in unpackreports.keys():
		if 'checksum' in unpackreports[r]:
			if unpackreports[r]['checksum'] in filehashes:
				filehashes[unpackreports[r]['checksum']].append(r)
			else:
				filehashes[unpackreports[r]['checksum']] = [r]
	duplicates = []
	for h in filehashes:
		if len(filehashes[h]) > 1:
			duplicates.append(filehashes[h])
	if duplicates != []:
		return {'duplicates': duplicates}
