#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, multiprocessing

'''
This plugin for BAT looks at the extracted identifiers and looks at if there
is some sort of copyright notice in an extracted identifier. This might not
work well in the case of multiline copyright notices.
'''

def reportcopyright(unpackreports, scantempdir, topleveldir, processors, scanenv, batcursors, batcons, scandebug=False, unpacktempdir=None):
	for i in unpackreports:
		if not 'checksum' in unpackreports[i]:
			continue
		filehash = unpackreports[i]['checksum']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		if not 'identifier' in unpackreports[i]['tags']:
			continue

		## read pickle file
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		writeback = False
		strs = leafreports['identifier']['strings']
		copyrights = []
		for line in strs:
			if 'copyright' in line.lower():
				writeback = True
				copyrights.append(line)
				continue
			if '(c)' in line.lower():
				writeback = True
				copyrights.append(line)
		if writeback:
			unpackreports[i]['tags'].append('copyright')
			leafreports['tags'].append('copyright')
			leafreports['copyrights'] = copyrights

			leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
			leafreports = cPickle.dump(leafreports, leaf_file)
			leaf_file.close()
