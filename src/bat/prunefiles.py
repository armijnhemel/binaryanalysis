#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys

'''
This method can be used to prune scans, by for example ignoring all graphics files
'''

def prunefiles(unpackreports, scantempdir, topleveldir, processors, scanenv={}, scandebug=False, unpacktempdir=None):
	if not scanenv.has_key("PRUNE_TAGS"):
		return
	prunes = scanenv['PRUNE_TAGS']
	prunetags = set(prunes.split(','))

	cleanpickles = False
	if scanenv.get('PRUNE_FILEREPORT_CLEAN', 0) == '1':
		cleanpickles = True

	cleanfiles = set()
	for u in unpackreports.keys():
		if set(unpackreports[u]['tags']).intersection(prunetags) != set():
			if cleanpickles:
				filehash = unpackreports[u]['sha256']
				cleanfiles.add(filehash)
			del unpackreports[u]

	for filehash in cleanfiles:
		try:
			os.unlink(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash))
		except Exception, e:
			print >>sys.stderr, "error removing", filehash, e
			sys.stderr.flush()
