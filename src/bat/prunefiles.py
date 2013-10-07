#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, multiprocessing

'''
This method can be used to prune scans, by for example ignoring all graphics files
'''

def prunefiles(unpackreports, scantempdir, topleveldir, processors, debug=False, envvars=None, unpacktempdir=None):
	scanenv = os.environ.copy()
	if envvars == None:
		return
	for en in envvars.split(':'):
		try:
			(envname, envvalue) = en.split('=')
			scanenv[envname] = envvalue
		except Exception, e:
			pass
	if not scanenv.has_key("PRUNE_TAGS"):
		return
	prunes = scanenv['PRUNE_TAGS']
	prunetags = set(prunes.split(':'))

	## TODO: also remove filereport pickles, make it configurable
	for u in unpackreports.keys():
		if set(unpackreports[u]['tags']).intersection(prunetags) != set():
			del unpackreports[u]
