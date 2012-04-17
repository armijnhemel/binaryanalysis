#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. It takes the output of hexdump -Cv
and writes it to a file with gzip compression. The output is later used in the
(upcoming) graphical user interface.

This should be run as a postrun scan
'''

import os, os.path, sys, subprocess, gzip

def generateHexdump(filename, unpackreport, leafscans, scantempdir, toplevelscandir, envvars={}):
	if not unpackreport.has_key('sha256'):
		return
	ignorelist = ['graphics', 'text', 'compressed', 'pdf', 'xml']
	## not interested in text files or graphics
	## TODO: make this configurable
	for s in leafscans:
		if s.keys()[0] == 'tags':
			for i in ignorelist:
				if i in s['tags']:
					return
	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	## TODO: check if BAT_REPORTDIR exists
	reportdir = scanenv.get('BAT_REPORTDIR', '.')

	if not os.path.exists("%s/%s-hexdump.gz" % (reportdir, unpackreport['sha256'])):
		p = subprocess.Popen(['hexdump', '-Cv', "%s/%s" % (scantempdir, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if stanout != "":
			gf = gzip.open("%s/%s-hexdump.gz" % (reportdir, unpackreport['sha256']), 'w')
			gf.write(stanout)
			gf.close()
