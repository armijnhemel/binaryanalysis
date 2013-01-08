#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. It generates a HTML file which
contains strings that were not matched.

This should be run as a postrun scan
'''

import os, os.path, sys, gzip, cgi

def generateHTML(filename, unpackreport, leafscans, scantempdir, toplevelscandir, envvars={}):
	if not unpackreport.has_key('sha256'):
		return
	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	reportdir = scanenv.get('BAT_REPORTDIR', '.')
	try:
		os.stat(reportdir)
	except:
		## BAT_REPORTDIR does not exist
		try:
			os.makedirs(reportdir)
		except Exception, e:
			return

	if leafscans.has_key('ranking') :
		## the ranking result is (res, dynamicRes, variablepvs)
		(res, dynamicRes, variablepvs) = leafscans['ranking']
		if res['unmatched'] != []:
			unmatchedhtml = "<html><body><h1>Unmatched strings for %s</h1><p><ul>" % filename
			for i in res['unmatched']:
				unmatchedhtml = unmatchedhtml + "%s<br>\n" % i
			unmatchedhtml = unmatchedhtml + "</body></html>"
			unmatchedhtmlfile = gzip.open("%s/%s-unmatched.html.gz" % (reportdir, unpackreport['sha256']), 'wb')
			unmatchedhtmlfile.write(unmatchedhtml)
			unmatchedhtmlfile.close()
