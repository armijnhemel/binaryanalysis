#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool.

This should be run as a postrun scan
'''

import os, os.path, sys, cPickle

def guireport(filename, unpackreport, scantempdir, topleveldir, envvars={}):
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

	filehash = unpackreport['sha256']
	if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
		return

	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()

	tablerowtemplate = "<tr><td><b>%s</b></td><td>%s</td></tr>\n"

	## build HTML
	overviewstring = '''
<html>
<body>
<h2>Overview</h2>
<table>
<tr><td><b>Name</b></td><td>%s</td></tr>
<tr><td><b>Path</b></td><td>%s</td></tr>
<tr><td><b>Absolute path</b></td><td>%s</td></tr>
<tr><td><b>Size</b></td><td>%s bytes</td></tr>
<tr><td><b>File type</b></td><td>%s</td></tr>
		         '''
	tablerows = ""

	if leafreports.has_key('busybox-version'):
		tablerows = tablerows + tablerowtemplate % ("BusyBox version", leafreports['busybox-version'])
	if leafreports.has_key('architecture'):
		tablerows = tablerows + tablerowtemplate % ("Architecture", leafreports['architecture'])
	if leafreports.has_key('kernelmodulelicense'):
		tablerows = tablerows + tablerowtemplate % ("Kernel module license", leafreports['kernelmodulelicense'])
	if leafreports.has_key('libs'):
		tablerows = tablerows + tablerowtemplate % ("Declared shared libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['libs']))

	if leafreports.has_key('elfused'):
		if leafreports['elfused'] != []:
			tablerows = tablerows + tablerowtemplate % ("Used shared libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['elfused']))
	if leafreports.has_key('elfunused'):
		if leafreports['elfunused'] != []:
			tablerows = tablerows + tablerowtemplate % ("Unused (but declared) shared libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['elfunused']))
	if leafreports.has_key('notfoundfuncs'):
		if leafreports['notfoundfuncs'] != []:
			tablerows = tablerows + tablerowtemplate % ("Unresolved function symbols", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['notfoundfuncs']))
	if leafreports.has_key('notfoundvars'):
		if leafreports['notfoundvars'] != []:
			tablerows = tablerows + tablerowtemplate % ("Unresolved variable symbols", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['notfoundvars']))
	if leafreports.has_key('elfusedby'):
		if leafreports['elfusedby'] != []:
			tablerows = tablerows + tablerowtemplate % ("Used by", reduce(lambda x, y: x + ", " + y, leafreports['elfusedby']))

	if leafreports.has_key('licenses'):
		tablerows = tablerows + tablerowtemplate % ("Licenses/license families", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['licenses'].keys()))
	if leafreports.has_key('forges'):
		tablerows = tablerows + tablerowtemplate % ("Forges", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['forges'].keys()))
	if leafreports.has_key('redboot'):
		tablerows = tablerows + tablerowtemplate % ("Bootloader", "RedBoot")
	for j in ['dproxy', 'ez-ipupdate', 'iproute', 'iptables', 'libusb', 'loadlin', 'vsftpd', 'wireless-tools', 'wpa-supplicant']:
		if leafreports.has_key(j):
			applications.append(j)
	if leafreports.has_key('kernelchecks'):
		for j in leafreports['kernelchecks']:
			if j == 'version':
				tablerows = tablerows + tablerowtemplate % ("Linux kernel", leafreports['kernelchecks']['version'])
	print >>sys.stderr, tablerows
