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

	## TODO: check if BAT_REPORTDIR exists
	reportdir = scanenv.get('BAT_REPORTDIR', '.')

	for i in leafscans:
		if i.keys()[0] == 'ranking':
			if len(i['ranking']['reports']) != 0:
				htmllinks = []
				for j in i['ranking']['reports']:
					if len(j[2]) != 0:
						## here we should either do a database lookup to get the checksum,
						## or check if they are already in the report
						htmllinks.append((j[1], j[2]))
				if htmllinks != []:
					uniquehtml = "<html><body><h1>Unique matches per package</h1><p><ul>"
					## first generate a header
					for h in htmllinks:
						uniquehtml = uniquehtml + "<li><a href=\"#%s\">%s</a>" % (h[0], h[0])
					uniquehtml = uniquehtml + "</ul></p>"
					for h in htmllinks:
						uniquehtml = uniquehtml + "<hr><h2><a name=\"%s\" href=\"#%s\">Matches for: %s (%d)</a></h2>" % (h[0], h[0], h[0], len(h[1]))
						for k in h[1]:
							## we have a list of tuples, per unique string we have a list of sha256sums and meta info
							if len(k) > 1:
								uniquehtml = uniquehtml + "<h5>%s</h5><p><table><td><b>Filename</b></td><td><b>Version</b></td><td><b>Line number</b></td><td><b>SHA256</b></td></tr>" % cgi.escape(k[0])
								uniqtablerows = map(lambda x: "<tr><td>%s</td><td><a href=\"unique:/%s#%d\">%s</a></td><td>%d</td><td>%s</td></tr>" % (x[3], x[0], x[2], x[1], x[2], x[0]), k[1])
								uniquehtml = uniquehtml + reduce(lambda x, y: x + y, uniqtablerows) + "</table></p>\n"
							else:
								uniquehtml = uniquehtml + "<h5>%s</h5>" % cgi.escape(k[0])
					uniquehtml = uniquehtml + "</body></html>"
					uniquehtmlfile = open("%s/%s-unique.html" % (reportdir, unpackreport['sha256']), 'w')
					uniquehtmlfile.write(uniquehtml)
					uniquehtmlfile.close()
