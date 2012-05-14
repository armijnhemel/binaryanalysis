#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. It generates a HTML file which
contains unique strings that were matched, with links to pretty printed source
code, which can be displayed in the BAT GUI.

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
			if len(i['ranking'][0]['reports']) != 0:
				htmllinks = []
				for j in i['ranking'][0]['reports']:
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
							## This is really hairy
							if len(k) > 1:
								uniquehtml = uniquehtml + "<h5>%s</h5><p><table><td><b>Filename</b></td><td><b>Version(s)</b></td><td><b>Line number</b></td><td><b>SHA256</b></td></tr>" % cgi.escape(k[0])
								uniqtablerows = []
								sh = {}
								for s in k[1]:
									## if possible, remove the package name, plus version number, from the path
									## that is displayed. This is to prevent that a line is printed for every
									## version, even when the code has not changed. Usually it will be clear
									## which file is meant.
									(pv, fp) = s[3].split('/', 1)
									## clean up some names first, especially when they have been changed by Debian
									for e in ["+dfsg", "~dfsg", ".orig", ".dfsg1", ".dfsg2"]:
										if pv.endswith(e):
											pv = pv[:-len(e)]
											break
									if pv == "%s-%s" % (h[0], s[1]) or pv == "%s_%s" % (h[0], s[1]):
										if sh.has_key(s[0]):
											sh[s[0]].append((fp,s[1], s[2]))
										else:
											sh[s[0]] = [(fp, s[1], s[2])]
									else:	
										if sh.has_key(s[0]):
											sh[s[0]].append((s[3],s[1], s[2]))
										else:
											sh[s[0]] = [(s[3], s[1], s[2])]
								for s in sh:
									## per checksum we have a list of (filename, version)
									## Now we need to check if we only have one filename, or if there are multiple.
									## If there is just one it is easy:
									if len(set(map(lambda x: x[0], sh[s]))) == 1:
										lines = sorted(set(map(lambda x: (x[2]), sh[s])))
										versions = sorted(set(map(lambda x: (x[1]), sh[s])))
										versionline = reduce(lambda x, y: x + ", " + y, versions)
										numlines = reduce(lambda x, y: x + ", " + y, map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (s, x, x), lines))
										uniqtablerows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (sh[s][0][0], versionline, numlines, s))
									else:
										for d in list(set(map(lambda x: x[0], sh[s]))):
											filterd = filter(lambda x: x[0] == d, sh[s])
											lines = sorted(set(map(lambda x: (x[2]), filterd)))

											## TODO: if there are many versions (for example: Linux kernel)
											## we should condense it a bit more
											versions = sorted(set(map(lambda x: (x[1]), filterd)))
											versionline = reduce(lambda x, y: x + ", " + y, versions)
											numlines = reduce(lambda x, y: x + ", " + y, map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (s, x, x), lines))
											uniqtablerows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (d, versionline, numlines, s))
								uniquehtml = uniquehtml + reduce(lambda x, y: x + y, uniqtablerows, "") + "</table></p>\n"
							else:
								uniquehtml = uniquehtml + "<h5>%s</h5>" % cgi.escape(k[0])
					uniquehtml = uniquehtml + "</body></html>"
					uniquehtmlfile = gzip.open("%s/%s-unique.html.gz" % (reportdir, unpackreport['sha256']), 'wb')
					uniquehtmlfile.write(uniquehtml)
					uniquehtmlfile.close()
