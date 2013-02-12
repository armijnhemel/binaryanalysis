#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. It generates HTML files for the
following:

* unique strings that were matched, with links to pretty printed source code,
which can be displayed in the BAT GUI.
* unmatched strings

This should be run as a postrun scan
'''

import os, os.path, sys, gzip, cgi, cPickle

## helper function to condense version numbers and squash numbers.
def squash_versions(versions):
	if len(versions) <= 3:
		versionline = reduce(lambda x, y: x + ", " + y, versions)
		return versionline
	# check if we have versions without '.'
	if len(filter(lambda x: '.' not in x, versions)) != 0:
		versionline = reduce(lambda x, y: x + ", " + y, versions)
		return versionline
	versionparts = []
	# get the major version number first
	majorv = list(set(map(lambda x: x.split('.')[0], versions)))
	for m in majorv:
		maxconsolidationlevel = 0
		## determine how many subcomponents we have at max
		filterversions = filter(lambda x: x.startswith(m + "."), versions)
		if len(filterversions) == 1:
			versionparts.append(reduce(lambda x, y: x + ", " + y, filterversions))
			continue
		minversionsplits = min(list(set(map(lambda x: len(x.split('.')), filterversions)))) - 1
		## split with a maximum of minversionsplits splits
		splits = map(lambda x: x.split('.', minversionsplits), filterversions)
		for c in range(0, minversionsplits):
			if len(list(set(map(lambda x: x[c], splits)))) == 1:
				maxconsolidationlevel = maxconsolidationlevel + 1
			else: break
		if minversionsplits != maxconsolidationlevel:
			splits = map(lambda x: x.split('.', maxconsolidationlevel), filterversions)
		versionpart = reduce(lambda x, y: x + "." + y, splits[0][:maxconsolidationlevel]) + ".{" + reduce(lambda x, y: x + ", " + y, map(lambda x: x[-1], splits)) + "}"
		versionparts.append(versionpart)
	if len(versionparts) != 1:
		sys.stdout.flush()
	versionline = reduce(lambda x, y: x + ", " + y, versionparts)
	return versionline

def generateHTML(filename, unpackreport, scantempdir, topleveldir, envvars={}):
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

	filehash = unpackreport['sha256']

	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()

	if leafreports.has_key('ranking') :
		## the ranking result is (res, dynamicRes, variablepvs)
		(res, dynamicRes, variablepvs) = leafreports['ranking']
		if res == None:
			return
		if res['reports'] != []:
			htmllinks = []
			for j in res['reports']:
				if len(j[2]) != 0:
					## here we should either do a database lookup to get the checksum,
					## or check if they are already in the report
					htmllinks.append((j[1], j[2]))
			if htmllinks != []:
				uniquehtml = "<html><body><h1>Unique matches per package</h1><p><ul>"
				## first generate a header
				for h in htmllinks:
					uniquehtml = uniquehtml + "<li><a href=\"#%s\">%s (%d)</a>" % (h[0], h[0], len(h[1]))
				uniquehtml = uniquehtml + "</ul></p>"
				for h in htmllinks:
					uniquehtml = uniquehtml + "<hr><h2><a name=\"%s\" href=\"#%s\">Matches for: %s (%d)</a></h2>" % (h[0], h[0], h[0], len(h[1]))
					for k in h[1]:
						## we have a list of tuples, per unique string we have a list of sha256sums and meta info
						## This is really hairy
						if len(k) > 1:
							uniquehtml = uniquehtml + "<h5>%s</h5><p><table><tr><td><b>Filename</b></td><td><b>Version(s)</b></td><td><b>Line number</b></td><td><b>SHA256</b></td></tr>" % cgi.escape(k[0])
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
									versionline = squash_versions(versions)
									numlines = reduce(lambda x, y: x + ", " + y, map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (s, x, x), lines))
									uniqtablerows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (sh[s][0][0], versionline, numlines, s))
								else:
									for d in list(set(map(lambda x: x[0], sh[s]))):
										filterd = filter(lambda x: x[0] == d, sh[s])
										lines = sorted(set(map(lambda x: (x[2]), filterd)))

										versions = sorted(set(map(lambda x: (x[1]), filterd)))
										versionline = squash_versions(versions)
										numlines = reduce(lambda x, y: x + ", " + y, map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (s, x, x), lines))
										uniqtablerows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (d, versionline, numlines, s))
							uniquehtml = uniquehtml + reduce(lambda x, y: x + y, uniqtablerows, "") + "</table></p>\n"
						else:
							uniquehtml = uniquehtml + "<h5>%s</h5>" % cgi.escape(k[0])
				uniquehtml = uniquehtml + "</body></html>"
				uniquehtmlfile = gzip.open("%s/%s-unique.html.gz" % (reportdir, unpackreport['sha256']), 'wb')
				uniquehtmlfile.write(uniquehtml)
				uniquehtmlfile.close()

		if res['unmatched'] != []:
			unmatches = list(set(res['unmatched']))
			unmatches.sort()
			unmatchedhtml = "<html><body><h1>Unmatched strings for %s</h1><p><ul>" % filename
			for i in unmatches:
				unmatchedhtml = unmatchedhtml + "%s<br>\n" % cgi.escape(i)
			unmatchedhtml = unmatchedhtml + "</body></html>"
			unmatchedhtmlfile = gzip.open("%s/%s-unmatched.html.gz" % (reportdir, unpackreport['sha256']), 'wb')
			unmatchedhtmlfile.write(unmatchedhtml)
			unmatchedhtmlfile.close()
