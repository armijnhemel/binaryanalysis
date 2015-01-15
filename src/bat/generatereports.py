#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This plugin is used to generate reports. It is run as an aggregate scan for
a reason: as it turns out many reports that are generated are identical:
matched strings are often the same since the same database is used.

Since generating reports can have quite a bit of overhead it makes sense
to first deduplicate and then generate reports.

The method works as follows:

1. All data from pickles that is needed to generate reports is extracted in
parallel.
2. The checksums of the pickles are computed and recorded. If there is a
duplicate the duplicate pickle is removed and it is recorded which file it
originally belonged to.
3. Reports are (partially) generated in parallel for the remaining pickle files.
4. The reports are copied and renamed, or assembled from partial reports
'''

import os, os.path, sys, copy, cPickle, tempfile, hashlib, shutil, multiprocessing, cgi, gzip

## compute a SHA256 hash. This is done in chunks to prevent a big file from
## being read in its entirety at once, slowing down a machine.
def gethash(path):
	scanfile = open(path, 'r')
	h = hashlib.new('sha256')
	scanfile.seek(0)
	hashdata = scanfile.read(10000000)
	while hashdata != '':
		h.update(hashdata)
		hashdata = scanfile.read(10000000)
	scanfile.close()
	return h.hexdigest()

## helper function to condense version numbers and squash numbers.
def squash_versions(versions):
	if len(versions) <= 3:
		versionline = reduce(lambda x, y: "%s, %s" % (x,y), versions)
		return versionline
	# check if we have versions without '.'
	if len(filter(lambda x: '.' not in x, versions)) != 0:
		versionline = reduce(lambda x, y: "%s, %s" % (x,y), versions)
		return versionline
	versionparts = []
	# get the major version number first
	majorv = set(map(lambda x: x.split('.')[0], versions))
	for m in majorv:
		maxconsolidationlevel = 0
		## determine how many subcomponents we have at max
		filterversions = filter(lambda x: x.startswith(m + "."), versions)
		if len(filterversions) == 1:
			versionparts.append(reduce(lambda x, y: "%s, %s" % (x, y), filterversions))
			continue
		minversionsplits = min(set(map(lambda x: len(x.split('.')), filterversions))) - 1
		## split with a maximum of minversionsplits splits
		splits = map(lambda x: x.split('.', minversionsplits), filterversions)
		for c in xrange(0, minversionsplits):
			if len(set(map(lambda x: x[c], splits))) == 1:
				maxconsolidationlevel = maxconsolidationlevel + 1
			else: break
		if minversionsplits != maxconsolidationlevel:
			splits = map(lambda x: x.split('.', maxconsolidationlevel), filterversions)
		versionpart = reduce(lambda x, y: "%s.%s" % (x, y), splits[0][:maxconsolidationlevel]) + ".{%s}" % reduce(lambda x, y: x + ", " + y, map(lambda x: x[-1], splits))
		versionparts.append(versionpart)
	versionline = reduce(lambda x, y: x + ", " + y, versionparts)
	return versionline

def generatehtmlsnippet((picklefile, pickledir, picklehash, reportdir)):
	html_pickle = open(os.path.join(pickledir, picklefile), 'rb')
	(packagename, uniquematches) = cPickle.load(html_pickle)
	html_pickle.close()
	os.unlink(os.path.join(pickledir, picklefile))
	lenuniquematches = len(uniquematches)
	if lenuniquematches == 0:
		return

	squashed_versions = {}

	uniquehtmlfile = open("%s/%s-unique.snippet" % (reportdir, picklehash), 'wb')
	uniquehtmlfile.write("<hr><h2><a name=\"%s\" href=\"#%s\">Matches for: %s (%d)</a></h2>" % (packagename, packagename, packagename, lenuniquematches))
	uniquematches.sort()
	for k in uniquematches:
		(programstring, results) = k
		## we have a list of tuples, per unique string we have a list of sha256sums and meta info
		## This is really hairy
		if len(results) > 0:
			uniquehtmlfile.write("<h5>%s</h5><p><table><tr><td><b>Filename</b></td><td><b>Version(s)</b></td><td><b>Line number</b></td><td><b>SHA256</b></td></tr>" % cgi.escape(programstring))
			sh = {}
			for s in results:
				(checksum, linenumber, versionsourcefiles) = s
				for vs in versionsourcefiles:
					(version, sourcefile) = vs
					## if possible, remove the package name, plus version number, from the path
					## that is displayed. This is to prevent that a line is printed for every
					## version, even when the code has not changed. Usually it will be clear
					## which file is meant.
					if len(sourcefile.split('/', 1)) > 1:
						(pv, fp) = sourcefile.split('/', 1)
						## clean up some names first, especially when they have been changed by Debian
						for e in ["+dfsg", "~dfsg", ".orig", ".dfsg1", ".dfsg2"]:
							if pv.endswith(e):
								pv = pv[:-len(e)]
								break
						## then check if the file directory name follows a certain pattern
						if pv == "%s-%s" % (packagename, version) or pv == "%s_%s" % (packagename, version):
							if sh.has_key(checksum):
								sh[checksum].add((fp, version, linenumber))
							else:
								sh[checksum] = set([(fp, version, linenumber)])
						else:
							if sh.has_key(checksum):
								sh[checksum].add((sourcefile, version, linenumber))
							else:
								sh[checksum] = set([(sourcefile, version, linenumber)])
					else:
						if sh.has_key(checksum):
							sh[checksum].add((sourcefile, version, linenumber))
						else:
							sh[checksum] = set([(sourcefile, version, linenumber)])

			for checksum in sh:
				## per checksum we have a list of (filename, version)
				## Now we need to check if we only have one filename, or if there are multiple.
				## If there is just one it is easy:
				chs = set(map(lambda x: x[0], sh[checksum]))
				if len(chs) == 1:
					linenumbers = sorted(set(map(lambda x: (x[2]), sh[checksum])))
					versions = sorted(set(map(lambda x: (x[1]), sh[checksum])))
					if squashed_versions.has_key(checksum):
						versionline = squashed_versions[checksum]
					else:
						versionline = squash_versions(versions)
						squashed_versions[checksum] = versionline
					ch = sh[checksum].pop()
					numlines = reduce(lambda x, y: "%s, %s" % (x,y), map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (checksum, x, x), linenumbers))
					uniquehtmlfile.write("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (ch[0], versionline, numlines, checksum))
				else:   
					for d in chs:
						filterd = filter(lambda x: x[0] == d, sh[checksum])
						linenumbers = sorted(set(map(lambda x: (x[2]), filterd)))
						versions = sorted(set(map(lambda x: (x[1]), filterd)))
						versionline = squash_versions(versions)
						numlines = reduce(lambda x, y: "%s, %s" % (x,y), map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (checksum, x, x), linenumbers))
						uniquehtmlfile.write("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (d, versionline, numlines, checksum))
			uniquehtmlfile.write("</table></p>\n")
		else:
			uniquehtmlfile.write("<h5>%s</h5>" % cgi.escape(programstring))
	uniquehtmlfile.close()

## generate several output files and extract pickles
## TODO: change name
def extractpickles((filehash, pickledir, topleveldir, reportdir, unpacktempdir)):
	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()

	## return type: (filehash, reportresults, unmatchedresult)
	reportresults = []
	functionresults = []

	## (picklehash, picklename)
	unmatchedresult = None
	if not leafreports.has_key('ranking'):
		return (filehash, reportresults, functionresults, unmatchedresult)
	## the ranking result is (res, dynamicRes, variablepvs)
	(res, dynamicRes, variablepvs, language) = leafreports['ranking']

	if dynamicRes != {}:
		html = ""
		## if the results are stored in the pickle generate nice reports.
		if dynamicRes.has_key('kernelfunctions'):
			if dynamicRes['kernelfunctions'] != []:
				if not dynamicRes.has_key('versionresults'):
					kernelfuncs = list(set(dynamicRes['kernelfunctions']))
					kernelfuncs.sort()
					html += "<h1>Kernel function name matches</h1><p><ul>\n"
					for d in kernelfuncs:
						html += "<li>%s</li>" % d
					html += "</ul></p>\n"
		if dynamicRes.has_key('versionresults'):
			if dynamicRes['versionresults'] != {}:
				squashed_versions = {}
				html += "<h1>Unique function name matches per package</h1><p><ul>\n"
				ukeys = map(lambda x: (x[0], len(x[1])), dynamicRes['versionresults'].items())
				ukeys.sort(key=lambda x: x[1], reverse=True)
				for i in ukeys:
					html += "<li><a href=\"#%s\">%s (%d)</a></li>" % (i[0], i[0], i[1])
				html += "</ul></p>\n"
				for i in ukeys:
					packagename = i[0]
					html += "<hr><h2><a name=\"%s\" href=\"#%s\">Matches for %s (%d)</a></h2>\n" % (packagename, packagename, packagename, i[1])
					upkgs = dynamicRes['versionresults'][packagename]
					upkgs.sort()
					for up in upkgs:
						sh = {}
						(funcname, results) = up
						html += "<h5>%s</h5><p><table><tr><td><b>Filename</b></td><td><b>Version(s)</b></td><td><b>Line number</b></td><td><b>SHA256</b></td></tr>" % cgi.escape(funcname)
						for r in results:
							(checksum, linenumber, versionfilenames) = r 
							for vf in versionfilenames:
								(version, filename) = vf

								## if possible, remove the package name, plus version number, from the path
								## that is displayed. This is to prevent that a line is printed for every
								## version, even when the code has not changed. Usually it will be clear
								## which file is meant.
								if len(filename.split('/', 1)) > 1:
									(pv, fp) = filename.split('/', 1)
									## clean up some names first, especially when they have been changed by Debian
									for e in ["+dfsg", "~dfsg", ".orig", ".dfsg1", ".dfsg2"]:
										if pv.endswith(e):
											pv = pv[:-len(e)]
											break
									## then check if the file directory name follows a certain pattern
									if pv == "%s-%s" % (packagename, version) or pv == "%s_%s" % (packagename, version):
										if sh.has_key(checksum):
											sh[checksum].add((fp, version, linenumber))
										else:
											sh[checksum] = set([(fp, version, linenumber)])
								else:
									if sh.has_key(checksum):
										sh[checksum].add((filename, version, linenumber))
									else:
										sh[checksum] = set([(filename, version, linenumber)])
						for checksum in sh:
							## per checksum we have a list of (filename, version)
							## Now we need to check if we only have one filename, or if there are multiple.
							## If there is just one it is easy:
							chs = set(map(lambda x: x[0], sh[checksum]))

							if len(chs) == 1:
								linenumbers = sorted(set(map(lambda x: (x[2]), sh[checksum])))
								versions = sorted(set(map(lambda x: (x[1]), sh[checksum])))
								if squashed_versions.has_key(checksum):
									versionline = squashed_versions[checksum]
								else:
									versionline = squash_versions(versions)
									squashed_versions[checksum] = versionline
								ch = sh[checksum].pop()
								numlines = reduce(lambda x, y: "%s, %s" % (x,y), map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (checksum, x, x), linenumbers))
								html+= "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (ch[0], versionline, numlines, checksum)
							else:
								for d in chs:
									filterd = filter(lambda x: x[0] == d, sh[checksum])
									linenumbers = sorted(set(map(lambda x: (x[2]), filterd)))
									versions = sorted(set(map(lambda x: (x[1]), filterd)))
									versionline = squash_versions(versions)
									numlines = reduce(lambda x, y: "%s, %s" % (x,y), map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (checksum, x, x), linenumbers))
									html += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (d, versionline, numlines, checksum)


						html += "</table></p>\n"
		elif dynamicRes.has_key('uniquepackages'):
			if dynamicRes['uniquepackages'] != {}:
				html += "<h1>Unique function name matches per package</h1><p><ul>\n"
				ukeys = map(lambda x: (x[0], len(x[1])), dynamicRes['uniquepackages'].items())
				ukeys.sort(key=lambda x: x[1], reverse=True)
				for i in ukeys:
					html += "<li><a href=\"#%s\">%s (%d)</a></li>" % (i[0], i[0], i[1])
				html += "</ul></p>"
				for i in ukeys:
					html += "<hr><h2><a name=\"%s\" href=\"#%s\">Matches for %s (%d)</a></h2><p>\n" % (i[0], i[0], i[0], i[1])
					upkgs = dynamicRes['uniquepackages'][i[0]]
					upkgs.sort()
					for v in upkgs:
						html += "%s<br>\n" % cgi.escape(v)
					html += "</p>\n"
		if html != "":
			nameshtmlfile = gzip.open("%s/%s-functionnames.html.gz" % (reportdir, filehash), 'wb')
			nameshtmlfile.write("<html><body>%s</body></html>" % html)
			nameshtmlfile.close()

	if variablepvs != {}:
		squashed_versions = {}
		if language == 'Java':
			header = "<html><body><h1>Unique matches of class names, field names and source file names</h1>"
		elif language == 'C':
			header = "<html><body><h1>Matches of variable names</h1>"
		html = ""

		if language == 'Java':
			totalvars = 0
			fieldspackages = {}
			sourcespackages = {}
			classespackages = {}
			fieldscount = {}
			sourcescount = {}
			classescount = {}
			for i in ['classes', 'sources', 'fields']:
				if not variablepvs.has_key(i):
					continue
				totalvars += len(variablepvs[i])
				packages = {}
				packagecount = {}
				if variablepvs[i] != []:
					for c in variablepvs[i]:
						lenres = len(set(map(lambda x: x[0], variablepvs[i][c])))
						if lenres == 1:
							pvs = variablepvs[i][c]
							(package,version) = variablepvs[i][c][0]
							if packagecount.has_key(package):
								packagecount[package] = packagecount[package] + 1
							else:
								packagecount[package] = 1
				if packagecount != {}:
					if i == 'classes':
						classescount = packagecount
					if i == 'sources':
						sourcescount = packagecount
					if i == 'fields':
						fieldscount = packagecount

				if packages != {}:
					if i == 'classes':
						classespackages = packages
					if i == 'sources':
						sourcespackages = packages
					if i == 'fields':
						fieldspackages = packages

			if classescount != {}:
				html = html + "<h3>Unique matches of class names</h3>\n<table>\n"
				html = html + "<tr><td><b>Name</b></td><td><b>Unique matches</b></td></tr>"
				for i in classescount:
					html = html + "<tr><td>%s</td><td>%d</td></tr>\n" % (i, classescount[i])
				html = html + "</table>\n"

			if sourcescount != {}:
				html = html + "<h3>Unique matches of source file names</h3>\n<table>\n"
				html = html + "<tr><td><b>Name</b></td><td><b>Unique matches</b></td></tr>"
				for i in sourcescount:
					html = html + "<tr><td>%s</td><td>%d</td></tr>\n" % (i, sourcescount[i])
				html = html + "</table>\n"

			if fieldscount != {}:
				html = html + "<h3>Unique matches of field names</h3>\n<table>\n"
				html = html + "<tr><td><b>Name</b></td><td><b>Unique matches</b></td></tr>"
				for i in fieldscount:
					html = html + "<tr><td>%s</td><td>%d</td></tr>\n" % (i, fieldscount[i])
				html = html + "</table>\n"

		if language == 'C':
			totalvars = 0
			if variablepvs.has_key('versionresults'):
				if variablepvs['versionresults'] != {}:
					html += "<h1>Unique variable name matches per package</h1><p><ul>\n"
					ukeys = map(lambda x: (x[0], len(x[1])), variablepvs['versionresults'].items())
					ukeys.sort(key=lambda x: x[1], reverse=True)
					for i in ukeys:
						html += "<li><a href=\"#%s\">%s (%d)</a></li>" % (i[0], i[0], i[1])
					html += "</ul></p>\n"
					for i in ukeys:
						packagename = i[0]
						html += "<hr><h2><a name=\"%s\" href=\"#%s\">Matches for %s (%d)</a></h2>\n" % (packagename, packagename, packagename, i[1])
						upkgs = variablepvs['versionresults'][packagename]
						upkgs.sort()
						for up in upkgs:
							sh = {}
							(funcname, results) = up
							html += "<h5>%s</h5><p><table><tr><td><b>Filename</b></td><td><b>Version(s)</b></td><td><b>Line number</b></td><td><b>SHA256</b></td></tr>" % cgi.escape(funcname)
							for r in results:
								(checksum, linenumber, versionfilenames) = r 
								for vf in versionfilenames:
									(version, filename) = vf
	
									## if possible, remove the package name, plus version number, from the path
									## that is displayed. This is to prevent that a line is printed for every
									## version, even when the code has not changed. Usually it will be clear
									## which file is meant.
									if len(filename.split('/', 1)) > 1:
										(pv, fp) = filename.split('/', 1)
										## clean up some names first, especially when they have been changed by Debian
										for e in ["+dfsg", "~dfsg", ".orig", ".dfsg1", ".dfsg2"]:
											if pv.endswith(e):
												pv = pv[:-len(e)]
												break
										## then check if the file directory name follows a certain pattern
										if pv == "%s-%s" % (packagename, version) or pv == "%s_%s" % (packagename, version):
											if sh.has_key(checksum):
												sh[checksum].add((fp, version, linenumber))
											else:
												sh[checksum] = set([(fp, version, linenumber)])
									else:
										if sh.has_key(checksum):
											sh[checksum].add((filename, version, linenumber))
										else:
											sh[checksum] = set([(filename, version, linenumber)])
							for checksum in sh:
								## per checksum we have a list of (filename, version)
								## Now we need to check if we only have one filename, or if there are multiple.
								## If there is just one it is easy:
								chs = set(map(lambda x: x[0], sh[checksum]))

								if len(chs) == 1:
									linenumbers = sorted(set(map(lambda x: (x[2]), sh[checksum])))
									versions = sorted(set(map(lambda x: (x[1]), sh[checksum])))
									if squashed_versions.has_key(checksum):
										versionline = squashed_versions[checksum]
									else:
										versionline = squash_versions(versions)
										squashed_versions[checksum] = versionline
									ch = sh[checksum].pop()
									numlines = reduce(lambda x, y: "%s, %s" % (x,y), map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (checksum, x, x), linenumbers))
									html+= "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (ch[0], versionline, numlines, checksum)
								else:
									for d in chs:
										filterd = filter(lambda x: x[0] == d, sh[checksum])
										linenumbers = sorted(set(map(lambda x: (x[2]), filterd)))
										versions = sorted(set(map(lambda x: (x[1]), filterd)))
										versionline = squash_versions(versions)
										numlines = reduce(lambda x, y: "%s, %s" % (x,y), map(lambda x: "<a href=\"unique:/%s#%d\">%d</a>" % (checksum, x, x), linenumbers))
										html += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (d, versionline, numlines, checksum)


							html += "</table></p>\n"
			elif variablepvs.has_key('uniquepackages'):
				if variablepvs['uniquepackages'] != {}:

					ukeys = map(lambda x: (x[0], len(x[1])), variablepvs['uniquepackages'].items())
					ukeys.sort(key=lambda x: x[1], reverse=True)
					for i in ukeys:
						html += "<li><a href=\"#%s\">%s (%d)</a></li>" % (i[0], i[0], i[1])
					html += "</ul></p>"
					for i in ukeys:
						html += "<hr><h2><a name=\"%s\" href=\"#%s\">Matches for %s (%d)</a></h2><p>\n" % (i[0], i[0], i[0], i[1])
						upkgs = variablepvs['uniquepackages'][i[0]]
						upkgs.sort()
						for v in upkgs:
							html += "%s<br>\n" % cgi.escape(v)
						html += "</p>\n"

		footer = "</body></html>"
		if html != "":
			nameshtmlfile = gzip.open("%s/%s-names.html.gz" % (reportdir, filehash), 'wb')
			nameshtmlfile.write(header)
			nameshtmlfile.write(html)
			nameshtmlfile.write(footer)
			nameshtmlfile.close()

	if res != None:
		if res['unmatched'] != []:
			unmatches = list(set(res['unmatched']))
			unmatches.sort()

			tmppickle = tempfile.mkstemp(dir=unpacktempdir)

			cPickle.dump(unmatches, os.fdopen(tmppickle[0], 'wb'))
			picklehash = gethash(tmppickle[1])
			unmatchedresult = (picklehash, tmppickle[1])

		if res['reports'] != []:
			for j in res['reports']:
				(rank, packagename, uniquematches, uniquematcheslen, percentage, packageversions, licenses, copyrights) = j
				if len(uniquematches) == 0:
					continue
				tmppickle = tempfile.mkstemp(dir=unpacktempdir)
				cPickle.dump((packagename, uniquematches), os.fdopen(tmppickle[0], 'wb'))
				picklehash = gethash(tmppickle[1])
				reportresults.append((rank, picklehash, tmppickle[1], uniquematcheslen, packagename))
		if res['nonUniqueMatches'] != {}:
			order = map(lambda x: (len(res['nonUniqueMatches'][x]), x), res['nonUniqueMatches'].keys())
			order.sort(reverse=True)
			html = "<html><body><h1>Assigned strings per package</h1><p><ul>"
			for r in order:
				(count, packagename) = r
				html += "<li><a href=\"#%s\">%s (%d)</a></li>" % (packagename, packagename, count)
			html += "</ul></p><hr>"
			html += "</body></html>"
			for r in order:
				(count, packagename) = r
				html += "<h2><a name=\"%s\" href=\"#%s\">Matches for %s (%d)</a></h2><p>" % (packagename, packagename, packagename, count)
				assignedmatches = res['nonUniqueMatches'][packagename]
				assignedmatches.sort()
				for rr in assignedmatches:
					html += "%s<br>\n" % cgi.escape(rr)
				html += "</p><hr>"
			assignedhtmlfile = gzip.open("%s/%s-assigned.html.gz" % (reportdir, filehash), 'wb')
			assignedhtmlfile.write(html)
			assignedhtmlfile.write(footer)
			assignedhtmlfile.close()
	return (filehash, reportresults, functionresults, unmatchedresult)

def generateunmatched((picklefile, pickledir, filehash, reportdir)):

	unmatched_pickle = open(os.path.join(pickledir, picklefile), 'rb')
	unmatches = cPickle.load(unmatched_pickle)
        unmatched_pickle.close()

	unmatchedhtml = "<html><body><h1>Unmatched strings (%d strings)</h1><p>" % (len(unmatches),)
	unmatchedsnippets = map(lambda x: "%s<br>\n" % cgi.escape(x), unmatches)
	unmatchedhtml = unmatchedhtml + "".join(unmatchedsnippets)
	unmatchedhtml = unmatchedhtml + "</p></body></html>"
	unmatchedhtmlfile = gzip.open("%s/%s-unmatched.html.gz" % (reportdir, filehash), 'wb')
	unmatchedhtmlfile.write(unmatchedhtml)
	unmatchedhtmlfile.close()
	os.unlink(os.path.join(pickledir, picklefile))

def generatereports(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):
	if scanenv.has_key('overridedir'):
		try:
			del scanenv['BAT_REPORTDIR']
		except:
			pass
		try:
			del scanenv['BAT_PICKLEDIR']
		except:
			pass

	reportdir = scanenv.get('BAT_REPORTDIR', os.path.join(topleveldir, "reports"))
	try:
		os.stat(reportdir)
	except:
		## BAT_REPORTDIR does not exist
		try:
			os.makedirs(reportdir)
		except Exception, e:
			return

	pickledir = scanenv.get('BAT_PICKLEDIR', os.path.join(topleveldir, "pickles"))
	try:
		os.stat(pickledir)
	except:
		## BAT_PICKLEDIR does not exist
		try:
			os.makedirs(pickledir)
		except Exception, e:
			return

	filehashes = set()

	## filter out the files which don't have ranking results
	for i in unpackreports:
		if not unpackreports[i].has_key('sha256'):
			continue
		if not unpackreports[i].has_key('tags'):
			continue
		if not 'ranking' in unpackreports[i]['tags']:
			continue
		filehash = unpackreports[i]['sha256']
		if filehash in filehashes:
			continue
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		filehashes.add(filehash)

	if len(filehashes) == 0:
		return

	unmatchedpicklespackages = set()
	picklespackages = set()
	picklehashes = {}
	unmatchedpickles = set()
	reportpickles = set()

	## extract pickles and generate some files
	extracttasks = map(lambda x: (x, pickledir, topleveldir, reportdir, unpacktempdir), filehashes)
	pool = multiprocessing.Pool(processes=processors)
	res = filter(lambda x: x != None, pool.map(extractpickles, extracttasks, 1))
	pool.terminate()

	## {filehash: [(picklehash, uniquematcheslen, packagename)]
	## misnomer since 'rank' is no longer used
	resultranks = {}

	for r in res:
		(filehash, resultreports, functionresults, unmatchedresult) = r
		if unmatchedresult != None:
			(picklehash, tmppickle) = unmatchedresult
			if picklehash in unmatchedpickles:
				unmatchedpicklespackages.add((picklehash, filehash))
				os.unlink(tmppickle)
			else:
				shutil.move(tmppickle, pickledir)
				unmatchedpickles.add(picklehash)
				unmatchedpicklespackages.add((picklehash, filehash))
				picklehashes[picklehash] = os.path.basename(tmppickle)
		if resultreports != []:
			for report in resultreports:
				(rank, picklehash, tmppickle, uniquematcheslen, packagename) = report
				if resultranks.has_key(filehash):
					resultranks[filehash].append((picklehash, uniquematcheslen, packagename))
				else:
					resultranks[filehash] = [(picklehash, uniquematcheslen, packagename)]
				if picklehash in reportpickles:
					picklespackages.add((picklehash, filehash))
					os.unlink(tmppickle)
				else:
					shutil.move(tmppickle, pickledir)
					reportpickles.add(picklehash)
					picklespackages.add((picklehash, filehash))
					picklehashes[picklehash] = os.path.basename(tmppickle)

	pool = multiprocessing.Pool(processes=processors)

	## generate files for unmatched strings
	if unmatchedpickles != set():
		unmatchedtasks = set(map(lambda x: (picklehashes[x[0]], pickledir, x[0], reportdir), unmatchedpicklespackages))
		results = pool.map(generateunmatched, unmatchedtasks, 1)
		for p in unmatchedpicklespackages:
			oldfilename = "%s-%s" % (p[0], "unmatched.html.gz")
			filename = "%s-%s" % (p[1], "unmatched.html.gz")
			if os.path.exists(os.path.join(reportdir, oldfilename)):
				shutil.copy(os.path.join(reportdir, oldfilename), os.path.join(reportdir, filename))
		for p in unmatchedpicklespackages:
			try:
				filename = "%s-%s" % (p[0], "unmatched.html.gz")
				os.unlink(os.path.join(reportdir, filename))
			except Exception, e:
				#print >>sys.stderr, "ERR", e
				pass
	if reportpickles != set():
		reporttasks = set(map(lambda x: (picklehashes[x[0]], pickledir, x[0], reportdir), picklespackages))
		pool.map(generatehtmlsnippet, reporttasks, 1)
		## now recombine the results and write to a HTML file
		pickleremoves = set()
		for filehash in resultranks.keys():
			uniquehtmlfile = gzip.open("%s/%s-unique.html.gz" % (reportdir, filehash), 'wb')
			uniquehtmlfile.write("<html><body><h1>Unique matches per package</h1><p><ul>")
			for r in resultranks[filehash]:
				(picklehash, uniquematcheslen, packagename) = r
				uniquehtmlfile.write("<li><a href=\"#%s\">%s (%d)</a></li>" % (packagename, packagename, uniquematcheslen))
			uniquehtmlfile.write("</ul></p>")
			for r in resultranks[filehash]:
				(picklehash, uniquematcheslen, packagename) = r
				picklehtmlfile = open(os.path.join(reportdir, "%s-unique.snippet" % picklehash))
				uniquehtmlfile.write(picklehtmlfile.read())
				picklehtmlfile.close()
				pickleremoves.add(picklehash)
				
			uniquehtmlfile.write("</body></html>")
			uniquehtmlfile.close()
		for i in pickleremoves:
			try:
				os.unlink(os.path.join(reportdir, "%s-unique.snippet" % i))
			except Exception, e:
				## print >>sys.stderr, e
				pass
	pool.terminate()
