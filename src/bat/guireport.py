#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool.

This should be run as a postrun scan
'''

import os, os.path, sys, cPickle, gzip

def guireport(filename, unpackreport, scantempdir, topleveldir, debug=False, envvars={}):
	if not unpackreport.has_key('sha256'):
		return
	scanenv = os.environ.copy()
	## this is a placeholder. The GUI should replace this one on the fly
	imagesdir = "REPLACEME"
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

        tmpimagedir = scanenv.get('BAT_IMAGEDIR')
	try:
		os.stat(tmpimagedir)
	except:
		## BAT_IMAGEDIR does not exist
		tmpimagedir = None

	filehash = unpackreport['sha256']
	if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
		return

	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()


	footer = '''
</body>
</html>
'''
	tag = ""
	tablerows = ''
	tablerowtemplate = "<tr><td><b>%s</b></td><td>%s</td></tr>\n"
	functionmatches = ""
	matchesrows = ""
	applications = []

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

	tablerows = tablerows + tablerowtemplate % ("SHA256", filehash)
	if leafreports.has_key('duplicates'):
		dups = "<ul>"
		for d in leafreports['duplicates']:
			dups = dups + "<li>" + reduce(lambda x, y: "%s, %s" % (x, y), d) + "</li>"
		dups = dups + "</ul>"
		tablerows = tablerows + tablerowtemplate % ("Duplicate files", dups)
	if leafreports.has_key('kernelmoduleversionmismatch'):
		tablerows = tablerows + tablerowtemplate % ("Kernel module version mismatch", 'yes')
	if leafreports.has_key('kernelmodulearchitecturemismatch'):
		tablerows = tablerows + tablerowtemplate % ("Kernel module architecture mismatch", 'yes')
	if leafreports.has_key('busybox-version'):
		tablerows = tablerows + tablerowtemplate % ("BusyBox version", leafreports['busybox-version'])
	if leafreports.has_key('architecture'):
		tablerows = tablerows + tablerowtemplate % ("Architecture", leafreports['architecture'])
	if leafreports.has_key('kernelmodulelicense'):
		tablerows = tablerows + tablerowtemplate % ("Kernel module license", leafreports['kernelmodulelicense'])
	if leafreports.has_key('libs'):
		if leafreports['libs'] != []:
			tablerows = tablerows + tablerowtemplate % ("Declared shared libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['libs']))

	if leafreports.has_key('elfused'):
		if leafreports['elfused'] != []:
			tablerows = tablerows + tablerowtemplate % ("Used shared libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['elfused']))
	if leafreports.has_key('elfunused'):
		if leafreports['elfunused'] != []:
			tablerows = tablerows + tablerowtemplate % ("Unused (but declared) shared libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['elfunused']))

	if leafreports.has_key('elfusedby'):
		if leafreports['elfusedby'] != []:
			tablerows = tablerows + tablerowtemplate % ("Used by", reduce(lambda x, y: x + ", " + y, leafreports['elfusedby']))
	if leafreports.has_key('licenses'):
		if leafreports['licenses'] != []:
			tablerows = tablerows + tablerowtemplate % ("Licenses/license families", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['licenses']))
	if leafreports.has_key('forges'):
		if leafreports['forges'] != []:
			tablerows = tablerows + tablerowtemplate % ("Forges", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['forges']))
	if leafreports.has_key('redboot'):
		tablerows = tablerows + tablerowtemplate % ("Bootloader", "RedBoot")
	for j in ['dproxy', 'ez-ipupdate', 'iproute', 'iptables', 'libusb', 'loadlin', 'vsftpd', 'wireless-tools', 'wpa-supplicant']:
		if leafreports.has_key(j):
			applications.append(j)
	if leafreports.has_key('kernelchecks'):
		for j in leafreports['kernelchecks']:
			if j == 'version':
				tablerows = tablerows + tablerowtemplate % ("Linux kernel", leafreports['kernelchecks']['version'])
	if leafreports.has_key('tags'):
		if leafreports['tags'] != []:
			tablerows = tablerows + tablerowtemplate % ("Tags", reduce(lambda x, y: x + ", " + y, leafreports['tags']))

	if leafreports.has_key('ranking'):
		(stringsres, dynamicres, variablepvs) = leafreports['ranking']
		if dynamicres.has_key('packages'):
			functionmatches = '''<h2><a name="functionmatches" href="#functionnames">Function match statistics</a></h2>
<table>
<tr><td><b>Extracted function names</b></td><td>%d</td></tr>
<tr><td><b>Matched function names</b></td><td>%d</td></tr>
</table>
'''
			functionmatches = functionmatches % (dynamicres['totalnames'], (dynamicres['namesmatched']))
			functionmatches = functionmatches + '''<h3>Matched packages (function names method)</h3>
<table><tr><td>
  <table>
    <tr><td><b>Name</b></td><td><b>Unique matches (maximum for single version)</b></td></tr>\n'''
			versionhtml = ""
			for j in dynamicres['packages']:
				if dynamicres['packages'][j] != []:
					## for now: just take the version with the most matches, only report the amount of matches
					functionmatches = functionmatches + "    <tr><td>%s</td><td>%d</td></tr>\n" % (j, max(map(lambda x: x[1], dynamicres['packages'][j])))
					versionhtml = versionhtml + "<h5>%s</h5><p><img src=\"%s\"/></p>\n" % (j, "%s/%s-%s-funcversion.png" % (imagesdir, filehash, j))
			functionmatches = functionmatches + "</table>"
			if versionhtml != "":
				functionmatches = functionmatches + "<h2>Versions per package</h2>" + versionhtml

		if not stringsres == None:
			if not (stringsres['extractedlines']) == 0 and not (stringsres['matchedlines']) == 0:
				matchesrows = '''
<h2><a name="stringmatches" href="#stringmatches">String match statistics</a></h2>
<table>
<tr><td><b>Extracted lines</b></td><td>%d</td></tr>
<tr><td><b>Matched lines</b></td><td>%d</td></tr>
<tr><td><b>Match percentage</b></td><td>%f%%</td></tr>
</table>
                                                '''
				matchesrows = matchesrows % (stringsres['extractedlines'], stringsres['matchedlines'], (float(stringsres['matchedlines'])/stringsres['extractedlines']*100))
				if len(stringsres['reports']) != 0:
					versionhtml = ""
					## nested table, urgghhhh
					matchesrows = matchesrows + '''<h3>Matched packages (strings method)</h3>
<table>
  <tr><td>
    <table>
      <tr>
        <td><b>Rank</b></td>
        <td><b>Name</b></td>
        <td><b>Percentage</b></td>
        <td><b>Unique matches</b></td>
        <td><b>Non unique matches assigned</b></td>
        <td><b>Licenses (Ninka)</b></td>
        <td><b>Licenses (FOSSology)</b></td>
        <td><b>Determined licenses (Ninka &amp; FOSSology report the same)</b></td>
      </tr>\n'''
					for j in stringsres['reports']:
						(rank, packagename, uniquematches, percentage, packageversions, licenses, language) = j
						determinedlicenses = map(lambda x: x[0], filter(lambda x: x[1] == 'squashed', licenses))
						ninkalicenses = map(lambda x: x[0], filter(lambda x: x[1] == 'ninka', licenses))
						fossologylicenses = map(lambda x: x[0], filter(lambda x: x[1] == 'fossology', licenses))
						determinedlicenses.sort()
						ninkalicenses.sort()
						fossologylicenses.sort()
						if len(ninkalicenses) > 0:
							if len(ninkalicenses) > 1:
								ninkalicensestring = ninkalicenses[0] + reduce(lambda x, y: x + " " + y, ninkalicenses[1:], "")
							else:
								ninkalicensestring = ninkalicenses[0]
						else:
							ninkalicensestring = ""
						if len(fossologylicenses) > 0:
							if len(fossologylicenses) > 1:
								fossologylicensestring = fossologylicenses[0] + reduce(lambda x, y: x + " " + y, fossologylicenses[1:], "")
							else:
								fossologylicensestring = fossologylicenses[0]
						else:
							fossologylicensestring = ""
						if len(determinedlicenses) > 0:
							if len(determinedlicenses) > 1:
								determinedlicensestring = determinedlicenses[0] + reduce(lambda x, y: x + " " + y, determinedlicenses[1:], "")
							else:
								determinedlicensestring = determinedlicenses[0]
						else:
							determinedlicensestring = ""
						matchesrows = matchesrows + "    <tr><td>%d</td><td>%s</td><td>%f%%</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (rank, packagename, percentage, len(uniquematches), stringsres['nonUniqueAssignments'].get(packagename, 0), ninkalicensestring, fossologylicensestring, determinedlicensestring)
						if len(uniquematches) != 0:
							## don't replace %s/% with os.path.join here, since this is valid in HTML
							versionhtml = versionhtml + "<h5>%s</h5><p><img src=\"%s\"/></p>\n" % (packagename, "%s/%s-%s-version.png" % (imagesdir, filehash, packagename))
					## don't replace %s/% with os.path.join here, since this is valid in HTML
					matchesrows = matchesrows + "</table><td><img src=\"%s\"/></td></tr></table>" % ("%s/%s-piechart.png" % (imagesdir, filehash))
					if versionhtml != "":
						matchesrows = matchesrows + "<h2>Versions per package</h2>" + versionhtml

	distrohtml = ''
	if leafreports.has_key('file2package'):
		distrohtml = "<hr><a name=\"distro\" href=\"#distro\"><h2>Distribution matches</h2></a><ul>"
		distrohtml += "<table><tr><th><b>Package</b></th><th><b>Version</b></th><th><b>Distribution</b></th></tr>"
		for d in leafreports['file2package']:
			distrohtml = distrohtml + "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % d
		distrohtml = distrohtml + "</table>"

	if applications != []:
		tablerows = tablerows + "<tr><td><b>Applications</b></td><td>%s</td></tr>\n" % reduce(lambda x, y: "%s, %s" % (x,y), applications)

	name = unpackreport['name']
	path = unpackreport['path']
	realpath = unpackreport['realpath']
	magic = unpackreport['magic']
	if not "symbolic link" in magic:
		if unpackreport.has_key('size'):
			size = unpackreport['size']
		else:
			size = 0
	else:
		size = 0
	overviewstring = overviewstring % (name, path, realpath, size, magic)
	hreflist = ''
	if matchesrows != '' or functionmatches != '':
		hreflist = '<hr><ul>'
		if matchesrows != '':
			matchesrows = '<hr>' + matchesrows
			hreflist += '<li><a href="#stringmatches">string matches</a></li>'
		if functionmatches != '':
			functionmatches = '<hr>' + functionmatches
			hreflist += '<li><a href="#functionmatches">function name matches</a></li>'
		if distrohtml != '':
			hreflist += '<li><a href="#distro">distribution file name matches</a></li>'
		hreflist += '</ul>'
	overviewstring = overviewstring + tablerows + "</table>" + hreflist + matchesrows + functionmatches + distrohtml + footer

	guireportfile = gzip.open("%s/%s-guireport.html.gz" % (reportdir, filehash), 'wb')
	guireportfile.write(overviewstring)
	guireportfile.close()

	## ideally this should move to findlibs.py, where pictures are generated
	elfheader = "<html><body><h1>Detailed ELF analysis</h1><table>"
	elftablefooter = "</table></body>"
	elffooter = "</html>"
	tablerows = ""
	imagehtml = ""
	if leafreports.has_key('libs'):
		if leafreports['libs'] != []:
			tablerows = tablerows + tablerowtemplate % ("Declared shared libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['libs']))
	if leafreports.has_key('elfused'):
		if leafreports['elfused'] != []:
			tablerows = tablerows + tablerowtemplate % ("Used shared libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['elfused']))
	if leafreports.has_key('elfunused'):
		if leafreports['elfunused'] != []:
			tablerows = tablerows + tablerowtemplate % ("Unused (but declared) shared libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['elfunused']))
	if leafreports.has_key('elfusedby'):
		if leafreports['elfusedby'] != []:
			tablerows = tablerows + tablerowtemplate % ("Used by", reduce(lambda x, y: x + ", " + y, leafreports['elfusedby']))
	if leafreports.has_key('notfoundfuncs'):
		if leafreports['notfoundfuncs'] != []:
			tablerows = tablerows + tablerowtemplate % ("Unresolved function symbols", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['notfoundfuncs']))
	if leafreports.has_key('notfoundvars'):
		if leafreports['notfoundvars'] != []:
			tablerows = tablerows + tablerowtemplate % ("Unresolved variable symbols", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['notfoundvars']))
	if leafreports.has_key('elfpossiblyused'):
		if leafreports['elfpossiblyused'] != []:
			tablerows = tablerows + tablerowtemplate % ("Possibly used (but undeclared) libraries", reduce(lambda x, y: "%s, %s" % (x,y), leafreports['elfpossiblyused']))
	if tmpimagedir != None:
		if os.path.exists(os.path.join(tmpimagedir, "%s-graph.png" % filehash)):
			imagehtml = "<h2>Dynamic linking graph</h2><p><img src=\"%s/%s-graph.png\"/></p>" % (imagesdir, filehash)
			imagehtml += "<p><ul><li>black solid line: defined and used dependency</li>"
			imagehtml += "<li>blue dashed line: defined but unused dependency</li>"
			imagehtml += "<li>red solid line: undefined but used dependency</li>"
			imagehtml += "<li>black dotted line: defined and used dependency, part of standard API</li>"
			imagehtml += "</ul></p>"
	if tablerows != "":
		elfstring = elfheader + tablerows + elftablefooter + imagehtml + elffooter
		elfreportfile = gzip.open("%s/%s-elfreport.html.gz" % (reportdir, filehash), 'wb')
		elfreportfile.write(elfstring)
		elfreportfile.close()
