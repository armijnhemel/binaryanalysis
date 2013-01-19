#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. It generates a HTML file which
contains information about function names, methods, variables, and so on, which
can be displayed in the BAT GUI.

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
		if variablepvs == {} and dynamicRes == {}:
			return

		if dynamicRes != {}:
			header = "<html><body>"
			html = ""
			if dynamicRes.has_key('uniquepackages'):
				if dynamicRes['uniquepackages'] != {}:
					html += "<h1>Unique function name matches per package</h1><p><ul>\n"
					ukeys = map(lambda x: (x[0], len(x[1])), dynamicRes['uniquepackages'].items())
					ukeys.sort(key=lambda x: x[1], reverse=True)
					for i in ukeys:
						html += "<li><a href=\"#%s\">%s (%d)</a>" % (i[0], i[0], i[1])
					html += "</ul></p>"
					for i in ukeys:
						html += "<hr><h2><a name=\"%s\" href=\"#%s\">Matches for %s (%d)</a></h2><p>\n" % (i[0], i[0], i[0], i[1])
						upkgs = dynamicRes['uniquepackages'][i[0]]
						upkgs.sort()
						for v in upkgs:
							html += "%s<br>\n" % v
						html += "</p>\n"
			footer = "</body></html>"
			if html != "":
				html = header + html + footer
				nameshtmlfile = gzip.open("%s/%s-functionnames.html.gz" % (reportdir, unpackreport['sha256']), 'wb')
				nameshtmlfile.write(html)
				nameshtmlfile.close()
		if variablepvs != {}:
			header = "<html><body>"
			html = ""
			language = variablepvs['language']

			if language == 'Java':
				fieldspackages = {}
				sourcespackages = {}
				classespackages = {}
				fieldscount = {}
				sourcescount = {}
				classescount = {}
				for i in ['classes', 'sources', 'fields']:
					if not variablepvs.has_key(i):
						continue
					packages = {}
					packagecount = {}
					if variablepvs[i] != []:
						for c in variablepvs[i]:
							lenres = len(list(set(map(lambda x: x[0], variablepvs[i][c]))))
							if lenres == 1:
								pvs = variablepvs[i][c]
								(package,version) = variablepvs[i][c][0]
								if packagecount.has_key(package):
									packagecount[package] = packagecount[package] + 1
								else:
									packagecount[package] = 1
								'''
								## for later use
								for p in pvs:
									(package,version) = p
									if packages.has_key(package):
										packages[package].append(version)
									else:
										packages[package] = [version]
								'''
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
				if variablepvs.has_key('variables'):
					packages = {}
					packagecount = {}
					for c in variablepvs['variables']:
						lenres = len(list(set(map(lambda x: x[0], variablepvs['variables'][c]))))
						if lenres == 1:
							pvs = variablepvs['variables'][c]
							(package,version) = variablepvs['variables'][c][0]
							if packagecount.has_key(package):
								packagecount[package] = packagecount[package] + 1
							else:
								packagecount[package] = 1
								
							'''
							## for later use
							for p in pvs:
								(package,version) = p
								if packages.has_key(package):
									packages[package].append(version)
								else:
									packages[package] = [version]
							'''
	
					if packagecount != {}:
						html = html + "<h3>Unique matches of variables</h3>\n<table>\n"
						html = html + "<tr><td><b>Name</b></td><td><b>Unique matches</b></td></tr>"
						for i in packagecount:
							html = html + "<tr><td>%s</td><td>%d</td></tr>\n" % (i, packagecount[i])
						html = html + "</table>\n"
	
			footer = "</body></html>"
			if html != "":
				html = header + html + footer
				nameshtmlfile = gzip.open("%s/%s-names.html.gz" % (reportdir, unpackreport['sha256']), 'wb')
				nameshtmlfile.write(html)
				nameshtmlfile.close()
