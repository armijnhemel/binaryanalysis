#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy

'''
This plugin is used to aggregate ranking results for Java JAR files.
The ranking scan only ranks individual class files, which often do not
contain enough information. By aggregating the results of these classes
it is possible to get a better view of what is inside a JAR.
'''

def aggregatejars(unpackreports, leafreports, scantempdir, envvars=None):
	## find all JAR files. Do this by:
	## 1. checking the tags for 'zip'
	## 2. verifying for unpacked files that there are .class files
	## 3. possibly verifying there is a META-INF directory with a manifest
	jarfiles = []
	for i in unpackreports:
		if leafreports.has_key(i):
			## add a name check. TODO: make case insensitive
			if i.endswith('.jar'):
				if leafreports[i].has_key('tags'):
					## check if it was tagged as a ZIP file
					if 'zip' in leafreports[i]['tags']:
						## sanity checks
						if unpackreports[i]['scans'] != []:
							## since it was a single ZIP file there should be only
							## one item in unpackreports[i]['scan']
							if len(unpackreports[i]['scans']) != 1:
								continue
							## more sanity checks
							if unpackreports[i]['scans'][0]['offset'] != 0:
								continue
							if unpackreports[i]['scans'][0]['scanname'] != 'zip':
								continue
							jarfiles.append(i)
	rankresults = {}

	for i in jarfiles:
		rankres = {}
		classfiles = filter(lambda x: x.endswith('.class'), unpackreports[i]['scans'][0]['scanreports'])
		matchedlines = 0
		reports = []
		extractedlines = 0
		nonUniqueAssignments = {}
		unmatched = []
		nonUniqueMatches = {}
		totalscore = 0
		scoresperpkg = {}
		uniqueMatchesperpkg = {}
		packageversionsperpkg = {}
		packagelicensesperpkg = {}

		fieldmatches = {}
		classmatches = {}
		sourcematches = {}

		for c in classfiles:
			if not leafreports.has_key(c):
				continue
			## sanity checks
			if not leafreports[c].has_key('ranking'):
				continue
			if not leafreports[c].has_key('tags'):
				continue
			if not 'binary' in leafreports[c]['tags']:
				continue
			(stringmatches, statistics, varfunmatches) = leafreports[c]['ranking']
			if varfunmatches['language'] != 'Java':
				continue
			if varfunmatches.has_key('fields'):
				for f in varfunmatches['fields']:
					## we only need one copy
					if not fieldmatches.has_key(f):
						fieldmatches[f] = varfunmatches['fields'][f]
			if varfunmatches.has_key('classes'):
				for c in varfunmatches['classes']:
					## we only need one copy
					if not classmatches.has_key(c):
						classmatches[f] = varfunmatches['classes'][c]
			if varfunmatches.has_key('sources'):
				for c in varfunmatches['sources']:
					## we only need one copy
					if not sourcematches.has_key(c):
						sourcematches[f] = varfunmatches['sources'][c]
			if stringmatches == None:
				continue
			matchedlines = matchedlines + stringmatches['matchedlines']
			extractedlines = extractedlines + stringmatches['extractedlines']
			if stringmatches['unmatched'] != []:
				unmatched = unmatched + stringmatches['unmatched']
			if stringmatches['nonUniqueAssignments'] != {}:
				for n in stringmatches['nonUniqueAssignments'].keys():
					if nonUniqueAssignments.has_key(n):
						nonUniqueAssignments[n] = nonUniqueAssignments[n] + stringmatches['nonUniqueAssignments'][n]
					else:
						nonUniqueAssignments[n] = stringmatches['nonUniqueAssignments'][n]
			if stringmatches['nonUniqueMatches'] != {}:
				for n in stringmatches['nonUniqueMatches'].keys():
					if nonUniqueMatches.has_key(n):
						nonUniqueMatches[n] = list(set(nonUniqueMatches[n] + stringmatches['nonUniqueMatches'][n]))
					else:
						nonUniqueMatches[n] = stringmatches['nonUniqueMatches'][n]
			if stringmatches['scores'] != {}:
				for s in stringmatches['scores']:
					totalscore = totalscore + stringmatches['scores'][s]
					if scoresperpkg.has_key(s):
						scoresperpkg[s] = scoresperpkg[s] + stringmatches['scores'][s]
					else:
						scoresperpkg[s] = stringmatches['scores'][s]
			if stringmatches['reports'] != []:
				for r in stringmatches['reports']:
					(rank, package, unique, percentage, packageversions, packagelicenses) = r
					## ignore rank and percentage
					if uniqueMatchesperpkg.has_key(package):
						uniqueMatchesperpkg[package] = uniqueMatchesperpkg[package] + r[2]
					else:
						uniqueMatchesperpkg[package] = r[2]
					if packageversions != {}:
						if not packageversionsperpkg.has_key(package):
							packageversionsperpkg[package] = {}
						for k in packageversions:
							if packageversionsperpkg[package].has_key(k):
								packageversionsperpkg[package][k] = packageversionsperpkg[package][k] + packageversions[k]
							else:
								packageversionsperpkg[package][k] = packageversions[k]
					if packagelicensesperpkg.has_key(package):
						packagelicensesperpkg[package] = packagelicensesperpkg[package] + r[5]
					else:
						packagelicensesperpkg[package] = r[5]

		scores_sorted = sorted(scoresperpkg, key = lambda x: scoresperpkg.__getitem__(x), reverse=True)

		rank = 1
		reports = []
		for s in scores_sorted:
			try:
				percentage = (scoresperpkg[s]/totalscore)*100.0
			except:
				percentage = 0.0
			reports.append((rank, s, uniqueMatchesperpkg.get(s,[]), percentage, packageversionsperpkg.get(s, {}), list(set(packagelicensesperpkg.get(s, [])))))
			rank = rank+1


		rankres['unmatched'] = unmatched
		rankres['matchedlines'] = matchedlines
		rankres['extractedlines'] = extractedlines
		rankres['nonUniqueAssignments'] = nonUniqueAssignments
		rankres['nonUniqueMatches'] = nonUniqueMatches
		rankres['reports'] = reports
		rankresults[i] = {'ranking': (rankres, {}, {'language': 'Java', 'classes': classmatches, 'fields': fieldmatches, 'sources': sourcematches})}
	return rankresults
