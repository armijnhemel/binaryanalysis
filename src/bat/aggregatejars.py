#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, multiprocessing

'''
This plugin is used to aggregate ranking results for Java JAR files.
The ranking scan only ranks individual class files, which often do not
contain enough information. By aggregating the results of these classes
it is possible to get a better view of what is inside a JAR.
'''

def aggregatejars(unpackreports, scantempdir, topleveldir, processors, debug=False, envvars=None):
	cleanclasses = False

	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass
	if scanenv.get('AGGREGATE_CLEAN', 0) == '1':
		cleanclasses = True

	## find all JAR files. Do this by:
	## 1. checking the tags for 'zip'
	## 2. verifying for unpacked files that there are .class files
	## 3. possibly verifying there is a META-INF directory with a manifest
	sha256stofiles = {}
	jarfiles = []
	sha256seen = []
	alljarfiles = []
	for i in unpackreports:
		if not unpackreports[i].has_key('sha256'):
			continue
		else:
			filehash = unpackreports[i]['sha256']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		if cleanclasses:
			if sha256stofiles.has_key(filehash):
				sha256stofiles[filehash].append(i)
			else:
				sha256stofiles[filehash] = [i]
		## check extension: JAR, WAR, RAR (not Resource adapter), EAR
		i_nocase = i.lower()
		if i_nocase.endswith('.jar') or i_nocase.endswith('.ear') or i_nocase.endswith('.war') or i_nocase.endswith('.rar'):
			if filehash in sha256seen:
				alljarfiles.append(i)
				continue
			leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
			leafreports = cPickle.load(leaf_file)
			leaf_file.close()
			if leafreports.has_key('tags'):
				## check if it was tagged as a ZIP file
				if 'zip' in leafreports['tags']:
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
						sha256seen.append(filehash)
						alljarfiles.append(i)
	jartasks = []

	for i in jarfiles:
		classfiles = filter(lambda x: x.endswith('.class'), unpackreports[i]['scans'][0]['scanreports'])
		classreports = map(lambda x: unpackreports[x], classfiles)
		jartasks.append((i, unpackreports[i], classreports, topleveldir))

	## check whether or not a pool needs to be created
	if jartasks != []:
		pool = multiprocessing.Pool(processes=processors)
		res = pool.map(aggregate, jartasks, 1)
		pool.terminate()

	## TODO: only for files for which there actually is a result, plus
	## all the clones of these files
	for i in alljarfiles:
		if unpackreports[i].has_key('tags'):
			unpackreports[i]['tags'].append('ranking')
		else:
			unpackreports[i]['tags'] = ['ranking']

	## if cleanclasses is set the following should be removed:
	## * reference in unpackreports (always)
	## * pickle of file, only if either unique to a JAR, or shared in several JARs,
	##   but not when the class file can also be found outside of a JAR.
	if cleanclasses:
		for i in jarfiles:
			classfiles = filter(lambda x: x.endswith('.class'), unpackreports[i]['scans'][0]['scanreports'])
			for c in classfiles:
				filehash = unpackreports[c]['sha256']
				if len(sha256stofiles[filehash]) == 1:
					try:
						os.unlink(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash))
					except Exception, e:
						print >>sys.stderr, "error removing", c, e
						sys.stderr.flush()
					sha256stofiles[filehash].remove(c)
				else:
					sha256stofiles[filehash].remove(c)
				del unpackreports[c]

def aggregate((jarfile, jarreport, unpackreports, topleveldir)):
	rankres = {}
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

	## from dynamicres
	totalnames = 0
	uniquematches = 0
	namesmatched = 0
	packagesmatched = {}
	dynamicresfinal = {}
	pv = {}

	upp = {}

	aggregated = False

	for c in unpackreports:
		## sanity checks
		if not c.has_key('tags'):
			continue
		if not 'ranking' in c['tags']:
			continue
		filehash = c['sha256']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue

		## read pickle file
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		## and more sanity checks
		if not 'binary' in leafreports['tags']:
			continue
		(stringmatches, dynamicres, varfunmatches) = leafreports['ranking']
		if varfunmatches['language'] != 'Java':
			continue
		if varfunmatches.has_key('fields'):
			for f in varfunmatches['fields']:
				## we only need one copy
				if not fieldmatches.has_key(f):
					fieldmatches[f] = varfunmatches['fields'][f]
					aggregated = True
		if varfunmatches.has_key('classes'):
			for c in varfunmatches['classes']:
				## we only need one copy
				if not classmatches.has_key(c):
					classmatches[c] = varfunmatches['classes'][c]
					aggregated = True
		if varfunmatches.has_key('sources'):
			for c in varfunmatches['sources']:
				## we only need one copy
				if not sourcematches.has_key(c):
					sourcematches[c] = varfunmatches['sources'][c]
					aggregated = True
		if stringmatches != None:
			aggregated = True
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
					(rank, package, unique, percentage, packageversions, packagelicenses, language) = r
					## ignore rank and percentage
					if uniqueMatchesperpkg.has_key(package):
						tmpres = []
						for p in r[2]:
							if upp.has_key(p[0]):
								continue
							else:
								tmpres.append(p)
								upp[p[0]] = 1
						uniqueMatchesperpkg[package] = uniqueMatchesperpkg[package] + tmpres
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
		if dynamicres != {}:
			aggregated = True
			if dynamicres.has_key('uniquepackages'):
				if dynamicres['uniquepackages'] != {}:
					if not dynamicresfinal.has_key('uniquepackages'):
						dynamicresfinal['uniquepackages'] = {}
					for d in dynamicres['uniquepackages'].keys():
						if dynamicresfinal['uniquepackages'].has_key(d):
							dynamicresfinal['uniquepackages'][d] = list(set(dynamicresfinal['uniquepackages'][d] + dynamicres['uniquepackages'][d]))
						else:
							dynamicresfinal['uniquepackages'][d] = dynamicres['uniquepackages'][d]
		'''
		## this is unreliable: we could be counting many unique method
		## names twice. We actually need the names of the methods that
		## were found.
		if dynamicres != {}:
			totalnames = totalnames + dynamicres['totalnames']
			uniquematches = uniquematches + dynamicres['uniquematches']
			namesmatched = namesmatched + dynamicres['namesmatched']
			if dynamicres.has_key('packages'):
				for p in dynamicres['packages']:
					if packagesmatched.has_key(p):
						for m in packagesmatched[p]:
							if pv.has_key(p):
								if pv[p].has_key(m[0]):
									pv[p][m[0]] = pv[p][m[0]] + m[1]
								else:
									pv[p][m[0]] = m[1]
							else:
								pv[p] = {}
								pv[p][m[0]] = m[1]
					else:
						packagesmatched[p] = dynamicres['packages'][p]
		'''

	if not aggregated:
		return (jarfile, aggregated)

	scores_sorted = sorted(scoresperpkg, key = lambda x: scoresperpkg.__getitem__(x), reverse=True)

	rank = 1
	reports = []
	for s in scores_sorted:
		try:
			percentage = (scoresperpkg[s]/totalscore)*100.0
		except:
			percentage = 0.0
		reports.append((rank, s, uniqueMatchesperpkg.get(s,[]), percentage, packageversionsperpkg.get(s, {}), list(set(packagelicensesperpkg.get(s, []))), 'Java'))
		rank = rank+1

	if dynamicresfinal.has_key('uniquepackages'):

		dynamicresfinal['namesmatched'] = reduce(lambda x, y: x + y, map(lambda x: len(x[1]), dynamicresfinal['uniquepackages'].items()))
	else:
		dynamicresfinal['namesmatched'] = 0
	dynamicresfinal['uniquematches'] = uniquematches
	dynamicresfinal['totalnames'] = namesmatched
	dynamicresfinal['packages'] = packagesmatched

	rankres['unmatched'] = list(set(unmatched))
	rankres['matchedlines'] = matchedlines
	rankres['extractedlines'] = extractedlines
	rankres['nonUniqueAssignments'] = nonUniqueAssignments
	rankres['nonUniqueMatches'] = nonUniqueMatches
	rankres['reports'] = reports

	## now write the new result
	## TODO: only do this if there actually is an aggregate result
	filehash = jarreport['sha256']
	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()

	leafreports['ranking'] = (rankres, dynamicresfinal, {'language': 'Java', 'classes': classmatches, 'fields': fieldmatches, 'sources': sourcematches})

	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
	leafreports = cPickle.dump(leafreports, leaf_file)
	leaf_file.close()
	return (jarfile, aggregated)
