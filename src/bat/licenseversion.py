
## Binary Analysis Tool
## Copyright 2011-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, Queue
import multiprocessing, re, datetime
from multiprocessing import Process, Lock
from multiprocessing.sharedctypes import Value, Array
import bat.batdb
if sys.version_info[1] == 7:
	import collections
	have_counter = True
else:
	have_counter = False

'''
This file contains the ranking algorithm as described in the paper
"Finding Software License Violations Through Binary Code Clone Detection"
by Armijn Hemel, Karl Trygve Kalleberg, Eelco Dolstra and Rob Vermaas, as
presented at the Mining Software Repositories 2011 conference.

Configuration parameters for databases are:

BAT_CLONE_DB :: location of database containing information about which packages
                should be treated as equivalent from a scanning point of view,
                like renamed packages.

Per language:
BAT_STRINGSCACHE_$LANGUAGE :: location of database with cached strings
                              in $LANGUAGE per package to reduce lookups

An additional classification method for dynamically linked executables or
Java binaries based on function or method names takes this parameter:

BAT_NAMECACHE_$LANGUAGE :: location of database containing cached
                           function names and variable names per package
                           to reduce lookups

In this scan results can optionally be pruned. Results of scans can get very
large, for example a scan of a Linux kernel image could have thousands of
string matches, which can each be found in a few hundred kernel source code
archives.

By pruning results the amount of noise can be much reduced, reports can be made
smaller and source code checks using the results of BAT can be made more
effective.

To remove a version A from the set of versions the following conditions have
to hold:

* there is a minimum amount of results available (20 or 30 seems a good cut off value)

* all strings/variables/function names found in A are found in the most promising
version

* the amount of strings/variables/function names found in A are significantly
smaller than the amount in the most promising version (expressed as a maximum
percentage)

Ranking results for Java JAR files are aggregated. Individual class files often
do not contain enough information. By aggregating the results of these classes
it is possible to get a better view of what is inside a JAR.

The parameter AGGREGATE_CLEAN can be set to 1 to indicated that .class files
should be removed from the result set after aggregation. By default these files
are not removed.
'''

## mapping of environment variable names for databases per language
namecacheperlanguageenv = { 'C':       'BAT_NAMECACHE_C'
                          , 'Java':    'BAT_NAMECACHE_JAVA'
                          }

namecacheperlanguagetable = { 'C':      'functionnamecache_c'
                            , 'Java':   'functionnamecache_java'
                            }

## mapping of environment variable names for databases per language
stringsdbperlanguageenv = { 'C':              'BAT_STRINGSCACHE_C'
                          , 'C#':             'BAT_STRINGSCACHE_C#'
                          , 'Java':           'BAT_STRINGSCACHE_JAVA'
                          , 'JavaScript':     'BAT_STRINGSCACHE_JAVASCRIPT'
                          , 'PHP':            'BAT_STRINGSCACHE_PHP'
                          , 'Python':         'BAT_STRINGSCACHE_PYTHON'
                          , 'Ruby':           'BAT_STRINGSCACHE_Ruby'
                          , 'ActionScript':   'BAT_STRINGSCACHE_ACTIONSCRIPT'
                          }

stringsdbperlanguagetable = { 'C':                'stringscache_c'
                            , 'C#':               'stringscache_csharp'
			    , 'Java':             'stringscache_java'
                            , 'JavaScript':       'stringscache_javascript'
                            , 'PHP':              'stringscache_php'
                            , 'Python':           'stringscache_python'
                            , 'Ruby':             'stringscache_ruby'
                            , 'ActionScript':     'stringscache_actionscript'
                            }

avgstringsdbperlanguagetable = { 'C':                'avgstringscache_c'
                               , 'C#':               'avgstringscache_csharp'
                               , 'Java':             'avgstringscache_java'
                               , 'JavaScript':       'avgstringscache_javascript'
                               , 'PHP':              'avgstringscache_php'
                               , 'Python':           'avgstringscache_python'
                               , 'Ruby':             'avgstringscache_ruby'
                               , 'ActionScript':     'avgstringscache_actionscript'
                               }


## mappings from FOSSology to Ninka and vice versa
ninka_to_fossology = { 'LesserGPLv2+': 'LGPL-2.0+'
                     , 'BSD3': 'BSD-3-Clause'
                     , 'boostV1Ref': 'BSL-1.0'
                     }

fossology_to_ninka = { 'No_license_found': 'NONE'
                     , 'GPL-1.0': 'GPLv1'
                     , 'GPL-1.0+': 'GPLv1+'
                     , 'GPL-2.0': 'GPLv2'
                     , 'GPL-2.0+': 'GPLv2+'
                     , 'GPL-3.0': 'GPLv3'
                     , 'GPL-3.0+': 'GPLv3+'
                     , 'LGPL-2.0': 'LibraryGPLv2'
                     , 'LGPL-2.0+': 'LibraryGPLv2+'
                     , 'LGPL-2.1': 'LesserGPLv2.1'
                     , 'LGPL-2.1+': 'LesserGPLv2.1+'
                     , 'LGPL-3.0': 'LesserGPLv3'
                     , 'LGPL-3.0+': 'LesserGPLv3+'
                     , 'Apache-1.0': 'Apachev1.0'
                     , 'Apache-1.1': 'Apachev1.1'
                     , 'Apache-2.0': 'Apachev2'
                     , 'BSL-1.0': 'boostV1'
                     , 'MPL-1.0': 'MPLv1_0'
                     , 'FTL': 'FreeType'
                     , 'PHP-3.01': 'phpLicV3.01'
                     , 'Postfix': 'Postfix'
                     , 'QPL-1.0': 'QTv1'
                     , 'MPL-1.1': 'MPLv1_1'
                     , 'Zend-2.0': 'zendv2'
                     , 'NPL-1.1': 'NPLv1_1'
                     , 'BSD-2-Clause': 'spdxBSD2'
                     , 'BSD-3-Clause': 'spdxBSD3'
                     , 'EPL-1.0': 'EPLv1'
                     , 'Artifex': 'artifex'
                     , 'CDDL': 'CDDLic'
                     , 'Public-domain': 'publicDomain'
                     , 'Public-domain-ref': 'publicDomain'
                     , 'IPL': 'IBMv1'
                     , 'Intel': 'IntelACPILic'
                     , 'MX4J-1.0': 'MX4JLicensev1'
                     , 'Beerware': 'BeerWareVer42'
                     , 'CPL-1.0': 'CPLv1'
                     , 'Sun': 'sunRPC'
                     , 'SunPro': 'SunSimpleLic'
                     , 'W3C-IP': 'W3CLic'
                     , 'Artistic-1.0': 'ArtisticLicensev1'
                     }

reerrorlevel = re.compile("<[\d+cd]>")
reparam = re.compile("([\w_]+)\.([\w_]+)")
rematch = re.compile("\d+")

## The scanners that are used in BAT are Ninka and FOSSology. These scanners
## don't always agree on results, but when they do, it is very reliable.
def squashlicenses(licenses):
	## licenses: [(license, scanner)]
	if len(licenses) != 2:
		return licenses
	if licenses[0][1] == 'ninka':
		if fossology_to_ninka.has_key(licenses[1][0]):
			if fossology_to_ninka[licenses[1][0]] == licenses[0][0]:
				if licenses[0][0] == 'InterACPILic':
					licenses = [('IntelACPILic', 'squashed')]
				else:   
					licenses = [(licenses[0][0], 'squashed')]
		else:   
			status = "difference"
	elif licenses[1][1] == 'ninka':
		if fossology_to_ninka.has_key(licenses[0][0]):
			if fossology_to_ninka[licenses[0][0]] == licenses[1][0]:
				if licenses[0][0] == 'InterACPILic':
					licenses = [('IntelACPILic', 'squashed')]
				else:
					licenses = [(licenses[0][0], 'squashed')]
	return licenses

def aggregatejars(unpackreports, scantempdir, topleveldir, pool, scanenv, scandebug=False, unpacktempdir=None):
	cleanclasses = False

	if scanenv.get('AGGREGATE_CLEAN', 0) == '1':
		cleanclasses = True

	## find all JAR files. Do this by:
	## 1. checking the tags for 'zip'
	## 2. verifying for unpacked files that there are .class files
	## 3. TODO: possibly verifying there is a META-INF directory with a manifest
	sha256stofiles = {}
	jarfiles = []
	sha256seen = []
	alljarfiles = []
	for i in unpackreports:
		if not 'checksum' in unpackreports[i]:
			continue
		else:
			filehash = unpackreports[i]['checksum']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		if cleanclasses:
			if filehash in sha256stofiles:
				sha256stofiles[filehash].append(i)
			else:
				sha256stofiles[filehash] = [i]
		## check extension: JAR, WAR, RAR (not Resource adapter), EAR
		i_nocase = i.lower()
		if i_nocase.endswith('.jar') or i_nocase.endswith('.ear') or i_nocase.endswith('.war') or i_nocase.endswith('.rar'):
			if 'tags' in unpackreports[i]:
				if 'duplicate' in unpackreports[i]['tags']:
					alljarfiles.append(i)
					continue
			if filehash in sha256seen:
				alljarfiles.append(i)
				continue
			leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
			leafreports = cPickle.load(leaf_file)
			leaf_file.close()
			if 'tags' in leafreports:
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

	ranked = set()
	if jartasks != []:
		res = pool.map(aggregate, jartasks, 1)
		for i in res:
			(jarfile, rankres) = i
			if rankres:
				for j in sha256stofiles[unpackreports[jarfile]['checksum']]:
					ranked.add(j)

	for i in ranked:
		if 'tags' in unpackreports[i]:
			unpackreports[i]['tags'].append('ranking')
		else:
			unpackreports[i]['tags'] = ['ranking']

	## if cleanclasses is set the following should be removed:
	## * reference in unpackreports (always)
	## * pickle of file, only if either unique to a JAR, or shared in several JARs,
	##   but not when the class file can also be found outside of a JAR.
	if cleanclasses:
		for i in alljarfiles:
			if 'tags' in unpackreports[i]:
				if 'duplicate' in unpackreports[i]['tags']:
					continue
			classfiles = filter(lambda x: x.endswith('.class'), unpackreports[i]['scans'][0]['scanreports'])
			for c in classfiles:
				filehash = unpackreports[c]['checksum']
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

## aggregate results for a single JAR file
def aggregate((jarfile, jarreport, unpackreports, topleveldir)):
	rankres = {}
	matchedlines = 0
	matchednonassignedlines = 0
	matcheddirectassignedlines = 0
	matchednotclonelines = 0
	unmatchedlines = 0
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

	uniquematcheslenperpkg = {}
	upp = {}

	aggregated = False

	for c in unpackreports:
		## sanity checks
		if not 'tags' in c:
			continue
		if not 'ranking' in c['tags']:
			continue
		filehash = c['checksum']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue

		## read pickle file
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		## and more sanity checks
		if not 'binary' in leafreports['tags']:
			continue
		(stringmatches, dynamicres, varfunmatches, language) = leafreports['ranking']
		if language != 'Java':
			continue
		if 'fields' in varfunmatches:
			for f in varfunmatches['fields']:
				if not f in fieldmatches:
					fieldmatches[f] = varfunmatches['fields'][f]
					aggregated = True
				else:
					fieldmatches[f] += varfunmatches['fields'][f]
		if 'classes' in varfunmatches:
			for c in varfunmatches['classes']:
				if not c in classmatches:
					classmatches[c] = varfunmatches['classes'][c]
					aggregated = True
				else:
					classmatches[c] += varfunmatches['classes'][c]
		if 'sources' in varfunmatches:
			for c in varfunmatches['sources']:
				if not c in sourcematches:
					sourcematches[c] = varfunmatches['sources'][c]
					aggregated = True
				else:
					sourcematches[c] += varfunmatches['sources'][c]
		if stringmatches != None:
			aggregated = True
			matchedlines = matchedlines + stringmatches['matchedlines']
			matchednonassignedlines = matchednonassignedlines + stringmatches['matchednonassignedlines']
			matchednotclonelines = matchednotclonelines + stringmatches['matchednotclonelines']
			unmatchedlines = unmatchedlines + stringmatches['unmatchedlines']
			extractedlines = extractedlines + stringmatches['extractedlines']
			if stringmatches['unmatched'] != []:
				unmatched = unmatched + stringmatches['unmatched']
			if stringmatches['nonUniqueAssignments'] != {}:
				for n in stringmatches['nonUniqueAssignments'].keys():
					if n in nonUniqueAssignments:
						nonUniqueAssignments[n] = nonUniqueAssignments[n] + stringmatches['nonUniqueAssignments'][n]
					else:
						nonUniqueAssignments[n] = stringmatches['nonUniqueAssignments'][n]
			if stringmatches['nonUniqueMatches'] != {}:
				for n in stringmatches['nonUniqueMatches'].keys():
					if n in nonUniqueMatches:
						nonUniqueMatches[n] = list(set(nonUniqueMatches[n] + stringmatches['nonUniqueMatches'][n]))
					else:
						nonUniqueMatches[n] = stringmatches['nonUniqueMatches'][n]
			if stringmatches['scores'] != {}:
				for s in stringmatches['scores']:
					totalscore = totalscore + stringmatches['scores'][s]
					if s in scoresperpkg:
						scoresperpkg[s] = scoresperpkg[s] + stringmatches['scores'][s]
					else:
						scoresperpkg[s] = stringmatches['scores'][s]
			if stringmatches['reports'] != []:
				for r in stringmatches['reports']:
					(rank, package, unique, uniquematcheslen, percentage, packageversions, packagelicenses, packagecopyrights) = r
					## ignore rank and percentage
					if package in uniqueMatchesperpkg:
						tmpres = []
						for p in r[2]:
							if p[0] in upp:
								continue
							else:
								tmpres.append(p)
								upp[p[0]] = 1
						uniqueMatchesperpkg[package] = uniqueMatchesperpkg[package] + tmpres
					else:
						uniqueMatchesperpkg[package] = r[2]
					if packageversions != {}:
						if not package in packageversionsperpkg:
							packageversionsperpkg[package] = {}
						for k in packageversions:
							if k in packageversionsperpkg[package]:
								packageversionsperpkg[package][k] = packageversionsperpkg[package][k] + packageversions[k]
							else:
								packageversionsperpkg[package][k] = packageversions[k]
					if package in packagelicensesperpkg:
						packagelicensesperpkg[package] = packagelicensesperpkg[package] + packagelicenses
					else:
						packagelicensesperpkg[package] = packagelicenses
					if package in uniquematcheslenperpkg:
						uniquematcheslenperpkg[package] += uniquematcheslen
					else:
						uniquematcheslenperpkg[package] = uniquematcheslen
		if dynamicres != {}:
			aggregated = True
			if 'uniquepackages' in dynamicres:
				if dynamicres['uniquepackages'] != {}:
					if not 'uniquepackages' in dynamicresfinal:
						dynamicresfinal['uniquepackages'] = {}
					for d in dynamicres['uniquepackages'].keys():
						if d in dynamicresfinal['uniquepackages']:
							dynamicresfinal['uniquepackages'][d] = list(set(dynamicresfinal['uniquepackages'][d] + dynamicres['uniquepackages'][d]))
						else:
							dynamicresfinal['uniquepackages'][d] = dynamicres['uniquepackages'][d]
	if not aggregated:
		return (jarfile, aggregated)

	scores_sorted = sorted(scoresperpkg, key = lambda x: scoresperpkg.__getitem__(x), reverse=True)

	rank = 1
	reports = []
	packagecopyrights = []
	for s in scores_sorted:
		try:
			percentage = (scoresperpkg[s]/totalscore)*100.0
		except:
			percentage = 0.0
		reports.append((rank, s, uniqueMatchesperpkg.get(s,[]), uniquematcheslenperpkg.get(s,0), percentage, packageversionsperpkg.get(s, {}), list(set(packagelicensesperpkg.get(s, []))), packagecopyrights))
		rank = rank+1

	if dynamicresfinal.has_key('uniquepackages'):

		dynamicresfinal['namesmatched'] = reduce(lambda x, y: x + y, map(lambda x: len(x[1]), dynamicresfinal['uniquepackages'].items()))
	else:
		dynamicresfinal['namesmatched'] = 0
	dynamicresfinal['uniquematches'] = uniquematches
	dynamicresfinal['totalnames'] = namesmatched
	dynamicresfinal['packages'] = packagesmatched

	unmatched = list(set(unmatched))
	unmatched.sort()
	rankres['unmatched'] = unmatched
	rankres['matchedlines'] = matchedlines
	rankres['matchednonassignedlines'] = matchednonassignedlines
	rankres['matchednotclonelines'] = matchednotclonelines
	rankres['unmatchedlines'] = unmatchedlines
	rankres['extractedlines'] = extractedlines
	rankres['nonUniqueAssignments'] = nonUniqueAssignments
	rankres['nonUniqueMatches'] = nonUniqueMatches
	rankres['reports'] = reports

	## now write the new result
	## TODO: only do this if there actually is an aggregate result
	filehash = jarreport['checksum']
	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()

	leafreports['ranking'] = (rankres, dynamicresfinal, {'classes': classmatches, 'fields': fieldmatches, 'sources': sourcematches}, 'Java')

	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
	leafreports = cPickle.dump(leafreports, leaf_file)
	leaf_file.close()
	return (jarfile, aggregated)

def prune(uniques, package):
	if have_counter:
		uniqueversions = collections.Counter()
	else:
		uniqueversions = {}

	linesperversion = {}

	for u in uniques:
		(line, res) = u
		versions = set()
		for r in res:
			(checksum, linenumber, versionfilenames) = r
			map(lambda x: versions.add(x[0]), versionfilenames)
		for version in versions:
			if version in linesperversion:
				linesperversion[version].add(line)
			else:
				linesperversion[version] = set([line])
		if have_counter:
			uniqueversions.update(versions)
		else:
			for version in versions:
				if version in uniqueversions:
					uniqueversions[version] += 1
				else:
					uniqueversions[version] = 1
				
	## there is only one version, so no need to continue
	if len(uniqueversions.keys()) == 1:
		return uniques

	pruneme = set()

	unique_sorted_rev = sorted(uniqueversions, key = lambda x: uniqueversions.__getitem__(x), reverse=True)
	unique_sorted = sorted(uniqueversions, key = lambda x: uniqueversions.__getitem__(x))

	equivalents = set()
	for l in unique_sorted_rev:
		if l in pruneme:
			continue
		if l in equivalents:
			continue
		linesperversion_l = set(linesperversion[l])
		pruneremove = set()
		for k in unique_sorted:
			if uniqueversions[k] == uniqueversions[l]:
				## Both versions have the same amount of identifiers, so
				## could be the same. If so, add to 'equivalents'
				## and skip all equivalents since the results would be the
				## same as with the current 'l' and no versions would be
				## pruned that weren't already pruned.
				if linesperversion[k] == linesperversion_l:
					equivalents.add(k)
				continue
			if uniqueversions[k] > uniqueversions[l]:
				break
			if set(linesperversion[k]).issubset(linesperversion_l):
				pruneme.add(k)
				pruneremove.add(k)
		## make the inner loop a bit shorter
		for k in pruneremove:
			unique_sorted.remove(k)

	## TODO: pruneme might have length 0, so uniques can be returned. Verify this.
	notpruned = set(uniqueversions.keys()).difference(pruneme)
	newuniques = []
	for u in uniques:
		(line, res) = u
		newres = []
		for r in res:
			(checksum, linenumber, versionfilenames) = r
			filterres = filter(lambda x: x[0] in notpruned, versionfilenames)
			if filterres != []:
				newres.append((checksum, linenumber, filterres))
		newuniques.append((line, newres))

	return newuniques

def determinelicense_version_copyright(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):

	(envresult, newenv) = licensesetup(scanenv, scandebug)

	if not envresult:
		return None

	## the environment might have changed and been cleaned up,
	## so overwrite the old one
	determineversion = False
	if newenv.get('BAT_RANKING_VERSION', 0) == '1':
		determineversion = True

	determinelicense = False
	if newenv.get('BAT_RANKING_LICENSE', 0) == '1':
		determinelicense = True

	determinecopyright = False
	if newenv.get('BAT_RANKING_COPYRIGHT', 0) == '1':
		determinecopyright = True

	## only continue if there actually is a need
	if not determinelicense and not determineversion and not determinecopyright:
		return None

	## ignore files which don't have ranking results
	rankingfiles = set()
	filehashseen = set()
	hashtoname = {}

	rankingfilesperlanguage = {}
	for i in unpackreports:
		if not 'checksum' in unpackreports[i]:
			continue
		if not 'tags' in unpackreports[i]:
			continue
		if not 'identifier' in unpackreports[i]['tags']:
			continue
		filehash = unpackreports[i]['checksum']
		if filehash in hashtoname:
			hashtoname[filehash].append(i)
		else:
			hashtoname[filehash] = [i]
		if filehash in filehashseen:
			continue
		filehashseen.add(filehash)
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()
		if not 'identifier' in leafreports:
			continue
		language = leafreports['identifier']['language']
		if language in rankingfilesperlanguage:
			rankingfilesperlanguage[language].add(i)
		else:
			rankingfilesperlanguage[language] = set([i])

	if len(rankingfilesperlanguage) == 0:
		return None

	batdb = bat.batdb.BatDb(newenv['DBBACKEND'])

	## Some methods use a database to lookup renamed packages.
	clonedb = newenv.get('BAT_CLONE_DB')
	clones = {}
	if clonedb != None:
		conn = batdb.getConnection(clonedb,newenv)
		c = conn.cursor()
		c.execute("SELECT originalname,newname from renames")
		clonestmp = c.fetchall()
		conn.commit()
		c.close() 
		conn.close()
		for cl in clonestmp:
			(originalname,newname) = cl
			if not originalname in clones:
				clones[originalname] = newname

	## suck the average string scores database into memory. Even with a few million packages
	## this will not cost much memory and it prevents many database lookups.
	avgscores = {}
	for language in avgstringsdbperlanguagetable:
		if not language in rankingfilesperlanguage:
			continue
		stringscache = newenv.get(stringsdbperlanguageenv[language])
		if stringscache == None:
			continue
		## open the database containing all the strings that were extracted
		## from source code.
		conn = batdb.getConnection(stringscache,newenv)
		c = conn.cursor()
		avgscores[language] = {}
		avgquery = "select package, avgstrings from %s" % avgstringsdbperlanguagetable[language]
		c.execute(avgquery)
		res = c.fetchall()
		conn.commit()
		c.close()
		conn.close()

		for r in filter(lambda x: x[1] != 0, res):
			avgscores[language][r[0]] = r[1]

	## create a queue for tasks, with a few threads reading from the queue
	## and looking up results and putting them in a result queue
	scanmanager = multiprocessing.Manager()
	res = []
	batcons = []
	batcursors = []

	if processors == None:
		processamount = 1
	else:
		processamount = processors
	minprocessamount = min(max(map(lambda x: len(rankingfilesperlanguage[x]), rankingfilesperlanguage)), processamount)

	for i in range(0,minprocessamount):
		## then a cursor for the main database
		conn = batdb.getConnection(newenv['BAT_DB'],newenv)
		cursor = conn.cursor()
		batcursors.append(cursor)
		batcons.append(conn)

	## now per language
	for language in rankingfilesperlanguage:
		## creating new queues
		scanqueue = multiprocessing.JoinableQueue(maxsize=0)
		reportqueue = scanmanager.Queue(maxsize=0)

		lookup_tasks = map(lambda x: (unpackreports[x]['checksum'], os.path.join(unpackreports[x]['realpath'], unpackreports[x]['name'])),rankingfilesperlanguage[language])
		map(lambda x: scanqueue.put(x), lookup_tasks)

		stringcacheconns = []
		namecacheconns = []
		processpool = []

		## first a cursor for the cache of each supported language
		stringcachecursors = []
		namecachecursors = []
		for i in range(0,minprocessamount):
			if language in stringsdbperlanguagetable:
				stringscache = newenv.get(stringsdbperlanguageenv[language])
				if stringscache == None:
					continue
				conn = batdb.getConnection(stringscache,newenv)
				c = conn.cursor()
				stringcacheconns.append(conn)
				stringcachecursors.append(c)
			## then for namecaches
			if language in namecacheperlanguagetable:
				namecache = newenv.get(namecacheperlanguageenv[language])
				if namecache == None:
					continue
				conn = batdb.getConnection(namecache,newenv)
				c = conn.cursor()
				namecacheconns.append(conn)
				namecachecursors.append(c)

			p = multiprocessing.Process(target=lookup_identifier, args=(scanqueue,reportqueue, stringcachecursors[i], stringcacheconns[i],namecachecursors[i],namecacheconns[i],batdb,newenv,topleveldir,avgscores,clones,scandebug))
			processpool.append(p)
			p.start()

        	scanqueue.join()

		while True:
			try:
				val = reportqueue.get_nowait()
				res.append(val)
				reportqueue.task_done()
			except Queue.Empty, e:
				## Queue is empty
				break
		reportqueue.join()

		for p in processpool:
			p.terminate()
		for c in stringcachecursors:
			c.close()
		for c in stringcacheconns:
			c.close()
		for c in namecachecursors:
			c.close()
		for c in namecacheconns:
			c.close()

	for c in batcursors:
		c.close()
	for c in batcons:
		c.close()

	for filehash in res:
		if filehash != None:
			if filehash in hashtoname:
				for w in hashtoname[filehash]:
					unpackreports[w]['tags'].append('ranking')

	if 'Java' in rankingfilesperlanguage:
		pool = multiprocessing.Pool(processes=processors)
		## aggregate the JAR files
		aggregatejars(unpackreports, scantempdir, topleveldir, pool, newenv, scandebug=False, unpacktempdir=None)
		pool.terminate()

	## .class files might have been removed at this point, so sanity check first
	rankingfiles = set()
	filehashseen = set()
	for i in unpackreports:
		if not 'checksum' in unpackreports[i]:
			continue
		if not 'tags' in unpackreports[i]:
			continue
		if not 'ranking' in unpackreports[i]['tags']:
			continue
		filehash = unpackreports[i]['checksum']
		if filehash in filehashseen:
			continue
		filehashseen.add(filehash)
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		rankingfiles.add(i)

	## and determine versions, etc.
	compute_version(processors, newenv, unpackreports, rankingfiles, topleveldir, determinelicense, determinecopyright, batdb)

## grab variable names.
def grab_sha256_varname(scanqueue, reportqueue, cursor, conn, query):
	while True:
		sha256sum = scanqueue.get(timeout=2592000)
		c.execute(query, (sha256sum,))
		results = c.fetchall()
		conn.commit()
		reportqueue.put({sha256sum: results})
		scanqueue.task_done()

def grab_sha256_filename(scanqueue, reportqueue, cursor, conn, query):
	while True:
		sha256sum = scanqueue.get(timeout=2592000)
		cursor.execute(query, (sha256sum,))
		results = cursor.fetchall()
		conn.commit()
		reportqueue.put({sha256sum: results})
		scanqueue.task_done()

## grab copyright statements from the license database
def grab_sha256_copyright(scanqueue, reportqueue, cursor, conn, query):
	while True:
		sha256sum = scanqueue.get(timeout=2592000)
		cursor.execute(query, (sha256sum,))
		results = cursor.fetchall()
		conn.commit()
		## 'statements' are not very accurate so ignore those
		results = filter(lambda x: x[1] != 'statement', results)
		reportqueue.put({sha256sum: results})
		scanqueue.task_done()

## grab licenses from the license database
def grab_sha256_license(scanqueue, reportqueue, cursor, conn, query):
	while True:
		sha256sum = scanqueue.get(timeout=2592000)
		cursor.execute(query, (sha256sum,))
		results = cursor.fetchall()
		conn.commit()
		reportqueue.put({sha256sum: results})
		scanqueue.task_done()

def grab_sha256_parallel(scanqueue, reportqueue, cursor, conn, batdb, language, querytype):
	stringquery = batdb.getQuery("select distinct checksum, linenumber, language from extracted_string where stringidentifier=%s and language=%s")
	functionquery = batdb.getQuery("select distinct checksum, linenumber, language from extracted_function where functionname=%s")
	variablequery = batdb.getQuery("select distinct checksum, linenumber, language, type from extracted_name where name=%s")
	kernelvarquery = batdb.getQuery("select distinct checksum, linenumber, language, type from extracted_name where name=%s")
	while True:
		res = None
		line = scanqueue.get(timeout=2592000)
		if querytype == "string":
			cursor.execute(stringquery, (line,language))
			res = cursor.fetchall()
		elif querytype == 'function':
			cursor.execute(functionquery, (line,))
			res = cursor.fetchall()
		elif querytype == 'variable':
			cursor.execute(variablequery, (line,))
			res = cursor.fetchall()
			res = filter(lambda x: x[3] == 'variable', res)
		elif querytype == 'kernelvariable':
			cursor.execute(kernelvarquery, (line,))
			res = cursor.fetchall()
			res = filter(lambda x: x[3] == 'kernelsymbol', res)
		conn.commit()
		if res != None:
			res = filter(lambda x: x[2] == language, res)
			## TODO: make a list of line numbers
			res = map(lambda x: (x[0], x[1]), res)
			reportqueue.put((line, res))
		scanqueue.task_done()

def extractJava(javameta, scanenv, funccursor, funcconn, batdb, clones):
	dynamicRes = {}  # {'namesmatched': 0, 'totalnames': int, 'uniquematches': int, 'packages': {} }
	namesmatched = 0
	uniquematches = 0
	uniquepackages = {}

	variablepvs = {}
	if 'fields' in javameta:
		fields = javameta['fields']
	else:
		fields = []
	if 'classes' in javameta:
		classes = javameta['classes']
	else:
		classes = []
	if 'sourcefiles' in javameta:
		sourcefiles = javameta['sourcefiles']
	else:
		sourcefiles = []

	classname = javameta['classes']
	methods = javameta['methods']
	fields = javameta['fields']
	sourcefile = javameta['sourcefiles']

	if 'BAT_METHOD_SCAN' in scanenv:

		query = batdb.getQuery("select distinct package from %s where functionname=" % namecacheperlanguagetable['Java'] + "%s")
		for meth in methods:
			if meth == 'main':
				continue
			funccursor.execute(query, (meth,))
			res = funccursor.fetchall()
			funcconn.commit()
			if res != []:
				namesmatched += 1
				packages_tmp = []
				for r in res:
					if r[0] in clones:
						package_tmp = clones[r[0]]
						packages_tmp.append(package_tmp)
					else:
						packages_tmp.append(r[0])
				packages_tmp = list(set(packages_tmp))

				## unique match
				if len(packages_tmp) == 1:
					uniquematches += 1
					if uniquepackages.has_key(packages_tmp[0]):
						uniquepackages[packages_tmp[0]].append(meth)
					else:
						uniquepackages[packages_tmp[0]] = [meth]

	dynamicRes['namesmatched'] = namesmatched
	dynamicRes['totalnames'] = len(set(methods))
	dynamicRes['uniquepackages'] = uniquepackages
	dynamicRes['uniquematches'] = uniquematches

	## unique matches found. 
	if uniquematches != 0:
		dynamicRes['packages'] = {}

	## Now variable names
	classpvs = {}
	sourcepvs = {}
	fieldspvs = {}

	## classes and source file names are searched in a similar way.
	## Of course, it could be that the source file is different from the
	## class file (apart from the extension of course) but this is very
	## uncommon. TODO: merge class name and source file name searching
	if 'BAT_CLASSNAME_SCAN' in scanenv:
		classes = set(map(lambda x: x.split('$')[0], classes))
		query = batdb.getQuery("select package from classcache_java where classname=%s")
		for i in classes:
			pvs = []
			## first try the name as found in the binary. If it can't
			## be found and has dots in it split it on '.' and
			## use the last component only.
			classname = i
			funccursor.execute(query, (classname,))
			classres = funccursor.fetchall()
			funcconn.commit()	
			if classres == []:
				## check just the last component
				classname = classname.split('.')[-1]
				classres = funccursor.execute(query, (classname,))
				classres = funccursor.fetchall()
				funcconn.commit()	
			## check the cloning database
			if classres != []:
				classres_tmp = []
				for r in classres:
					if r[0] in clones:
						class_tmp = clones[r[0]]
						classres_tmp.append(class_tmp)
					else:   
						classres_tmp.append(r[0])
				classres_tmp = list(set(classres_tmp))
				classres = map(lambda x: (x, 0), classres_tmp)
				classpvs[classname] = classres

		for i in javameta['sourcefiles']:
			pvs = []
			## first try the name as found in the binary. If it can't
			## be found and has dots in it split it on '.' and
			## use the last component only.
			if i.lower().endswith('.java'):
				classname = i[0:-5]
			else:
				classname = i

			## first try the name as found in the binary. If it can't
			## be found and has dots in it split it on '.' and
			## use the last component only.
			funccursor.execute(query, (classname,))
			classres = funccursor.fetchall()
			funcconn.commit()	
			## check the cloning database
			if classres != []:
				classres_tmp = []
				for r in classres:
					if r[0] in clones:
						class_tmp = clones[r[0]]
						classres_tmp.append(class_tmp)
					else:   
						classres_tmp.append(r[0])
				classres_tmp = set(classres_tmp)
				classres = map(lambda x: (x, 0), classres_tmp)
				sourcepvs[classname] = classres

	## Keep a list of which sha256s were already seen. Since the files are
	## likely only coming from a few packages there is no need to hit the database
	## that often.
	sha256cache = {}
	if 'BAT_FIELDNAME_SCAN' in scanenv:
		query = batdb.getQuery("select package from fieldcache_java where fieldname=%s")
		for f in fields:
			## a few fields are so common that they will be completely useless
			## for reporting, but processing them will take a *lot* of time, so
			## just skip them. This list is based on research of many many Java
			## source code files.
			if f in ['value', 'name', 'type', 'data', 'options', 'parent', 'description', 'instance', 'port', 'out', 'properties', 'project', 'next', 'id', 'listeners', 'status', 'target', 'result', 'index', 'buffer', 'values', 'count', 'size', 'key', 'path', 'cache', 'map', 'file', 'context', 'initialized', 'verbose', 'version', 'debug', 'message', 'attributes', 'url', 'DEBUG', 'NAME', 'state', 'source', 'password', 'text', 'start', 'factory', 'entries', 'buf', 'args', 'logger', 'config', 'length', 'encoding', 'method', 'resources', 'timeout', 'filename', 'offset', 'server', 'mode', 'in', 'connection']:
				continue
			pvs = []

			funccursor.execute(query, (f,))
			fieldres = funccursor.fetchall()
			funcconn.commit()	
			if fieldres != []:
				fieldres_tmp = []
				for r in fieldres:
					if r[0] in clones:
						field_tmp = clones[r[0]]
						fieldres_tmp.append(field_tmp)
					else:   
						fieldres_tmp.append(r[0])
				fieldres_tmp = set(fieldres_tmp)
				fieldres = map(lambda x: (x, 0), fieldres_tmp)
				fieldspvs[f] = fieldres

	variablepvs['fields'] = fieldspvs
	variablepvs['sources'] = sourcepvs
	variablepvs['classes'] = classpvs
	## these are the unique function names only, just add some stubs here
	for i in uniquepackages:
		versions = []
		dynamicRes['packages'][i] = []
	return (dynamicRes, variablepvs)

def scankernelsymbols(variables, scanenv, kernelquery, funccursor, funcconn, clones):
	allvvs = {}
	uniquevvs = {}
	variablepvs = {}
	for v in variables:
		pvs = []
		funccursor.execute(kernelquery, (v,))
		res = funccursor.fetchall()
		funcconn.commit()
		if res != []:
			pvs = map(lambda x: x[0], res)

		pvs_tmp = []
		for r in pvs:
			if r in clones:
				pvs_tmp.append(clones[r])
			else:
				pvs_tmp.append(r)
		if len(pvs_tmp) == 1:
			if uniquevvs.has_key(pvs_tmp[0]):
				uniquevvs[pvs_tmp[0]].append(v)
			else:
				uniquevvs[pvs_tmp[0]] = [v]
		allvvs[v] = pvs_tmp

	variablepvs = {'uniquepackages': uniquevvs, 'allvariables': allvvs}
	variablepvs['packages'] = {}
	variablepvs['versionresults'] = {}
	variablepvs['type'] = 'linuxkernel'
	for package in uniquevvs:
		variablepvs['versionresults'][package] = []
		variablepvs['packages'][package] = []
	return variablepvs

## From dynamically linked ELF files it is possible to extract the dynamic
## symbol table. This table lists the functions and variables which are needed
## from external libraries, but also lists local functions and variables.
## By searching a database that contains which function names and variable names
## can be found in which packages it is possible to identify which package was
## used.
def scanDynamic(scanstr, variables, scanenv, funccursor, funcconn, batdb, clones):
	dynamicRes = {}
	variablepvs = {}

	if not ('BAT_FUNCTION_SCAN' in scanenv or 'BAT_VARNAME_SCAN' in scanenv):
		return (dynamicRes, variablepvs)

	if 'BAT_FUNCTION_SCAN' in scanenv:
		uniquepackages = {}
		namesmatched = 0
		uniquematches = 0

		## caching datastructure, only needed in case there is no full cache
		sha256_packages = {}

		## the database made from ctags output only has function names, not the types. Since
		## C++ functions could be in an executable several times with different types we
		## deduplicate first
		query = batdb.getQuery("select package from %s where functionname=" % namecacheperlanguagetable['C'] + "%s")
		for funcname in scanstr:
			funccursor.execute(query, (funcname,))
			res = funccursor.fetchall()
			funcconn.commit()
			pkgs = []
			if res != []:
				packages_tmp = []
				for r in res:
					if r[0] in clones:
						package_tmp = clones[r[0]]
						packages_tmp.append(package_tmp)
					else:
						packages_tmp.append(r[0])
				packages_tmp = list(set(packages_tmp))
				namesmatched += 1
				## unique match
				if len(packages_tmp) == 1:
					uniquematches += 1
					if uniquepackages.has_key(packages_tmp[0]):
						uniquepackages[packages_tmp[0]] += [funcname]
					else:
						uniquepackages[packages_tmp[0]] = [funcname]
		dynamicRes['namesmatched'] = namesmatched
		dynamicRes['uniquepackages'] = uniquepackages
		dynamicRes['totalnames'] = len(scanstr)

		## unique matches found. 
		dynamicRes['uniquematches'] = uniquematches
		if uniquematches != 0:
			dynamicRes['packages'] = {}
			dynamicRes['versionresults'] = {}
		## these are the unique function names only
		## TODO: here versions for function names were computed. This needs clean ups.
		for package in uniquepackages:
			versions = []
			dynamicRes['versionresults'][package] = []

			dynamicRes['packages'][package] = []
			for v in set(versions):
				dynamicRes['packages'][package].append((v, versions.count(v)))

	## Scan C variables extracted from dynamically linked files.
	if scanenv.get('BAT_VARNAME_SCAN'):

		## keep two mappings:
		## 1. unique variable names per package
		## 2. package per variable name
		uniquevvs = {}
		allvvs = {}
		query = batdb.getQuery("select distinct package from varnamecache_c where varname=%s")
		for v in variables:
			## These variable names are very generic and would not be useful, so skip.
			## This is based on research of millions of C files.
			if v in ['options', 'debug', 'options', 'verbose', 'optarg', 'optopt', 'optfind', 'optind', 'opterr']:
				continue
			pvs = []
			funccursor.execute(query, (v,))
			res = funccursor.fetchall()
			funcconn.commit()
			if res != []:
				pvs = map(lambda x: x[0], res)

			pvs_tmp = []
			for r in pvs:
				if r in clones:
					pvs_tmp.append(clones[r])
				else:
					pvs_tmp.append(r)
			if len(pvs_tmp) == 1:
				if uniquevvs.has_key(pvs_tmp[0]):
					uniquevvs[pvs_tmp[0]].append(v)
				else:
					uniquevvs[pvs_tmp[0]] = [v]
			allvvs[v] = pvs_tmp

		variablepvs = {'uniquepackages': uniquevvs, 'allvariables': allvvs}
		variablepvs['packages'] = {}
		variablepvs['versionresults'] = {}
		for package in uniquevvs:
			variablepvs['versionresults'][package] = []

			variablepvs['packages'][package] = []

	return (dynamicRes, variablepvs)

## match identifiers with data in the database
## First match string literals, then function names and variable names for various languages
def lookup_identifier(scanqueue, reportqueue, stringcursor, stringconn, funccursor, funcconn, batdb, scanenv, topleveldir, avgscores, clones, scandebug):
	## first some things that are shared between all scans
	if 'BAT_STRING_CUTOFF' in scanenv:
		try:
			stringcutoff = int(scanenv['BAT_STRING_CUTOFF'])
		except:
			stringcutoff = 5
	else:
		stringcutoff = 5

	## TODO: this should be done per language
	if 'BAT_SCORE_CACHE' in scanenv:
		precomputescore = True
	else:
		precomputescore = False

	usesourceorder = False
	if 'USE_SOURCE_ORDER' in scanenv:
		usesourceorder = True
		## don't use precomputed scores when using source order
		precomputescore = False

	## default parameters for scoring
	alpha = 5.0
	scorecutoff = 1.0e-20
	gaincutoff = 1

	kernelquery = batdb.getQuery("select package FROM linuxkernelfunctionnamecache WHERE functionname=%s LIMIT 1")
	precomputequery = batdb.getQuery("select score from scores where stringidentifier=%s LIMIT 1")

	while True:
		## get a new task from the queue
		(filehash, filename) = scanqueue.get(timeout=2592000)

		## read the pickle with the data
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()
		if not 'identifier' in leafreports:
			## If there is no relevant data to scan continue to the next file
			scanqueue.task_done()
			continue

		if leafreports['identifier'] == {}:
			## If there is no relevant data to scan continue to the next file
			scanqueue.task_done()
			continue

		## grab the lines extracted earlier
		lines = leafreports['identifier']['strings']

		language = leafreports['identifier']['language']

		## this should of course not happen, but hey...
		scanlines = True
		if not scanenv.has_key(stringsdbperlanguageenv[language]):
			scanlines = False

		if lines == None:
			lenlines = 0
			scanlines = False
		else:
			lenlines = len(lines)

		linuxkernel = False
		scankernelfunctions = False
		if 'linuxkernel' in leafreports['tags']:
			linuxkernel = True
			if scanenv.get('BAT_KERNELFUNCTION_SCAN') == 1 and language == 'C':
				scankernelfunctions = True

		## first compute the score for the lines
		if lenlines != 0 and scanlines:
			## keep a dict of versions, license and copyright statements per package. TODO: remove these.
			packageversions = {}
			packagelicenses = {}
			packagecopyrights = {}

			if have_counter:
				linecount = collections.Counter(lines)
			else:
				linecount = {}
				for l in lines:
					if l in linecount:
						linecount[l] += 1
					else:
						linecount[l] = 1

			## first look up and assign strings for as far as possible.
			## strings that have not been assigned will be assigned later based
			## on their score.
			## Look up strings in the database and assign strings to packages.
			uniqueMatches = {}
			nonUniqueScore = {}
			stringsLeft = {}
			sameFileScore = {}
			nonUniqueMatches = {}
			nonUniqueMatchLines = []
			nonUniqueAssignments = {}
			directAssignedString = {}
			unmatched = []
			unmatchedignorecache = set()

			kernelfuncres = []
			kernelparamres = []

			if scandebug:
				print >>sys.stderr, "total extracted strings for %s: %d" % (filename, lenlines)

			## some counters for keeping track of how many matches there are
			matchedlines = 0
			unmatchedlines = 0
			matchednotclonelines = 0
			matchednonassignedlines = 0
			matcheddirectassignedlines = 0
			nrUniqueMatches = 0

			## start values for some state variables that are used
			## most of these are only used if 'usesourceorder' == False
			matched = False
			matchednonassigned = False
			matchednotclones = False
			kernelfunctionmatched = False
			uniquematch = False
			oldline = None
			notclones = []

			if usesourceorder:
				## keep track of which package was the most uniquely matched package
				uniquepackage_tmp = None
				uniquefilenames_tmp = []

				## keep a backlog for strings that could possibly be assigned later
				backlog = []
				notclonesbacklog = []
			else:
				## sort the lines first, so it is easy to skip duplicates
				lines.sort()

			stringquery = batdb.getQuery("select package, filename FROM %s WHERE stringidentifier=" % stringsdbperlanguagetable[language] + "%s")

			for line in lines:
				#if scandebug:
				#	print >>sys.stderr, "processing <|%s|>" % line
				kernelfunctionmatched = False

				if not usesourceorder:
					## speedup if the line happens to be the same as the old one
					## This does *not* alter the score in any way, but perhaps
					## it should: having a very significant string a few times
					## is a strong indication.
					if line == oldline:
						if matched:
							matchedlines += 1
							if uniquematch:
								nrUniqueMatches += 1
								#uniqueMatches[package].append((line, []))
						elif matchednonassigned:
							linecount[line] = linecount[line] - 1
							matchednonassignedlines += 1
						elif matchednotclones:
							linecount[line] = linecount[line] - 1
							matchednotclonelines += 1
						else:
							unmatchedlines += 1
							linecount[line] = linecount[line] - 1
						continue
					uniquematch = False
					matched = False
					matchednonassigned = False
					matchednotclones = False
					oldline = line

				## skip empty lines (only triggered if stringcutoff == 0)
				if line == "":
					continue

				## An extra check for lines that score extremely low. This
				## helps reduce load on databases stored on slower disks. Only used if
				## precomputescore is set and "source order" is False.
				if precomputescore:
					stringcursor.execute(precomputequery, (line,))
					scoreres = stringcursor.fetchone()
					stringconn.commit()
					if scoreres != None:
						## If the score is so low it will not have any influence on the final
						## score, why even bother hitting the disk?
						## Since there might be package rewrites this should be a bit less than the
						## cut off value that was defined.
						if scoreres[0] < scorecutoff/100:
							nonUniqueMatchLines.append(line)
							matchednonassignedlines += 1
							matchednonassigned = True
							linecount[line] = linecount[line] - 1
							continue

				if line in unmatchedignorecache:
					unmatched.append(line)
					unmatchedlines += 1
					linecount[line] = linecount[line] - 1
					continue

				## if scoreres is None the line could still be something else like a kernel function, or a
				## kernel string in a different format, so keep searching.
				## If the image is a Linux kernel image first try Linux kernel specific matching
				## like function names, then continue as normal.

				if linuxkernel:
					## This is where things get a bit ugly. The strings in a Linux
					## kernel image could also be function names, not string constants.
					## There could be false positives here...
					if scankernelfunctions:
						funccursor.execute(kernelquery, (line,))
						kernelres = funccursor.fetchall()
						funcconn.commit()
						if len(kernelres) != 0:
							kernelfuncres.append(line)
							kernelfunctionmatched = True
							linecount[line] = linecount[line] - 1
							continue

				## then see if there is anything in the cache at all
				stringcursor.execute(stringquery, (line,))
				res = stringcursor.fetchall()
				stringconn.commit()

				if len(res) == 0 and linuxkernel:
					origline = line
					## try a few variants that could occur in the Linux kernel
					## The values of KERN_ERR and friends have changed in the years.
					## In 2.6 it used to be for example <3> (defined in include/linux/kernel.h
					## or include/linux/printk.h )
					## In later kernels this was changed.
					matchres = reerrorlevel.match(line)
					if matchres != None:
						scanline = line.split('>', 1)[1]
						if len(scanline) < stringcutoff:
							unmatched.append(line)
							unmatchedlines += 1
							linecount[line] = linecount[line] - 1
							continue
						stringcursor.execute(stringquery, (scanline,))
						res = stringcursor.fetchall()
						stringconn.commit()
						if len(res) != 0:
							line = scanline
						else:
							scanline = scanline.split(':', 1)
							if len(scanline) > 1:
								scanline = scanline[1]
								if scanline.startswith(" "):
									scanline = scanline[1:]
								if len(scanline) < stringcutoff:
									unmatched.append(line)
									unmatchedlines += 1
									linecount[line] = linecount[line] - 1
									unmatchedignorecache.add(origline)
									continue
								stringcursor.execute(stringquery, (scanline,))
								res = stringcursor.fetchall()
								stringconn.commit()
								if len(res) != 0:
									if len(scanline) != 0:
										line = scanline
					else:
						## In include/linux/kern_levels.h since kernel 3.6 a different format is
						## used. TODO: actually check in the binary whether or not a match (if any)
						## is preceded by 0x01
						matchres = rematch.match(line)
						if matchres != None:
							scanline = line[1:]
							if len(scanline) < stringcutoff:
								unmatched.append(line)
								unmatchedlines += 1
								linecount[line] = linecount[line] - 1
								unmatchedignorecache.add(origline)
								continue
							stringcursor.execute(stringquery, (scanline,))
							res = stringcursor.fetchall()
							stringconn.commit()
							if len(res) != 0:
								if len(scanline) != 0:
									line = scanline

						if len(res) == 0:
							scanline = line.split(':', 1)
							if len(scanline) > 1:
								scanline = scanline[1]
								if scanline.startswith(" "):
									scanline = scanline[1:]
								if len(scanline) < stringcutoff:
									unmatched.append(line)
									unmatchedlines += 1
									linecount[line] = linecount[line] - 1
									unmatchedignorecache.add(origline)
									continue
								stringcursor.execute(stringquery, (scanline,))
								res = stringcursor.fetchall()
								stringconn.commit()
								if len(res) != 0:
									if len(scanline) != 0:
										line = scanline

					## result is still empty, perhaps it is a module parameter. TODO
					if len(res) == 0:
						if '.' in line:
							if line.count('.') == 1:
								paramres = reparam.match(line)
								if paramres != None:
									pass

					## if 'line' has been changed, then linecount should be changed accordingly
					if line != origline:
						linecount[origline] = linecount[origline] - 1
						if line in linecount:
							linecount[line] = linecount[line] + 1
						else:
							linecount[line] = 1

				## nothing in the cache
				if len(res) == 0:
					unmatched.append(line)
					unmatchedlines += 1
					linecount[line] = linecount[line] - 1
					unmatchedignorecache.add(line)
					continue
				if len(res) != 0:
					## Assume:
					## * database has no duplicates
					## * filenames in the database have been processed using os.path.basename()

					if scandebug:
						print >>sys.stderr, "\n%d matches found for <(|%s|)> in %s" % (len(res), line, filename)

					pkgs = {}    ## {package name: set([filenames without path])}
	
					filenames = {}

					## For each string determine in how many packages (without version) the string
					## is found.
					## If the string is only found in one package the string is unique to the package
					## so record it as such and add its length to a score.
					for result in res:
						(package, sourcefilename) = result
						if package in clones:
							package = clones[package]
						if not package in pkgs:
							pkgs[package] = set([sourcefilename])
						else:
							pkgs[package].add(sourcefilename)
						if not sourcefilename in filenames:
							filenames[sourcefilename] = [package]
						else:
							filenames[sourcefilename] = list(set(filenames[sourcefilename] + [package]))

					if len(pkgs) != 1:
						nonUniqueMatchLines.append(line)
						## The string found is not unique to a package, but is it 
						## unique to a filename?
						## This method assumes that files that are named the same
						## also contain the same or similar content. This could lead
						## to incorrect results.

						## now determine the score for the string
						try:
							score = len(line) / pow(alpha, (len(filenames) - 1))
						except Exception, e:
							## pow(alpha, (len(filenames) - 1)) is overflowing here
							## so the score would be very close to 0. The largest value
							## is sys.maxint, so use that one. The score will be
							## smaller than almost any value of scorecutoff...
							if usesourceorder:
								score = len(line) / sys.maxint
							else:
								matchednonassigned = True
								matchednonassignedlines += 1
								linecount[line] = linecount[line] - 1
								continue

						## if it is assumed that the compiler puts string constants in the
						## same order in the generated code then strings can be assigned
						## to the package directly
						if usesourceorder:
							if uniquepackage_tmp in pkgs:
								assign_string = False
								assign_filename = None
								for pf in uniquefilenames_tmp:
									if pf in pkgs[uniquepackage_tmp]:
										assign_string = True
										assign_filename = pf
										break
								if assign_string:
									if not nonUniqueMatches.has_key(uniquepackage_tmp):
										nonUniqueMatches[uniquepackage_tmp] = [line]
									else:
										nonUniqueMatches[uniquepackage_tmp].append(line)
									if directAssignedString.has_key(uniquepackage_tmp):
										directAssignedString[uniquepackage_tmp].append((line, assign_filename, score))
									else:
										directAssignedString[uniquepackage_tmp] = [(line, assign_filename, score)]
									matcheddirectassignedlines += 1
									nonUniqueAssignments[uniquepackage_tmp] = nonUniqueAssignments.get(uniquepackage_tmp,0) + 1

									matchedlines += 1
									linecount[line] = linecount[line] - 1
									continue
								else:
									## store pkgs and line for backward lookups
									backlog.append((line, pkgs[uniquepackage_tmp], score))

						if not score > scorecutoff:
							matchednonassigned = True
							matchednonassignedlines += 1
							if not usesourceorder:
								linecount[line] = linecount[line] - 1
							continue

						## After having computed a score determine if the files
						## the string was found in in are all called the same.
						## filenames {name of file: { name of package: 1} }
						if filter(lambda x: len(filenames[x]) != 1, filenames.keys()) == []:
							matchednotclonelines += 1
							for fn in filenames:
								## The filename fn containing the matched string can only
								## be found in one package.
								## For example: string 'foobar' is present in 'foo.c' in package 'foo'
								## and 'bar.c' in package 'bar', but not in 'foo.c' in package 'bar'
								## or 'bar.c' in foo (if any).
								fnkey = filenames[fn][0]
								nonUniqueScore[fnkey] = nonUniqueScore.get(fnkey,0) + score
							matchednotclones = True
							if not usesourceorder:
								linecount[line] = linecount[line] - 1
								notclones.append((line, filenames))
							else:
								notclonesbacklog.append((line, filenames))
							continue
						else:
							for fn in filenames:
								## There are multiple packages in which the same
								## filename contains this string, for example 'foo.c'
								## in packages 'foo' and 'bar. This is likely to be
								## internal cloning in the repo.  This string is
								## assigned to a single package in the loop below.
								## Some strings will not signficantly contribute to the score, so they
								## could be ignored and not added to the list.
								## For now exclude them, but in the future they could be included for
								## completeness.
								stringsLeft['%s\t%s' % (line, fn)] = {'string': line, 'score': score, 'filename': fn, 'pkgs' : filenames[fn]}
								## lookup

					else:
						## the string is unique to this package and this package only
						uniquematch = True
						## store the uniqueMatches without any information about checksums
						if not package in uniqueMatches:
							uniqueMatches[package] = [(line, [])]
						else:
							uniqueMatches[package].append((line, []))
						linecount[line] = linecount[line] - 1
						if usesourceorder:
							uniquepackage_tmp = package
							uniquefilenames_tmp = pkgs[package]
							## process backlog
							for b in xrange(len(backlog), 0, -1):
								assign_string = False
								assign_filename = None
								(backlogline, backlogfilenames, backlogscore) = backlog[b-1]
								for pf in uniquefilenames_tmp:
									if pf in backlogfilenames:
										assign_string = True
										assign_filename = pf
										break
								if assign_string:
									## keep track of the old score in case it is changed/recomputed here
									oldbacklogscore = backlogscore
									if not nonUniqueMatches.has_key(uniquepackage_tmp):
										nonUniqueMatches[uniquepackage_tmp] = [backlogline]
									else:
										nonUniqueMatches[uniquepackage_tmp].append(backlogline)
									if directAssignedString.has_key(uniquepackage_tmp):
										directAssignedString[uniquepackage_tmp].append((backlogline, assign_filename, backlogscore))
									else:
										directAssignedString[uniquepackage_tmp] = [(backlogline, assign_filename, backlogscore)]
									matcheddirectassignedlines += 1
									nonUniqueAssignments[uniquepackage_tmp] = nonUniqueAssignments.get(uniquepackage_tmp,0) + 1
									## remove the directly assigned string from stringsLeft,
									## at least for *this* package
									try:
										for pf in backlogfilenames:
											del stringsLeft['%s\t%s' % (backlogline, pf)]
									except KeyError, e:
										pass
									## decrease matchednonassigned if the originally computed score
									## is too low
									if not oldbacklogscore > scorecutoff:
										matchednonassigned = matchednonassigned - 1
									linecount[backlogline] = linecount[backlogline] - 1
									for cl in notclonesbacklog:
										(notclone, filenames) = cl
										if notclone == backlogline:
											matchednotclonelines -= 1
											for fn in filenames:
												fnkey = filenames[fn][0]
												nonUniqueScore[fnkey] = nonUniqueScore.get(fnkey) - backlogscore
											notclonesbacklog.remove(cl)
											break
								else:
									break
							## store notclones for later use
							notclones += notclonesbacklog
							backlog = []
							notclonesbacklog = []
					matched = True

					## for statistics it's nice to see how many lines were matched
					matchedlines += 1

			## clean up stringsLeft first
			for l in stringsLeft.keys():
				if linecount[stringsLeft[l]['string']] == 0:
					del stringsLeft[l]
			## done looking up and assigning all the strings

			uniqueScore = {}
			for package in uniqueMatches:
				if not package in uniqueScore:
					uniqueScore[package] = 0
				for line in uniqueMatches[package]:
					uniqueScore[package] += len(line[0])

			directAssignedScore = {}
			for package in directAssignedString:
				if not package in directAssignedScore:
					directAssignedScore[package] = 0
				for line in directAssignedString[package]:
					directAssignedScore[package] += line[2]

			## If the string is not unique, do a little bit more work to determine which
			## file is the most likely, so also record the filename.
			##
			## 1. determine whether the string is unique to a package
			## 2. if not, determine which filenames the string is in
			## 3. for each filename, determine whether or not this file (containing the string)
			##    is unique to a package
			## 4. if not, try to determine the most likely package the string was found in

			## For each string that occurs in the same filename in multiple
			## packages (e.g., "debugXML.c", a cloned file of libxml2 in several
			## packages), assign it to one package.  We do this by picking the
			## package that would gain the highest score increment across all
			## strings that are left.  This is repeated until no strings are left.
			pkgsScorePerString = {}
			for stri in stringsLeft:
				pkgsSortedTmp = map(lambda x: {'package': x, 'uniquescore': uniqueScore.get(x, 0)}, stringsLeft[stri]['pkgs'])

				## get the unique score per package and sort in reverse order
				pkgsSorted = sorted(pkgsSortedTmp, key=lambda x: x['uniquescore'], reverse=True)
				## and get rid of the unique scores again. Now it's sorted.
				pkgsSorted = map(lambda x: x['package'], pkgsSorted)
				pkgs2 = []

				for pkgSort in pkgsSorted:
					if uniqueScore.get(pkgSort, 0) == uniqueScore.get(pkgsSorted[0], 0):
						pkgs2.append(pkgSort)
				pkgsScorePerString[stri] = pkgs2

			newgain = {}
			for stri in stringsLeft:
				for p2 in pkgsScorePerString[stri]:
					newgain[p2] = newgain.get(p2, 0) + stringsLeft[stri]['score']

			useless_packages = set()
			for p in newgain.keys():
				## check if packages could ever contribute usefully.
				if newgain[p] < gaincutoff:
					useless_packages.add(p)

			## walk through the data again, filter out useless stuff
			new_stringsleft = {}

			string_split = {}

			for stri in stringsLeft:
				## filter out the strings that only occur in packages that will contribute
				## to the score. Ignore the rest.
				if filter(lambda x: x not in useless_packages, pkgsScorePerString[stri]) != []:
					new_stringsleft[stri] = stringsLeft[stri]
					strsplit = stri.rsplit('\t', 1)[0]
					if strsplit in string_split:
						string_split[strsplit].add(stri)
					else:
						string_split[strsplit] = set([stri])

			## the difference between stringsLeft and new_stringsleft is matched
			## but unassigned if the strings *only* occur in stringsLeft
			oldstrleft = set()
			for i in stringsLeft:
				oldstrleft.add(stringsLeft[i]['string'])
			for i in oldstrleft.difference(set(string_split.keys())):
				matchednonassignedlines += linecount[i]
				matchedlines -= linecount[i]

			stringsLeft = new_stringsleft

			roundNr = 0
			strleft = len(stringsLeft)

			## keep track of which strings were already found. This is because each string
			## is only considered once anyway.
			while strleft > 0:
				roundNr = roundNr + 1
				#if scandebug:
				#	print >>sys.stderr, "\nround %d: %d strings left" % (roundNr, strleft)
				gain = {}
				stringsPerPkg = {}

				## cleanup
				if roundNr != 0:
					todelete = set()
					for stri in stringsLeft:
						if linecount[stringsLeft[stri]['string']] == 0:
							todelete.add(stri)

					for a in todelete:
						del stringsLeft[a]

				oldstrleft = set()
				for i in stringsLeft:
					oldstrleft.add(stringsLeft[i]['string'])

				## Determine to which packages the remaining strings belong.
				newstrleft = set()
				for stri in stringsLeft:
					for p2 in pkgsScorePerString[stri]:
						if p2 in useless_packages:
							continue
						gain[p2] = gain.get(p2, 0) + stringsLeft[stri]['score']
						if not p2 in stringsPerPkg:
							stringsPerPkg[p2] = []
						stringsPerPkg[p2].append(stri)
						newstrleft.add(stringsLeft[stri]['string'])

				for i in oldstrleft.difference(newstrleft):
					if linecount[i] == 0:
						continue
					matchednonassignedlines += 1
					matchedlines -= 1
					linecount[i] -= 1

				for p2 in gain.keys():
					## check if packages could ever contribute usefully.
					if gain[p2] < gaincutoff:
						useless_packages.add(p2)

				## gain_sorted contains the sort order, gain contains the actual data
				gain_sorted = sorted(gain, key = lambda x: gain.__getitem__(x), reverse=True)
				if gain_sorted == []:
					break

				## so far value is the best, but that might change
				best = gain_sorted[0]

				## Possible optimisation: skip the last step if the gain is not high enough
				if filter(lambda x: x[1] > gaincutoff, gain.items()) == []:
					break

				## if multiple packages have a big enough gain, add them to 'close'
				## and 'fight' to see which package is the most likely hit.
				close = filter(lambda x: gain[x] > (gain[best] * 0.9), gain_sorted)

       				## Let's hope "sort" terminates on a comparison function that
       				## may not actually be a proper ordering.	
				if len(close) > 1:
					#if scandebug:
					#	print >>sys.stderr, "  doing battle royale between", close
					## reverse sort close, then best = close_sorted[0][0]
					close_sorted = map(lambda x: (x, avgscores[language][x]), close)
					close_sorted = sorted(close_sorted, key = lambda x: x[1], reverse=True)
					## If we don't have a unique score *at all* it is likely that everything
					## is cloned. There could be a few reasons:
					## 1. there are duplicates in the database due to renaming
					## 2. package A is completely contained in package B (bundling).
					## If there are no hits for package B, it is more likely we are
					## actually seeing package A.
					if uniqueScore == {}:
						best = close_sorted[-1][0]
					else:
						best = close_sorted[0][0]
					#if scandebug:
					#	print >>sys.stderr, "  %s won" % best
				best_score = 0
				## for each string in the package with the best gain add the score
				## to the package and move on to the next package.
				todelete = set()
				for xy in stringsPerPkg[best]:
					x = stringsLeft[xy]
					strsplit = xy.rsplit('\t', 1)[0]
					if linecount[strsplit] == 0:
						## is this correct here? There are situations where one
						## string appears multiple times in a single source file
						## and also the binary (eapol_sm.c in hostapd 0.3.9 contains
						## the string "%s    state=%s" several times and binaries
						## do too.
						todelete.add(strsplit)
						continue
					sameFileScore[best] = sameFileScore.get(best, 0) + x['score']
					best_score += 1
					linecount[strsplit] = linecount[strsplit] - 1
					if best in nonUniqueMatches:
						nonUniqueMatches[best].append(strsplit)
					else:
						nonUniqueMatches[best]  = [strsplit]

				for a in todelete:
					for st in string_split[a]:
						del stringsLeft[st]
				## store how many non unique strings were assigned per package
				nonUniqueAssignments[best] = nonUniqueAssignments.get(best,0) + best_score
				if gain[best] < gaincutoff:
					break
				strleft = len(stringsLeft)

			for i in stringsLeft:
				strsplit = i.rsplit('\t', 1)[0]
				if linecount[strsplit] == 0:
					continue
				matchednonassignedlines += 1
				matchedlines -= 1
				linecount[strsplit] -= 1

			scores = {}
			for k in set(uniqueScore.keys() + sameFileScore.keys()):
				scores[k] = uniqueScore.get(k, 0) + sameFileScore.get(k, 0) + nonUniqueScore.get(k,0) + directAssignedScore.get(k,0)
			scores_sorted = sorted(scores, key = lambda x: scores.__getitem__(x), reverse=True)

			rank = 1
			reports = []
			if scores == {}:
				totalscore = 0.0
			else:
				totalscore = float(reduce(lambda x, y: x + y, scores.values()))

			for s in scores_sorted:
				try:
					percentage = (scores[s]/totalscore)*100.0
				except:
					percentage = 0.0
				reports.append((rank, s, uniqueMatches.get(s,[]), len(uniqueMatches.get(s,[])), percentage, packageversions.get(s, {}), packagelicenses.get(s, []), packagecopyrights.get(s,[])))
				rank = rank+1

			if matchedlines == 0 and unmatched == []:
				res = None
			else:
				if scankernelfunctions:
					matchedlines = matchedlines - len(kernelfuncres)
					lenlines = lenlines - len(kernelfuncres)
				res = {'matchedlines': matchedlines, 'extractedlines': lenlines, 'reports': reports, 'nonUniqueMatches': nonUniqueMatches, 'nonUniqueAssignments': nonUniqueAssignments, 'unmatched': unmatched, 'scores': scores, 'unmatchedlines': unmatchedlines, 'matchednonassignedlines': matchednonassignedlines, 'matchednotclonelines': matchednotclonelines, 'matcheddirectassignedlines': matcheddirectassignedlines}
		else:
			res = None

		## then look up results for function names, variable names, and so on.
		if language == 'C':
			if linuxkernel:
				functionRes = {}
				if scanenv.has_key('BAT_KERNELSYMBOL_SCAN'):
					kernelquery = batdb.getQuery("select distinct package from linuxkernelnamecache where varname=%s")
					variablepvs = scankernelsymbols(leafreports['identifier']['kernelsymbols'], scanenv, kernelquery, funccursor, funcconn, clones)
				## TODO: clean up
				if leafreports['identifier'].has_key('kernelfunctions'):
					if leafreports['identifier']['kernelfunctions'] != []:
						functionRes['kernelfunctions'] = copy.deepcopy(leafreports['identifier']['kernelfunctions'])
			else:
				(functionRes, variablepvs) = scanDynamic(leafreports['identifier']['functionnames'], leafreports['identifier']['variablenames'], scanenv, funccursor, funcconn, batdb, clones)
		elif language == 'Java':
			if not scanenv.has_key(namecacheperlanguageenv['Java']):
				variablepvs = {}
				functionRes = {}
			else:
				(functionRes, variablepvs) = extractJava(leafreports['identifier'], scanenv, funccursor, funcconn, batdb, clones)
		else:
			variablepvs = {}
			functionRes = {}

		## then write results back to disk. This needs to be done because results for
		## Java might need to be aggregated first.
		leafreports['ranking'] = (res, functionRes, variablepvs, language)
		leafreports['tags'].append('ranking')
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
		leafreports = cPickle.dump(leafreports, leaf_file)
		leaf_file.close()
		reportqueue.put(filehash)
		scanqueue.task_done()

## determine the most likely versions for each of the scanned binaries
## Currently finding the version is based on unique matches that were found.
## If determinelicense or determinecopyright are set licenses and copyright statements
## are also extracted.
def compute_version(processors, scanenv, unpackreports, rankingfiles, topleveldir, determinelicense, determinecopyright, batdb):
	masterdb = scanenv.get('BAT_DB')
	if determinelicense or determinecopyright:
		licensedb = scanenv.get('BAT_LICENSE_DB')

	pruning = False
	if scanenv.has_key('BAT_KEEP_VERSIONS'):
		keepversions = int(scanenv.get('BAT_KEEP_VERSIONS', 0))
		if keepversions > 0:
			## there need to be a minimum of unique hits (like strings), otherwise
			## it's silly
			if scanenv.has_key('BAT_MINIMUM_UNIQUE'):
				minimumunique = int(scanenv.get('BAT_MINIMUM_UNIQUE', 0))
				if minimumunique > 0:
					pruning = True
	if processors == None:
		processors = multiprocessing.cpu_count()

	if processors == None:
		processamount = 1
	else:
		processamount = processors

	batcons = []
	batcursors = []

	licensecons = []
	licensecursors = []

	for i in range(0,processamount):
		c = batdb.getConnection(scanenv['BAT_DB'],scanenv)
		cursor = c.cursor()
		batcursors.append(cursor)
		batcons.append(c)

	if determinelicense or determinecopyright:
		for i in range(0,processamount):
			c = batdb.getConnection(licensedb,scanenv)
			cursor = c.cursor()
			licensecursors.append(cursor)
			licensecons.append(c)

	scanmanager = multiprocessing.Manager()

	sha256_filename_query = batdb.getQuery("select version, pathname from processed_file where checksum=%s")
	sha256_license_query = batdb.getQuery("select distinct license, scanner from licenses where checksum=%s")
	sha256_copyright_query = batdb.getQuery("select distinct copyright, type from extracted_copyright where checksum=%s")

	rankingfilesperlanguage = {}
	for rankingfile in rankingfiles:
		unpackreport = unpackreports[rankingfile]
		## read the pickle
		filehash = unpackreport['checksum']
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()
		if not 'ranking' in leafreports:
			continue

		(res, functionRes, variablepvs, language) = leafreports['ranking']
		if not language in rankingfilesperlanguage:
			rankingfilesperlanguage[language] = set([rankingfile])
		else:
			rankingfilesperlanguage[language].add(rankingfile)

	for l in rankingfilesperlanguage:
		for rankingfile in rankingfilesperlanguage[l]:
			unpackreport = unpackreports[rankingfile]
			## read the pickle
			filehash = unpackreport['checksum']
			leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
			leafreports = cPickle.load(leaf_file)
			leaf_file.close()

			(res, functionRes, variablepvs, language) = leafreports['ranking']

			## indicate whether or not the pickle should be written back to disk.
			## If uniquematches is empty, functionRes is empty, and variablepvs
			## is also empty, then nothing needs to be written.
			changed = False

			if res == None and functionRes == {} and variablepvs == {}:
				continue

			## keep a list of versions per sha256, since source files often are in more than one version
			sha256_versions = {}

			## First process all the string identifiers
			if res != None:
				newreports = []

				for r in res['reports']:
					(rank, package, unique, uniquematcheslen, percentage, packageversions, packagelicenses, packagecopyrights) = r
					if unique == []:
						## Continue to the next item if there are no unique matches
						newreports.append(r)
						continue

					## There are unique matches, so results should
					## be written back to disk
					changed = True
					newuniques = []
					newpackageversions = {}
					packagecopyrights = []
					packagelicenses = []
					uniques = set(map(lambda x: x[0], unique))
					lenuniques = len(uniques)

					## first grab all possible checksums, plus associated line numbers
					## for this string. Since these are unique strings they will only be
					## present in the package (or clones of the package).
					processpool = []
					vsha256s = []

					scanqueue = multiprocessing.JoinableQueue(maxsize=0)
					reportqueue = scanmanager.Queue(maxsize=0)

					map(lambda x: scanqueue.put(x), uniques)

					minprocessamount = min(len(uniques), processamount)

					for i in range(0,minprocessamount):
						p = multiprocessing.Process(target=grab_sha256_parallel, args=(scanqueue,reportqueue,batcursors[i], batcons[i], batdb, language, 'string'))
						processpool.append(p)
						p.start()

        				scanqueue.join()

					while True:
						try:
							val = reportqueue.get_nowait()
							vsha256s.append(val)
							reportqueue.task_done()
						except Queue.Empty, e:
							## Queue is empty
							break
					reportqueue.join()

					for p in processpool:
						p.terminate()

					## for each combination (line,sha256,linenumber) store per checksum
					## the line and linenumber(s). The checksums are used to look up version
					## and filename information.
					sha256_scan_versions = {}

					for l in vsha256s:
						(line, versionsha256s) = l
						for s in versionsha256s:
							(checksum, linenumber) = s
							if not checksum in sha256_versions:
								if checksum in sha256_scan_versions:
									sha256_scan_versions[checksum].add((line, linenumber))
								else:
									sha256_scan_versions[checksum] = set([(line, linenumber)])

					processpool = []
					fileres = []

					scanqueue = multiprocessing.JoinableQueue(maxsize=0)
					reportqueue = scanmanager.Queue(maxsize=0)

					map(lambda x: scanqueue.put(x), sha256_scan_versions.keys())

					minprocessamount = min(len(sha256_scan_versions.keys()), processamount)

					for i in range(0,minprocessamount):
						p = multiprocessing.Process(target=grab_sha256_filename, args=(scanqueue,reportqueue,batcursors[i], batcons[i], sha256_filename_query))
						processpool.append(p)
						p.start()

        				scanqueue.join()

					while True:
						try:
							val = reportqueue.get_nowait()
							fileres.append(val)
							reportqueue.task_done()
						except Queue.Empty, e:
							## Queue is empty
							break
					reportqueue.join()

					for p in processpool:
						p.terminate()

					resdict = {}
					map(lambda x: resdict.update(x), fileres)

					tmplines = {}
					## construct the full information needed by other scans
					for checksum in resdict:
						versres = resdict[checksum]
						for l in sha256_scan_versions[checksum]:
							(line, linenumber) = l
							if not line in tmplines:
								tmplines[line] = []
							## TODO: store (checksum, linenumber(s), versres)
							tmplines[line].append((checksum, linenumber, versres))
						for v in versres:
							(version, filename) = v
							if checksum in sha256_versions:
								sha256_versions[checksum].append((version, filename))
							else:
								sha256_versions[checksum] = [(version, filename)]
					for l in tmplines.keys():
						newuniques.append((l, tmplines[l]))

					## optionally prune version information
					if pruning:
						if len(newuniques) > minimumunique:
							newuniques = prune(newuniques, package)

					## optionally fill two lists with sha256 for license schanning and copyright scanning
					licensesha256s = []
					copyrightsha256s = []

					for u in newuniques:
						versionsha256s = u[1]
						vseen = set()
						if determinelicense:
							licensesha256s += map(lambda x: x[0], versionsha256s)
						if determinecopyright:
							copyrightsha256s += map(lambda x: x[0], versionsha256s)
						for s in versionsha256s:
							(checksum, linenumber, versionfilenames) = s
							for v in versionfilenames:
								(version, filename) = v
								if version in vseen:
									continue
								if version in newpackageversions:
									newpackageversions[version] = newpackageversions[version] + 1
								else:   
									newpackageversions[version] = 1
								vseen.add(version)

					## Ideally the version number should be stored with the license.
					## There are good reasons for this: files are sometimes collectively
					## relicensed when there is a new release (example: Samba 3.2 relicensed
					## to GPLv3+) so the version number can be very significant for licensing.
					## determinelicense and determinecopyright *always* imply determineversion
					## TODO: store license with version number.
					if determinelicense:
						if len(licensesha256s) != 0:
							licensesha256s = set(licensesha256s)
							processpool = []

							scanqueue = multiprocessing.JoinableQueue(maxsize=0)
							reportqueue = scanmanager.Queue(maxsize=0)

							map(lambda x: scanqueue.put(x), licensesha256s)
							minprocessamount = min(len(licensesha256s), processamount)

							for i in range(0,minprocessamount):
								p = multiprocessing.Process(target=grab_sha256_license, args=(scanqueue,reportqueue,licensecursors[i], licensecons[i], sha256_license_query))
								processpool.append(p)
								p.start()

        						scanqueue.join()

							while True:
								try:
									val = reportqueue.get_nowait()
									packagelicenses.append(val)
									reportqueue.task_done()
								except Queue.Empty, e:
									## Queue is empty
									break
							reportqueue.join()

							for p in processpool:
								p.terminate()

							packagelicenses_tmp = []
							for p in packagelicenses:
								packagelicenses_tmp += reduce(lambda x,y: x + y, p.values(), [])
							packagelicenses = list(set(packagelicenses_tmp))

					if determinecopyright:
						if len(copyrightsha256s) != 0:
							processpool = []

							scanqueue = multiprocessing.JoinableQueue(maxsize=0)
							reportqueue = scanmanager.Queue(maxsize=0)

							map(lambda x: scanqueue.put(x), copyrightsha256s)
							minprocessamount = min(len(copyrightsha256s), processamount)

							for i in range(0,minprocessamount):
								p = multiprocessing.Process(target=grab_sha256_copyright, args=(scanqueue,reportqueue,licensecursors[i], licensecons[i], sha256_copyright_query))
								processpool.append(p)
								p.start()

        						scanqueue.join()

							while True:
								try:
									val = reportqueue.get_nowait()
									packagecopyrights.append(val)
									reportqueue.task_done()
								except Queue.Empty, e:
									## Queue is empty
									break
							reportqueue.join()

							for p in processpool:
								p.terminate()

							## result is a list of {sha256sum: list of copyright statements}
							packagecopyrights_tmp = []
							for p in packagecopyrights:
								packagecopyrights_tmp += reduce(lambda x,y: x + y, p.values(), [])
							packagecopyrights = list(set(packagecopyrights_tmp))
					newreports.append((rank, package, newuniques, uniquematcheslen, percentage, newpackageversions, packagelicenses, packagecopyrights))
				res['reports'] = newreports

			## Then process the results for the function names
			if 'versionresults' in functionRes:

				for package in functionRes['versionresults'].keys():
					if not functionRes.has_key('uniquepackages'):
						continue
					if not functionRes['uniquepackages'].has_key(package):
						continue
					changed = True
					functionnames = functionRes['uniquepackages'][package]

					## right now only C is supported. TODO: fix this for other languages such as Java.
					processpool = []
					vsha256s = []

					scanqueue = multiprocessing.JoinableQueue(maxsize=0)
					reportqueue = scanmanager.Queue(maxsize=0)

					map(lambda x: scanqueue.put(x), functionnames)
					minprocessamount = min(len(functionnames), processamount)

					for i in range(0,minprocessamount):
						p = multiprocessing.Process(target=grab_sha256_parallel, args=(scanqueue,reportqueue,batcursors[i], batcons[i], batdb, 'C', 'function'))
						processpool.append(p)
						p.start()

        				scanqueue.join()

					while True:
						try:
							val = reportqueue.get_nowait()
							vsha256s.append(val)
							reportqueue.task_done()
						except Queue.Empty, e:
							## Queue is empty
							break
					reportqueue.join()

					for p in processpool:
						p.terminate()

					sha256_scan_versions = {}
					tmplines = {}

					for p in vsha256s:
						(functionname, vres) = p
						for s in vres:
							(checksum, linenumber) = s
							if not checksum in sha256_versions:
								if checksum in sha256_scan_versions:
									sha256_scan_versions[checksum].add((functionname, linenumber))
								else:
									sha256_scan_versions[checksum] = set([(functionname, linenumber)])
							else:
								for v in sha256_versions[checksum]:
									(version, filename) = v
									if not functionname in tmplines:
										tmplines[functionname] = []
								tmplines[functionname].append((checksum, linenumber, sha256_versions[checksum]))
					fileres = []
					if len(sha256_scan_versions.keys()) != 0:
						processpool = []

						scanqueue = multiprocessing.JoinableQueue(maxsize=0)
						reportqueue = scanmanager.Queue(maxsize=0)

						map(lambda x: scanqueue.put(x), sha256_scan_versions.keys())
						minprocessamount = min(len(sha256_scan_versions.keys()), processamount)

						for i in range(0,minprocessamount):
							p = multiprocessing.Process(target=grab_sha256_filename, args=(scanqueue,reportqueue,batcursors[i], batcons[i], sha256_filename_query))
							processpool.append(p)
							p.start()

        					scanqueue.join()

						while True:
							try:
								val = reportqueue.get_nowait()
								fileres.append(val)
								reportqueue.task_done()
							except Queue.Empty, e:
								## Queue is empty
								break
						reportqueue.join()

						for p in processpool:
							p.terminate()

					resdict = {}
					map(lambda x: resdict.update(x), fileres)

					## construct the full information needed by other scans
					for checksum in resdict:
						versres = resdict[checksum]
						for l in sha256_scan_versions[checksum]:
							(functionname, linenumber) = l
							if not functionname in tmplines:
								tmplines[functionname] = []
							## TODO: store (checksum, linenumber(s), versres)
							tmplines[functionname].append((checksum, linenumber, versres))
						for v in versres:
							if checksum in sha256_versions:
								sha256_versions[checksum].append((v[0], v[1]))
							else:
								sha256_versions[checksum] = [(v[0], v[1])]
					for l in tmplines.keys():
						functionRes['versionresults'][package].append((l, tmplines[l]))

				newresults = {}
				for package in functionRes['versionresults'].keys():
					newuniques = functionRes['versionresults'][package]
					## optionally prune version information
					if pruning:
						if len(newuniques) > minimumunique:
							newuniques = prune(newuniques, package)

					newresults[package] = newuniques
					uniqueversions = {}
					functionRes['packages'][package] = []
					if have_counter:
						vs = collections.Counter()
					else:
						vs = {}
					for u in newuniques:
						versionsha256s = u[1]
						for s in versionsha256s:
							(checksum, linenumber, versionfilenames) = s
							if have_counter:
								vs.update(set(map(lambda x: x[0], versionfilenames)))
							else:
								for v in set(map(lambda x: x[0], versionfilenames)):
									if v in vs:
										vs[v] += 1
									else:
										vs[v] = 1

					for v in vs:
						functionRes['packages'][package].append((v, vs[v]))
				functionRes['versionresults'] = newresults

			## Then process the results for the variable names
			if variablepvs != {}:
				if language == 'C':
					if 'uniquepackages' in variablepvs:
						if variablepvs['uniquepackages'] != {}:
							changed = True
						for package in variablepvs['uniquepackages']:
							vartype = 'variable'
							if 'type' in variablepvs:
								vartype = 'variable'
								if variablepvs['type'] == 'linuxkernel':
									vartype = 'kernelvariable'
							uniques = variablepvs['uniquepackages'][package]

							processpool = []
							vsha256s = []

							scanqueue = multiprocessing.JoinableQueue(maxsize=0)
							reportqueue = scanmanager.Queue(maxsize=0)

							map(lambda x: scanqueue.put(x), uniques)
							minprocessamount = min(len(uniques), processamount)

							for i in range(0,minprocessamount):
								p = multiprocessing.Process(target=grab_sha256_parallel, args=(scanqueue,reportqueue,batcursors[i], batcons[i], batdb, language, vartype))
								processpool.append(p)
								p.start()

        						scanqueue.join()

							while True:
								try:
									val = reportqueue.get_nowait()
									vsha256s.append(val)
									reportqueue.task_done()
								except Queue.Empty, e:
									## Queue is empty
									break
							reportqueue.join()

							for p in processpool:
								p.terminate()

                        					sha256_scan_versions = {}
                        					tmplines = {}

							for p in vsha256s:
								(variablename, varres) = p
								for s in varres:
									(checksum, linenumber) = s
									if not checksum in sha256_versions:
										if checksum in sha256_scan_versions:
											sha256_scan_versions[checksum].add((variablename, linenumber))
										else:
											sha256_scan_versions[checksum] = set([(variablename, linenumber)])
									else:
										for v in sha256_versions[checksum]:
											(version, filename) = v
											if not variablename in tmplines:
												tmplines[variablename] = []
										tmplines[variablename].append((checksum, linenumber, sha256_versions[checksum]))

							resdict = {}
							if len(sha256_scan_versions.keys()) != 0:
								processpool = []
								fileres = []

								scanqueue = multiprocessing.JoinableQueue(maxsize=0)
								reportqueue = scanmanager.Queue(maxsize=0)

								map(lambda x: scanqueue.put(x), sha256_scan_versions.keys())
								minprocessamount = min(len(sha256_scan_versions.keys()), processamount)

								for i in range(0,minprocessamount):
									p = multiprocessing.Process(target=grab_sha256_filename, args=(scanqueue,reportqueue,batcursors[i], batcons[i], sha256_filename_query))
									processpool.append(p)
									p.start()

        							scanqueue.join()

								while True:
									try:
										val = reportqueue.get_nowait()
										fileres.append(val)
										reportqueue.task_done()
									except Queue.Empty, e:
										## Queue is empty
										break
								reportqueue.join()

								for p in processpool:
									p.terminate()

								map(lambda x: resdict.update(x), fileres)

							## construct the full information needed by other scans
							for checksum in resdict:
								versres = resdict[checksum]
								for l in sha256_scan_versions[checksum]:
									(variablename, linenumber) = l
									if not variablename in tmplines:
										tmplines[variablename] = []
									## TODO: store (checksum, linenumber(s), versres)
									tmplines[variablename].append((checksum, linenumber, versres))
								for v in versres:
									if checksum in sha256_versions:
										sha256_versions[checksum].append((v[0], v[1]))
									else:
										sha256_versions[checksum] = [(v[0], v[1])]
							for l in tmplines.keys():
								variablepvs['versionresults'][package].append((l, tmplines[l]))

						newresults = {}
						for package in variablepvs['versionresults'].keys():
							newuniques = variablepvs['versionresults'][package]
							## optionally prune version information

							if pruning:
								if len(newuniques) > minimumunique:
									newuniques = prune(newuniques, package)

							newresults[package] = newuniques
							uniqueversions = {}
							variablepvs['packages'][package] = []
							if have_counter:
								vs = collections.Counter()
							else:
								vs = {}
							for u in newuniques:
								versionsha256s = u[1]
								for s in versionsha256s:
									(checksum, linenumber, versionfilenames) = s
									if have_counter:
										vs.update(set(map(lambda x: x[0], versionfilenames)))
									else:
										for v in set(map(lambda x: x[0], versionfilenames)):
											if v in vs:
												vs[v] += 1
											else:
												vs[v] = 1

							for v in vs:
								variablepvs['packages'][package].append((v, vs[v]))
						variablepvs['versionresults'] = newresults

			if changed:
				leafreports['ranking'] = (res, functionRes, variablepvs, language)
				leafreports['tags'] = list(set(leafreports['tags'] + ['ranking']))
				leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
				leafreports = cPickle.dump(leafreports, leaf_file)
				leaf_file.close()
				unpackreport['tags'].append('ranking')

	for c in batcons:
		c.close()
	for c in licensecons:
		c.close()

def licensesetup(scanenv, debug=False):
	if not 'DBBACKEND' in scanenv:
		return (False, None)
	if scanenv['DBBACKEND'] == 'sqlite3':
		return licensesetup_sqlite3(scanenv, debug)
	if scanenv['DBBACKEND'] == 'postgresql':
		return licensesetup_postgresql(scanenv, debug)
	return (False, None)

def licensesetup_postgresql(scanenv, debug=False):
	newenv = copy.deepcopy(scanenv)
	batdb = bat.batdb.BatDb('postgresql')
	conn = batdb.getConnection(None,scanenv)
	if conn == None:
		return (False, None)
	conn.commit()
	conn.close()
	newenv['BAT_CLASSNAME_SCAN'] = 1
	newenv['BAT_FIELDNAME_SCAN'] = 1
	newenv['BAT_METHOD_SCAN'] = 1
	newenv['BAT_KERNELSYMBOL_SCAN'] = 1
	newenv['BAT_VARNAME_SCAN'] = 1
	newenv['BAT_FUNCTION_SCAN'] = 1
	newenv['BAT_KERNELFUNCTION_SCAN'] = 1

	return (True, newenv)

## method that makes sure that everything is set up properly and modifies
## the environment, as well as determines whether the scan should be run at
## all.
## Returns tuple (run, environment)
## * run: boolean indicating whether or not the scan should run
## * environment: (possibly) modified
## This is the minimum that is needed for determining the licenses
def licensesetup_sqlite3(scanenv, debug=False):
	newenv = copy.deepcopy(scanenv)

	## Is the master database defined?
	if not scanenv.has_key('BAT_DB'):
		return (False, None)

	masterdb = scanenv.get('BAT_DB')

	## Does the master database exist?
	if not os.path.exists(masterdb):
		return (False, None)

	## Does the master database have the right tables?
	## processed_file is always needed
	batdb = bat.batdb.BatDb('sqlite3')
	conn = batdb.getConnection(masterdb)
	c = conn.cursor()
	res = c.execute("select * from sqlite_master where type='table' and name='processed_file'").fetchall()
	if res == []:
		c.close()
		conn.close()
		return (False, None)

	## extracted_string is needed for string matches
	res = c.execute("select * from sqlite_master where type='table' and name='extracted_string'").fetchall()
	if res == []:
		stringmatches = False
	else:
		stringmatches = True

	## check the license database. If it does not exist, or does not have
	## the right schema remove it from the configuration
	if scanenv.get('BAT_RANKING_LICENSE', 0) == '1' or scanenv.get('BAT_RANKING_COPYRIGHT', 0) == 1:
		if scanenv.get('BAT_LICENSE_DB') != None:
			if not os.path.exists(scanenv.get('BAT_LICENSE_DB')):
				if newenv.has_key('BAT_LICENSE_DB'):
					del newenv['BAT_LICENSE_DB']
				if newenv.has_key('BAT_RANKING_LICENSE'):
					del newenv['BAT_RANKING_LICENSE']
			else:
				try:
					licenseconn = batdb.getConnection(scanenv.get('BAT_LICENSE_DB'))
					licensecursor = licenseconn.cursor()
					licensecursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='licenses';")
					if licensecursor.fetchall() == []:
						if newenv.has_key('BAT_LICENSE_DB'):
							del newenv['BAT_LICENSE_DB']
						if newenv.has_key('BAT_RANKING_LICENSE'):
							del newenv['BAT_RANKING_LICENSE']
					## also check if copyright information exists
					licensecursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='extracted_copyright';")
					if licensecursor.fetchall() == []:
						if newenv.has_key('BAT_RANKING_COPYRIGHT'):
							del newenv['BAT_RANKING_COPYRIGHT']
					licensecursor.close()
					licenseconn.close()
				except:
					if newenv.has_key('BAT_LICENSE_DB'):
						del newenv['BAT_LICENSE_DB']
					if newenv.has_key('BAT_RANKING_LICENSE'):
						del newenv['BAT_RANKING_LICENSE']
					if newenv.has_key('BAT_RANKING_COPYRIGHT'):
						del newenv['BAT_RANKING_COPYRIGHT']
	## cleanup
	c.close()
	conn.close()

	for language in stringsdbperlanguageenv.keys():
		if scanenv.has_key(stringsdbperlanguageenv[language]):
			## sanity checks to see if the database exists.
			stringscache = scanenv.get(stringsdbperlanguageenv[language])
			if not os.path.exists(stringscache):
				## remove from the configuration
				if newenv.has_key(stringsdbperlanguageenv[language]):
					del newenv[stringsdbperlanguageenv[language]]
				continue

			stringscache = scanenv.get(stringsdbperlanguageenv[language])
			conn = batdb.getConnection(stringscache)
			c = conn.cursor()

			## TODO: check if the format of the cache database is sane

			## check if there is a precomputed scores table and if it has any content.
			## TODO: this really has to be done per language
			res = c.execute("select * from sqlite_master where type='table' and name='scores'").fetchall()
			if res != []:
				if not newenv.has_key('BAT_SCORE_CACHE'):
					newenv['BAT_SCORE_CACHE'] = 1
				res = c.execute("select * from scores LIMIT 1")
				if res == []:
					## if there are no precomputed scores remove it again to save queries later
					if newenv.has_key('BAT_SCORE_CACHE'):
						del newenv['BAT_SCORE_CACHE']
			c.close()
			conn.close()
		else:
			## strings cache is not defined, but it should be there according to
			## the configuration so remove from the configuration
			if newenv.has_key(stringsdbperlanguageenv[language]):
				del newenv[stringsdbperlanguageenv[language]]

	## check the cloning database. If it does not exist, or does not have
	## the right schema remove it from the configuration
	if scanenv.has_key('BAT_CLONE_DB'):
		clonedb = scanenv.get('BAT_CLONE_DB')
		if os.path.exists(clonedb):
			conn = batdb.getConnection(clonedb)
			c = conn.cursor()
			c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='renames';")
			if c.fetchall() == []:
				if newenv.has_key('BAT_CLONE_DB'):
					del newenv['BAT_CLONE_DB']
			c.close()
			conn.close()
		else:
			if newenv.has_key('BAT_CLONE_DB'):
				del newenv['BAT_CLONE_DB']

	## check the various caching databases, first for C
	if scanenv.has_key(namecacheperlanguageenv['C']):
		namecache = scanenv.get(namecacheperlanguageenv['C'])
		## the cache should exist. If it doesn't exist then something is horribly wrong.
		if not os.path.exists(namecache):
			if newenv.has_key('BAT_KERNELSYMBOL_SCAN'):
				del newenv['BAT_KERNELSYMBOL_SCAN']
			if newenv.has_key('BAT_KERNELFUNCTION_SCAN'):
				del newenv['BAT_KERNELFUNCTION_SCAN']
			if newenv.has_key('BAT_VARNAME_SCAN'):
				del newenv['BAT_VARNAME_SCAN']
			if newenv.has_key('BAT_FUNCTION_SCAN'):
				del newenv['BAT_FUNCTION_SCAN']
			if newenv.has_key(namecacheperlanguageenv['C']):
				del newenv[namecacheperlanguageenv['C']]
		else:
			## TODO: add checks for each individual table
			if not newenv.has_key('BAT_KERNELSYMBOL_SCAN'):
				newenv['BAT_KERNELSYMBOL_SCAN'] = 1
			if not newenv.has_key('BAT_VARNAME_SCAN'):
				newenv['BAT_VARNAME_SCAN'] = 1
			if not newenv.has_key('BAT_FUNCTION_SCAN'):
				newenv['BAT_FUNCTION_SCAN'] = 1

			## Sanity check for kernel function names
			cacheconn = batdb.getConnection(namecache)
			cachecursor = cacheconn.cursor()
			cachecursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='linuxkernelfunctionnamecache';")
			kernelfuncs = cachecursor.fetchall()
			if kernelfuncs == []:
				if newenv.has_key('BAT_KERNELFUNCTION_SCAN'):
					del newenv['BAT_KERNELFUNCTION_SCAN']
			else:
				if not newenv.has_key('BAT_KERNELFUNCTION_SCAN'):
					newenv['BAT_KERNELFUNCTION_SCAN'] = 1
			cachecursor.close()
			cacheconn.close()
	else:
		## undefined, so disable kernel scanning, variable/function name scanning
		if newenv.has_key('BAT_KERNELSYMBOL_SCAN'):
			del newenv['BAT_KERNELSYMBOL_SCAN']
		if newenv.has_key('BAT_KERNELFUNCTION_SCAN'):
			del newenv['BAT_KERNELFUNCTION_SCAN']
		if newenv.has_key('BAT_VARNAME_SCAN'):
			del newenv['BAT_VARNAME_SCAN']
		if newenv.has_key('BAT_FUNCTION_SCAN'):
			del newenv['BAT_FUNCTION_SCAN']

	## then check for Java
	if scanenv.has_key(namecacheperlanguageenv['Java']):
		namecache = scanenv.get(namecacheperlanguageenv['Java'])
		## check if the cache exists. If not, something is wrong.
		if not os.path.exists(namecache):
			if newenv.has_key('BAT_CLASSNAME_SCAN'):
				del newenv['BAT_CLASSNAME_SCAN']
			if newenv.has_key('BAT_FIELDNAME_SCAN'):
				del newenv['BAT_FIELDNAME_SCAN']
			if newenv.has_key('BAT_METHOD_SCAN'):
				del newenv['BAT_METHOD_SCAN']
			if newenv.has_key(namecacheperlanguageenv['Java']):
				del newenv[namecacheperlanguageenv['Java']]
		else:
			## TODO: add checks for each individual table
			if not newenv.has_key('BAT_CLASSNAME_SCAN'):
				newenv['BAT_CLASSNAME_SCAN'] = 1
			if not newenv.has_key('BAT_FIELDNAME_SCAN'):
				newenv['BAT_FIELDNAME_SCAN'] = 1
			if not newenv.has_key('BAT_METHOD_SCAN'):
				newenv['BAT_METHOD_SCAN'] = 1
	else:
		## undefined, so disable classname/fieldname/method name scan
		if newenv.has_key('BAT_CLASSNAME_SCAN'):
			del newenv['BAT_CLASSNAME_SCAN']
		if newenv.has_key('BAT_FIELDNAME_SCAN'):
			del newenv['BAT_FIELDNAME_SCAN']
		if newenv.has_key('BAT_METHOD_SCAN'):
			del newenv['BAT_METHOD_SCAN']

	## extra sanity check to see if there is at least one entry from
	## stringsdperlanguage and namecacheperlanguageenv in the new environment.
	scanenvkeys = newenv.keys()
	envcheck = set(map(lambda x: x in scanenvkeys, stringsdbperlanguageenv.values() + namecacheperlanguageenv.values()))
	if envcheck == set([False]):
		return (False, None)
	return (True, newenv)
