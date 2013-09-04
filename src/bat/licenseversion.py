#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, multiprocessing, sqlite3

'''
This program can be used to optionally prune results of a scan. Sometimes
results of scans can get very large, for example a scan of a Linux kernel image
could have thousands of string matches, which can each be found in a few
hundred kernel source code archives.

By pruning results the amount of noise can be much reduce, reports can be made
smaller and source code checks using the results of BAT can be made more
efficient.

To remove a version A from the set of versions the following conditions have
to hold:

* there is a minimum amount of results available (20 or 30 seems a good cut off value)

* all strings/variables/function names found in A are found in the most promising
version

* the amount of strings/variables/function names found in A are significantly
smaller than the amount in the most promising version (expressed as a maximum
percentage)
'''

def pruneresults(unpackreports, scantempdir, topleveldir, debug=False, envvars=None):
	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	if not scanenv.has_key('BAT_KEEP_VERSIONS'):
		## keep all versions
		return
	else:
		keepversions = int(scanenv.get('BAT_KEEP_VERSIONS', 0))
		if keepversions <= 0:
			## keep all versions
			return

	if not scanenv.has_key('BAT_KEEP_MAXIMUM_PERCENTAGE'):
		## keep all versions
		return
	else:
		keeppercentage = int(scanenv.get('BAT_KEEP_MAXIMUM_PERCENTAGE', 0))
		if keeppercentage == 0:
			## keep all versions
			return
		if keeppercentage >= 100:
			## keep all versions
			return

	rankingfiles = []

	## ignore files which don't have ranking results
	for i in unpackreports:
		if not unpackreports[i].has_key('sha256'):
			continue
		if not unpackreports[i].has_key('tags'):
			continue
		if not 'ranking' in unpackreports[i]['tags']:
			continue
		filehash = unpackreports[i]['sha256']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		rankingfiles.append(i)

	for i in rankingfiles:
		filehash = unpackreports[i]['sha256']
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()
		if not leafreports.has_key('ranking'):
			continue

		(res, dynamicRes, variablepvs) = leafreports['ranking']

		## first determine for strings
		if res != None:
			if res['reports'] != []:
				for j in res['reports']:
					keeppackageversions = []
					pruneversions = []
					pvs = {}
					(rank, packagename, uniquematches, percentage, packageversions, licenses, language) = j
					if len(uniquematches) == 0:
						continue

					topcandidate = None

					## check if the version was extracted for the Linux kernel, since the
					## version can fairly easily be extracted. TODO: make this more generic
					## so it can also be used for for example the BusyBox results.
					if packagename == 'linux':
						if leafreports.has_key('kernelchecks'):
							if leafreports['kernelchecks'].has_key('version'):
								kernelversion = leafreports['kernelchecks']['version']
								if kernelversion in packageversions:
									topcandidate = kernelversion
					## the amount of versions is lower than the maximum amount that should be
					## reported, so continue
					if len(packageversions) < keepversions:
						#print >>sys.stderr, "keeping all", packagename, packageversions, keepversions
						continue

					versioncount = {}
					for u in uniquematches:
						## string = u[0]
						## list of results = u[1]
						## walk through each of the unique matches.
						## Store which versions are used. If a certain match is only for
						## a single version store it in 'keeppackageversions'
						## u[1] : (checksum, version, line number, path)
						uniqueversions = list(set(map(lambda x: x[1], u[1])))

						if len(uniqueversions) == 1:
							keeppackageversions = list(set((keeppackageversions + uniqueversions)))

						for un in uniqueversions:
							if versioncount.has_key(un):
								versioncount[un] += 1
							else:
								versioncount[un] = 1
					if keeppackageversions != []:
						print >>sys.stderr, "UNIQUE", packagename, keeppackageversions

					## there are no differences between the different values: for each
					## version the same amount of hits was found.
					if min(versioncount.values()) == max(versioncount.values()):
						continue

					## If there is more than one version in keeppackageversions, then there is either
					## a database error, a string extraction error (for ELF files sometimes bogus data
					## is extracted, or the binary was made from modified source code (forward porting
					## of patches, backporting of patches, etc.)
					filterversions = []
					filtercount = keepversions

					if len(uniquematches) > max(versioncount.values()):
						## none of the versions match all the strings
						## This could indicate backporting or forward porting of code
						if topcandidate != None:
							if max(versioncount.values()) == versioncount[topcandidate]:
								## the top candidate indeed is the top candidate
								filterversions.append(topcandidate)
								keepversions = keepversions - 1
							else:
								pass
					else:
						if topcandidate != None:
							if max(versioncount.values()) == versioncount[topcandidate]:
								## the top candidate indeed is the top candidate
								filterversions.append(topcandidate)
								keepversions = keepversions - 1
							else:
								## set the top candidate to the version with the most hits
								## Possibly store the old top candidate as well, for use with
								## for example functions.
								pass

					if keeppackageversions != []:
						filterversions = keeppackageversions

		## then determine the top candidates for function names, if any
		## then variable names, if any

def determinelicense_version_copyright(unpackreports, scantempdir, topleveldir, debug=False, envvars=None):
	scanenv = os.environ.copy()
	envvars = licensesetup(envvars, debug)
	if envvars != []:
		for en in envvars[1].items():
			try:
				(envname, envvalue) = en
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	determineversion = False
	if scanenv.get('BAT_RANKING_VERSION', 0) == '1':
		determineversion = True

	determinelicense = False
	if scanenv.get('BAT_RANKING_LICENSE', 0) == '1':
		determinelicense = True
		#licenseconn = sqlite3.connect(scanenv.get('BAT_LICENSE_DB'))
		#licensecursor = licenseconn.cursor()

	determinecopyright = False
	if scanenv.get('BAT_RANKING_COPYRIGHT', 0) == '1':
		determinecopyright = True
		#copyrightconn = sqlite3.connect(scanenv.get('BAT_LICENSE_DB'))
		#copyrightcursor = copyrightconn.cursor()

	## only continue if there actually is a need
	if not determinelicense and not determineversion and not determinecopyright:
		#c.close()
		#conn.close()
		return None

	## now read the pickles
	rankingfiles = []

	## ignore files which don't have ranking results
	filehashseen = []
	for i in unpackreports:
		if not unpackreports[i].has_key('sha256'):
			continue
		if not unpackreports[i].has_key('tags'):
			continue
		if not 'ranking' in unpackreports[i]['tags']:
			continue
		filehash = unpackreports[i]['sha256']
		if filehash in filehashseen:
			continue
		filehashseen.append(filehash)
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		rankingfiles.append((scanenv, unpackreports[i], topleveldir, determinelicense, determineversion, determinecopyright))
	pool = multiprocessing.Pool()
	pool.map(compute_version, rankingfiles)

def compute_version((scanenv, unpackreport, topleveldir, determinelicense, determineversion, determinecopyright)):
	masterdb = scanenv.get('BAT_DB')

	## open the database containing all the strings that were extracted
	## from source code.
	conn = sqlite3.connect(masterdb)
	## we have byte strings in our database, not utf-8 characters...I hope
	conn.text_factory = str
	c = conn.cursor()

	if determinelicense:
		licenseconn = sqlite3.connect(scanenv.get('BAT_LICENSE_DB'))
		licensecursor = licenseconn.cursor()

	if determinecopyright:
		copyrightconn = sqlite3.connect(scanenv.get('BAT_LICENSE_DB'))
		copyrightcursor = copyrightconn.cursor()

	## keep a list of versions per sha256, since source files could contain more than one license
	seensha256 = []

	## keep a list of versions per sha256, since source files often are in more than one version
	sha256_versions = {}
	newreports = []
	filehash = unpackreport['sha256']
	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()
	if not leafreports.has_key('ranking'):
		return

	(res, dynamicRes, variablepvs) = leafreports['ranking']
	if res == None:
		return
	for r in res['reports']:
		(rank, package, unique, percentage, packageversions, packagelicenses, language) = r
		if unique == []:
			newreports.append(r)
			continue
		newuniques = []
		newpackageversions = {}
		packagecopyrights = []
		for u in unique:
			line = u[0]
			## We should store the version number with the license.
			## There are good reasons for this: files are sometimes collectively
			## relicensed when there is a new release (example: Samba 3.2 relicensed
			## to GPLv3+) so the version number can be very significant.
			## determinelicense should *always* imply determineversion
			if determineversion or determinelicense or determinecopyright:
				c.execute("select distinct sha256, linenumber, language from extracted_file where programstring=?", (line,))
				versionsha256s = filter(lambda x: x[2] == language, c.fetchall())

				pv = {}
				line_sha256_version = []
				for s in versionsha256s:
					if not sha256_versions.has_key(s[0]):
						c.execute("select distinct version, package, filename from processed_file where sha256=?", (s[0],))
						versions = c.fetchall()
						versions = filter(lambda x: x[1] == package, versions)
						sha256_versions[s[0]] = map(lambda x: (x[0], x[2]), versions)
						for v in versions:
							if not pv.has_key(v[0]):
								pv[v[0]] = 1
							line_sha256_version.append((s[0], v[0], s[1], v[2]))
					else:
						for v in sha256_versions[s[0]]:
							if not pv.has_key(v[0]):
								pv[v[0]] = 1
							line_sha256_version.append((s[0], v[0], s[1], v[1]))
				for v in pv:
					if newpackageversions.has_key(v):
						newpackageversions[v] = newpackageversions[v] + 1
					else:   
						newpackageversions[v] = 1
				newuniques.append((line, line_sha256_version))
				if determinelicense:
					licensepv = []
					for s in versionsha256s:
						if not s[0] in seensha256:
							licensecursor.execute("select distinct license, scanner from licenses where sha256=?", (s[0],))
							licenses = licensecursor.fetchall()
							if not len(licenses) == 0:
								#licenses = squashlicenses(licenses)
								licensepv = licensepv + licenses
								#for v in map(lambda x: x[0], licenses):
								#       licensepv.append(v)
							seensha256.append(s[0])
					packagelicenses = list(set(packagelicenses + licensepv))

				## extract copyrights. 'statements' are not very accurate so ignore those for now in favour of URL
				## and e-mail
				if determinecopyright:
					copyrightpv = []
					copyrightcursor.execute("select distinct * from extracted_copyright where sha256=?", (s[0],))
					copyrights = copyrightcursor.fetchall()
					copyrights = filter(lambda x: x[2] != 'statement', copyrights)
					if copyrights != []:
						copyrights = list(set(map(lambda x: (x[1], x[2]), copyrights)))
						copyrightpv = copyrightpv + copyrights
						packagecopyrights = list(set(packagecopyrights + copyrightpv))

		newreports.append((rank, package, newuniques, percentage, newpackageversions, packagelicenses, language))
	res['reports'] = newreports
	leafreports['ranking'] = (res, dynamicRes, variablepvs)

	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
	leafreports = cPickle.dump(leafreports, leaf_file)
	leaf_file.close()

	## cleanup
	if determinelicense:
		licensecursor.close()
		licenseconn.close()

	if determinecopyright:
		copyrightcursor.close()
		copyrightconn.close()

	c.close()
	conn.close()

## method that makes sure that everything is set up properly and modifies
## the environment, as well as determines whether the scan should be run at
## all.
## Returns tuple (run, envvars)
## * run: boolean indicating whether or not the scan should run
## * envvars: (possibly) modified
## This is the minimum that is needed for determining the licenses
def licensesetup(envvars, debug=False):
	scanenv = os.environ.copy()
	newenv = {}
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
				newenv[envname] = envvalue
			except Exception, e:
				pass

	## Is the master database defined?
	if not scanenv.has_key('BAT_DB'):
		return (False, None)

	masterdb = scanenv.get('BAT_DB')

	## Does the master database exist?
	if not os.path.exists(masterdb):
		return (False, None)

	## Does the master database have the right tables?
	## processed_file is always needed
	conn = sqlite3.connect(masterdb)
	c = conn.cursor()
	res = c.execute("select * from sqlite_master where type='table' and name='processed_file'").fetchall()
	if res == []:
		c.close()
		conn.close()
		return (False, None)

	## extracted_file is needed for string matches
	res = c.execute("select * from sqlite_master where type='table' and name='extracted_file'").fetchall()
	if res == []:
		stringmatches = False
	else:
		stringmatches = True

	## TODO: copy checks for functions as well

	## check the license database. If it does not exist, or does not have
	## the right schema remove it from the configuration
	if scanenv.get('BAT_RANKING_LICENSE', 0) == '1' or scanenv.get('BAT_RANKING_COPYRIGHT', 0) == 1:
		if scanenv.get('BAT_LICENSE_DB') != None:
			try:
				licenseconn = sqlite3.connect(scanenv.get('BAT_LICENSE_DB'))
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
	return (True, newenv)
