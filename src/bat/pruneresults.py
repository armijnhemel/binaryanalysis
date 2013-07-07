#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, multiprocessing

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
		if res['reports'] != []:
			for j in res['reports']:
				keeppackageversions = []
				pruneversions = []
				pvs = {}
				(rank, packagename, uniquematches, percentage, packageversions, licenses) = j
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
