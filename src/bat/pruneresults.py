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

By pruning results the amount of noise can be much reduced.

To remove a version A from the set of versions the following conditions have
to hold:

* there is a minimum amount of results available (20 or 30 seems a good cut off value)

* all strings/variables/function names found in A are found in the most promising
version

* the amount of strings/variables/function names found in A are significantly
smaller than the amount in the most promising version (expressed as a maximum
percentage)
'''

def pruneresults(unpackreports, scantempdir, topleveldir, envvars=None):
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

		if res['reports'] != []:
			for j in res['reports']:
				keeppackageversions = []
				pruneversions = []
				pvs = {}
				(rank, packagename, uniquematches, percentage, packageversions, licenses) = j
				if len(uniquematches) == 0:
					continue
				## the amount of versions is lower than the maximum amount that should be
				## reported, so continue
				if len(packageversions) < keepversions:
					continue
				candidates = set(packageversions)
				#print >>sys.stderr, "CANDIDATES", packagename, candidates, filehash

				for u in uniquematches:
					## string = u[0]
					## list of results = u[1]
					## walk through each of the unique matches.
					## Store which versions are used. If a certain match is only for
					## a single version store it in 'keeppackageversions'
					## u[1] : (checksum, version, line number, path)
					## only 
					uniqueversions = list(set(map(lambda x: x[1], u[1])))
					if len(uniqueversions) == 1:
						#print >>sys.stderr, "UNIQUE HIT", u[0], u[1]
						keeppackageversions = list(set((keeppackageversions + uniqueversions)))
					candidates = candidates.intersection(set(uniqueversions))
					#print >>sys.stderr
					#print >>sys.stderr, u[0], uniqueversions, filehash
					#print >>sys.stderr
				if keeppackageversions != []:
					print >>sys.stderr, "UNIQUE", packagename, keeppackageversions, candidates
				## Having a match for a single string is significant. If the version is also
				## the only one that is left over in 'candidates' it is extremely likely that it
				## is the right version (barring errors in the database).
				## If there is more than one unique version, or it is not in 'candidates'
				## then there is either a database error, a string extraction error (for ELF files
				## sometimes bogus data is extracted, or the binary was made from modified source
				## code (forward porting of patches, backporting of patches, etc.)
