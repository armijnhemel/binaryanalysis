#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Copyright 2015 Black Duck Software, Inc. All Rights Reserved.
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin to create JSON output of all results of the Binary Analysis Tool,
including the ranking algorithm.

The documentation of the format can be found in the 'doc' directory (subject to change)
'''

import os, sys, re, json, cPickle, multiprocessing, copy, gzip, codecs
import bat.batdb

def writejson((filehash,topleveldir, outputhash, hashdatabase, batdb, scanenv)):
	if outputhash == None:
		outputhash = 'sha256'
	batconnection = None
	if batdb != None:
		batconnection = batdb.getConnection(hashdatabase,scanenv)
		if batconnection != None:
			cursor = batconnection.cursor()
	hashcache = {}
	## read the data from the pickle file
	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()
	## then mangle the data and dump it into a JSON file
	jsonreport = {}

	if "tags" in leafreports:
		jsonreport['tags'] = list(set(copy.deepcopy(leafreports['tags'])))
	## now go through all of the scans that are there. This is hardcoded.
	## TODO: make more generic based on configuration.
	for i in ['busybox-version', 'forges', 'licenses']:
		if i in leafreports:
			jsonreport[i] = copy.deepcopy(leafreports[i])

	if outputhash != 'sha256' and batconnection != None:
		query = batdb.getQuery("select %s from hashconversion where sha256=" % outputhash + "%s")

	## then the 'ranking' scan
	if 'ranking' in leafreports:
		jsonreport['ranking'] = {}
		(stringidentifiers, functionnameresults, variablenameresults, language) = leafreports['ranking']

		## first the language
		jsonreport['ranking']['language'] = language

		## then the string identifier results
		jsonreport['ranking']['stringresults'] = {}
		jsonreport['ranking']['stringresults']['unmatched'] = []
		jsonreport['ranking']['stringresults']['matchednonassignedlines'] = 0
		jsonreport['ranking']['stringresults']['matchednotclonelines'] = 0
		jsonreport['ranking']['stringresults']['nonUniqueMatches'] = []
		jsonreport['ranking']['stringresults']['scores'] = []
		jsonreport['ranking']['stringresults']['reports'] = []
		if stringidentifiers != None:
			if 'unmatched' in stringidentifiers:
				jsonreport['ranking']['stringresults']['unmatched'] = stringidentifiers['unmatched']

			if 'matchednonassignedlines' in stringidentifiers:
				jsonreport['ranking']['stringresults']['matchednonassignedlines'] = stringidentifiers['matchednonassignedlines']
			if 'matchednotclonelines' in stringidentifiers:
				jsonreport['ranking']['stringresults']['matchednotclonelines'] = stringidentifiers['matchednotclonelines']

			if 'nonUniqueMatches' in stringidentifiers:
				jsonreport['ranking']['stringresults']['nonUniqueMatches'] = []
				for u in stringidentifiers['nonUniqueMatches']:
					nonuniquereport = {}
					nonuniquereport['packagename'] = u
					nonuniquereport['nonuniquelines'] = stringidentifiers['nonUniqueMatches'][u]
					jsonreport['ranking']['stringresults']['nonUniqueMatches'].append(nonuniquereport)

			if 'scores' in stringidentifiers:
				jsonreport['ranking']['stringresults']['scores'] = []
				for u in stringidentifiers['scores']:
					scorereport = {}
					scorereport['packagename'] = u
					scorereport['computedscore'] = stringidentifiers['scores'][u]
					jsonreport['ranking']['stringresults']['scores'].append(scorereport)

			if 'reports' in stringidentifiers:
				jsonreport['ranking']['stringresults']['reports'] = []
				for u in stringidentifiers['reports']:
					(rank, package, unique, uniquematcheslen, percentage, packageversions, packagelicenses, packagecopyrights) = u
					report = {}
					report['packagename'] = package
					report['rank'] = rank
					report['percentage'] = percentage
					report['unique'] = []
					for un in unique:
						(identifier, identifierdata) = un
						uniquereport = {}
						uniquereport['identifier'] = identifier
						uniquereport['identifierdata'] = []
						for iddata in identifierdata:
							(filechecksum, linenumber, fileversiondata) = iddata
							identifierdatareport = {}
							if outputhash != 'sha256' and batconnection != None:
								if filechecksum in hashcache:
									identifierdatareport['filechecksum'] = hashcache[filechecksum]
									identifierdatareport['filechecksumtype'] = outputhash
								else:
									cursor.execute(query, (filechecksum,))
									convertedhash = cursor.fetchone()
									if convertedhash != None:
										hashcache[filechecksum] = convertedhash[0]
										identifierdatareport['filechecksum'] = convertedhash[0]
										identifierdatareport['filechecksumtype'] = outputhash
									else:
										identifierdatareport['filechecksum'] = filechecksum
										identifierdatareport['filechecksumtype'] = 'sha256'
							else:
								identifierdatareport['filechecksum'] = filechecksum
								identifierdatareport['filechecksumtype'] = 'sha256'
							identifierdatareport['linenumber'] = linenumber
							identifierdatareport['packagedata'] = []
							for pack in fileversiondata:
								(packageversion, sourcefilename) = pack
								fileversionreport = {}
								fileversionreport['packageversion'] = packageversion
								fileversionreport['sourcefilename'] = sourcefilename
								identifierdatareport['packagedata'].append(fileversionreport)
							uniquereport['identifierdata'].append(identifierdatareport)
						report['unique'].append(uniquereport)
					report['packageversions'] = []
					for p in packageversions:
						packagereport = {}
						packagereport['packageversion'] = p
						packagereport['packagehits'] = packageversions[p]
						report['packageversions'].append(packagereport)
					jsonreport['ranking']['stringresults']['reports'].append(report)

		## then the functionname results
		jsonreport['ranking']['functionnameresults'] = {}
		jsonreport['ranking']['functionnameresults']['totalfunctionnames'] = 0
		jsonreport['ranking']['functionnameresults']['versionresults'] = []
		if 'totalnames' in functionnameresults:
			jsonreport['ranking']['functionnameresults']['totalfunctionnames'] = functionnameresults['totalnames']
		if 'versionresults' in functionnameresults:
			for packagename in functionnameresults['versionresults']:
				packagereport = {}
				packagereport['packagename'] = packagename
				packagereport['unique'] = []
				for un in functionnameresults['versionresults'][packagename]:
					(identifier, identifierdata) = un
					uniquereport = {}
					uniquereport['identifier'] = identifier
					uniquereport['identifierdata'] = []
					for iddata in identifierdata:
						(filechecksum, linenumber, fileversiondata) = iddata
						identifierdatareport = {}
						if outputhash != 'sha256':
							if filechecksum in hashcache:
								identifierdatareport['filechecksum'] = hashcache[filechecksum]
								identifierdatareport['filechecksumtype'] = outputhash
							else:
								cursor.execute(query, (filechecksum,))
								convertedhash = cursor.fetchone()
								if convertedhash != None:
									hashcache[filechecksum] = convertedhash[0]
									identifierdatareport['filechecksum'] = convertedhash[0]
									identifierdatareport['filechecksumtype'] = outputhash
								else:
									identifierdatareport['filechecksum'] = filechecksum
									identifierdatareport['filechecksumtype'] = 'sha256'
						else:
							identifierdatareport['filechecksum'] = filechecksum
							identifierdatareport['filechecksumtype'] = 'sha256'
						identifierdatareport['linenumber'] = linenumber
						identifierdatareport['packagedata'] = []
						for pack in fileversiondata:
							(packageversion, sourcefilename) = pack
							fileversionreport = {}
							fileversionreport['packageversion'] = packageversion
							fileversionreport['sourcefilename'] = sourcefilename
							identifierdatareport['packagedata'].append(fileversionreport)
						uniquereport['identifierdata'].append(identifierdatareport)
					packagereport['unique'].append(uniquereport)
				jsonreport['ranking']['functionnameresults']['versionresults'].append(packagereport)

		## then the variablename results
		jsonreport['ranking']['variablenameresults'] = {}
		jsonreport['ranking']['variablenameresults'] = {}
		jsonreport['ranking']['variablenameresults']['totalvariablenames'] = 0
		jsonreport['ranking']['variablenameresults']['versionresults'] = []
		if 'totalnames' in variablenameresults:
			jsonreport['ranking']['variablenameresults']['totalvariablenames'] = variablenameresults['totalnames']
		if 'versionresults' in variablenameresults:
			for packagename in variablenameresults['versionresults']:
				packagereport = {}
				packagereport['packagename'] = packagename
				packagereport['unique'] = []
				for un in variablenameresults['versionresults'][packagename]:
					(identifier, identifierdata) = un
					uniquereport = {}
					uniquereport['identifier'] = identifier
					uniquereport['identifierdata'] = []
					for iddata in identifierdata:
						(filechecksum, linenumber, fileversiondata) = iddata
						identifierdatareport = {}
						if outputhash != 'sha256':
							if filechecksum in hashcache:
								identifierdatareport['filechecksum'] = hashcache[filechecksum]
								identifierdatareport['filechecksumtype'] = outputhash
							else:
								cursor.execute(query, (filechecksum,))
								convertedhash = cursor.fetchone()
								if convertedhash != None:
									hashcache[filechecksum] = convertedhash[0]
									identifierdatareport['filechecksum'] = convertedhash[0]
									identifierdatareport['filechecksumtype'] = outputhash
								else:
									identifierdatareport['filechecksum'] = filechecksum
									identifierdatareport['filechecksumtype'] = 'sha256'
						else:
							identifierdatareport['filechecksum'] = filechecksum
							identifierdatareport['filechecksumtype'] = 'sha256'
						identifierdatareport['linenumber'] = linenumber
						identifierdatareport['packagedata'] = []
						for pack in fileversiondata:
							(packageversion, sourcefilename) = pack
							fileversionreport = {}
							fileversionreport['packageversion'] = packageversion
							fileversionreport['sourcefilename'] = sourcefilename
							identifierdatareport['packagedata'].append(fileversionreport)
						uniquereport['identifierdata'].append(identifierdatareport)
					packagereport['unique'].append(uniquereport)
				jsonreport['ranking']['variablenameresults']['versionresults'].append(packagereport)

	## then security information
	## TODO
	if batconnection != None:
		cursor.close()
		batconnection.close()

	## dump the JSON to a file
	jsonfile = gzip.open(os.path.join(topleveldir, "reports", "%s.json.gz" % filehash), 'w')
	jsonfile.write(json.dumps(jsonreport, indent=4))
	jsonfile.close()

def printjson(unpackreports, scantempdir, topleveldir, processors, scanenv={}, scandebug=False, unpacktempdir=None):
	toplevelelem = None
	for u in unpackreports:
		if "toplevel" in unpackreports[u]['tags']:
			toplevelelem = u
			break

	## first the data needs to be a bit mangled
	jsondumps = []

	if "OUTPUTHASH" in scanenv:
		outputhash = scanenv['OUTPUTHASH']
	else:
		outputhash = 'sha256'

	if outputhash != 'sha256':
		if not 'DBBACKEND' in scanenv:
			return
		batdb = bat.batdb.BatDb(scanenv['DBBACKEND'])
		if not scanenv.has_key('BAT_DB'):
			return
	else:
		batdb = None

	for unpackreport in unpackreports:
		jsonreport = {}
		filehash = None
		if "checksum" in unpackreports[unpackreport]:
			filehash = copy.deepcopy(unpackreports[unpackreport]['checksum'])
			jsonreport['checksum'] = filehash
			jsonreport['checksumtype'] = outputhash
		for p in ["name", "path", "realpath"]:
			if p in unpackreports[unpackreport]:
				nodename = copy.deepcopy(unpackreports[unpackreport][p])
				## check whether or not the name of the file does not contain any weird
				## characters by decoding it to UTF-8
				decoded = False
				for i in ['utf-8','ascii','latin-1','euc_jp', 'euc_jis_2004', 'jisx0213', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr','shift_jis','shift_jis_2004','shift_jisx0213']:
					try:
						nodename = nodename.decode(i)
						decoded = True
						break
					except Exception, e:
						pass
				if decoded:
					jsonreport[p] = nodename
				else:
					if filehash != None:
						jsonreport[p] = "name-for-%s-cannot-be-displayed" % filehash
		if "tags" in unpackreports[unpackreport]:
			jsonreport['tags'] = list(set(copy.deepcopy(unpackreports[unpackreport]['tags'])))
		if "magic" in unpackreports[unpackreport]:
			jsonreport['magic'] = copy.deepcopy(unpackreports[unpackreport]['magic'])
		if "checksum" in unpackreports[unpackreport]:
			jsonreport['checksum'] = filehash
			jsonreport['checksumtype'] = outputhash
		if "scans" in unpackreports[unpackreport]:
			if unpackreports[unpackreport]['scans'] != []:
				reps = copy.deepcopy(unpackreports[unpackreport]['scans'])
				for r in reps:
					if 'scanreports' in r:
						newscanreports = []
						for s in r['scanreports']:
							decoded = False
							for i in ['utf-8','ascii','latin-1','euc_jp', 'euc_jis_2004', 'jisx0213', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr','shift_jis','shift_jis_2004','shift_jisx0213']:
								try:
									s = s.decode(i)
									decoded = True
									break
								except Exception, e:
									pass
							if decoded:
								newscanreports.append(s)
							else:
								if filehash != None:
									newscanreports.append("name-for-%s-cannot-be-displayed" % filehash)
						r['scanreports'] = newscanreports
				jsonreport['scans'] = reps
		jsondumps.append(jsonreport)

	if jsondumps != []:
		jsonfile = open(os.path.join(topleveldir, "scandata.json"), 'w')
		jsonfile.write(json.dumps(jsondumps, indent=4))
		jsonfile.close()

	filehashes = set()
	jsontasks = []

	## create tasks for printing results for each of the individual reports
	for unpackreport in unpackreports:
		## first see if there is a filehash. If not, continue
		if not "checksum" in unpackreports[unpackreport]:
			continue
		filehash = unpackreports[unpackreport]['checksum']
		if filehash in filehashes:
			continue
		## then check if there is a pickle file. If not, continue
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		## then check if the data for this file has already been dumped (this should not
		## happen). If so, continue.
		if os.path.exists(os.path.join(topleveldir, "reports", "%s.json.gz" % filehash)):
			continue
		filehashes.add(filehash)
		jsontasks.append((filehash, topleveldir, outputhash, scanenv['BAT_DB'], batdb, scanenv))

	if len(jsontasks) != 0:
		pool = multiprocessing.Pool(processes=processors)
		pool.map(writejson, jsontasks,1)
		pool.terminate()
