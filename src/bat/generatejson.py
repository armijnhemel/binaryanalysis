#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Copyright 2015 Black Duck Software, Inc. All Rights Reserved.
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin to create JSON output of all results of the Binary Analysis Tool,
including the ranking algorithm.

The documentation of the format can be found in the 'doc' directory (subject to change)
'''

import os, sys, re, json, cPickle, multiprocessing, copy, gzip, codecs, Queue, shutil
from multiprocessing import Process, Lock
from multiprocessing.sharedctypes import Value, Array

def writejson(scanqueue, topleveldir, outputhash, cursor, conn, scanenv, converthash, compressed):
	hashcache = {}
	while True:
		filehash = scanqueue.get(timeout=2592000)
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

		if converthash:
			query = "select %s from hashconversion where sha256=" % outputhash + "%s"

		## then the 'ranking' scan
		if 'ranking' in leafreports:
			jsonreport['ranking'] = {}
			(stringidentifiers, functionnameresults, variablenameresults, language) = leafreports['ranking']

			## first the language
			jsonreport['ranking']['language'] = language

			totalextracted = 0

			## then the string identifier results
			jsonreport['ranking']['stringresults'] = {}
			jsonreport['ranking']['stringresults']['unmatched'] = []
			jsonreport['ranking']['stringresults']['ignored'] = []
			jsonreport['ranking']['stringresults']['matchednonassignedlines'] = 0
			jsonreport['ranking']['stringresults']['matchednotclonelines'] = 0
			jsonreport['ranking']['stringresults']['nonUniqueMatches'] = []
			jsonreport['ranking']['stringresults']['scores'] = []
			jsonreport['ranking']['stringresults']['reports'] = []
			jsonreport['ranking']['stringresults']['totalstrings'] = 0
			totalunique = 0
			if stringidentifiers != None:
				jsonreport['ranking']['stringresults']['totalstrings'] = stringidentifiers['extractedlines']
				totalextracted += stringidentifiers['extractedlines']
				for todecode in ['ignored', 'unmatched']:
					if todecode in stringidentifiers:
						newres = []
						for u in stringidentifiers[todecode]:
							decoded = False
							for i in ['utf-8','ascii','latin-1','euc_jp', 'euc_jis_2004', 'jisx0213', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr','shift_jis','shift_jis_2004','shift_jisx0213']:
								try:
									decodeline = u.decode(i)
									decoded = True
									break
								except Exception, e:
									pass
							if decoded:
								newres.append(decodeline)
							else:
								pass
						jsonreport['ranking']['stringresults'][todecode] = newres

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
						rank = u['rank']
						package = u['package']
						unique = u['unique']
						totalunique += len(unique)
						percentage = u['percentage']
						packageversions = u['packageversions']
						packagecopyrights = u['packagecopyrights']
						packagelicenses = u['packagelicenses']
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
								if converthash:
									if filechecksum in hashcache:
										identifierdatareport['filechecksum'] = hashcache[filechecksum]
										identifierdatareport['filechecksumtype'] = outputhash
									else:
										cursor.execute(query, (filechecksum,))
										convertedhash = cursor.fetchone()
										conn.commit()
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
						determinedlicenses = map(lambda x: x[0], filter(lambda x: x[1] == 'squashed', packagelicenses))
						report['determinedlicenses'] = determinedlicenses
						for p in packageversions:
							packagereport = {}
							packagereport['packageversion'] = p
							packagereport['packagehits'] = packageversions[p]
							report['packageversions'].append(packagereport)
						jsonreport['ranking']['stringresults']['reports'].append(report)

			jsonreport['ranking']['stringresults']['totalunique'] = totalunique

			## then the functionname results
			jsonreport['ranking']['functionnameresults'] = {}
			jsonreport['ranking']['functionnameresults']['totalfunctionnames'] = 0
			jsonreport['ranking']['functionnameresults']['versionresults'] = []
			if 'totalnames' in functionnameresults:
				jsonreport['ranking']['functionnameresults']['totalfunctionnames'] = functionnameresults['totalnames']
				totalextracted += functionnameresults['totalnames']
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
									conn.commit()
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
				totalextracted += variablenameresults['totalnames']

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
									conn.commit()
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

			jsonreport['ranking']['totalextracted'] = totalextracted

		## then security information
		## TODO

		## dump the JSON to a file
		jsonfilename = os.path.join(topleveldir, "reports", "%s.json" % filehash)
		jsonfile = open(jsonfilename, 'w')
		for chunk in json.JSONEncoder(indent=4).iterencode(jsonreport):
			jsonfile.write(chunk)
		jsonfile.close()
		if compressed:
			fin = open(jsonfilename, 'rb')
			fout = gzip.open("%s.gz" % jsonfilename, 'wb')
			## workaround for https://bugs.python.org/issue23306
			## result: JSON will not be gzip compressed
			try:
				fout.write(fin.read())
				fout.close()
				fin.close()
				os.unlink(fin.name)
			except:
				fout.close()
				fin.close()
				os.unlink(fout.name)
		scanqueue.task_done()

def printjson(unpackreports, scantempdir, topleveldir, processors, scanenv, batcursors, batcons, scandebug=False, unpacktempdir=None):
	toplevelelem = None
	for u in unpackreports:
		if "tags" in unpackreports[u]:
			if "toplevel" in unpackreports[u]['tags']:
				toplevelelem = u
				break

	## first the data needs to be a bit mangled
	jsondumps = []

	if "OUTPUTHASH" in scanenv:
		outputhash = scanenv['OUTPUTHASH']
	else:
		outputhash = 'sha256'
	if "compress" in scanenv:
		compressed = scanenv['compress']
	else:
		compressed = False

	usedb = False
	if batcursors != []:
		usedb = True

	decodingneeded = ['utf-8','ascii','latin-1','euc_jp', 'euc_jis_2004', 'jisx0213', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr','shift_jis','shift_jis_2004','shift_jisx0213']

	jsondir = scanenv.get('BAT_JSONDIR', None)
	if jsondir != None:
		if not os.path.isdir(jsondir):
			jsondir = None

	unpackreportslen = len(unpackreports)
	unpackreportsprocessed = 0

	if unpackreportslen != 0:
		## open the JSON file
		jsonfilename = os.path.join(topleveldir, "scandata.json")
		jsonfile = open(jsonfilename, 'w')
		jsonfile.write('[\n')

		unpackreportskeys = unpackreports.keys()
		unpackreportskeys.sort()
		toplevelhash = None
		for unpackreport in unpackreportskeys:
			jsonreport = {}
			filehash = None
			if "checksum" in unpackreports[unpackreport]:
				filehash = copy.deepcopy(unpackreports[unpackreport]['checksum'])
				jsonreport['checksum'] = filehash
				jsonreport['checksumtype'] = outputhash
				for c in ['sha256', 'md5', 'sha1', 'crc32', 'tlsh']:
					if c in unpackreports[unpackreport]:
						if unpackreports[unpackreport][c] != None:
							jsonreport[c] = copy.deepcopy(unpackreports[unpackreport][c])
			for p in ["name", "path", "realpath", "relativename"]:
				if p in unpackreports[unpackreport]:
					nodename = copy.deepcopy(unpackreports[unpackreport][p])
					## check whether or not the name of the file does not contain any weird
					## characters by decoding it to UTF-8
					decoded = False
					for i in decodingneeded:
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
				if 'toplevel' in jsonreport['tags']:
					toplevelhash = filehash
			if "magic" in unpackreports[unpackreport]:
				jsonreport['magic'] = copy.deepcopy(unpackreports[unpackreport]['magic'])
			if "size" in unpackreports[unpackreport]:
				jsonreport['size'] = copy.deepcopy(unpackreports[unpackreport]['size'])
			if "scans" in unpackreports[unpackreport]:
				if unpackreports[unpackreport]['scans'] != []:
					reps = copy.deepcopy(unpackreports[unpackreport]['scans'])
					for r in reps:
						if 'scanreports' in r:
							newscanreports = []
							for s in r['scanreports']:
								decoded = False
								for i in decodingneeded:
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
			unpackreportsprocessed += 1
			for chunk in json.JSONEncoder(indent=4).iterencode(jsonreport):
				jsonfile.write(chunk)
			if unpackreportsprocessed < unpackreportslen:
				jsonfile.write(',\n')
		jsonfile.write(']\n')
		jsonfile.close()
		if jsondir != None:
			shutil.copy(jsonfilename, os.path.join(jsondir, 'scandata-%s.json' % toplevelhash))

	jsontaskamount = 0

	converthash = False

	havetasks = False

	scanqueue = multiprocessing.JoinableQueue(maxsize=0)
	## create tasks for printing results for each of the individual reports
	for unpackreport in unpackreports:
		## first see if there is a filehash. If not, continue
		if not "checksum" in unpackreports[unpackreport]:
			continue
		filehash = unpackreports[unpackreport]['checksum']
		if 'duplicate' in unpackreports[unpackreport]['tags']:
			continue
		## then check if there is a pickle file. If not, continue
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		## then check if the data for this file has already been dumped (this should not
		## happen). If so, continue.
		if os.path.exists(os.path.join(topleveldir, "reports", "%s.json.gz" % filehash)):
			continue

		if 'ranking' in unpackreports[unpackreport]['tags']:
			if outputhash != 'sha256':
				converthash = True
		jsontaskamount += 1
		havetasks = True
		scanqueue.put(filehash)

	if havetasks:
		if processors == None:
			processamount = 1
		else:
			processamount = processors
		processamount = min(processamount, jsontaskamount)
		scanmanager = multiprocessing.Manager()
		processpool = []

		for i in range(0,processamount):
			if usedb:
				cursor = batcursors[i]
				conn = batcons[i]
			else:
				cursor = None
				conn = None
			p = multiprocessing.Process(target=writejson, args=(scanqueue,topleveldir,outputhash, cursor, conn, scanenv, converthash, compressed))
			processpool.append(p)
			p.start()

		scanqueue.join()

		for p in processpool:
			p.terminate()
