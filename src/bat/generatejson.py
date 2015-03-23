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

import os, sys, re, json, cPickle, multiprocessing, copy

def printjson(unpackreports, scantempdir, topleveldir, processors, scanenv={}, scandebug=False, unpacktempdir=None):
	toplevelelem = None
	for u in unpackreports:
		if "toplevel" in unpackreports[u]['tags']:
			toplevelelem = u
			break

	## first the data needs to be a bit mangled
	jsondumps = []

	for unpackreport in unpackreports:
		jsonreport = {}
		if "name" in unpackreports[unpackreport]:
			jsonreport['name'] = copy.deepcopy(unpackreports[unpackreport]['name'])
		if "path" in unpackreports[unpackreport]:
			jsonreport['path'] = copy.deepcopy(unpackreports[unpackreport]['path'])
		if "tags" in unpackreports[unpackreport]:
			jsonreport['tags'] = list(set(copy.deepcopy(unpackreports[unpackreport]['tags'])))
		if "magic" in unpackreports[unpackreport]:
			jsonreport['magic'] = copy.deepcopy(unpackreports[unpackreport]['magic'])
		if "sha256" in unpackreports[unpackreport]:
			jsonreport['checksum'] = copy.deepcopy(unpackreports[unpackreport]['sha256'])
			jsonreport['checksumtype'] = 'sha256'
		if "scans" in unpackreports[unpackreport]:
			if unpackreports[unpackreport]['scans'] != []:
				jsonreport['scans'] = copy.deepcopy(unpackreports[unpackreport]['scans'])
		jsondumps.append(jsonreport)

	if jsondumps != []:
		jsonfile = open(os.path.join(topleveldir, "scandata.json"), 'w')
		jsonfile.write(json.dumps(jsondumps, indent=4))
		jsonfile.close()

	filehashes = set()
	## then print results for each of the individual reports
	for unpackreport in unpackreports:
		## first see if there is a filehash. If not, skip
		if not "sha256" in unpackreports[unpackreport]:
			continue
		filehash = unpackreports[unpackreport]['sha256']
		if filehash in filehashes:
			continue
		## then check if there is a pickle file. If not, continue
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		## then check if the data for this file has already been dumped. If so, continue.
		if os.path.exists(os.path.join(topleveldir, "reports", "%s.json" % filehash)):
			continue
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

		## then the 'ranking' scan
		if 'ranking' in leafreports:
			jsonreport['ranking'] = {}
			(stringidentifiers, functionnameresults, variablenameresults, language) = leafreports['ranking']
			jsonreport['ranking']['language'] = language

		## dump the JSON to a file
		jsonfile = open(os.path.join(topleveldir, "reports", "%s.json" % filehash), 'w')
		jsonfile.write(json.dumps(jsonreport, indent=4))
		jsonfile.close()

		## finally add the hash to the list of hashes that can be skipped
		filehashes.add(filehash)
