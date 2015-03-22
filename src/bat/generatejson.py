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
		print json.dumps(jsondumps, indent=4)

	## then print results for each of the individual reports
	for unpackreport in unpackreports:
		## first see if there is a filehash
		if "filehash" in unpackreports[unpackreport]:
			## then see if there is already a JSON file
			pass
			## then mangle the data and dump it into a JSON file
