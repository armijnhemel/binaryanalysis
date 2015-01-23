#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains a few methods that can be useful for security scanning.
'''

import os, sys, sqlite3, zipfile, subprocess, re, cPickle

## This method extracts the CRC32 checksums from the entries of the encrypted zip file and checks
## whether or not there are any files in the database with the same CRC32. If so, a known plaintext
## attack is possible to decrypt the archive and extract the key. The return value will be the files
## or checksums in the database for which there is a plaintext version available.
def scanEncryptedZip(path, tags, blacklist=[], scanenv={}, scandebug=False, unpacktempdir=None):
	if not 'zip' in tags and not 'encrypted' in tags:
		return

	if not scanenv.has_key('BAT_DB'):
		return

	encryptedzip = zipfile.ZipFile(path, 'r')
	encryptedinfos = encryptedzip.infolist()
	c = sqlite3.connect(scanenv['BAT_DB'])
	cursor = c.cursor()
	plaintexts = set()
	for e in encryptedinfos:
		crc = e.CRC
		## if the CRC is 0 it is a directory entry
		if crc == 0:
			continue
		cursor.execute("select sha256 from hashconversion where crc32=?", (crc,))
		res = cursor.fetchone()
		if res != None:
			plaintexts.add(res[0])
	cursor.close()
	c.close()
	if len(plaintexts) != 0:
		return (['encryptedzip-attack'], plaintexts)
	return

def encryptedZipSetup(scanenv, debug=False):
	## first check if there is a database defined
	if not scanenv.has_key('BAT_DB'):
		return (False, None)
	if not os.path.exists(scanenv['BAT_DB']):
		return (False, None)
	c = sqlite3.connect(scanenv['BAT_DB'])
	cursor = c.cursor()

	## then check the database schema to see if there are crc32 checksums
	res = c.execute("select * from sqlite_master where type='table' and name='hashconversion'").fetchall()
	if res == []:
		cursor.close()
		c.close()
		return (False, None)

	## then check if there is a column 'crc32'
	res = c.execute("pragma table_info('hashconversion')").fetchall()
	if res == []:
		cursor.close()
		c.close()
		return (False, None)

	cursor.close()
	c.close()

	process = False

	for i in res:
		if i[1] == 'crc32':
			process = True
			break
	if not process:
		return (False, None)
		
	return (True, newenv)


## experimental clamscan feature
## Always run freshclam before scanning to get the latest
## virus signatures!
def scanVirus(path, tags, blacklist=[], scanenv={}, scandebug=False, unpacktempdir=None):
	p = subprocess.Popen(['clamscan', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode == 0:
               	return
	else:
		## Oooh, virus found!
		viruslines = stanout.split("\n")
		## first line contains the report:
		virusname = viruslines[0].strip()[len(path) + 2:-6]
		return (['virus'], virusname)

## experimental feature to detect possible smells in binaries
## Many ODMs use shell commands in their programs using the system() call
## which has turned out to be vulnerable in certain instances.
## Some of these can be detected by looking for typical shell invocation
## patterns, such as %s or * in combination with hard coded paths
## TODO: add more patterns
def scanShellInvocations(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):
	for i in unpackreports:
		## Limit to ELF binaries for now
		if not unpackreports[i].has_key('tags'):
			continue
		if not unpackreports[i].has_key('sha256'):
			continue
		if not 'elf' in unpackreports[i]['tags']:
			continue
		if not 'identifier' in unpackreports[i]['tags']:
			continue

		filehash = unpackreports[i]['sha256']

		## read pickle file
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		strs = leafreports['identifier']['strings']
		buggylines = []
		for line in strs:
			if '/sbin' in line or '/bin' in line:
				possiblybuggy = False
				for c in ['%s', '*']:
					if c in line:
						buggylines.append(line)
						break
		## now write back the results
		if buggylines != []:
			leafreports['shellinvocations'] = buggylines
			leafreports['tags'].append('shellinvocations')
			unpackreports[i]['tags'].append('shellinvocations')
			leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
			cPickle.dump(leafreports, leaf_file)
			leaf_file.close()
