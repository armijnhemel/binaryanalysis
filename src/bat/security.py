#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains a few methods that can be useful for security scanning.
'''

import os, sys, sqlite3, zipfile, subprocess

## This method extracts the CRC32 checksums from the entries of the encrypted zip file and checks
## whether or not there are any files in the database with the same CRC32. If so, a known plaintext
## attack is possible to decrypt the archive and extract the key. The return value will be the files
## or checksums in the database for which there is a plaintext version available.
def scanEncryptedZip(path, tags, blacklist=[], scandebug=False, envvars=None, unpacktempdir=None):
	if not 'zip' in tags and not 'encrypted' in tags:
		return
	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

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

def encryptedZipSetup(envvars, debug=False):
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

	## first check if there is a database defined
	if not scanenv.has_key('BAT_DB'):
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
def scanVirus(path, tags, blacklist=[], scandebug=False, envvars=None, unpacktempdir=None):
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
