#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains a few methods that can be useful for security scanning.
'''

import os, sys, zipfile, subprocess, re, cPickle, copy, tempfile
import bat.batdb

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
	batdb = bat.batdb.BatDb(scanenv['DBBACKEND'])
	c = batdb.getConnection(scanenv['BAT_DB'],scanenv)
	cursor = c.cursor()
	plaintexts = set()
	query = batdb.getQuery("select sha256 from hashconversion where crc32=%s")
	for e in encryptedinfos:
		crc = e.CRC
		## if the CRC is 0 it is a directory entry
		if crc == 0:
			continue
		cursor.execute(query, (crc,))
		res = cursor.fetchone()
		if res != None:
			plaintexts.add(res[0])
	cursor.close()
	c.close()
	if len(plaintexts) != 0:
		return (['encryptedzip-attack'], plaintexts)
	return

def encryptedZipSetup(scanenv, debug=False):
	if not 'DBBACKEND' in scanenv:
		return (False, None)
	if scanenv['DBBACKEND'] == 'sqlite3':
		return encryptedZipSetup_sqlite3(scanenv, debug)
	return (False, None)

def encryptedZipSetup_sqlite3(scanenv, debug=False):
	## first check if there is a database defined
	if not scanenv.has_key('BAT_DB'):
		return (False, None)
	if not os.path.exists(scanenv['BAT_DB']):
		return (False, None)

	newenv = copy.deepcopy(scanenv)
	batdb = bat.batdb.BatDb(scanenv['DBBACKEND'])
	c = batdb.getConnection(scanenv['BAT_DB'])
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
	p = subprocess.Popen(['clamscan', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

## stubs for cracking passwords with "John the Ripper"
## 1. look for files called 'passwd' and 'shadow'
## 2. search for individual entries in the database
## 3. crack unknown entries
##
## This is implemented as an "aggregate scan". Running "John the Ripper"
## is an expensive operation and often there can be duplicate password
## or shadow files in firmwares.
def crackPasswords(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):
	passwdfiles = []
	for u in unpackreports.keys():
		if not (os.path.basename(u) == 'shadow' or os.path.basename(u) == 'passwd'):
			continue
		if 'symlink' in unpackreports[u]['tags']:
			continue
		if 'elf' in unpackreports[u]['tags']:
			continue
		if os.path.basename(u) == 'shadow':
			passwdfiles.append((u, 'shadow'))
		else:
			passwdfiles.append((u, 'passwd'))

	(envresult, newenv) = crackPasswordsSetup(scanenv, scandebug)

	if envresult:
		newscanenv = newenv
	else:
		newscanenv = scanenv

	db = False
	if "BAT_SECURITY_DB" in newscanenv:
		db = True
		conn = sqlite3.connect(newscanenv['BAT_SECURITY_DB'])
		cursor = conn.cursor()

	seenhashes = set()
	foundpasswords = []
	hashestopassword = {}
	hashestologins = {}

	for i in passwdfiles:
		(pwdfilename, pwdfiletype) = i
		pwdfile = os.path.join(scantempdir, pwdfilename)
		pwentries = map(lambda x: x.strip(), open(pwdfile).readlines())
		scanfile = False
		scanlines = []
		for p in pwentries:
			pwfields = p.split(':')

			if len(pwfields) < 7:
				continue
			if len(pwfields[1]) > 1:
				if pwfields[1] not in hashestologins:
					hashestologins[pwfields[1]] = set()
				hashestologins[pwfields[1]].add(pwfields[0])
				if pwfields[1] in seenhashes:
					continue
				seenhashes.add(pwfields[1])
				if db:
					cursor.execute("select password from security_password where hash=?", (pwfields[1],))
					res = cursor.fetchone()
					if res != None:
						password = res[0]
						foundpasswords.append((pwfields[1],password))
						hashestopassword[pwfields[1]] = password
						continue
				scanfile = True
				scanlines.append(p)
		if scanfile:
			## print the lines with passwords that need to be
			## scanned with JTR to a separate file
			tmppwdfile = tempfile.mkstemp()
			os.fdopen(tmppwdfile[0]).close()
			newpwdfile = open(tmppwdfile[1], 'w')
			for s in scanlines:
				newpwdfile.write(s)
			newpwdfile.close()

			## now scan with JTR
			if processors == None or processors <= 1:
				p = subprocess.Popen(['john', "%s" % (tmppwdfile[1],)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p.communicate()
			else:
				p = subprocess.Popen(['john', "--fork=%d" % processors, "%s" % (tmppwdfile[1],)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stanout, stanerr) = p.communicate()
			if p.returncode != 0:
				os.unlink(tmppwdfile[1])
				if db:
					cursor.close()
					conn.close()
               			return

			## JTR has successfully run, so now get the results
			p = subprocess.Popen(['john', "--show", "%s" % (tmppwdfile[1],)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stanout, stanerr) = p.communicate()
			counter = 0
			for stan in stanout.split('\n'):
				if ":NO PASSWORD:" in stan.strip():
					counter += 1
					continue
				stansplit = stan.strip().split(':')
				if len(stansplit) < 8:
					counter += 1
					continue
				if pwdfiletype == 'passwd':
					pass
				else:
					if len(stansplit) == 9:
						password = stansplit[1]
						orighash = scanlines[counter].split(':')[1]
						foundpasswords.append((orighash, password))
						hashestopassword[orighash] = password
				counter += 1
			os.unlink(tmppwdfile[1])

	if db:
		cursor.close()
		conn.close()

	res = set()
	## now return the found login + password combinations
	for f in foundpasswords:
		(orighash, foundpassword) = f
		for l in hashestologins[orighash]:
			res.add((l, foundpassword))
	if len(res) != 0:
		return {'passwords': res}
			
def crackPasswordsSetup(scanenv, debug=False):
	## first check if there is a database defined
	if not scanenv.has_key('BAT_SECURITY_DB'):
		return (False, None)
	if not os.path.exists(scanenv['BAT_SECURITY_DB']):
		del newenv['BAT_SECURITY_DB']
		return (True, newenv)

	newenv = copy.deepcopy(scanenv)
	c = sqlite3.connect(scanenv['BAT_SECURITY_DB'])
	cursor = c.cursor()
	## then check the database schema to see if the right table is there
	res = c.execute("select * from sqlite_master where type='table' and name='security_password'").fetchall()
	if res == []:
		cursor.close()
		c.close()
		del newenv['BAT_SECURITY_DB']
		return (True, newenv)
	cursor.close()
	c.close()
	## environment hasn't changed
	return (False, None)

## search all files based on the usernames and passwords found
## Of special interest are:
## * binaries
## * HTML pages
## * JavaScript files
def searchLogins(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):
	toplevelelem = None
	for u in unpackreports.keys():
		if 'toplevel' in unpackreports[u]['tags']:
			toplevelelem = u
			break
	if toplevelelem == None:
		return

	if not "passwords" in unpackreports[toplevelelem]['tags']:
		return

	filehash = unpackreports[u]['sha256']
	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()

	logins = map(lambda x: x[0], leafreports['passwords'])

	if logins == []:
		return

	candidates = set()
	for u in unpackreports.keys():
		## scan dupes or not? It could save a lot of disk I/O
		#if 'dupe' in unpackreports[u]['tags']:
		#	continue
		if 'symlink' in unpackreports[u]['tags']:
			continue
		if 'empty' in unpackreports[u]['tags']:
			continue
		if 'linuxkernel' in unpackreports[u]['tags']:
			continue
		if 'graphics' in unpackreports[u]['tags']:
			continue
		if os.path.basename(u) == 'shadow' or os.path.basename(u) == 'passwd':
			continue
		## TODO: make this more efficient
		scanfile = open(os.path.join(scantempdir, u), 'rb')
		scandata = scanfile.read()
		scanfile.close()
		for l in logins:
			if l in scandata:
				candidates.add((l,u))
	return {'logins': candidates}
