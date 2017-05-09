#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to analyse binary blobs, using a "brute force" approach

The script has a few separate scanning phases:

1. marker scanning phase, to search for specific markers (compression, file
systems, media formats), if available. This information is later used to filter
scans and to find the start/end of embedded files and carve them out from a
larger binary blob.

2. prerun phase for tagging files. This is a first big rough sweep to determine
what files are to prevent spending too much time on useless scanning in the
following phases.  Some things that tagged in this phase (by some of the BAT
default scans) are text files, XML files, various graphics formats and some
other files.

3. unpack phase for unpacking files. In this phase several methods for
unpacking files are run, using the information from the marker scanning phase
if applicable. Also some simple metadata about files is recorded in this phase.
This method runs recursively: if a file system was found and unpacked all the
scans from steps 1, 2, 3 are run on the files that were unpacked.

4. individual file scanning phase. In this phase each file will be inspected
individually. There are many different scans in BAT, like extraction of
markers, and so on.

5. aggregate file scanning phase. In this phase all files are inspected in
context, because some information only makes sense in context, for example
ELF dynamic linking analysis.

6. postrun phase. In this phase methods that just process results of earlier
scans, but which do not modify the results or add to the results are run, such
as generating pictures or creating reports.

7. packing phase. In this phase several datafiles, plus the state of the
running program, are packed in a tar file.
'''

## import a few standard Python modules
import sys, os, os.path, hashlib, subprocess, tempfile, shutil, stat, multiprocessing
import platform, cPickle, glob, tarfile, copy, gzip, Queue
from optparse import OptionParser
import datetime, re, struct, ConfigParser
from multiprocessing import Process, Lock
from multiprocessing.sharedctypes import Value, Array

## import the Python magic module
## NOTE: there are various incompatible python-magic modules
import magic

## import the PostgreSQL connection module
import psycopg2

## finally import a few BAT specific modules
import extractor, prerun, fsmagic

## load the magic library. Some versions of libmagic are too old
## to have the NO_CHECK_CDF magic flag, which might be problematic
## with some files.
try:
	ms = magic.open(magic.MAGIC_NO_CHECK_CDF|magic.MAGIC_NONE)
except:
	ms = magic.open(magic.MAGIC_NONE)
ms.load()

## Try to load the TLSH module if available, else disable TLSH
## scanning, as TLSH is not standard on every Linux distribution.
try:
	import tlsh
	tlshscan = True
except Exception, e:
	tlshscan = False

## Method to run a setup scan. Returns the result of the setup
## scan, which is in the form of a tuple (boolean, environment).
## The environment returned is always a dictionary, like os.environ
def runSetup(setupscan, usedatabase, cursor, conn, debug=False):
	module = setupscan['module']
	method = setupscan['setup']
	if debug:
		print >>sys.stderr, module, method
		sys.stderr.flush()

	if setupscan['needsdatabase'] and not usedatabase:
		return (False, {})

	try:
		exec "from %s import %s as bat_%s" % (module, method, method)
	except Exception, e:
		return (False, {})
	scanres = locals()["bat_%s" % method](setupscan['environment'], cursor, conn, debug=debug)
	return scanres

## convenience method to run the genericMarkerSearch in parallel chunks if needed
def paralleloffsetsearch((filedir, filename, magicscans, optmagicscans, offset, length)):
	return prerun.genericMarkerSearch(os.path.join(filedir, filename), magicscans, optmagicscans, offset, length)

## method to filter scans, based on the tags that were found for a
## file, plus a list of tags that the scan should skip.
## This is done to avoid scans running unnecessarily.
def filterScans(scans, tags):
	filteredscans = []
	for scan in scans:
		if scan['scanonly'] != None:
			scanonly = scan['scanonly'].split(':')
			if set(tags).intersection(set(scanonly)) == set():
				continue
		if scan['noscan'] != None:
			noscans = scan['noscan'].split(':')
			if set(noscans).intersection(set(tags)) != set():
				continue
			else:
				filteredscans.append(scan)
		else:
			filteredscans.append(scan)
	return filteredscans

## compute a SHA256, and possibly other hashes as well. This is done in chunks
## to prevent a big file from being read in its entirety at once, slowing down
## the machine.
def gethash(filepath, filename, hashtypes, tlshmaxsize):
	hashestocompute = set()
	## always compute SHA256
	hashestocompute.add('sha256')
	for hashtype in hashtypes:
		hashestocompute.add(hashtype)

	hashresults = {}

	## initiate new hashing objects, except for CRC32
	## and TLSH, which need to be treated slightly differently
	hashdict = {}
	for h in hashestocompute:
		if h == 'crc32' or h == 'tlsh':
			continue
		hashdict[h] = hashlib.new(h)

	scanfile = open(os.path.join(filepath, filename), 'rb')
	scanfile.seek(0)
	hashdata = scanfile.read(10000000)
	while hashdata != '':
		for h in hashestocompute:
			## CRC32 is not yet supported, TLSH is
			## processed later
			if h == 'crc32' or h == 'tlsh':
				continue
			hashdict[h].update(hashdata)
		hashdata = scanfile.read(10000000)
	scanfile.close()
	for h in hashestocompute:
		if h == 'crc32' or h == 'tlsh':
			continue
		hashresults[h] = hashdict[h].hexdigest()
	filesize = os.stat(os.path.join(filepath, filename)).st_size

	## compute TLSH, as long as it is not too big (determined by tlshmaxsize)
	if 'tlsh' in hashestocompute:
		if tlshscan:
			if filesize >= 256 and filesize <= tlshmaxsize:
				scanfile = open(os.path.join(filepath, filename), 'rb')
				scanfile.seek(0)
				hashdata = scanfile.read()
				scanfile.close()
				hashresults['tlsh'] = tlsh.hash(hashdata)
			else:
				hashresults['tlsh'] = None
	return hashresults

## continuously grab tasks (files) from a queue, tag ('prerun phase'), possibly unpack
## and recurse ('unpack'). Then run different scans per file ('leaf').
def scan(scanqueue, reportqueue, scans, leafscans, prerunscans, prerunignore, prerunmagic, magicscans, optmagicscans, processid, hashdict, llock, template, unpacktempdir, topleveldir, tempdir, outputhash, cursor, conn, scansourcecode, dumpoffsets, offsetdir, compressed, timeout, scan_binary_basename, tlshmaxsize):
	lentempdir = len(tempdir)
	sourcecodequery = "select checksum from processed_file where checksum=%s limit 1"

	## import all methods defined in the scans, once per thread
	## ignore all scans that cannot be loaded successfully
	blacklistscans = set()
	for prerunscan in prerunscans:
		module = prerunscan['module']
		method = prerunscan['method']
		try:
			exec "from %s import %s as bat_%s" % (module, method, method)
		except Exception, e:
			blacklistscans.add((module, method))
			continue

	for unpackscan in scans:
		module = unpackscan['module']
		method = unpackscan['method']
		try:
			exec "from %s import %s as bat_%s" % (module, method, method)
		except Exception, e:
			blacklistscans.add((module, method))
			continue

	for leafscan in leafscans:
		module = leafscan['module']
		method = leafscan['method']
		try:
			exec "from %s import %s as bat_%s" % (module, method, method)
		except Exception, e:
			blacklistscans.add((module, method))
			continue

	## grab tasks from the queue continuously until there are no more tasks left
	while True:
		## reset the reports, blacklist, offsets and tags for each new scan
		blacklist = []
		(dirname, filename, lenscandir, debug, tags, scanhints, offsets) = scanqueue.get(timeout=timeout)

		if debug:
			## record the time when processing of the file started
			## in case debugging is enabled.
			starttime = datetime.datetime.utcnow().isoformat()

		## absolute path of the file in the file system (so including temporary dir)
		filetoscan = os.path.join(dirname, filename)

		## path of the file relative to the temporary dir
		relfiletoscan = filetoscan[lentempdir:]
		if relfiletoscan.startswith('/'):
			relfiletoscan = relfiletoscan[1:]

		## initialize the result dictionary
		unpackreports = {}
		unpackreports['name'] = filename

		## use libmagic to find out the 'magic' of the file for reporting
		## It cannot properly handle file names with 'exotic' encodings,
		## so wrap it in a try statement and provide a default value of
		## 'data'.
		magic = 'data'
		try:
			magic = ms.file(filetoscan)
		except Exception, e:
			## libmagic could not handle it, likely because of an encoding
			## issue (name with 'weird' characters, so try to workaround the
			## problem. In case of a regular file (anything but a link) copy
			## the file to a temporary location with a file name that libmagic
			## will be able to handle.
			if not os.path.islink(filetoscan):
				tmpmagic = tempfile.mkstemp()
				os.fdopen(tmpmagic[0]).close()
				shutil.copy(filetoscan, tmpmagic[1])
				magic = ms.file(tmpmagic[1])
				os.unlink(tmpmagic[1])
			else:
				## TODO: create a better value for 'magic'
				magic = 'symbolic link'
		unpackreports['magic'] = magic

		## Add both the path to indicate the position inside the file sytem
        	## or file that was unpacked, as well as the position of the files as unpacked
		## by BAT, convenient for later analysis of binaries.
		## In case of squashfs remove the "squashfs-root" part of the temporary
		## directory too, if it is present (not always).
		## TODO: validate if this is stil needed
		storepath = dirname[lenscandir:].replace("/squashfs-root", "")
		unpackreports['path'] = storepath
		unpackreports['realpath'] = dirname
		unpackreports['relativename'] = relfiletoscan

		## if the file is a symbolic link, then there is not much
		## to report about it, so continue.
		if os.path.islink(filetoscan):
			tags.append('symlink')
			unpackreports['tags'] = tags
			reportqueue.put({relfiletoscan: unpackreports})
			scanqueue.task_done()
			continue

		## no use to further check pipes, sockets, device files, etcetera
		if not os.path.isfile(filetoscan) and not os.path.isdir(filetoscan):
			reportqueue.put({relfiletoscan: unpackreports})
			scanqueue.task_done()
			continue

		## store the size of the file
		filesize = os.lstat(filetoscan).st_size
		unpackreports['size'] = filesize

		## empty file, not interested in further scanning
		if filesize == 0:
			tags.append('empty')
			unpackreports['tags'] = tags
			reportqueue.put({relfiletoscan: unpackreports})
			scanqueue.task_done()
			continue

		## Store the hash of the file for identification and for possibly
		## querying the knowledgebase later on.
		filehashresults = gethash(dirname, filename, [outputhash, 'sha1', 'md5', 'tlsh'], tlshmaxsize)
		unpackreports['checksum'] = filehashresults[outputhash]
		for u in filehashresults:
			unpackreports[u] = filehashresults[u]
		filehash = filehashresults[outputhash]

		exactmatches = []
		seenbefore = False
		if cursor != None:
			cursor.execute("select pathname, parentname, parentchecksum from batresult where checksum=%s", (filehash,))
			res = cursor.fetchall()
			if res != []:
				seenbefore = True
				for r in res:
					exactmatches.append(res)

		blacklistedfiles = []
		if cursor != None:
			pass
		## blacklisted file, not interested in further scanning
		if filehash in blacklistedfiles:
			tags.append('blacklisted')
			unpackreports['tags'] = tags
			reportqueue.put({relfiletoscan: unpackreports})
			scanqueue.task_done()
			continue

		## acquire the lock for the shared dictionary to see if this file was already
		## scanned, or is in the process of being scanned.
		llock.acquire()
		if filehash in hashdict:
			llock.release()
			## if the hash is already there mark it as a
			## duplicate and stop scanning.
			unpackreports['tags'] = ['duplicate']
			reportqueue.put({relfiletoscan: unpackreports})
			scanqueue.task_done()
			continue
		else:
			## add the file to the shared dictionary
			hashdict[filehash] = relfiletoscan
			llock.release()

		## look up the file in the BAT database to see if it is
		## a known source code file.
		if scansourcecode:
			cursor.execute(sourcecodequery, (filehash,))
			fetchres = cursor.fetchone()
			if fetchres != None:
				tags.append('inbatdb')
				tags.append('sourcecode')

		## first see if a shortcut can be taken to unpack the file
		## directly based on its extension.
		unpacked = False
		knownfile = False
		if 'knownfile' in scanhints:
			knownfile = scanhints['knownfile']
			unpacked = True
		else:
			blacklistignorescans = set()
			if "blacklistignorescans" in scanhints:
				blacklistignorescans = scanhints['blacklistignorescans']

			for unpackscan in scans:
				if not 'knownfilemethod' in unpackscan:
					continue
				fileextensions = filename.lower().rsplit('.', 1)
				if len(fileextensions) != 2:
					continue
				fileextension = fileextensions[1]
				if not fileextension in unpackscan['extensions']:
					continue
				module = unpackscan['module']
				method = unpackscan['knownfilemethod']
				if 'minimumsize' in unpackscan:
					if filesize < unpackscan['minimumsize']:
						continue
				if debug:
					print >>sys.stderr, module, method, filetoscan, datetime.datetime.utcnow().isoformat()
					sys.stderr.flush()

				## make a copy before changing the environment
				newenv = copy.deepcopy(unpackscan['environment'])

				if template != None:
					templen = len(re.findall('%s', template))
					if templen == 2:
						newenv['TEMPLATE'] = template % (os.path.basename(filetoscan), unpackscan['name'])
					elif templen == 1:
						newenv['TEMPLATE'] = template % unpackscan['name']
					else:
						newenv['TEMPLATE'] = template
				try:
					exec "from %s import %s as bat_%s" % (module, method, method)
				except Exception, e:
					continue

				## run the known unpack method
				scanres = eval("bat_%s(filetoscan, tempdir, newenv, debug=debug)" % (method))
				if scanres == ([], [], [], {}):
					## no result, so move on to the next scan
					continue
				(diroffsets, blacklist, scantags, hints) = scanres
				newblacklist = []
				for b in blacklist:
					if len(b) == 2:
						b = b + (unpackscan['name'],)
					newblacklist.append(b)
				blacklist = newblacklist
				tags = list(set(tags + scantags))
				knownfile = True
				unpacked = True
				unpackreports['scans'] = []

				## special case: the whole file was unpacked and blacklisted
				## but 'blacklistignorescans' was set. Resubmitting into the queue is
				## not a possibility
				if len(diroffsets) == 0:
					if filetoscan in hints:
						if 'blacklistignorescans' in hints[filetoscan]:
							blacklistignorescans = hints[filetoscan]['blacklistignorescans']

				## Add all the files found to the scan queue
				## each diroffset is a (path, offset) tuple
				for diroffset in diroffsets:
					if diroffset == None:
						continue
					report = {}
					scandir = diroffset[0]

					## recursively scan all files in the directory
					osgen = os.walk(scandir)
					scanreports = []
					try:
       						while True:
							i = osgen.next()
							## make sure all directories can be accessed
							for d in i[1]:
								directoryname = os.path.join(i[0], d)
								if not os.path.islink(directoryname):
									os.chmod(directoryname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
							for p in i[2]:
								leaftags = []
								filepathname = os.path.join(i[0], p)
								try:
									if not os.path.islink(filepathname):
										os.chmod(filepathname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
									scannerhints = {}
									if filepathname in hints:
										if 'tags' in hints[filepathname]:
											leaftags = list(set(leaftags + hints[filepathname]['tags']))
										if 'scanned' in hints[filepathname]:
											if hints[filepathname]['scanned']:
												scannerhints['knownfile'] = True
										for sc in hints[filepathname]:
											scannerhints[sc] = copy.deepcopy(hints[filepathname][sc])
									if "temporary" in tags and diroffset[1] == 0 and diroffset[2] == filesize:
										leaftags.append('temporary')
									scantask = (i[0], p, len(scandir), debug, leaftags, scannerhints, {})
									scanqueue.put(scantask)
									relscanpath = "%s/%s" % (i[0][lentempdir:], p)
									if relscanpath.startswith('/'):
										relscanpath = relscanpath[1:]
									scanreports.append(relscanpath)
								except Exception, e:
									pass
					except StopIteration:
						pass
					unpackreports['scans'].append({'scanname': unpackscan['name'], 'scanreports': scanreports, 'offset': diroffset[1], 'size': diroffset[2]})
				break

		if not knownfile or 'blacklistignorescans' in scanhints:
			## scan for markers in case they are not already known
			if offsets == {}:
				(offsets, offsetkeys, isascii) = prerun.genericMarkerSearch(filetoscan, magicscans, optmagicscans)
				if isascii:
					tags.append('text')
				else:
					tags.append('binary')

		if dumpoffsets:
			## write pickles with offsets to disk
			offsetpicklename = os.path.join(offsetdir, '%s-offsets.pickle' % filehash)
			if compressed:
				checkoffsetpicklename = "%s.gz" % offsetpicklename
			else:
				checkoffsetpicklename = offsetpicklename
			try:
				os.stat(checkoffsetpicklename)
			except:
				picklefile = open(offsetpicklename, 'wb')
				cPickle.dump(offsets, picklefile)
				picklefile.close()

				## optionally compress the pickle files to save space
				if compressed:
					fin = open(offsetpicklename, 'rb')
					fout = gzip.open("%s.gz" % offsetpicklename, 'wb')
					fout.write(fin.read())
					fout.close()
					fin.close()
					os.unlink(fin.name)

		if "encrypted" in tags:
			knownfile = True

		blacklisted = False
		if not knownfile or 'blacklistignorescans' in scanhints:
			## all offsets are known now, so scans that are not needed can
			## be filtered out. Also keep track of the "most promising" scans
			## (offset 0) to try them first.
			filterscans = set()
			zerooffsets = set()
			for magictype in offsets:
				if offsets[magictype] != []:
					filterscans.add(magictype)
					if offsets[magictype][0] - fsmagic.correction.get(magictype, 0) == 0:
						zerooffsets.add(magictype)

			## prerun scans should be run before any of the other scans
			for prerunscan in prerunscans:
				ignore = False
				if 'extensionsignore' in prerunscan:
					extensionsignore = prerunscan['extensionsignore'].split(':')
					for e in extensionsignore:
						if filetoscan.endswith(e):
							ignore = True
							break
				if ignore:
					continue
				if prerunscan['name'] in prerunignore:
					if set(tags).intersection(set(prerunignore[prerunscan['name']])) != set():
						continue
				if prerunscan['name'] in prerunmagic:
					if set(prerunmagic[prerunscan['name']]).intersection(filterscans) == set():
						continue
				module = prerunscan['module']
				method = prerunscan['method']
				if (module, method) in blacklistscans:
					continue
				if debug:
					print >>sys.stderr, module, method, filetoscan, datetime.datetime.utcnow().isoformat()
					sys.stderr.flush()

				scantags = locals()['bat_%s' % method](filetoscan, cursor, conn, tempdir, tags, offsets, prerunscan['environment'], debug=debug, unpacktempdir=unpacktempdir, filehashes=filehashresults)
				## append the tag results. These will be used later to be able to specifically filter
				## out files
				if scantags != []:
					tags = tags + scantags

			## Reorder the scans based on information about offsets. If one scan has a
			## match for offset 0 (after correction of the offset, like for tar, gzip,
			## iso9660, etc.) make sure it is run first (not enabled now, unsafe in some
			## cases).
			unpackscans = []
			scanfirst = []

			## Filter scans
			filteredscans = filterScans(scans, tags)
			for unpackscan in filteredscans:
				## filter the scan again as the tags might have changed
				if unpackscan['noscan'] != None:
					noscans = unpackscan['noscan'].split(':')
					if set(noscans).intersection(set(tags)) != set():
						continue
				if unpackscan['magic'] != None:
					scanmagic = unpackscan['magic'].split(':')
					if set(scanmagic).intersection(filterscans) != set():
						if set(scanmagic).intersection(zerooffsets) != set():
							if unpackscan['name'] != 'lzma':
								scanfirst.append(unpackscan)
							else:
								unpackscans.append(unpackscan)
						else:
							unpackscans.append(unpackscan)
				else:
					unpackscans.append(unpackscan)

			## sort 'unpackscans' in decreasing priority, so highest
			## priority scans are run first.
			unpackscans = sorted(unpackscans, key=lambda x: x['priority'], reverse=True)

			## prepend the most promising scans at offset 0 (if any)
			scanfirst = sorted(scanfirst, key=lambda x: x['priority'], reverse=True)
			unpackscans = scanfirst + unpackscans

			unpackreports['scans'] = []

			blacklistignorescans = set()
			if "blacklistignorescans" in scanhints:
				blacklistignorescans = scanhints['blacklistignorescans']

			unpacked = False
			for unpackscan in unpackscans:
				blacklistignored = False
				if extractor.inblacklist(0, blacklist) == filesize:
					## the whole file has already been scanned by other scans, so
					## continue with the leaf scans.
					blacklisted = True
					if len(blacklistignorescans) == 0:
						break
					if not unpackscan['name'] in blacklistignorescans:
						continue

					## store a copy of the old blacklist
					blacklistignored = True
					oldblacklist = copy.deepcopy(blacklist)
					blacklist = []

				if 'minimumsize' in unpackscan:
					if filesize < unpackscan['minimumsize']:
						continue

				if unpackscan['noscan'] != None:
					noscans = unpackscan['noscan'].split(':')
					if list(set(tags).intersection(set(noscans))) != []:
						continue
		
				ignore = False
				if 'extensionsignore' in unpackscan:
					extensionsignore = unpackscan['extensionsignore'].split(':')
					for e in extensionsignore:
						if filetoscan.endswith(e):
							ignore = True
						break
				if ignore:
					continue
				module = unpackscan['module']
				method = unpackscan['method']
				if (module, method) in blacklistscans:
					continue
				if debug:
					print >>sys.stderr, module, method, filetoscan, datetime.datetime.utcnow().isoformat()
					sys.stderr.flush()

				## make a copy before changing the environment
				newenv = copy.deepcopy(unpackscan['environment'])
				newenv['BAT_UNPACKED'] = unpacked

				if template != None:
					templen = len(re.findall('%s', template))
					if templen == 2:
						newenv['TEMPLATE'] = template % (os.path.basename(filetoscan), unpackscan['name'])
					elif templen == 1:
						newenv['TEMPLATE'] = template % unpackscan['name']
					else:
						newenv['TEMPLATE'] = template

				## return value is the temporary dir, plus offset in the parent file
				## plus a blacklist containing blacklisted ranges for the *original*
				## file and a hash with offsets for each marker.
				scanres = locals()["bat_%s" % method](filetoscan, tempdir, blacklist, offsets, newenv, debug=debug)
				## result is either empty, or contains offsets, blacklist, tags and hints
				if len(scanres) == 0:
					continue
				if len(scanres) != 4:
					continue
				(diroffsets, blacklist, scantags, hints) = scanres
				tags = list(set(tags + scantags))
				if extractor.inblacklist(0, blacklist) == filesize:
					blacklisted = True

				## special case: the whole file was unpacked and blacklisted
				## but 'blacklistignorescans' was set. Resubmitting into the queue is
				## not a possibility
				if len(diroffsets) == 0:
					if filetoscan in hints:
						if 'blacklistignorescans' in hints[filetoscan]:
							blacklistignorescans = hints[filetoscan]['blacklistignorescans']
				for diroffset in diroffsets:
					if diroffset == None:
						continue
					unpacked = True
					report = {}
					scandir = diroffset[0]

					## recursively scan all files in the directory
					osgen = os.walk(scandir)
					scanreports = []
					try:
       						while True:
                					i = osgen.next()
							## make sure all directories can be accessed
							for d in i[1]:
								directoryname = os.path.join(i[0], d)
								if not os.path.islink(directoryname):
									os.chmod(directoryname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
                					for p in i[2]:
								filepathname = os.path.join(i[0], p)
								try:
									leaftags = []
									scannerhints = {}
									if not os.path.islink(filepathname):
										os.chmod(filepathname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
									if filepathname in hints:
										if 'tags' in hints[filepathname]:
											leaftags = list(set(leaftags + hints[filepathname]['tags']))
										if 'scanned' in hints[filepathname]:
											if hints[filepathname]['scanned']:
												scannerhints['knownfile'] = True
												## TODO: add offsets if available
										for sc in hints[filepathname]:
											scannerhints[sc] = copy.deepcopy(hints[filepathname][sc])
									if "temporary" in tags and diroffset[1] == 0 and diroffset[2] == filesize:
										leaftags.append('temporary')
									scantask = (i[0], p, len(scandir), debug, leaftags, scannerhints, {})
									scanqueue.put(scantask)
									relscanpath = "%s/%s" % (i[0][lentempdir:], p)
									if relscanpath.startswith('/'):
										relscanpath = relscanpath[1:]
									scanreports.append(relscanpath)
								except Exception, e:
									pass
					except StopIteration:
						pass
					unpackreports['scans'].append({'scanname': unpackscan['name'], 'scanreports': scanreports, 'offset': diroffset[1], 'size': diroffset[2]})
				newblacklist = []
				for b in blacklist:
					if len(b) == 2:
						b = b + (unpackscan['name'],)
					newblacklist.append(b)
				blacklist = newblacklist
				if blacklistignored:
					## restore the old blacklist
					blacklist = copy.deepcopy(oldblacklist)
					## add anything new
					for b in newblacklist:
						blacklist.append(b)

		blacklist.sort()

		carveout = False
		if carveout and not (blacklisted or knownfile):
			if blacklist != []:
				## TODO: make configurable
				if not 'elf' in tags:
					counter = 1
					byteoffset = 0
					prevblacklist = (0,0)
					origfile = open(filetoscan, 'r')
					for r in range(0, len(blacklist)):
						b = blacklist[r]
						if byteoffset == b[0]:
							byteoffset = b[1]
							prevblacklist = b
							continue

						origfile.seek(prevblacklist[1])

						try:
							tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filetoscan), os.path.basename(filetoscan), "carveout", counter)
							os.makedirs(tmpdir)
							carveoutfile = open(os.path.join(tmpdir, "carveout"), 'w')
							carveoutfile.write(origfile.read(b[0] - prevblacklist[1]))
							carveoutfile.close()
							## now write the data
							counter += 1
						except Exception, e:
							break
						byteoffset = b[1]
						prevblacklist = b
					if filesize > byteoffset:
						try:
							origfile.seek(prevblacklist[1])
							tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filetoscan), os.path.basename(filetoscan), "carveout", counter)
							os.makedirs(tmpdir)
							carveoutfile = open(os.path.join(tmpdir, "carveout"), 'w')
							carveoutfile.write(origfile.read(filesize - prevblacklist[1]))
							carveoutfile.close()
							## now write the data
							counter += 1
						except Exception, e:
							pass
					origfile.close()

		unpackreports['tags'] = tags
		if not unpacked and 'temporary' in tags:
			os.unlink(filetoscan)
			reportqueue.put({relfiletoscan: unpackreports})
		else:
			reports = {}

			## First compute the closest
			## a threshold for TLSH for the files to be considered similar.
			## TODO: make configurable
			tlshthreshold = 60
			closestfile = None
			if cursor != None:
				if tlshscan and not seenbefore:
					if 'tlsh' in filehashresults:
						if filehashresults['tlsh'] != None:
							tlshminimum = sys.maxint
							decoded = False
							for i in ['utf-8','ascii','latin-1','euc_jp', 'euc_jis_2004', 'jisx0213', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr','shift_jis','shift_jis_2004','shift_jisx0213']:
								try:
									decodefilename = u.decode(i)
									decoded = True
									break
								except Exception, e:
									pass

							if decoded:
								cursor.execute("select tlsh, pathname, parentname, parentchecksum from batresult where filename=%s", (decodefilename,))
							else:
								cursor.execute("select tlsh, pathname, parentname, parentchecksum from batresult where filename=%s", (filename,))
							res = cursor.fetchall()
							for r in res:
								(tlshchecksum, tlshpathname, parentname, parentchecksum) = r
								if tlshchecksum == None:
									continue
								tlshdistance = tlsh.diff(filehashresults['tlsh'], tlshchecksum)
								if tlshdistance < tlshminimum:
									tlshminimum = tlshdistance
							if tlshminimum < tlshthreshold:
								closestfile = (tlshpathname, parentname, tlshdistance)
			if closestfile != None:
				reports['closematch'] = closestfile
				tags.append('closematch')

			if seenbefore:
				reports['exactbinarymatches'] = exactmatches
				tags.append('exactbinarymatch')

			## run the leaf scans for the file
			for leafscan in filterScans(leafscans, tags):
				## filter the scan again as the tags might have changed
				if leafscan['noscan'] != None:
					noscans = leafscan['noscan'].split(':')
					if set(noscans).intersection(set(tags)) != set():
						continue

				ignore = False
				if 'extensionsignore' in leafscan:
					extensionsignore = leafscan['extensionsignore'].split(':')
					for e in extensionsignore:
						if filetoscan.endswith(e):
							ignore = True
							break
				if ignore:
					continue
				report = {}
				module = leafscan['module']
				method = leafscan['method']

				if (module, method) in blacklistscans:
					continue

				scandebug = False
				if 'debug' in leafscan:
					scandebug = True
					debug = True

				if debug:
					print >>sys.stderr, module, method, filetoscan, datetime.datetime.utcnow().isoformat()
					sys.stderr.flush()
					scandebug = True

				res = eval("bat_%s(filetoscan, tags, cursor, conn, filehashresults, blacklist, leafscan['environment'], scandebug=scandebug, unpacktempdir=unpacktempdir)" % (method))
				if res != None:
					(nt, leafres) = res
					reports[leafscan['name']] = leafres
					tags += list(set(tags + nt))

			reports['tags'] = list(set(tags))
			unpackreports['tags'] = list(set(unpackreports['tags'] + reports['tags']))

			## write pickles with information to disk here to reduce memory usage
			try:
				os.stat('%s/filereports/%s-filereport.pickle' % (topleveldir,filehash))
			except Exception, e:
				picklefile = open('%s/filereports/%s-filereport.pickle' % (topleveldir,filehash), 'wb')
				cPickle.dump(reports, picklefile)
				picklefile.close()
			reportqueue.put({relfiletoscan: unpackreports})
		if debug:
			print >>sys.stderr, "DONE", filetoscan, starttime, datetime.datetime.utcnow().isoformat()
			sys.stderr.flush()
		scanqueue.task_done()

def aggregatescan(unpackreports, aggregatescans, processors, scantempdir, topleveldir, scan_binary, scandate, batcursors, batcons, debug, unpacktempdir):
	## aggregate scans look at the entire result and possibly modify it.
	## The best example is JAR files: individual .class files will not be
	## very significant (or even insignificant), but combined results are.
	## Because aggregate scans have to look at everything as a whole, these
	## cannot be run in parallel.

	statistics = {}

	for aggregatescan in aggregatescans:
		module = aggregatescan['module']
		method = aggregatescan['method']

		scandebug = False
		if 'debug' in aggregatescan:
			scandebug = True
			debug = True

		starttime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "AGGREGATE BEGIN", module, method, starttime.isoformat()
			sys.stderr.flush()
			scandebug = True

		try:
			exec "from %s import %s as bat_%s" % (module, method, method)
		except Exception, e:
			continue

		res = eval("bat_%s(unpackreports, scantempdir, topleveldir, processors, aggregatescan['environment'], batcursors, batcons, scandebug=scandebug, unpacktempdir=unpacktempdir)" % (method))
		if res != None:
			if res.keys() != []:
				filehash = unpackreports[scan_binary]['checksum']
				leaf_file_path = os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)
				leaf_file = open(leaf_file_path, 'rb')
				leafreports = cPickle.load(leaf_file)
				leaf_file.close()

				for reskey in set(res.keys()):
					leafreports[reskey] = res[reskey]
					unpackreports[scan_binary]['tags'].append(reskey)
					leafreports['tags'].append(reskey)

				leaf_file = open(leaf_file_path, 'wb')
				leafreports = cPickle.dump(leafreports, leaf_file)
				leaf_file.close()
		endtime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "AGGREGATE END", method, endtime.isoformat()
		statistics[method] = endtime - starttime
	return statistics

## continuously grab tasks (files) from a queue and process
def postrunscan(scanqueue, postrunscans, topleveldir, scantempdir, cursor, conn, debug, timeout):

	## import all methods defined in the scans
	blacklistscans = set()
	extensionsignore = []

	for postrunscan in postrunscans:
		module = postrunscan['module']
		method = postrunscan['method']
		try:
			exec "from %s import %s as bat_%s" % (module, method, method)
		except Exception, e:
			blacklistscans.add((module, method))
			continue
		ignore = False
		if 'extensionsignore' in postrunscan:
			extensionsignore = postrunscan['extensionsignore'].split(':')

	## grab tasks from the queue continuously until there are no more tasks
	while True:
		(filetoscan, unpackreports) = scanqueue.get(timeout=timeout)
		ignore = False
		for e in extensionsignore:
			if filetoscan.endswith(e):
				ignore = True
				break
		if ignore:
			scanqueue.task_done()
			continue
		for postrunscan in postrunscans:
			module = postrunscan['module']
			method = postrunscan['method']
			res = eval("bat_%s(filetoscan, unpackreports, scantempdir, topleveldir, postrunscan['environment'], cursor, conn, debug=debug)" % (method))
			## TODO: find out what to do with this
			if res != None:
				pass
		scanqueue.task_done()

## process a single configuration section
def scanconfigsection(config, section, scanenv, batconf):
	if config.has_option(section, 'type'):
		debug = False
		mandatory = False
		## some scans are mandatory
		if not config.has_option(section, 'mandatory'):
			if config.get(section, 'enabled') == 'yes':
				mandatory = True

		## scans have to be explicitely enabled
		if not config.has_option(section, 'enabled'):
			return
		if config.get(section, 'enabled') == 'no':
			if not mandatory:
				return
			else:
				## TODO: figure out the cleanest way to
				## handle this, probably passing some
				## error message back
				return
		conf = {}

		try:
			conf['module'] = config.get(section, 'module')
			conf['method'] = config.get(section, 'method')
		except Exception, e:
			return

		## some scans might, or might not, have these defined
		try:
			conf['name']   = config.get(section, 'name')
		except:
			conf['name']   = section

		## deal with the environment
		newenv = copy.deepcopy(scanenv)
		try:
			envvars = config.get(section, 'envvars')
			if envvars == None:
				pass
			else:
				for en in envvars.split(':'):
					try:
						(envname, envvalue) = en.split('=')
						newenv[envname] = envvalue
					except Exception, e:
						print >>sys.stderr, "EXCEPTION", e
						pass
		except:
			pass

		conf['environment'] = newenv
		try:
			conf['magic'] = config.get(section, 'magic')
		except:
			conf['magic'] = None
		try:
			conf['optmagic'] = config.get(section, 'optmagic')
		except:
			conf['optmagic'] = None
		try:
			conf['noscan'] = config.get(section, 'noscan')
		except:
			conf['noscan'] = None
		try:
			conf['scanonly'] = config.get(section, 'scanonly')
		except:
			conf['scanonly'] = None
		try:
			conf['extensionsignore'] = config.get(section, 'extensionsignore')
		except:
			pass
		try:
			conf['minimumsize'] = max(0, int(config.get(section, 'minimumsize')))
		except:
			pass
		try:
			scandebug = config.get(section, 'debug')
			if scandebug == 'yes':
				debug = True
				conf['debug'] = True
		except:
			pass
		try:
			parallel = config.get(section, 'parallel')
			if parallel == 'yes':
				conf['parallel'] = True
			else:
				conf['parallel'] = False
		except:
			conf['parallel'] = True
		try:
			conf['priority'] = int(config.get(section, 'priority'))
		except:
			conf['priority'] = 0
		try:
			conf['ppoutput'] = config.get(section, 'ppoutput')
		except:
			pass
		try:
			conf['setup'] = config.get(section, 'setup')
		except:
			pass
		try:
			needsdatabase = config.get(section, 'needsdatabase')
			if needsdatabase == 'yes':
				conf['needsdatabase'] = True
			else:
				conf['needsdatabase'] = False
		except:
			conf['needsdatabase'] = False
		try:
			conf['conflicts'] = config.get(section, 'conflicts').split(':')
		except:
			pass
		try:
			conf['extensions'] = config.get(section, 'extensions').split(':')
		except:
			pass
		try:
			conf['knownfilemethod'] = config.get(section, 'knownfilemethod')
		except:
			pass

		## some things only make sense in a particular context
		if config.get(section, 'type') == 'postrun' or config.get(section, 'type') == 'aggregate':
			try:
				## all three parameters should be there together
				conf['storedir'] = config.get(section, 'storedir')
				conf['storetarget'] = config.get(section, 'storetarget')
				conf['storetype'] = config.get(section, 'storetype')
				try:
					cleanup = config.get(section, 'cleanup')
					if cleanup == 'yes':
						conf['cleanup'] = True
					else:
						conf['cleanup'] = False
				except:
					conf['cleanup'] = False
			except:
				conf['storedir'] = None
				conf['storetarget'] = None
				conf['storetype'] = None
				conf['cleanup'] = False
			try:
				compress = config.get(section, 'compress')
				if compress == 'yes':
					conf['compress'] = True
				else:
					conf['compress'] = False
			except:
				## copy the defaulf from batconf, if any, otherwise
				## default to no compression
				if 'compress' in batconf:
					conf['compress'] = batconf['compress']
				else:
					conf['compress'] = False

		## finally add the configurations to the right list
		if config.get(section, 'type') == 'leaf':
			if debug:
				return(conf, 'leaf', 'leaf')
			return(conf, 'leaf', None)
		elif config.get(section, 'type') == 'unpack':
			if debug:
				return(conf, 'unpack', 'unpack')
			return(conf, 'unpack', None)
		elif config.get(section, 'type') == 'prerun':
			if debug:
				return(conf, 'prerun', 'prerun')
			return(conf, 'prerun', None)
		elif config.get(section, 'type') == 'postrun':
			if debug:
				return(conf, 'postrun', 'postrun')
			return(conf, 'postrun', None)
		elif config.get(section, 'type') == 'aggregate':
			if debug:
				return(conf, 'aggregate', 'aggregate')
			return(conf, 'aggregate', None)

## arrays for storing data for the scans
## unpackscans: {name, module, method, ppoutput, priority}
## These are sorted by priority
## leafscans: {name, module, method, ppoutput}
def readconfig(config, configfilename):
	unpackscans = []
	leafscans = []
	prerunscans = []
	postrunscans = []
	aggregatescans = []
	errors = []
	batconf = {}
	tmpbatconfdebug = set()

	## first create an environment so every scan has the same one
	oldenv = os.environ.copy()
	scanenv = {}

	for i in ['PATH', 'PWD', 'HOME', 'HOSTNAME', 'LANG', 'USER']:
		if i in oldenv:
			scanenv[i] = copy.deepcopy(oldenv[i])

	sectionstoprocess = set()

	sectionsseen = set()
	## process sections, make sure that the global configuration is
	## always processed first.
	for section in config.sections():
		if section != "batconfig":
			sectionstoprocess.add(section)
			continue

		## first set the environment
		newenv = copy.deepcopy(scanenv)
		try:
			## global set of environment variables
			envvars = config.get(section, 'envvars')
			if envvars == None:
				pass
			else:
				for en in envvars.split(':'):
					try:
						(envname, envvalue) = en.split('=')
						newenv[envname] = envvalue
					except Exception, e:
						pass
		except:
			pass
		batconf['environment'] = newenv

		try:
			mp = config.get(section, 'multiprocessing')
			if mp == 'yes':
				batconf['multiprocessing'] = True
			else:
				batconf['multiprocessing'] = False
		except:
			batconf['multiprocessing'] = False
		try:
			batconf['output'] = config.get(section, 'output')
			batconf['module'] = config.get(section, 'module')
			batconf['method'] = config.get(section, 'method')
		except:
			pass
		try:
			reporthash = config.get(section, 'reporthash')
			## TODO: make more configurable, perform checks, etc. etc.
			if reporthash in ['sha256', 'sha1', 'md5', 'crc32']:
				batconf['reporthash'] = reporthash
		except:
			pass
		try:
			batconf['processors'] = int(config.get(section, 'processors'))
		except:
			pass
		try:
			packconfig = config.get(section, 'packconfig')
			if packconfig == 'yes':
				batconf['packconfig'] = True
			else:
				batconf['packconfig'] = False
		except:
			batconf['packconfig'] = False
		try:
			scansourcecode = config.get(section, 'scansourcecode')
			if scansourcecode == 'yes':
				batconf['scansourcecode'] = True
			else:
				batconf['scansourcecode'] = False
		except:
			batconf['scansourcecode'] = False
		try:
			dumpoffsets = config.get(section, 'dumpoffsets')
			if dumpoffsets == 'yes':
				batconf['dumpoffsets'] = True
			else:
				batconf['dumpoffsets'] = False
		except:
			batconf['dumpoffsets'] = False
		try:
			packconfig = config.get(section, 'cleanup')
			if packconfig == 'yes':
				batconf['cleanup'] = True
			else:
				batconf['cleanup'] = False
		except:
			batconf['cleanup'] = False
		try:
			extrapack = config.get(section, 'extrapack')
			batconf['extrapack'] = extrapack.split(':')
		except:
			batconf['extrapack'] = []
		try:
			scrub = config.get(section, 'scrub')
			batconf['scrub'] = scrub.split(':')
		except:
			batconf['scrub'] = []
		try:
			markersearchminimum = int(config.get(section, 'markersearchminimum'))
			batconf['markersearchminimum'] = markersearchminimum
		except:
			## set a default minimum threshold of 20 million bytes
			batconf['markersearchminimum'] = 20000000
		try:
			tasktimeout = int(config.get(section, 'tasktimeout'))
			batconf['tasktimeout'] = tasktimeout
		except:
			## set a default minimum threshold of a month
			batconf['tasktimeout'] = 2592000
		try:
			postgresql_user = config.get(section, 'postgresql_user')
			postgresql_password = config.get(section, 'postgresql_password')
			postgresql_db = config.get(section, 'postgresql_db')

			## check to see if a host (IP-address) was supplied either
			## as host or hostaddr. hostaddr is not supported on older
			## versions of psycopg2, for example CentOS 6.6, so it is not
			## used at the moment.
			try:
				postgresql_host = config.get(section, 'postgresql_host')
			except:
				postgresql_host = None
			try:
				postgresql_hostaddr = config.get(section, 'postgresql_hostaddr')
			except:
				postgresql_hostaddr = None

			## check to see if a port was specified. If not, default to 'None'
			try:
				postgresql_port = config.get(section, 'postgresql_port')
			except Exception, e:
				postgresql_port = None

			## store it in the environment
			batconf['environment']['POSTGRESQL_USER'] = postgresql_user
			batconf['environment']['POSTGRESQL_PASSWORD'] = postgresql_password
			batconf['environment']['POSTGRESQL_DB'] = postgresql_db
			if postgresql_port != None:
				batconf['environment']['POSTGRESQL_PORT'] = postgresql_port
			if postgresql_host != None:
				batconf['environment']['POSTGRESQL_HOST'] = postgresql_host
			if postgresql_hostaddr != None:
				batconf['environment']['POSTGRESQL_HOSTADDR'] = postgresql_hostaddr
		except:
			pass
		try:
			packpickles = config.get(section, 'packpickles')
			if packpickles == 'yes':
				batconf['packpickles'] = True
			else:
				batconf['packpickles'] = False
		except:
			batconf['packpickles'] = False
		try:
			reportendofphase = config.get(section, 'reportendofphase')
			if reportendofphase == 'yes':
				batconf['reportendofphase'] = True
			else:
				batconf['reportendofphase'] = False
		except:
			batconf['reportendofphase'] = False
		try:
			## check if the database should be used. The default
			## is to use the database and this configuration option
			## is mostly meant to quickly disable the database.
			usedatabase = config.get(section, 'usedatabase')
			if usedatabase == 'yes':
				batconf['usedatabase'] = True
			else:
				batconf['usedatabase'] = False
		except:
			batconf['usedatabase'] = True
		try:
			batconf['tlshmaxsize'] = int(config.get(section, 'tlshmaxsize'))
		except:
			pass
		try:
			debug = config.get(section, 'debug')
			if debug == 'yes':
				batconf['debug'] = True
			else:
				batconf['debug'] = False
		except:
			batconf['debug'] = False
		try:
			debugphases = config.get(section, 'debugphases')
			if debugphases.strip() == "":
				batconf['debugphases'] = []
			else:
				batconf['debugphases'] = debugphases.split(':')
		except:
			batconf['debugphases'] = []
		try:
			writeoutputfile = config.get(section, 'writeoutputfile')
			if writeoutputfile == 'yes':
				batconf['writeoutputfile'] = True
			else:
				batconf['writeoutputfile'] = False
		except:
			batconf['writeoutputfile'] = True
		try:
			outputlite = config.get(section, 'outputlite')
			if outputlite == 'yes':
				batconf['outputlite'] = True
			else:
				batconf['outputlite'] = False
		except:
			batconf['outputlite'] = False
		try:
			configdir = config.get(section, 'configdirectory')
			if not os.path.isdir(configdir):
				batconf['configdirectory'] = None
			else:
				batconf['configdirectory'] = configdir
		except:
			batconf['configdirectory'] = None
		try:
			unpackdir = config.get(section, 'unpackdirectory')
			if not os.path.isdir(unpackdir):
				batconf['unpackdirectory'] = None
			else:
				batconf['unpackdirectory'] = unpackdir
				## TODO: try to create a temporary directory
				## to see if the directory is writable
		except:
			batconf['unpackdirectory'] = None
		try:
			unpackdir = config.get(section, 'temporary_unpackdirectory')
			if not os.path.isdir(unpackdir):
				batconf['temporary_unpackdirectory'] = None
			else:
				try:
					testfile = tempfile.mkstemp(dir=unpackdir)
					os.fdopen(testfile[0]).close()
					os.unlink(testfile[1])
					## store it in the environment
					batconf['environment']['UNPACK_TEMPDIR'] = unpackdir
				except OSError, e:
					pass
		except:
			batconf['temporary_unpackdirectory'] = None
		try:
			template = config.get(section, 'template')

			## check for certain values and reset template if necessary
			if '/' in template:
				template = None
				batconf['template'] = None
				continue
			if '%' in template:
				batconf['template'] = template
			template = template + "-%s"
			batconf['template']   = template
		except Exception, e:
			batconf['template']   = None
		try:
			compress = config.get(section, 'compress')
			if compress == 'yes':
				batconf['compress'] = True
			else:
				batconf['compress'] = False
		except:
			batconf['compress'] = False

	## then process configurations of any plugins
	## if defined.
	if batconf['configdirectory'] != None:
		## configuration files can end either with .conf or .config
		configs = filter(lambda x: x.endswith('.conf') or x.endswith('.config'), os.listdir(batconf['configdirectory']))
		## if the configuration directory is set to the same
		## directory as where the main configuration file is located
		## then don't process the main configuration file twice
		if os.path.realpath(batconf['configdirectory']) == os.path.dirname(configfilename):
			configs = filter(lambda x: x != os.path.basename(configfilename), configs)

		## read each individual configuration file and process all the sections.
		for mc in configs:
			mconfig = ConfigParser.ConfigParser()
			try:
				mconfigfile = open(os.path.join(batconf['configdirectory'], mc), 'rb')
				mconfig.readfp(mconfigfile)
			except Exception, e:
				pass
			for section in mconfig.sections():
				scanconfigres = scanconfigsection(mconfig, section, scanenv, batconf)
				if scanconfigres == None:
					continue

				if section in sectionsseen:
					errors.append({'errortype': 'duplicate', 'section': section})
					continue

				## add the section to the list of sections
				## that was seen. Prefer plug in configurations
				## over the regular configurations.
				sectionsseen.add(section)

				(scanconfig, scantype, scandebug) = scanconfigres
				if scandebug != None:
					tmpbatconfdebug.add(scandebug)
				if scantype == 'leaf':
					leafscans.append(scanconfig)
				elif scantype == 'unpack':
					unpackscans.append(scanconfig)
				elif scantype == 'prerun':
					prerunscans.append(scanconfig)
				elif scantype == 'postrun':
					postrunscans.append(scanconfig)
				elif scantype == 'aggregate':
					aggregatescans.append(scanconfig)
			mconfigfile.close()

	## finally process all the scans in the main configuration file
	for section in sectionstoprocess:
		scanconfigres = scanconfigsection(config, section, scanenv, batconf)
		if scanconfigres == None:
			continue
		if section in sectionsseen:
			errors.append({'errortype': 'duplicate', 'section': section})
			continue
		sectionstoprocess.add(section)
		sectionsseen.add(section)
		(scanconfig, scantype, scandebug) = scanconfigres
		if scandebug != None:
			tmpbatconfdebug.add(scandebug)
		if scantype == 'leaf':
			leafscans.append(scanconfig)
		elif scantype == 'unpack':
			unpackscans.append(scanconfig)
		elif scantype == 'prerun':
			prerunscans.append(scanconfig)
		elif scantype == 'postrun':
			postrunscans.append(scanconfig)
		elif scantype == 'aggregate':
			aggregatescans.append(scanconfig)

	if tmpbatconfdebug != set():
		tmpbatconfdebug.update(batconf['debugphases'])
		batconf['debugphases'] = list(tmpbatconfdebug)

	## set and/or amend environment for prerun scans
	for s in prerunscans:
		if not 'environment' in s:
			s['environment'] = copy.deepcopy(scanenv)
		else:
			for e in batconf['environment']:
				if not e in s['environment']:
					s['environment'][e] = copy.deepcopy(batconf['environment'][e])

	## set and/or amend environment for unpack scans
	for s in unpackscans:
		if not 'environment' in s:
			s['environment'] = copy.deepcopy(scanenv)
		else:
			for e in batconf['environment']:
				if not e in s['environment']:
					s['environment'][e] = copy.deepcopy(batconf['environment'][e])

		## sanity checks for known file method scans
		if not 'extensions' in s:
			try:
				del s['knownfilemethod']
			except:
				pass

	## set and/or amend environment for leaf scans
	for s in leafscans:
		if not 'environment' in s:
			s['environment'] = copy.deepcopy(scanenv)
		else:
			for e in batconf['environment']:
				if not e in s['environment']:
					s['environment'][e] = copy.deepcopy(batconf['environment'][e])

	## set and/or amend environment for aggregate scans
	for s in aggregatescans:
		if not 'environment' in s:
			s['environment'] = copy.deepcopy(scanenv)
		else:
			for e in batconf['environment']:
				if not e in s['environment']:
					s['environment'][e] = copy.deepcopy(batconf['environment'][e])
		if s['cleanup']:
			## this is an ugly hack *cringe*
			s['environment']['overridedir'] = True
		if s['compress']:
			## this is an ugly hack *cringe*
			s['environment']['compress'] = True
		if 'reporthash' in batconf:
			s['environment']['OUTPUTHASH'] = batconf['reporthash']
		if 'template' in batconf:
			s['environment']['TEMPLATE'] = batconf['template']

	## set and/or amend environment for postrun scans
	for s in postrunscans:
		if not 'environment' in s:
			s['environment'] = copy.deepcopy(scanenv)
		else:
			for e in batconf['environment']:
				if not e in s['environment']:
					s['environment'][e] = copy.deepcopy(batconf['environment'][e])
		if s['cleanup']:
			## this is an ugly hack *cringe*
			s['environment']['overridedir'] = True
		if s['compress']:
			## this is an ugly hack *cringe*
			s['environment']['compress'] = True

	## sort scans on priority (highest priority first)
	prerunscans = sorted(prerunscans, key=lambda x: x['priority'], reverse=True)
	leafscans = sorted(leafscans, key=lambda x: x['priority'], reverse=True)
	aggregatescans = sorted(aggregatescans, key=lambda x: x['priority'], reverse=True)
	return {'batconfig': batconf, 'unpackscans': unpackscans, 'leafscans': leafscans, 'prerunscans': prerunscans, 'postrunscans': postrunscans, 'aggregatescans': aggregatescans, 'errors': errors}

def dumpData(unpackreports, scans, tempdir, packpickles):
	## a dump of all the result contains:
	## * a copy of all the unpacked data
	## * whatever results from postrunscans that should be stored (defined in the config file)
	## * a pickle of all data
	## * separate pickles of the data of the ranking scan
	sha256spack = set([])
	for p in unpackreports:
		if 'checksum' in unpackreports[p]:
			sha256spack.add(unpackreports[p]['checksum'])
	oldstoredir = None
	oldlistdir = []
	for i in (scans['postrunscans'] + scans['aggregatescans']):
		## use parameters from configuration file. This assumes that the names of the
		## all output files of a particular scan start with the checksum of the scanned
		## file and have a common suffix.
		if i['storedir'] != None and i['storetarget'] != None and i['storetype'] != None:
			if not os.path.exists(i['storedir']):
				continue
			if not os.path.exists(os.path.join(tempdir, i['storetarget'])):
				os.mkdir(os.path.join(tempdir, i['storetarget']))
			target = os.path.join(tempdir, i['storetarget'])
			copyfiles = []
			filetypes = i['storetype'].split(':')
			## in case the storedir was also used in the previous run just reuse
			## the data instead of rereading it using os.listdir.
			if oldstoredir == i['storedir']:
				listdir = oldlistdir
			else:
				listdir = os.listdir(i['storedir'])
				oldstoredir = i['storedir']
				oldlistdir = listdir
			for f in filetypes:
				dirlisting = filter(lambda x: x.endswith(f), listdir)
				## apply a few filters to more efficiently grab only the files
				## that are really needed. This pays off in case there are tons
				## of files that need to be copied.
				dirfilter = set(map(lambda x: x.split('-')[0], dirlisting))
				inter = sha256spack.intersection(dirfilter)
				for s in inter:
					copyfiles = filter(lambda x: s in x, dirlisting)
					for c in copyfiles:
						dirlisting.remove(c)
					for c in set(copyfiles):
						shutil.copy(os.path.join(i['storedir'], c), target)
						if i['cleanup']:
							try:
								os.unlink(os.path.join(i['storedir'],c))
							except Exception, e:
								print >>sys.stderr, "dumpData: removing failed", c, e
		else:
			## nothing will be dumped if one of the three parameters is missing
			pass

		## Remove any results for which 'cleanup' has been set to True. For this at least 'storedir'
		## and 'storetype' have to be specified and 'cleanup' has to be set to True. For example, this
		## could be fluff from a previous run.
		if i['storedir'] != None and i['storetype'] != None and i['cleanup']:
			removefiles = []
		 	filetypes = i['storetype'].split(':')
			listdir = os.listdir(i['storedir'])
			for f in filetypes:
				dirlisting = filter(lambda x: x.endswith(f), listdir)
				for s in sha256spack:
					removefiles = removefiles + filter(lambda x: x.startswith(s), dirlisting)
			for r in set(removefiles):
				try:
					os.unlink(os.path.join(i['storedir'],r))
				except Exception, e:
					print >>sys.stderr, "dumpData: removing failed", r, e
					pass

	if packpickles:
		picklefile = open(os.path.join(tempdir, 'scandata.pickle'), 'wb')
		cPickle.dump(unpackreports, picklefile)
		picklefile.close()

def compressPickle((infile)):
	fin = open(infile, 'rb')
	fout = gzip.open("%s.gz" % infile, 'wb')
	fout.write(fin.read())
	fout.close()
	fin.close()
	os.unlink(fin.name)

## Write everything to a dump file. A few directories that always should be
## packed are hardcoded, the other files are determined from the configuration.
## The configuration option 'lite' allows to leave out the extracted data, to
## speed up extraction of data in the GUI.
def writeDumpfile(unpackreports, scans, processamount, outputfile, configfile, tempdir, batversion, statistics, packpickles, lite=False, debug=False, compress=True):
	dumpData(unpackreports, scans, tempdir, packpickles)
	dumpfile = tarfile.open(outputfile, 'w:gz')
	oldcwd = os.getcwd()
	os.chdir(tempdir)

	## write some statistics about BAT and the underlying
	## platform, mostly for debugging purposes
	statisticsfilename = 'STATISTICS'
	statisticsfile = open(statisticsfilename, 'wb')
	statisticsfile.write("BAT VERSION: %d\n" % batversion)
	statisticsfile.write("PLATFORM: %s\n" % platform.platform())
	statisticsfile.write("CPU: %s\n" % platform.processor())
	statisticsfile.write("PYTHON IMPLEMENTATION: %s\n" % platform.python_implementation())
	statisticsfile.write("PYTHON VERSION: %s\n" % platform.python_version())
	for i in statistics:
		statisticsfile.write("%s: %s\n" % (i.upper(), statistics[i]))
	statisticsfile.close()
	dumpfile.add(statisticsfilename)

	## see if the BAT configuration file needs to be
	## stored in the archive, with some information
	## possibly scrubbed.
	if scans['batconfig']['packconfig']:
		if scans['batconfig']['scrub'] != []:
			## pretty print the configuration file, scrubbed of
			## any of the values in 'scrub' (example: database
			## credentials)
			tmpscrub = tempfile.mkstemp()
			configlines = open(configfile, 'rb').readlines()
			for c in configlines:
				scrubline = c
				if c.startswith('scrub'):
					os.write(tmpscrub[0], scrubline)
					continue
				for sc in scans['batconfig']['scrub']:
					if sc in c:
						scrubsplits = scrubline.split('=', 1)
						if sc == scrubsplits[0].strip():
							scrubline = "%s = *****\n" % sc
				os.write(tmpscrub[0], scrubline)
			os.fdopen(tmpscrub[0]).close()
			scrubfile = tmpscrub[1]
			shutil.copy(scrubfile, os.path.basename(configfile))
			os.unlink(scrubfile)
		else:
			shutil.copy(configfile, '.')
		dumpfile.add(os.path.basename(configfile))

	## By default pack all the JSON files in the current directory
	dirfiles = os.listdir('.')
	jsonfiles = filter(lambda x: x.endswith('.json'), dirfiles)
	for j in jsonfiles:
		dumpfile.add(j)

	if scans['batconfig']['extrapack'] != []:
		for e in scans['batconfig']['extrapack']:
			if os.path.isabs(e):
				continue
			if os.path.islink(e):
				continue
			## only pack files once
			if e in jsonfiles:
				continue
			## TODO: many more checks
			if os.path.exists(e):
				dumpfile.add(e)
	if not lite:
		dumpfile.add('data')

	## optionally pack the Python pickles
	if packpickles:
		dumpfile.add('scandata.pickle')
		try:
			os.stat('filereports')
			if compress:
				## compress pickle files in parallel
				filereports = os.listdir('filereports')
				fnames = map(lambda x: os.path.join(tempdir, "filereports", x), filereports)
				if fnames != []:
					pool = multiprocessing.Pool(processes=processamount)
					pool.map(compressPickle, fnames, 1)
					pool.terminate()
			dumpfile.add('filereports')
		except Exception,e:
			if debug:
				print >>sys.stderr, "writeDumpfile", e
				sys.stderr.flush()

	dumpadds = set()
	for i in (scans['postrunscans'] + scans['aggregatescans']):
		if i['storedir'] != None and i['storetarget'] != None and i['storetype'] != None:
			try:
				os.stat(i['storetarget'])
				dumpadds.add(i['storetarget'])
			except Exception, e:
				if debug:
					print >>sys.stderr, "writeDumpfile:", e
					sys.stderr.flush()
				else:
					pass
	for i in dumpadds:
		dumpfile.add(i)
	dumpfile.close()
	os.chdir(oldcwd)

## runscan is the entry point for this file.
## It takes a list of binaries, a fully checked configuration
## and the BAT version number and then processes each
## binary separately.
def runscan(scans, binaries, batversion):
	## first some initialization code that is the same for
	## every binary to be scanned.
	debug = scans['batconfig']['debug']
	debugphases = scans['batconfig']['debugphases']
	compressed = scans['batconfig']['compress']

	## first split the scans per 'magic' (needed) and
	## 'optmagic' (optional).
	magicscans = []
	optmagicscans = []
	for k in ["prerunscans", "unpackscans", "leafscans", "postrunscans"]:
		for s in scans[k]:
			if s['magic'] != None:
				magicscans = magicscans + s['magic'].split(':')
			if s['optmagic'] != None:
				optmagicscans = optmagicscans + s['optmagic'].split(':')
	prerunignore = {}
	prerunmagic = {}
	for prerunscan in scans['prerunscans']:
		if 'noscan' in prerunscan:
			if not prerunscan['noscan'] == None:
				noscans = prerunscan['noscan'].split(':')
				prerunignore[prerunscan['name']] = noscans
		if 'magic' in prerunscan:
			if not prerunscan['magic'] == None:
				magics = prerunscan['magic'].split(':')
				if not prerunscan['name'] in prerunmagic:
					prerunmagic[prerunscan['name']] = magics
				else:
					prerunmagic[prerunscan['name']] = prerunmagic[prerunscan['name']] + magics
		if 'optmagic' in prerunscan:
			if not prerunscan['optmagic'] == None:
				magics = prerunscan['optmagic'].split(':')
				if not prerunscan['name'] in prerunmagic:
					prerunmagic[prerunscan['name']] = magics
				else:
					prerunmagic[prerunscan['name']] = prerunmagic[prerunscan['name']] + magics

	magicscans = list(set(magicscans))
	optmagicscans = list(set(optmagicscans))

	## Use multithreading to speed up scanning. Sometimes we hit
	## http://bugs.python.org/issue9207
	## Threading can be configured in the configuration file and
	## is enabled by default, but it might be necessary to disable
	## it in certain cases. In most cases it is highly desirable to
	## have multiprocessing enabled, as it speeds up unpacking and
	## processing individual files a lot.
	## By setting 'multiprocessing' to 'yes' and indicating that some scans should
	## not be run in parallel (which will actually be for the whole category of scans
	## where prerun, unpack and leaf are treated as a single category)
	## it is possible to have partial parallel scanning.

	## first see if unpacking should be done in parallel
	parallel = True
	if scans['batconfig']['multiprocessing']:
		if False in map(lambda x: x['parallel'], scans['unpackscans'] + scans['prerunscans']):
			parallel = False
	else:
		parallel = False
	if debug:
		if debugphases == []:
			parallel = False
		else:
			if 'unpack' in debugphases or 'prerun' in debugphases:
				parallel = False

	## Even if parallel is set it is possible to hardcode the
	## maximum amount of CPUs to use.
	if parallel:
		if 'processors' in scans['batconfig']:
			processamount = min(multiprocessing.cpu_count(),scans['batconfig']['processors'])
		else:
			processamount = multiprocessing.cpu_count()
	else:
		processamount = 1

	tmpdebug = False
	if debug:
		tmpdebug = True
		if debugphases != []:
			if not ('prerun' in debugphases or 'unpack' in debugphases):
				tmpdebug = False

	usedatabase = scans['batconfig']['usedatabase']

	## For TLSH a default maximum size is set to 50 MiB
	tlshmaxsize=52428800
	if 'tlshmaxsize' in scans['batconfig']:
		tlshmaxsize = scans['batconfig']['tlshmaxsize']

	## create a bunch of connections and cursors in case
	## the database is used.
	batcons = []
	batcursors = []

	scanenv = copy.deepcopy(scans['batconfig']['environment'])
	if usedatabase:
		for i in range(0,processamount):
			try:
				c = psycopg2.connect(database=scanenv['POSTGRESQL_DB'], user=scanenv['POSTGRESQL_USER'], password=scanenv['POSTGRESQL_PASSWORD'], host=scanenv.get('POSTGRESQL_HOST', None), port=scanenv.get('POSTGRESQL_PORT', None))
				cursor = c.cursor()
				batcons.append(c)
				batcursors.append(cursor)
			except Exception, e:
				usedatabase = False
				break

	## source code scanning only makes sense if there is
	## a database with source code in the first place
	scansourcecode = False
	if scans['batconfig']['scansourcecode'] and usedatabase:
		scansourcecode = True

	## First run the 'setup' hooks for the scans and pass
	## results via the environment. This should keep the
	## code cleaner.
	finalunpackscans = []
	unpackdebug=False
	if debug:
		unpackdebug = True
		if debugphases != []:
			if not 'unpack' in debugphases:
				unpackdebug = False

	## create the final list of unpack scans. If there
	## are any setup scans that need to be run (for example
	## to check if the right database tables are present)
	## then they are run here. If the setup scan for
	## an unpack scan does not work properly, then the unpack
	## scan is disabled.
	for sscan in scans['unpackscans']:
		if not 'setup' in sscan:
			finalunpackscans.append(sscan)
			continue
		if usedatabase:
			cursor = batcursors[0]
			conn = batcons[0]
		else:
			cursor = None
			conn = None
		## if any information from the setup scan should
		## be returned to the unpack scan, then this will be
		## done via the environment.
		setupres = runSetup(sscan, usedatabase, cursor, conn, unpackdebug)
		(setuprun, newenv) = setupres
		if not setuprun:
			continue
		## 'parallel' can be used to modify whether or not the
		## scans should be run in parallel. This is right now
		## the only 'special' keyword.
		if 'parallel' in newenv:
			if newenv['parallel'] == False:
				parallel = False
		sscan['environment'] = newenv
		finalunpackscans.append(sscan)

	## determine whether or not the leaf scans should be run in parallel
	parallel = True
	if scans['leafscans'] != []:
		finalleafscans = []
		if not scans['batconfig']['multiprocessing']:
			parallel = False

		leafdebug=False
		if debug:
			leafdebug = True
			if debugphases != []:
				if not 'leaf' in debugphases:
					leafdebug = False

		## First run setup scans, similar to for how it is
		## done for unpack scans.
		for sscan in scans['leafscans']:
			if not 'setup' in sscan:
				finalleafscans.append(sscan)
				continue
			if usedatabase:
				cursor = batcursors[0]
				conn = batcons[0]
			else:
				cursor = None
				conn = None
			setupres = runSetup(sscan, usedatabase, cursor, conn, leafdebug)
			(setuprun, newenv) = setupres
			if not setuprun:
				continue
			## 'parallel' can be used to modify whether or not the
			## scans should be run in parallel. This is right now
			## the only 'special' keyword.
			if 'parallel' in newenv:
				if newenv['parallel'] == False:
					parallel = False
			sscan['environment'] = newenv
			finalleafscans.append(sscan)

	if scans['aggregatescans'] != []:
		aggregatedebug=False
		finalaggregatescans = []
		if debug:
			aggregatedebug = True
			if debugphases != []:
				if not 'aggregate' in debugphases:
					aggregatedebug = False
		## First run setup scans, similar to for how it is
		## done for unpack scans.
		for sscan in scans['aggregatescans']:
			if not 'setup' in sscan:
				finalaggregatescans.append(sscan)
				continue
			if usedatabase:
				cursor = batcursors[0]
				conn = batcons[0]
			else:
				cursor = None
				conn = None
			setupres = runSetup(sscan, usedatabase, cursor, conn, aggregatedebug)
			(setuprun, newenv) = setupres
			if not setuprun:
				continue
			## 'parallel' can be used to modify whether or not the
			## scans should be run in parallel. This is right now
			## the only 'special' keyword.
			if 'parallel' in newenv:
				if newenv['parallel'] == False:
					parallel = False
			sscan['environment'] = newenv
			finalaggregatescans.append(sscan)

	unpackdirectory = scans['batconfig']['unpackdirectory']
	if unpackdirectory != None:
		if not os.path.exists(unpackdirectory):
			unpackdirectory = None

	## By default the output hash is set to SHA256, but
	## it can be changed to other hashes, such as MD5
	## or SHA1 (the only two other options supported at
	## the moment). Internally BAT will always use SHA256
	## for direct matches and TLSH for fuzzy matches.
	outputhash = scans['batconfig'].get('reporthash', 'sha256')
	if outputhash == 'crc32' or outputhash == 'tlsh':
		outputhash = 'sha256'

	timeout=scans['batconfig']['tasktimeout']

	## record the original working directory, as that is
	## what BAT will start at for each scan.
	origcwd = os.getcwd()

	## now process each of the binaries individually
	for bins in binaries:
		statistics = {}
		(scan_binary, writeconfig) = bins

		## extra sanity check, in case the binary was removed
		if not os.path.exists(scan_binary):
			continue
		scan_binary_basename = os.path.basename(scan_binary)

		## force the cwd to a known value. This is to prevent mysterious
		## errors in case some old results are cleaned up and the cwd is not
		## restored in the code that had to change cwd for some reason.
		os.chdir(origcwd)
		scandate = datetime.datetime.utcnow()

		## Per binary scanned a list with results is returned.
		## Each file system or compressed file inside the binary returns a list
		## with reports back as its result, so we have a list of lists.
		## Within the inner list there is a result tuple, which could contain
		## more lists in some fields, like libraries, or more result lists if
		## the file inside a file system we looked at was in fact a file system.
		unpackreports = {}

		try:
			## test if unpackdirectory is actually writable
			topleveldir = tempfile.mkdtemp(dir=unpackdirectory)
		except:
			unpackdirectory = None
			topleveldir = tempfile.mkdtemp(dir=unpackdirectory)

		## reset the environment to a fresh copy
		scanenv = copy.deepcopy(scans['batconfig']['environment'])

		## create the top level directory where all the unpacked data
		## will be stored
		scantempdir = os.path.join(topleveldir, "data")
		os.makedirs(scantempdir)

		## copy the binary to the root of the unpack directory
		starttime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "COPYING BEGIN", starttime.isoformat()
			sys.stderr.flush()

		shutil.copy(scan_binary, scantempdir)
		os.chmod(os.path.join(scantempdir, scan_binary_basename), stat.S_IRWXU)

		endtime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "COPYING END", endtime.isoformat()
			sys.stderr.flush()

		statistics['copying'] = endtime - starttime

		## create the directory where result files (internal use) will be stored
		if not os.path.exists(os.path.join(topleveldir, 'filereports')):
			os.mkdir(os.path.join(topleveldir, 'filereports'))

		## create the directory where result files (external) will be stored
		if not os.path.exists(os.path.join(topleveldir, 'reports')):
			os.mkdir(os.path.join(topleveldir, 'reports'))

		## initialize a few data structures for the top level file:
		## * tags    :: a list of tags that BAT will keep for the file
		## * offsets :: a dictionary with offsets for each file type
		##              found and which is used by unpacking scans
		## * hints   :: a dictionary to pass extra information back
		##              to the code launching the unpackers
		tags = []
		offsets = {}
		hints = {}

		## check if the file has an extension try to find if there
		## is a special method defined for processing fies with that
		## extension: often files with a particular extension will
		## actually be of that file type, and it is possible to take
		## a shortcut in those cases and skip many scans.
		knownextension = False
		fileextensions = scan_binary.lower().rsplit('.', 1)
		if len(fileextensions) == 2:
			fileextension = fileextensions[1]
			for unpackscan in finalunpackscans:
				if 'knownfilemethod' in unpackscan:
					if fileextension in unpackscan['extensions']:
						knownextension = True
						break

		## In case the extension is not known (and it is not possible to
		## take a shortcut) try to do the marker search for the top level
		## file in parallel if the file is big enough. For very big files
		## this can save quite a bit of time.
		if not knownextension:
			offsetcutoff = scans['batconfig']['markersearchminimum']
			if os.stat(scan_binary).st_size > offsetcutoff:
				offsettasks = []
				for i in range(0, os.stat(scan_binary).st_size, 100000):
					offsettasks.append((scantempdir, scan_binary_basename, magicscans, optmagicscans, max(i-50, 0), 100000+50))
				pool = multiprocessing.Pool(processes=processamount)
				res = pool.map(paralleloffsetsearch, offsettasks)
				pool.terminate()

				isascii = True

				for offsetresult in res:
					(i, offsettokeys, offsetisascii) = offsetresult
					for j in i:
						if j in offsets:
							offsets[j] += i[j]
						else:
							offsets[j] = copy.deepcopy(i[j])
					isascii = isascii and offsetisascii
				for i in offsets:
					offsets[i] = sorted(list(set(offsets[i])))
				if isascii:
					tags.append('text')
				else:
					tags.append('binary')

		## fill the scan task list with the first entry
		scantasks = [(scantempdir, scan_binary_basename, len(scantempdir), tmpdebug, tags, hints, offsets)]

		template = scans['batconfig']['template']

		starttime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "PRERUN UNPACK BEGIN", starttime.isoformat()
			sys.stderr.flush()

		## create the directory to dump offsets in case they need
		## to be dumped for later reference.
		offsetdir = os.path.join(topleveldir, "offsets")
		if scans['batconfig']['dumpoffsets']:
			os.makedirs(offsetdir)

		## use a queue made with a manager to avoid some issues, see:
		## http://docs.python.org/2/library/multiprocessing.html#pipes-and-queues
		lock = Lock()
		scanmanager = multiprocessing.Manager()
		scanqueue = multiprocessing.JoinableQueue(maxsize=0)
		reportqueue = scanmanager.Queue(maxsize=0)
		processpool = []

		## keep a dictionary for hashes, to see which ones
		## have already been processed, so duplicates can be
		## detected.
		hashdict = scanmanager.dict()

		map(lambda x: scanqueue.put(x), scantasks)
		for i in range(0,processamount):
			if usedatabase:
				cursor = batcursors[i]
				conn = batcons[i]
			else:
				cursor = None
				conn = None
			p = multiprocessing.Process(target=scan, args=(scanqueue, reportqueue, finalunpackscans, finalleafscans, scans['prerunscans'], prerunignore, prerunmagic, magicscans, optmagicscans, i, hashdict, lock, template, unpackdirectory, topleveldir, scantempdir, outputhash, cursor, conn, scansourcecode, scans['batconfig']['dumpoffsets'], offsetdir, compressed, timeout, scan_binary_basename, tlshmaxsize))
			processpool.append(p)
			p.start()

		scanqueue.join()

		## Sometimes there are identical files inside a blob.
		## To minimize time spent on scanning these should only be
		## scanned once. Since the results are independent anyway (the
		## unpacking phase is where unique paths are determined after all)
		## each sha256 can be scanned only once. If there are more files
		## with the same sha256 the result can simply be copied
		## with some data changed.
		##
		## * keep a list of which sha256 have duplicates.
		## * filter out the checksums
		## * for each sha256 scan once
		## * copy results in case there are duplicates
		dupes = []

		while True:
			try:
				val = reportqueue.get_nowait()
				for k in val:
					if 'tags' in val[k]:
						## the file is a duplicate, so store
						## it in a list dupes and continue
						## with the next item.
						if 'duplicate' in val[k]['tags']:
							dupes.append(val)
							continue
					unpackreports[k] = val[k]
				reportqueue.task_done()
			except Queue.Empty, e:
				## Queue is empty
				break

		## block here until the reportqueue is empty
		reportqueue.join()
	
		## for duplicate files copy some information into
		## unpackreports, except for the name and path
		for i in dupes:
			for k in i:
				dupesha256 = i[k]['checksum']
				origname = i[k]['name']
				origrealpath = i[k]['realpath']
				origpath = i[k]['path']
				origrelativename = i[k]['relativename']
				## keep name, realpath, relativename, path for
				## the duplicate, and copy the rest of the
				## data from the original.
				dupecopy = copy.deepcopy(unpackreports[hashdict[dupesha256]])
				dupecopy['name'] = origname
				dupecopy['path'] = origpath
				dupecopy['realpath'] = origrealpath
				dupecopy['relativename'] = origrelativename
				dupecopy['tags'].append('duplicate')
				unpackreports[k] = dupecopy

		## finally shut down all the processes and the scanmanager
		for p in processpool:
			p.terminate()

		scanmanager.shutdown()

		endtime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "PRERUN UNPACK END", endtime.isoformat()
		if scans['batconfig']['reportendofphase']:
			print "PRERUN UNPACK END %s" % scan_binary_basename, endtime.isoformat()
		statistics['prerununpack'] = endtime - starttime

		## always add an extra tag 'toplevel' for the top level item
		if 'checksum' in unpackreports[scan_binary_basename]:
			filehash = unpackreports[scan_binary_basename]['checksum']
			leaf_file_path = os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)

			## first record what the top level element is. This will be used by other scans
			leaf_file = open(leaf_file_path, 'rb')
			leafreports = cPickle.load(leaf_file)
			leaf_file.close()

			unpackreports[scan_binary_basename]['tags'].append('toplevel')
			unpackreports[scan_binary_basename]['scandate'] = scandate
			leafreports['tags'].append('toplevel')

			leaf_file = open(leaf_file_path, 'wb')
			leafreports = cPickle.dump(leafreports, leaf_file)
			leaf_file.close()

		## LEGACY: Now the next phase starts, namely scanning each individual
		## file. This is done once per unique file (based on checksum).
		## CURRENT: this is a NOP and just there to satisfy a few older use cases
		if scans['batconfig']['reportendofphase']:
			print "LEAF END %s" % scan_binary_basename, datetime.datetime.utcnow().isoformat()
			sys.stdout.flush()

		## Scan the files in context
		starttime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "AGGREGATE BEGIN", starttime.isoformat()
			sys.stderr.flush()
		if scans['aggregatescans'] != []:
			## because there are 'eval' statements the code to call aggregate scans
			## has to be in a separate method
			aggregatestatistics = aggregatescan(unpackreports, finalaggregatescans, processamount, scantempdir, topleveldir, scan_binary_basename, scandate, batcursors, batcons, aggregatedebug, unpackdirectory)
			statistics.update(aggregatestatistics)
		endtime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "AGGREGATE END", endtime.isoformat()
			sys.stderr.flush()
		if scans['batconfig']['reportendofphase']:
			print "AGGREGATE END %s" % scan_binary_basename, endtime.isoformat()
			sys.stdout.flush()
		statistics['aggregate'] = endtime - starttime

		for i in unpackreports:
			if 'tags' in unpackreports[i]:
				unpackreports[i]['tags'] = list(set(unpackreports[i]['tags']))

		starttime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "POSTRUN BEGIN", starttime.isoformat()
		## run postrunscans here, again in parallel, if needed/wanted
		## These scans typically only have a few side effects, but don't change
		## the reporting/scanning, just process the results. Examples: generate
		## fancier reports, use microblogging to post scan results, etc.
		## Duplicates that are tagged as 'duplicate' are not processed.
		if scans['postrunscans'] != [] and unpackreports != {}:
			scanqueue = multiprocessing.JoinableQueue(maxsize=0)

			havetask = False
			for i in unpackreports:
				if not 'checksum' in unpackreports[i]:
					continue
				if not 'tags' in unpackreports[i]:
					continue
				if 'duplicate' in unpackreports[i]['tags']:
					continue
				tmpdebug = False
				if debug:
					tmpdebug = True
					if debugphases != []:
						if not 'postrun' in debugphases:
							tmpdebug = False
				havetask = True
				scanqueue.put((i, unpackreports[i]))

			if havetask:
				processpool = []
				parallel = True
				if tmpdebug:
					if debugphases == []:
						parallel = False
					else:
						if 'postrun' in debugphases:
							parallel = False
				if not parallel:
					postrunprocessamount = 1
				else:
					postrunprocessamount = processamount
				for i in range(0,postrunprocessamount):
					if usedatabase:
						cursor = batcursors[i]
						conn = batcons[i]
					else:
						cursor = None
						conn = None
					p = multiprocessing.Process(target=postrunscan, args=(scanqueue, scans['postrunscans'], topleveldir, scantempdir, cursor, conn, tmpdebug, timeout))
					processpool.append(p)
					p.start()

				scanqueue.join()

				for p in processpool:
					p.terminate()

		endtime = datetime.datetime.utcnow()
		if debug:
			print >>sys.stderr, "POSTRUN END", endtime.isoformat()
		if scans['batconfig']['reportendofphase']:
			print "POSTRUN END %s" % scan_binary_basename, endtime.isoformat()
		statistics['postrun'] = endtime - starttime

		endtime = datetime.datetime.utcnow()
		statistics['total'] = endtime - scandate

		## finally write an archive file with all the data, if configured to do so
		if scans['batconfig']['writeoutputfile']:
			writeDumpfile(unpackreports, scans, processamount, writeconfig['outputfile'], writeconfig['config'], topleveldir, batversion, statistics, scans['batconfig']['packpickles'], scans['batconfig']['outputlite'], scans['batconfig']['debug'], compressed)
		if scans['batconfig']['cleanup']:
			try:
				shutil.rmtree(topleveldir)
			except Exception, e:
				pass
		if scans['batconfig']['reportendofphase']:
			print "done", scan_binary, datetime.datetime.utcnow().isoformat()
			sys.stdout.flush()

	## clean up the database connections and
	## close all connections to the database
	for c in batcursors:
		c.close()
	for c in batcons:
		c.close()
