#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to analyse binary blobs, using a "brute force" approach

The script has a few separate scanning phases:

1. marker scanning phase, to search for specific markers (compression, file systems,
media formats), if available. This information is later used to filter scans and to
carve files.

2. prerun phase for tagging files. This is a first big rough sweep of determining what
files are to prevent spending too much time on useless scanning in the following phases.
Some things that are tagged here are text files, XML files, various graphics formats and
some other files.

3. unpack phase for unpacking files. In this phase several methods for unpacking files are
run, using the information from the marker scanning phase (if a file system file or
compressed file actually uses markers, which is not always the case). Also some simple
metadata about files is recorded in this phase. This method runs recursively: if a file
system was found and unpacked all the scans from steps 1, 2, 3 are run on the files that
were unpacked.

4. individual file scanning phase. Here each file will be inspected individually. Based on
the configuration that was given this could be basically anything.

5. postrun phase. In this phase methods that are not necessary for generating output, but
which should be run anyway, are run. Examples are generating pictures or running statistics.

6. packing phase. In this phase several datafiles, plus the state of the running program,
are packed in a tar file.
'''

import sys, os, os.path, magic, hashlib, subprocess, tempfile, shutil, stat, multiprocessing, cPickle, glob, tarfile, copy, gzip, Queue
from optparse import OptionParser
import datetime, re, struct
import extractor
import prerun, fsmagic
from multiprocessing import Process, Lock
from multiprocessing.sharedctypes import Value, Array
import bat.batdb

try:
	ms = magic.open(magic.MAGIC_NO_CHECK_CDF|magic.MAGIC_NONE)
except:
	ms = magic.open(magic.MAGIC_NONE)
ms.load()

## convenience method to merge ranges that overlap in a blacklist
## We do multiple passes to make sure everything is correctly merged
## Example:
## [(1,3), (2,4), (5,7), (3,7)] would result in [(1,7)]
def mergeBlacklist(blacklist):
	if len(blacklist) == 0:
		return []
	blacklistold = []
	while (blacklistold != blacklist):
		res = []
		res.append(blacklist[0])
		for i in xrange(1,len(blacklist)):
			lower = res[-1][0]
			upper = res[-1][1]
			if upper >= blacklist[i][0] or lower >= blacklist[i][0]:
				if upper <= blacklist[i][1]:
					upper = blacklist[i][1]
				if lower >= blacklist[i][0]:
					lower = blacklist[i][0]
				res[-1] = (lower,upper)
				continue
			## no overlapping ranges, so just append
			res.append(blacklist[i])
		blacklistold = blacklist
		blacklist = res
	return blacklist

def runSetup(setupscan, debug=False):
	module = setupscan['module']
	method = setupscan['setup']
	if debug:
		print >>sys.stderr, module, method
		sys.stderr.flush()

	try:
		exec "from %s import %s as bat_%s" % (module, method, method)
	except:
		return (False, {})
	scanres = eval("bat_%s(setupscan['environment'], debug=debug)" % (method))
	return scanres

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
def gethash(path, filename, hashtype="sha256"):
	hashresults = {}
	if hashtype == None:
		hashtype = 'sha256'
	## CRC32 and TLSH are not yet supported
	elif hashtype == 'crc32':
		hashtype = 'sha256'
	elif hashtype == 'tlsh':
		hashtype = 'sha256'

	hashtypes = set()
	hashtypes.add(hashtype)
	hashtypes.add('sha256')

	hashdict = {}
	for hasht in hashtypes:
		hashdict[hasht] = hashlib.new(hashtype)

	scanfile = open(os.path.join(path, filename), 'r')
	scanfile.seek(0)
	hashdata = scanfile.read(10000000)
	while hashdata != '':
		for h in hashtypes:
			hashdict[h].update(hashdata)
		hashdata = scanfile.read(10000000)
	scanfile.close()
	for h in hashtypes:
		hashresults[h] = hashdict[h].hexdigest()
	return hashresults

## scan a single file, possibly unpack and recurse
def scan(scanqueue, reportqueue, leafqueue, scans, prerunscans, prerunignore, prerunmagic, magicscans, optmagicscans, processid, hashdict, blacklistedfiles, llock, template, unpacktempdir, tempdir, outputhash, cursor, sourcecodequery, dumpoffsets, offsetdir, compressed):
	lentempdir = len(tempdir)

	## import all methods defined in the scans
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
	while True:
		## reset the reports, blacklist, offsets and tags for each new scan
		leaftasks = []
		unpackreports = {}
		blacklist = []
		## set timeout to a month
		(dirname, filename, lenscandir, debug, tags, scanhints, offsets) = scanqueue.get(timeout=2592000)

		## absolute path of the file in the file system (so including temporary dir)
		filetoscan = os.path.join(dirname, filename)

		## relative path of the file in the temporary dir
		relfiletoscan = filetoscan[lentempdir:]
		if relfiletoscan.startswith('/'):
			relfiletoscan = relfiletoscan[1:]

		unpackreports[relfiletoscan] = {}
		unpackreports[relfiletoscan]['name'] = filename

		## use libmagic to find out the 'magic' of the file for reporting
		## It cannot properly handle file names with 'exotic' encodings,
		## so wrap it in a try statement.
		magic = 'data'
		try:
			magic = ms.file(filetoscan)
		except Exception, e:
			if not os.path.islink(filetoscan):
				## first copy the file to a temporary location
				tmpmagic = tempfile.mkstemp()
				os.fdopen(tmpmagic[0]).close()
				shutil.copy(filetoscan, tmpmagic[1])
				magic = ms.file(tmpmagic[1])
				os.unlink(tmpmagic[1])
			else:
				## TODO: create a better value for 'magic'
				magic = 'symbolic link'
		unpackreports[relfiletoscan]['magic'] = magic

		## Add both the path to indicate the position inside the file sytem
        	## or file that was unpacked, as well as the position of the files as unpacked
		## by BAT, convenient for later analysis of binaries.
		## In case of squashfs remove the "squashfs-root" part of the temporary
		## directory too, if it is present (not always).
		## TODO: validate if this is stil needed
		storepath = dirname[lenscandir:].replace("/squashfs-root", "")
		unpackreports[relfiletoscan]['path'] = storepath
		unpackreports[relfiletoscan]['realpath'] = dirname

		if os.path.islink(filetoscan):
			tags.append('symlink')
			unpackreports[relfiletoscan]['tags'] = tags
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
			scanqueue.task_done()
			continue

		## no use checking pipes, sockets, device files, etcetera
		if not os.path.isfile(filetoscan) and not os.path.isdir(filetoscan):
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
			scanqueue.task_done()
			continue

		filesize = os.lstat(filetoscan).st_size
		unpackreports[relfiletoscan]['size'] = filesize

		## empty file, not interested in further scanning
		if filesize == 0:
			tags.append('empty')
			unpackreports[relfiletoscan]['tags'] = tags
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
			scanqueue.task_done()
			continue

		## Store the hash of the file for identification and for possibly
		## querying the knowledgebase later on.
		filehashresults = gethash(dirname, filename, outputhash)
		unpackreports[relfiletoscan]['checksum'] = filehashresults[outputhash]
		unpackreports[relfiletoscan]['sha256'] = filehashresults['sha256']
		filehash = filehashresults[outputhash]

		## blacklisted file, not interested in further scanning
		if filehash in blacklistedfiles:
			tags.append('blacklisted')
			unpackreports[relfiletoscan]['tags'] = tags
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
			scanqueue.task_done()
			continue

		## acquire the lock for the shared dictionary to see if this file was already
		## scanned, or is in the process of being scanned.
		llock.acquire()
		if filehash in hashdict:
			## if the hash is already there, return
			unpackreports[relfiletoscan]['tags'] = ['duplicate']
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
			llock.release()
			scanqueue.task_done()
			continue
		else:
			hashdict[filehash] = relfiletoscan
			llock.release()

		if cursor != None:
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

		processdiroffsets = []
		for unpackscan in scans:
			if 'knownfilemethod' in unpackscan:
				fileextensions = filename.lower().rsplit('.', 1)
				if len(fileextensions) != 2:
					continue
				fileextension = fileextensions[1]
				if fileextension in unpackscan['extensions']:
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
					scanres = eval("bat_%s(filetoscan, tempdir, newenv, debug=debug)" % (method))
					if scanres != ([], [], [], {}):
						(diroffsets, blacklist, scantags, hints) = scanres
						tags = list(set(tags + scantags))
						knownfile = True
						unpacked = True
						unpackreports[relfiletoscan]['scans'] = []
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
							unpackreports[relfiletoscan]['scans'].append({'scanname': unpackscan['name'], 'scanreports': scanreports, 'offset': diroffset[1], 'size': diroffset[2]})
						break

		if not knownfile:
			## scan for markers.
			if offsets == {}:
				offsets =  prerun.genericMarkerSearch(filetoscan, magicscans, optmagicscans)

		if dumpoffsets:
			## write pickles with offsets to disk
			if compressed:
				offsetpicklename = os.path.join(offsetdir, '%s-offsets.pickle.gz' % filehash)
			else:
				offsetpicklename = os.path.join(offsetdir, '%s-offsets.pickle' % filehash)
			try:
				os.stat(offsetpicklename)
			except:
				picklefile = open(offsetpicklename, 'wb')
				cPickle.dump(offsets, picklefile)
				picklefile.close()
				if compressed:
					fin = open(picklefile, 'rb')
					fout = gzip.open("%s.gz" % infile, 'wb')
					fout.write(fin.read())
					fout.close()
					fin.close()
					os.unlink(fin.name)

		if "encrypted" in tags:
			knownfile = True

		if not knownfile:
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
				if prerunignore.has_key(prerunscan['name']):
					if set(tags).intersection(set(prerunignore[prerunscan['name']])) != set():
						continue
				if prerunmagic.has_key(prerunscan['name']):
					if set(prerunmagic[prerunscan['name']]).intersection(filterscans) == set():
						continue
				module = prerunscan['module']
				method = prerunscan['method']
				if (module, method) in blacklistscans:
					continue
				if debug:
					print >>sys.stderr, module, method, filetoscan, datetime.datetime.utcnow().isoformat()
					sys.stderr.flush()

				scantags = eval("bat_%s(filetoscan, tempdir, tags, offsets, prerunscan['environment'], debug=debug, unpacktempdir=unpacktempdir)" % (method))
				## append the tag results. These will be used later to be able to specifically filter
				## out files
				if scantags != []:
					tags = tags + scantags

			## Reorder the scans based on information about offsets. If one scan has a
			## match for offset 0 (after correction of the offset, like for tar, gzip,
			## iso9660, etc.) make sure it is run first.
			unpackscans = []
			scanfirst = []

			## Filter scans
			filteredscans = filterScans(scans, tags)
			for unpackscan in filteredscans:
				if unpackscan['magic'] != None:
					scanmagic = unpackscan['magic'].split(':')
					if set(scanmagic).intersection(filterscans) != set():
						if set(scanmagic).intersection(zerooffsets) != set():
							scanfirst.append(unpackscan)
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

			unpackreports[relfiletoscan]['scans'] = []

			unpacked = False
			for unpackscan in unpackscans:
				## the whole file has already been scanned by other scans, so
				## continue with the leaf scans.
				if extractor.inblacklist(0, blacklist) == filesize:
					break

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
				scanres = eval("bat_%s(filetoscan, tempdir, blacklist, offsets, newenv, debug=debug)" % (method))
				## result is either empty, or contains offsets, blacklist, tags and hints
				if len(scanres) == 0:
					continue
				if len(scanres) == 4:
					(diroffsets, blacklist, scantags, hints) = scanres
					tags = list(set(tags + scantags))
					#blacklist = mergeBlacklist(blacklist)
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
						unpackreports[relfiletoscan]['scans'].append({'scanname': unpackscan['name'], 'scanreports': scanreports, 'offset': diroffset[1], 'size': diroffset[2]})

		unpackreports[relfiletoscan]['tags'] = tags
		if not unpacked and 'temporary' in tags:
			os.unlink(filetoscan)
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
		else:
			blacklist.sort()
			leaftasks.append((filetoscan, tags, blacklist, filehash, filesize))
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
		scanqueue.task_done()

def leafScan((filetoscan, scans, tags, blacklist, filehash, topleveldir, debug, unpacktempdir)):
	reports = {}
	newtags = []

	for leafscan in scans:
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

		scandebug = False
		if 'debug' in leafscan:
			scandebug = True
			debug = True

		if debug:
			print >>sys.stderr, method, filetoscan, datetime.datetime.utcnow().isoformat()
			sys.stderr.flush()
			scandebug = True

		try:
			exec "from %s import %s as bat_%s" % (module, method, method)
		except Exception, e:
			continue
		res = eval("bat_%s(filetoscan, tags, blacklist, leafscan['environment'], scandebug=scandebug, unpacktempdir=unpacktempdir)" % (method))
		if res != None:
			(nt, leafres) = res
			reports[leafscan['name']] = leafres
			newtags = newtags + nt
			tags += list(set(newtags))
	reports['tags'] = list(set(tags))

	## write pickles with information to disk here to reduce memory usage
	try:
		os.stat('%s/filereports/%s-filereport.pickle' % (topleveldir,filehash))
	except:
		picklefile = open('%s/filereports/%s-filereport.pickle' % (topleveldir,filehash), 'wb')
		cPickle.dump(reports, picklefile)
		picklefile.close()
	return (filehash, list(set(newtags)))

def aggregatescan(unpackreports, aggregatescans, processors, scantempdir, topleveldir, scan_binary, scandate, debug, unpacktempdir):
	## aggregate scans look at the entire result and possibly modify it.
	## The best example is JAR files: individual .class files will not be
	## very significant (or even insignificant), but combined results are.
	## Because aggregate scans have to look at everything as a whole, these
	## cannot be run in parallel.

	if 'checksum' in unpackreports[scan_binary]:
		filehash = unpackreports[scan_binary]['checksum']
		leaf_file_path = os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)

		## first record what the top level element is. This will be used by other scans
		leaf_file = open(leaf_file_path, 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		unpackreports[scan_binary]['tags'].append('toplevel')
		unpackreports[scan_binary]['scandate'] = scandate
		leafreports['tags'].append('toplevel')

		leaf_file = open(leaf_file_path, 'wb')
		leafreports = cPickle.dump(leafreports, leaf_file)
		leaf_file.close()

	for aggregatescan in aggregatescans:
		module = aggregatescan['module']
		method = aggregatescan['method']

		scandebug = False
		if 'debug' in aggregatescan:
			scandebug = True
			debug = True

		if debug:
			print >>sys.stderr, "AGGREGATE BEGIN", method, datetime.datetime.utcnow().isoformat()
			sys.stderr.flush()
			scandebug = True

		try:
			exec "from %s import %s as bat_%s" % (module, method, method)
		except Exception, e:
			continue

		res = eval("bat_%s(unpackreports, scantempdir, topleveldir, processors, aggregatescan['environment'], scandebug=scandebug, unpacktempdir=unpacktempdir)" % (method))
		if res != None:
			if res.keys() != []:
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
		if debug:
			print >>sys.stderr, "AGGREGATE END", method, datetime.datetime.utcnow().isoformat()

def postrunscan((filetoscan, unpackreports, scans, scantempdir, topleveldir, debug)):
	for postrunscan in scans:
		ignore = False
		if 'extensionsignore' in postrunscan:
			extensionsignore = postrunscan['extensionsignore'].split(':')
			for e in extensionsignore:
				if filetoscan.endswith(e):
					ignore = True
					break
		if ignore:
			continue
		module = postrunscan['module']
		method = postrunscan['method']
		if debug:
			print >>sys.stderr, module, method, filetoscan, datetime.datetime.utcnow().isoformat()
			sys.stderr.flush()
		try:
			exec "from %s import %s as bat_%s" % (module, method, method)
		except Exception, e:
			continue

		res = eval("bat_%s(filetoscan, unpackreports, scantempdir, topleveldir, postrunscan['environment'], debug=debug)" % (method))
		## TODO: find out what to do with this
		if res != None:
			pass

## arrays for storing data for the scans
## unpackscans: {name, module, method, ppoutput, priority}
## These are sorted by priority
## leafscans: {name, module, method, ppoutput}
def readconfig(config):
	unpackscans = []
	leafscans = []
	prerunscans = []
	postrunscans = []
	aggregatescans = []
	batconf = {}
	tmpbatconfdebug = set()

	## first create an environment so every scan has the same one
	oldenv = os.environ.copy()
	scanenv = {}

	for i in ['PATH', 'PWD', 'HOME', 'HOSTNAME', 'LANG', 'USER']:
		if i in oldenv:
			scanenv[i] = copy.deepcopy(oldenv[i])

	sectionstoprocess = set()

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
			dbbackend = config.get(section, 'dbbackend')
			if dbbackend in ['sqlite3', 'postgresql']:
				batconf['dbbackend'] = dbbackend
				batconf['environment']['DBBACKEND'] = dbbackend
			if dbbackend == 'postgresql':
				try:
					postgresql_user = config.get(section, 'postgresql_user')
					postgresql_password = config.get(section, 'postgresql_password')
					postgresql_db = config.get(section, 'postgresql_db')
					try:
						postgresql_host = config.get(section, 'postgresql_host')
					except:
						postgresql_host = None
					try:
						postgresql_hostaddr = config.get(section, 'postgresql_hostaddr')
					except:
						postgresql_hostaddr = None
					try:
						postgresql_port = config.get(section, 'postgresql_port')
					except Exception, e:
						postgresql_port = None
					batconf['environment']['POSTGRESQL_USER'] = postgresql_user
					batconf['environment']['POSTGRESQL_PASSWORD'] = postgresql_password
					batconf['environment']['POSTGRESQL_DB'] = postgresql_db
					if postgresql_port != None:
						batconf['environment']['POSTGRESQL_PORT'] = postgresql_port
					if postgresql_host != None:
						batconf['environment']['POSTGRESQL_HOST'] = postgresql_host
					if postgresql_hostaddr != None:
						batconf['environment']['POSTGRESQL_HOSTADDR'] = postgresql_hostaddr
					batconf['environment']['DBBACKEND'] = dbbackend
				except:
					del batconf['dbbackend']
		except:
			pass
		try:
			reportendofphase = config.get(section, 'reportendofphase')
			if reportendofphase == 'yes':
				batconf['reportendofphase'] = True
			else:
				batconf['reportendofphase'] = False
		except:
			batconf['reportendofphase'] = False
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
			outputlite = config.get(section, 'outputlite')
			if outputlite == 'yes':
				batconf['outputlite'] = True
			else:
				batconf['outputlite'] = False
		except:
			batconf['outputlite'] = False
		try:
			unpacktempdir = config.get(section, 'tempdir')
			if not os.path.isdir(unpacktempdir):
				batconf['tempdir'] = None
			else:
				batconf['tempdir'] = unpacktempdir
				## TODO: try to create a temporary directory
				## to see if the directory is writable
		except:
			batconf['tempdir'] = None
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
	
	for section in sectionstoprocess:
		if config.has_option(section, 'type'):
			debug = False
			## scans have to be explicitely enabled
			if not config.has_option(section, 'enabled'):
				continue
			if config.get(section, 'enabled') == 'no':
				continue
			conf = {}

			try:
				conf['module'] = config.get(section, 'module')
				conf['method'] = config.get(section, 'method')
			except:
				continue

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
			## see if a dbbackend is defined. If not, check if the
			## top level configuration has it defined.
			try:
				dbbackend = config.get(section, 'dbbackend')
				if dbbackend in ['sqlite3', 'postgresql']:
					conf['dbbackend'] = dbbackend
					if dbbackend == 'postgresql':
						try:
							postgresql_user = config.get(section, 'postgresql_user')
							postgresql_password = config.get(section, 'postgresql_password')
							postgresql_db = config.get(section, 'postgresql_db')
							try:
								postgresql_host = config.get(section, 'postgresql_user')
							except:
								postgresql_host = None
							try:
								postgresql_port = config.get(section, 'postgresql_port')
							except:
								postgresql_port = None
							conf['environment']['POSTGRESQL_USER'] = postgresql_user
							conf['environment']['POSTGRESQL_PASSWORD'] = postgresql_password
							conf['environment']['POSTGRESQL_DB'] = postgresql_db
							if postgresql_port != None:
								batconf['environment']['POSTGRESQL_PORT'] = postgresql_port
							if postgresql_host != None:
								batconf['environment']['POSTGRESQL_HOST'] = postgresql_host
							if postgresql_hostaddr != None:
								batconf['environment']['POSTGRESQL_HOSTADDR'] = postgresql_hostaddr
						except:
							del conf['dbbackend']
			except:
				if 'dbbackend' in batconf:
					conf['dbbackend'] = copy.deepcopy(batconf['dbbackend'])
					dbbackend = conf['dbbackend']
					if dbbackend in ['sqlite3', 'postgresql']:
						conf['dbbackend'] = dbbackend
						if dbbackend == 'postgresql':
							try:
								postgresql_user = copy.deepcopy(batconf['environment']['POSTGRESQL_USER'])
								postgresql_password = copy.deepcopy(batconf['environment']['POSTGRESQL_PASSWORD'])
								postgresql_db = copy.deepcopy(batconf['environment']['POSTGRESQL_DB'])
								if 'POSTGRESQL_PORT' in batconf['environment']:
									batconf['environment']['POSTGRESQL_PORT'] = copy.deepcopy(batconf['environment']['POSTGRESQL_PORT'])
								if 'POSTGRESQL_HOST' in batconf['environment']:
									batconf['environment']['POSTGRESQL_HOST'] = copy.deepcopy(batconf['environment']['POSTGRESQL_HOST'])
								if 'POSTGRESQL_HOSTADDR' in batconf['environment']:
									batconf['environment']['POSTGRESQL_HOSTADDR'] = copy.deepcopy(batconf['environment']['POSTGRESQL_HOSTADDR'])
								conf['environment']['POSTGRESQL_USER'] = postgresql_user
								conf['environment']['POSTGRESQL_PASSWORD'] = postgresql_password
								conf['environment']['POSTGRESQL_DB'] = postgresql_db
							except Exception, e:
								del conf['dbbackend']
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
				conf['ppmodule'] = config.get(section, 'ppmodule')
			except:
				pass
			try:
				conf['setup'] = config.get(section, 'setup')
			except:
				pass
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
					conf['compress'] = False

			## finally add the configurations to the right list
			if config.get(section, 'type') == 'leaf':
				leafscans.append(conf)
				if debug:
					tmpbatconfdebug.add('leaf')
			elif config.get(section, 'type') == 'unpack':
				unpackscans.append(conf)
				if debug:
					tmpbatconfdebug.add('unpack')
			elif config.get(section, 'type') == 'prerun':
				prerunscans.append(conf)
				if debug:
					tmpbatconfdebug.add('prerun')
			elif config.get(section, 'type') == 'postrun':
				postrunscans.append(conf)
				if debug:
					tmpbatconfdebug.add('postrun')
			elif config.get(section, 'type') == 'aggregate':
				aggregatescans.append(conf)
				if debug:
					tmpbatconfdebug.add('aggregate')
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
		if 'dbbackend' in s:
			s['environment']['DBBACKEND'] = s['dbbackend']

	## set and/or amend environment for unpack scans
	for s in unpackscans:
		if not 'environment' in s:
			s['environment'] = copy.deepcopy(scanenv)
		else:
			for e in batconf['environment']:
				if not e in s['environment']:
					s['environment'][e] = copy.deepcopy(batconf['environment'][e])
		if 'dbbackend' in s:
			s['environment']['DBBACKEND'] = s['dbbackend']
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
		if 'dbbackend' in s:
			s['environment']['DBBACKEND'] = s['dbbackend']

	## set and/or amend environment for aggregate scans
	for s in aggregatescans:
		if not 'environment' in s:
			s['environment'] = copy.deepcopy(scanenv)
		else:
			for e in batconf['environment']:
				if not e in s['environment']:
					s['environment'][e] = copy.deepcopy(batconf['environment'][e])
		if 'dbbackend' in s:
			s['environment']['DBBACKEND'] = s['dbbackend']
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
		if 'dbbackend' in s:
			s['environment']['DBBACKEND'] = s['dbbackend']

	## sort scans on priority (highest priority first)
	prerunscans = sorted(prerunscans, key=lambda x: x['priority'], reverse=True)
	leafscans = sorted(leafscans, key=lambda x: x['priority'], reverse=True)
	aggregatescans = sorted(aggregatescans, key=lambda x: x['priority'], reverse=True)
	return {'batconfig': batconf, 'unpackscans': unpackscans, 'leafscans': leafscans, 'prerunscans': prerunscans, 'postrunscans': postrunscans, 'aggregatescans': aggregatescans}

def dumpData(unpackreports, scans, tempdir):
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
def writeDumpfile(unpackreports, scans, processamount, outputfile, configfile, tempdir, lite=False, debug=False, compress=True):
	dumpData(unpackreports, scans, tempdir)
	dumpfile = tarfile.open(outputfile, 'w:gz')
	oldcwd = os.getcwd()
	os.chdir(tempdir)
	scrub = False
	if scans['batconfig']['packconfig']:
		shutil.copy(configfile, '.')
		dumpfile.add(os.path.basename(configfile))
		scrub = True
	if scrub and scans['batconfig']['scrub'] != []:
		## TODO pretty print the configuration file, scrubbed of
		## any of the values in 'scrub'
		pass
	dumpfile.add('scandata.pickle')
	if scans['batconfig']['extrapack'] != []:
		for e in scans['batconfig']['extrapack']:
			if os.path.isabs(e):
				continue
			if os.path.islink(e):
				continue
			## TODO: many more checks
			if os.path.exists(e):
				dumpfile.add(e)
	if not lite:
		dumpfile.add('data')
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

def runscan(scans, binaries):
	## first some initialization code that is the same for
	## every binary that is scanned.
	debug = scans['batconfig']['debug']
	debugphases = scans['batconfig']['debugphases']
	compressed = True

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
		if prerunscan.has_key('noscan'):
			if not prerunscan['noscan'] == None:
				noscans = prerunscan['noscan'].split(':')
				prerunignore[prerunscan['name']] = noscans
		if prerunscan.has_key('magic'):
			if not prerunscan['magic'] == None:
				magics = prerunscan['magic'].split(':')
				if not prerunmagic.has_key(prerunscan['name']):
					prerunmagic[prerunscan['name']] = magics
				else:
					prerunmagic[prerunscan['name']] = prerunmagic[prerunscan['name']] + magics
		if prerunscan.has_key('optmagic'):
			if not prerunscan['optmagic'] == None:
				magics = prerunscan['optmagic'].split(':')
				if not prerunmagic.has_key(prerunscan['name']):
					prerunmagic[prerunscan['name']] = magics
				else:
					prerunmagic[prerunscan['name']] = prerunmagic[prerunscan['name']] + magics

	magicscans = list(set(magicscans))
	optmagicscans = list(set(optmagicscans))

	## Use multithreading to speed up scanning. Sometimes we hit http://bugs.python.org/issue9207
	## Threading can be configured in the configuration file, but
	## often it is wise to have it set to 'no'. This is because ranking writes
	## to databases and you don't want concurrent writes.
	## some categories of scans can still be run in parallel. For example
	## if only one of the leaf scans has a side effect, then prerun, unpack
	## and unpack scans can still be run in parallel.
	## By setting 'multiprocessing' to 'yes' and indicating that some scans should
	## not be run in parallel (which will be for the whole category of scans) it is
	## possible to have partial parallel scanning.

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

		## First run the 'setup' hooks for the scans and pass
		## results via the environment. This should keep the
		## code cleaner.
		for sscan in scans['leafscans']:
			if not 'setup' in sscan:
				finalleafscans.append(sscan)
				continue
			setupres = runSetup(sscan, leafdebug)
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
		## First run the 'setup' hooks for the scans and pass
		## results via the environment. This should keep the
		## code cleaner.
		for sscan in scans['aggregatescans']:
			if not 'setup' in sscan:
				finalaggregatescans.append(sscan)
				continue
			setupres = runSetup(sscan, leafdebug)
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

	unpacktempdir = scans['batconfig']['tempdir']
	if unpacktempdir != None:
		if not os.path.exists(unpacktempdir):
			unpacktempdir = None

	outputhash = scans['batconfig'].get('reporthash', 'sha256')
	if outputhash == 'crc32' or outputhash == 'tlsh':
		outputhash = 'sha256'

	origcwd = os.getcwd()
	for bins in binaries:
		(scan_binary, writeconfig) = bins
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
		leaftasks = []
		unpackreports_tmp = []
		unpackreports = {}

		try:
			## test if unpacktempdir is actually writable
			topleveldir = tempfile.mkdtemp(dir=unpacktempdir)
		except:
			unpacktempdir = None
			topleveldir = tempfile.mkdtemp(dir=unpacktempdir)

		## copy the binary
		scanenv = copy.deepcopy(scans['batconfig']['environment'])

		os.makedirs("%s/data" % (topleveldir,))
		scantempdir = "%s/data" % (topleveldir,)
		if debug:
			print >>sys.stderr, "COPYING BEGIN", datetime.datetime.utcnow().isoformat()
			sys.stderr.flush()

		shutil.copy(scan_binary, scantempdir)
		os.chmod(os.path.join(scantempdir, os.path.basename(scan_binary)), stat.S_IRWXU)

		if debug:
			print >>sys.stderr, "COPYING END", datetime.datetime.utcnow().isoformat()
			sys.stderr.flush()

		tags = []
		offsets = {}
		hints = {}

		knownextension = False
		fileextensions = scan_binary.lower().rsplit('.', 1)
		if len(fileextensions) == 2:
			fileextension = fileextensions[1]
			for unpackscan in scans['unpackscans']:
				if 'knownfilemethod' in unpackscan:
					if fileextension in unpackscan['extensions']:
						knownextension = True
						break

		if not knownextension:
			offsetcutoff = scans['batconfig']['markersearchminimum']
			if os.stat(scan_binary).st_size > offsetcutoff:
				offsettasks = []
				for i in range(0, os.stat(scan_binary).st_size, 100000):
					offsettasks.append((scantempdir, os.path.basename(scan_binary), magicscans, optmagicscans, max(i-50, 0), 100000+50))
				pool = multiprocessing.Pool(processes=processamount)
				res = pool.map(paralleloffsetsearch, offsettasks)
				pool.terminate()

				for i in res:
					for j in i:
						if j in offsets:
							offsets[j] += i[j]
						else:
							offsets[j] = copy.deepcopy(i[j])
				for i in offsets:
					offsets[i] = sorted(list(set(offsets[i])))

		scantasks = [(scantempdir, os.path.basename(scan_binary), len(scantempdir), tmpdebug, tags, hints, offsets)]

		template = scans['batconfig']['template']

		if debug:
			print >>sys.stderr, "PRERUN UNPACK BEGIN", datetime.datetime.utcnow().isoformat()
			sys.stderr.flush()

		offsetdir = os.path.join(topleveldir, "offsets")
		if scans['batconfig']['dumpoffsets']:
			os.makedirs(offsetdir)

		## use a queue made with a manager to avoid some issues, see:
		## http://docs.python.org/2/library/multiprocessing.html#pipes-and-queues
		lock = Lock()
		scanmanager = multiprocessing.Manager()
		scanqueue = multiprocessing.JoinableQueue(maxsize=0)
		reportqueue = scanmanager.Queue(maxsize=0)
		leafqueue = scanmanager.Queue(maxsize=0)
		processpool = []

		scansourcecode = False
		if scans['batconfig']['scansourcecode']:
			scansourcecode = True

		hashdict = scanmanager.dict()
		blacklistedfiles = []
		map(lambda x: scanqueue.put(x), scantasks)
		batcons = []
		cursor = None
		sourcecodequery = ''
		for i in range(0,processamount):
			if scansourcecode:
				if 'DBBACKEND' in scanenv:
					batdb = bat.batdb.BatDb(scanenv['DBBACKEND'])
					c = batdb.getConnection(scanenv['BAT_DB'],scanenv)
					if c != None:
						cursor = c.cursor()
						batcons.append(c)
						sourcecodequery = batdb.getQuery("select checksum from processed_file where checksum=%s limit 1")
						scansourcecode = True
					else:
						scansourcecode = False
			else:
				cursor = None
				sourcecodequery = None
				scansourcecode = False
			p = multiprocessing.Process(target=scan, args=(scanqueue,reportqueue,leafqueue, scans['unpackscans'], scans['prerunscans'], prerunignore, prerunmagic, magicscans, optmagicscans, i, hashdict, blacklistedfiles, lock, template, unpacktempdir, scantempdir, outputhash, cursor, sourcecodequery, scans['batconfig']['dumpoffsets'], offsetdir, compressed))
			processpool.append(p)
			p.start()

		scanqueue.join()

		while True:
			try:
				val = reportqueue.get_nowait()
				unpackreports_tmp.append(val)
				reportqueue.task_done()
			except Queue.Empty, e:
				## Queue is empty
				break
		while True:
			try:
				val = leafqueue.get_nowait()
				leaftasks.append(val)
				leafqueue.task_done()
			except Queue.Empty, e:
				## Queue is empty
				break
		leafqueue.join()
		reportqueue.join()
	
		for p in processpool:
			p.terminate()

		if scansourcecode:
			for c in batcons:
				c.close()

		## Sometimes there are identical files inside a blob.
		## To minimize time spent on scanning these should only be
		## scanned once. Since the results are independent anyway (the
		## unpacking phase is where unique paths are determined after all)
		## each sha256 can be scanned only once. If there are more files
		## with the same sha256 the result can simply be copied.
		##
		## * keep a list of which sha256 have duplicates.
		## * filter out the checksums
		## * for each sha256 scan once
		## * copy results in case there are duplicates
		dupes = []

		## the result is a list of dicts which needs to be turned into one dict
		for i in unpackreports_tmp:
			for k in i:
				if 'tags' in i[k]:
					## the file is a duplicate, store for later 
					if 'duplicate' in i[k]['tags']:
						dupes.append(i)
						continue
				unpackreports[k] = i[k]

		for i in dupes:
			for k in i:
				dupesha256 = i[k]['checksum']
				origname = i[k]['name']
				origrealpath = i[k]['realpath']
				origpath = i[k]['path']
				## keep: name, realpath, path, copy the rest of the original
				dupecopy = copy.deepcopy(unpackreports[hashdict[dupesha256]])
				dupecopy['name'] = origname
				dupecopy['path'] = origpath
				dupecopy['realpath'] = origrealpath
				dupecopy['tags'].append('duplicate')
				unpackreports[k] = dupecopy

		if debug:
			print >>sys.stderr, "PRERUN UNPACK END", datetime.datetime.utcnow().isoformat()
		if scans['batconfig']['reportendofphase']:
			print "PRERUN UNPACK END %s" % os.path.basename(scan_binary), datetime.datetime.utcnow().isoformat()

		if debug:
			print >>sys.stderr, "LEAF BEGIN", datetime.datetime.utcnow().isoformat()
		poolresult = []
		tagdict = {}

		## determine whether or not the leaf scans should be run in parallel
		parallel = True
		if scans['leafscans'] != []:
			## each entry in leaftasks: (filetoscan, tags, blacklist, filehash, filesize)
			sha256leaf = {}
			leaftasks_tmp = []
			for i in leaftasks:
				if not i[-2] in sha256leaf:
					sha256leaf[i[-2]] = 1
					leaftasks_tmp.append(i)

			## reverse sort on size: scan largest files first
			leaftasks_tmp.sort(key=lambda x: x[-1], reverse=True)
			leaftasks_tmp = map(lambda x: x[:1] + (filterScans(finalleafscans, x[1]),) + x[1:-1] + (topleveldir, leafdebug, unpacktempdir), leaftasks_tmp)

			if parallel:
				if False in map(lambda x: x['parallel'], finalleafscans):
					parallel = False
			if debug:
				if debugphases == []:
					parallel = False
				else:
					if 'leaf' in debugphases:
						parallel = False

			if not os.path.exists(os.path.join(topleveldir, 'filereports')):
				os.mkdir(os.path.join(topleveldir, 'filereports'))

			if len(leaftasks_tmp) == 0:
				poolresult = []
			else:
				if parallel:
					pool = multiprocessing.Pool(processes=processamount)
				else:
					pool = multiprocessing.Pool(processes=1)

				poolresult = pool.map(leafScan, leaftasks_tmp, 1)
				pool.terminate()

			## filter the results for the leafscans. These are the ones that
			## returned tags so need to be merged into unpackreports.
			mergetags = filter(lambda x: x[1] != [], poolresult)
			for m in mergetags:
				tagdict[m[0]] = m[1]

		for i in unpackreports.keys():
			if not 'checksum' in unpackreports[i]:
				continue
			unpacksha256 = unpackreports[i]['checksum']
			if unpacksha256 in tagdict:
				if 'tags' in unpackreports[i]:
					unpackreports[i]['tags'] = list(set(unpackreports[i]['tags'] + tagdict[unpacksha256]))
		if debug:
			print >>sys.stderr, "LEAF END", datetime.datetime.utcnow().isoformat()
		if scans['batconfig']['reportendofphase']:
			print "LEAF END %s" % os.path.basename(scan_binary), datetime.datetime.utcnow().isoformat()

		if debug:
			print >>sys.stderr, "AGGREGATE BEGIN", datetime.datetime.utcnow().isoformat()
		if scans['aggregatescans'] != []:
			aggregatescan(unpackreports, finalaggregatescans, processamount, scantempdir, topleveldir, os.path.basename(scan_binary), scandate, aggregatedebug, unpacktempdir)
		if debug:
			print >>sys.stderr, "AGGREGATE END", datetime.datetime.utcnow().isoformat()
		if scans['batconfig']['reportendofphase']:
			print "AGGREGATE END %s" % os.path.basename(scan_binary), datetime.datetime.utcnow().isoformat()

		for i in unpackreports:
			if 'tags' in unpackreports[i]:
				unpackreports[i]['tags'] = list(set(unpackreports[i]['tags']))

		if debug:
			print >>sys.stderr, "POSTRUN BEGIN", datetime.datetime.utcnow().isoformat()
		## run postrunscans here, again in parallel, if needed/wanted
		## These scans typically only have a few side effects, but don't change
		## the reporting/scanning, just process the results. Examples: generate
		## fancier reports, use microblogging to post scan results, etc.
		## Duplicates that are tagged as 'duplicate' are not processed.
		if scans['postrunscans'] != [] and unpackreports != {}:
			## if unpackreports != {} since deduplication has already been done

			dedupes = filter(lambda x: 'duplicate' not in unpackreports[x]['tags'], filter(lambda x: 'tags' in unpackreports[x], filter(lambda x: 'checksum' in unpackreports[x], unpackreports.keys())))
			postrunscans = []
			for i in dedupes:
				## results might have been changed by aggregate scans, so check if it still exists
				if i in unpackreports:
					tmpdebug = False
					if debug:
						tmpdebug = True
						if debugphases != []:
							if not 'postrun' in debugphases:
								tmpdebug = False
					postrunscans.append((i, unpackreports[i], scans['postrunscans'], scantempdir, topleveldir, tmpdebug))

			parallel = True
			if scans['batconfig']['multiprocessing']:
				if False in map(lambda x: x['parallel'], scans['postrunscans']):
					parallel = False
			else:
				parallel = False
			if debug:
				if debugphases == []:
					parallel = False
				else:
					if 'postrun' in debugphases:
						parallel = False

			if len(postrunscans) == 0:
				postrunresults = []
			else:
				if parallel:
					pool = multiprocessing.Pool(processes=processamount)
				else:
					pool = multiprocessing.Pool(processes=1)

				postrunresults = pool.map(postrunscan, postrunscans, 1)
				pool.terminate()
		if debug:
			print >>sys.stderr, "POSTRUN END", datetime.datetime.utcnow().isoformat()
		if scans['batconfig']['reportendofphase']:
			print "POSTRUN END %s" % os.path.basename(scan_binary), datetime.datetime.utcnow().isoformat()

		if writeconfig['writeoutput']:
			compress = True
			writeDumpfile(unpackreports, scans, processamount, writeconfig['outputfile'], writeconfig['config'], topleveldir, scans['batconfig']['outputlite'], scans['batconfig']['debug'], compress)
		if scans['batconfig']['cleanup']:
			try:
				shutil.rmtree(topleveldir)
			except Exception, e:
				pass
		if scans['batconfig']['reportendofphase']:
			print "done", scan_binary, datetime.datetime.utcnow().isoformat()
			sys.stdout.flush()
