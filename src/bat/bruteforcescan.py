#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to analyse binary blobs, using a "brute force" approach
and pretty print the analysis in a simple XML format.

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

5. output phase. Using a pretty printer a report is pretty printed. The pretty printer is
set in the configuration file and is optional.

6. postrun phase. In this phase methods that are not necessary for generating output, but
which should be run anyway, are run. Examples are generating pictures or running statistics.

7. packing phase. In this phase several datafiles, plus the state of the running program,
are packed in a tar file.
'''

import sys, os, os.path, magic, hashlib, subprocess, tempfile, shutil, stat, multiprocessing, cPickle, glob, tarfile, copy, gzip, Queue
from optparse import OptionParser
import datetime, sqlite3, re
import extractor
import prerun, fsmagic
from multiprocessing import Process, Lock
from multiprocessing.sharedctypes import Value, Array

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
	if setupscan.has_key('envvars'):
		envvars = setupscan['envvars']
	else:
		envvars = None

	exec "from %s import %s as bat_%s" % (module, method, method)
	scanres = eval("bat_%s(envvars, debug=debug)" % (method))
	return scanres

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

## compute a SHA256 hash. This is done in chunks to prevent a big file from
## being read in its entirety at once, slowing down a machine.
def gethash(path, filename):
	scanfile = open("%s/%s" % (path, filename), 'r')
	h = hashlib.new('sha256')
	scanfile.seek(0)
	hashdata = scanfile.read(10000000)
	while hashdata != '':
		h.update(hashdata)
		hashdata = scanfile.read(10000000)
	scanfile.close()
	return h.hexdigest()

## tag files based on extension and a few simple tests and possibly skip
## the generic marker search based on the results. This is to prevent
## a lot of I/O for large files.
## Example: ZIP files and JAR files often have a known extension. With
## a few simple tests it is easy to see if the entire file is a ZIP file
## or not.
## returns a dictionary with offsets
## TODO: refactor so code can be shared with fwunpack.py
def tagKnownExtension(filename):
	offsets = {}
	tags = []
	extensions = filename.rsplit('.', 1)
	if len(extensions) == 1:
		return (tags, offsets)

	extension = extensions[-1].lower()
	if extension == 'zip' or extension == 'jar' or extension == 'apk':
		datafile = open(filename, 'rb')
		databuffer = datafile.read(10)
		datafile.close()
		if databuffer.find(fsmagic.fsmagic['zip']) != 0:
			return (tags, offsets)
		p = subprocess.Popen(['zipinfo', '-v', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()

		res = re.search("Actual[\w\s]*end-(?:of-)?cent(?:ral)?-dir record[\w\s]*:\s*(\d+) \(", stanout)
		if res != None:
			endofcentraldir = int(res.groups(0)[0])
		else:
			return (tags, offsets)

		## TODO: determine commentsize
		commentsize = 0
		if endofcentraldir + 22 + commentsize == os.stat(filename).st_size:
			offsets['zip'] = [0]
			tags.append('zip')

		## check if the file is encrypted, if so bail out
		res = re.search("file security status:\s+(\w*)\sencrypted", stanout)
		if res == None:
			return ([], offsets)

		if res.groups(0)[0] != 'not':
			tags.append('encrypted')
			return (tags, offsets)
	return offsets

## scan a single file, possibly unpack and recurse
def scan(scanqueue, reportqueue, leafqueue, scans, prerunscans, magicscans, optmagicscans, processid, hashdict, llock, unpacktempdir):
	prerunignore = {}
	prerunmagic = {}
	for prerunscan in prerunscans:
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
	while True:
		## reset the reports, blacklist, offsets and tags for each new scan
		leaftasks = []
		unpackreports = {}
		blacklist = []
		offsets = {}
		tags = []
		(path, filename, lenscandir, tempdir, debug) = scanqueue.get()
		lentempdir = len(tempdir)

		## absolute path of the file in the file system (so including temporary dir)
		filetoscan = "%s/%s" % (path, filename)

		## relative path of the file in the temporary dir
		relfiletoscan = "%s/%s" % (path[lentempdir:], filename)
		if relfiletoscan.startswith('/'):
			relfiletoscan = relfiletoscan[1:]

		unpackreports[relfiletoscan] = {}
		unpackreports[relfiletoscan]['name'] = filename

		magic = ms.file(filetoscan)
		unpackreports[relfiletoscan]['magic'] = magic

		## Add both the path to indicate the position inside the file sytem
        	## or file that was unpacked, as well as the position of the files as unpacked
		## by BAT, convenient for later analysis of binaries.
		## In case of squashfs remove the "squashfs-root" part of the temporary
		## directory too, if it is present (not always).
		## TODO: validate if this is stil needed
		storepath = path[lenscandir:].replace("/squashfs-root", "")
		unpackreports[relfiletoscan]['path'] = storepath
		unpackreports[relfiletoscan]['realpath'] = path

		if os.path.islink("%s/%s" % (path, filename)):
			tags.append('symlink')
			unpackreports[relfiletoscan]['tags'] = tags
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
			scanqueue.task_done()
			continue
		## no use checking pipes, sockets, device files, etcetera
		if not os.path.isfile("%s/%s" % (path, filename)) and not os.path.isdir("%s/%s" % (path, filename)):
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
			scanqueue.task_done()
			continue

		filesize = os.lstat("%s/%s" % (path, filename)).st_size
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
		filehash = gethash(path, filename)
		unpackreports[relfiletoscan]['sha256'] = filehash

		## scan for markers
		tagOffsets = tagKnownExtension(filetoscan)
		if tagOffsets != {}:
			(tags, offsets) = tagOffsets
		else:
			offsets =  prerun.genericMarkerSearch(filetoscan, magicscans, optmagicscans)

		if "encrypted" in tags:
			leaftasks.append((filetoscan, magic, tags, blacklist, filehash, filesize))
			for l in leaftasks:
				leafqueue.put(l)
			unpackreports[relfiletoscan]['tags'] = tags
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
			scanqueue.task_done()
		## we have all offsets with markers here, so sscans that are not needed
		## can be filtered out.
		## Also keep track of the "most promising" scans (offset 0) to try
		## them first.
		filterscans = set()
		zerooffsets = set()
		for magictype in offsets:
			if offsets[magictype] != []:
				filterscans.add(magictype)
				if offsets[magictype][0] - fsmagic.correction.get(magictype, 0) == 0:
					zerooffsets.add(magictype)

		## acquire the lock for the shared dictionary to see if this file was already
		## scanned, or is in the process of being scanned.
		llock.acquire()
		if hashdict.has_key(filehash):
			## if the hash is alreay there, return
			unpackreports[relfiletoscan]['tags'] = ['duplicate']
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
			llock.release()
			scanqueue.task_done()
			continue
		else:
			hashdict[filehash] = relfiletoscan
			llock.release()

		## prerun scans should be run before any of the other scans
		for prerunscan in prerunscans:
			ignore = False
			if prerunscan.has_key('extensionsignore'):
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
			if debug:
				print >>sys.stderr, module, method, filename, datetime.datetime.utcnow().isoformat()
				sys.stderr.flush()
			## if there is extra information that needs to be pass, like locations
			## of databases the environment can be used for it
			if prerunscan.has_key('envvars'):
				envvars = prerunscan['envvars']
			else:
				envvars = None
			exec "from %s import %s as bat_%s" % (module, method, method)
			scantags = eval("bat_%s(filetoscan, tempdir, tags, offsets, debug=debug, envvars=envvars, unpacktempdir=unpacktempdir)" % (method))
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
		## TODO: sort per priority per offset for scans that are the most promising
		## but only for files that are fairly big, otherwise it has no use at all
		## since scanning smaller files is very fast.
		unpackscans = sorted(unpackscans, key=lambda x: x['priority'], reverse=True)
		'''
		if unpackscans != [] and filesize > 10000000:
			## first determine the priorities
			prios = map(lambda x: x['priority'], unpackscans)

			## sort them in reverse order
			prios = sorted(prios, reverse=True)

			## sort per priority based on first offset for each scan
			for p in prios:
				sortprios = filter(lambda x: x['priority'] == p, unpackscans)
				## now sort sortprios based on value of the first offset
		'''

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

			if unpackscan['noscan'] != None:
				noscans = unpackscan['noscan'].split(':')
				if list(set(tags).intersection(set(noscans))) != []:
					continue
		
			ignore = False
			if unpackscan.has_key('extensionsignore'):
				extensionsignore = unpackscan['extensionsignore'].split(':')
				for e in extensionsignore:
					if filetoscan.endswith(e):
						ignore = True
						break
			if ignore:
				continue
			module = unpackscan['module']
			method = unpackscan['method']
			if debug:
				print >>sys.stderr, module, method, filetoscan, datetime.datetime.utcnow().isoformat()
				sys.stderr.flush()
			## use the environment to pass extra information
			if unpackscan.has_key('envvars'):
				envvars = unpackscan['envvars'] + ":BAT_UNPACKED=%s" % unpacked
			else:
				envvars = "BAT_UNPACKED=%s" % unpacked
			## return value is the temporary dir, plus offset in the parent file
			## plus a blacklist containing blacklisted ranges for the *original*
			## file and a hash with offsets for each marker.
			exec "from %s import %s as bat_%s" % (module, method, method)
			scanres = eval("bat_%s(filetoscan, tempdir, blacklist, offsets, debug=debug, envvars=envvars)" % (method))
			## result is either empty, or contains offsets, tags and hints
			if len(scanres) == 4:
				(diroffsets, blacklist, scantags, hints) = scanres
				tags = list(set(tags + scantags))
			if len(diroffsets) == 0:
				continue
			#blacklist = mergeBlacklist(blacklist)
			## each diroffset is a (path, offset) tuple
			for diroffset in diroffsets:
				report = {}
				if diroffset == None:
					continue
				unpacked = True
				scandir = diroffset[0]

				## recursively scan all files in the directory
				osgen = os.walk(scandir)
				scanreports = []
				scantasks = []
				try:
       					while True:
                				i = osgen.next()
						## make sure all directories can be accessed
						for d in i[1]:
							if not os.path.islink("%s/%s" % (i[0], d)):
								os.chmod("%s/%s" % (i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
                				for p in i[2]:
							try:
								if not os.path.islink("%s/%s" % (i[0], p)):
									os.chmod("%s/%s" % (i[0], p), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
								scantasks.append((i[0], p, len(scandir), tempdir, debug))
								relscanpath = "%s/%s" % (i[0][lentempdir:], p)
								if relscanpath.startswith('/'):
									relscanpath = relscanpath[1:]
								scanreports.append(relscanpath)
							except Exception, e:
								pass
				except StopIteration:
        				for s in scantasks:
						scanqueue.put(s)
				unpackreports[relfiletoscan]['scans'].append({'scanname': unpackscan['name'], 'scanreports': scanreports, 'offset': diroffset[1], 'size': diroffset[2]})

		unpackreports[relfiletoscan]['tags'] = tags
		if not unpacked and 'temporary' in tags:
			os.unlink(filetoscan)
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
		else:
			leaftasks.append((filetoscan, magic, tags, blacklist, filehash, filesize))
			for l in leaftasks:
				leafqueue.put(l)
			for u in unpackreports:
				reportqueue.put({u: unpackreports[u]})
		scanqueue.task_done()

def leafScan((filetoscan, magic, scans, tags, blacklist, filehash, topleveldir, debug, unpacktempdir)):
	reports = {}
	newtags = []

	for leafscan in scans:
		ignore = False
		if leafscan.has_key('extensionsignore'):
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
		if leafscan.has_key('debug'):
			scandebug = True
			debug = True

		if debug:
			print >>sys.stderr, method, filetoscan, datetime.datetime.utcnow().isoformat()
			sys.stderr.flush()
			scandebug = True
		## use the environment to pass extra information
		if leafscan.has_key('envvars'):
			envvars = leafscan['envvars']
		else:
			envvars = None

		exec "from %s import %s as bat_%s" % (module, method, method)
		res = eval("bat_%s(filetoscan, tags, blacklist, scandebug=scandebug, envvars=envvars, unpacktempdir=unpacktempdir)" % (method))
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

def aggregatescan(unpackreports, scans, scantempdir, topleveldir, scan_binary, debug, unpacktempdir):
	## aggregate scans look at the entire result and possibly modify it.
	## The best example is JAR files: individual .class files will not be
	## very significant (or even insignificant), but combined results are.
	## Because aggregate scans have to look at everything as a whole, these
	## cannot be run in parallel.
	if scans['batconfig'].has_key('processors'):
		processors = scans['batconfig']['processors']
	else:
		processors = None
	for aggregatescan in scans['aggregatescans']:
		module = aggregatescan['module']
		method = aggregatescan['method']

		scandebug = False
		if aggregatescan.has_key('debug'):
			scandebug = True
			debug = True

		if debug:
			print >>sys.stderr, "AGGREGATE BEGIN", method, datetime.datetime.utcnow().isoformat()
			sys.stderr.flush()
			scandebug = True

		#if scandebug:
		#	processors=1

		## use the environment to pass extra information
		if aggregatescan.has_key('envvars'):
			envvars = aggregatescan['envvars']
		else:
			envvars = None
		if aggregatescan['cleanup']:
			## this is an ugly hack *cringe*
			envvars += ":overridedir=1"

		exec "from %s import %s as bat_%s" % (module, method, method)

		res = eval("bat_%s(unpackreports, scantempdir, topleveldir, processors, scandebug=scandebug, envvars=envvars, unpacktempdir=unpacktempdir)" % (method))
		if res != None:
			if res.keys() != []:
				filehash = unpackreports[scan_binary]['sha256']

				leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
				leafreports = cPickle.load(leaf_file)
				leaf_file.close()

				for reskey in set(res.keys()):
					leafreports[reskey] = res[reskey]
					unpackreports[scan_binary]['tags'].append(reskey)

				leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
				leafreports = cPickle.dump(leafreports, leaf_file)
				leaf_file.close()
		if debug:
			print >>sys.stderr, "AGGREGATE END", method, datetime.datetime.utcnow().isoformat()

def postrunscan((filetoscan, unpackreports, scans, scantempdir, topleveldir, debug)):
	for postrunscan in scans:
		ignore = False
		if postrunscan.has_key('extensionsignore'):
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
		## use the environment to pass extra information
		if postrunscan.has_key('envvars'):
			envvars = postrunscan['envvars']
		else:
			envvars = None
		if postrunscan['cleanup']:
			## this is an ugly hack *cringe*
			envvars += ":overridedir=1"
		exec "from %s import %s as bat_%s" % (module, method, method)

		res = eval("bat_%s(filetoscan, unpackreports, scantempdir, topleveldir, debug=debug, envvars=envvars)" % (method))
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
	for section in config.sections():
		if section == "batconfig":
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
				batconf['processors'] = int(config.get(section, 'processors'))
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
			continue
		
		elif config.has_option(section, 'type'):
			debug = False
			## scans have to be explicitely enabled
			if not config.has_option(section, 'enabled'):
				continue
			if config.get(section, 'enabled') == 'no':
				continue
			conf = {}
			conf['name']   = section
			conf['module'] = config.get(section, 'module')
			conf['method'] = config.get(section, 'method')

			## some scans might, or might not, have these defined
			try:
				conf['envvars'] = config.get(section, 'envvars')
			except:
				pass
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
		
	## sort scans on priority (highest priority first)
	prerunscans = sorted(prerunscans, key=lambda x: x['priority'], reverse=True)
	leafscans = sorted(leafscans, key=lambda x: x['priority'], reverse=True)
	aggregatescans = sorted(aggregatescans, key=lambda x: x['priority'], reverse=True)
	return {'batconfig': batconf, 'unpackscans': unpackscans, 'leafscans': leafscans, 'prerunscans': prerunscans, 'postrunscans': postrunscans, 'aggregatescans': aggregatescans}

def prettyprint(batconf, res, scandate, scans, toplevelfile, topleveldir):
	module = batconf['module']
	method = batconf['output']
	## use the environment to pass extra information
	if batconf.has_key('envvars'):
		envvars = batconf['envvars']
	else:
		envvars = None
	exec "from %s import %s as bat_%s" % (module, method, method)
	output = eval("bat_%s(res, scandate, scans, toplevelfile, topleveldir, envvars)" % (method))
	return output

def dumpData(unpackreports, scans, tempdir):
	## a dump of all the result contains:
	## * a copy of all the unpacked data
	## * whatever results from postrunscans that should be stored (defined in the config file)
	## * a pickle of all data, it saves parsing the XML report (or any other format for that matter),
	##   minus the data from the ranking scan
	## * separate pickles of the data of the ranking scan
	sha256spack = set([])
	for p in unpackreports:
		if unpackreports[p].has_key('sha256'):
			sha256spack.add(unpackreports[p]['sha256'])
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
def writeDumpfile(unpackreports, scans, outputfile, configfile, tempdir, lite=False, debug=False):
	dumpData(unpackreports, scans, tempdir)
	dumpfile = tarfile.open(outputfile, 'w:gz')
	os.chdir(tempdir)
	shutil.copy(configfile, '.')
	dumpfile.add('scandata.pickle')
	if not lite:
		dumpfile.add('data')
	try:
		os.stat('filereports')
		## compress pickle files in parallel
		filereports = os.listdir('filereports')
		if scans['batconfig'].has_key('processors'):
			pool = multiprocessing.Pool(processes=scans['batconfig']['processors'])
		else:
			pool = multiprocessing.Pool()
		fnames = map(lambda x: os.path.join(tempdir, "filereports", x), filereports)
		pool.map(compressPickle, fnames, 1)
		pool.terminate()
		dumpfile.add('filereports')
	except Exception,e:
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

def runscan(scans, scan_binary):
	unpacktempdir = scans['batconfig']['tempdir']
	if unpacktempdir != None:
		if not os.path.exists(unpacktempdir):
			unpacktempdir = None
	try:
		## test if unpacktempdir is actually writable
		topleveldir = tempfile.mkdtemp(dir=unpacktempdir)
	except:
		unpacktempdir = None
		topleveldir = tempfile.mkdtemp(dir=unpacktempdir)
	os.makedirs("%s/data" % (topleveldir,))
	scantempdir = "%s/data" % (topleveldir,)
	shutil.copy(scan_binary, scantempdir)
	debug = scans['batconfig']['debug']
	debugphases = scans['batconfig']['debugphases']

	magicscans = []
	optmagicscans = []
	for k in ["prerunscans", "unpackscans", "leafscans", "postrunscans"]:
		for s in scans[k]:
			if s['magic'] != None:
				magicscans = magicscans + s['magic'].split(':')
			if s['optmagic'] != None:
				optmagicscans = optmagicscans + s['optmagic'].split(':')
	magicscans = list(set(magicscans))
	optmagicscans = list(set(optmagicscans))

	## Per binary scanned we get a list with results.
	## Each file system or compressed file we can unpack gives a list with
	## reports back as its result, so we have a list of lists
	## within the inner list there is a result tuple, which could contain
	## more lists in some fields, like libraries, or more result lists if
	## the file inside a file system we looked at was in fact a file system.
	leaftasks = []
	unpackreports_tmp = []
	unpackreports = {}

	tmpdebug = False
	if debug:
		tmpdebug = True
		if debugphases != []:
			if not ('prerun' in debugphases or 'unpack' in debugphases):
				tmpdebug = False
	scantasks = [(scantempdir, os.path.basename(scan_binary), len(scantempdir), scantempdir, tmpdebug)]

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
		if scans['batconfig'].has_key('processors'):
			processamount = min(multiprocessing.cpu_count(),scans['batconfig']['processors'])
		else:
			processamount = multiprocessing.cpu_count()
	else:
		processamount = 1

	## use a queue made with a manager to avoid some issues, see:
	## http://docs.python.org/2/library/multiprocessing.html#pipes-and-queues
	if debug:
		print >>sys.stderr, "PRERUN UNPACK BEGIN", datetime.datetime.utcnow().isoformat()

	lock = Lock()
	scanmanager = multiprocessing.Manager()
	scanqueue = multiprocessing.JoinableQueue(maxsize=0)
	reportqueue = scanmanager.Queue(maxsize=0)
	leafqueue = scanmanager.Queue(maxsize=0)
	processpool = []
	hashdict = scanmanager.dict()
	map(lambda x: scanqueue.put(x), scantasks)
	for i in range(0,processamount):
		p = multiprocessing.Process(target=scan, args=(scanqueue,reportqueue,leafqueue, scans['unpackscans'], scans['prerunscans'], magicscans, optmagicscans, i, hashdict, lock, unpacktempdir))
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
	if debug:
		print >>sys.stderr, "PRERUN UNPACK END", datetime.datetime.utcnow().isoformat()

	if debug:
		print >>sys.stderr, "LEAF BEGIN", datetime.datetime.utcnow().isoformat()
	poolresult = []
	tagdict = {}
	finalscans = []
	if scans['leafscans'] != []:
		if scans['batconfig']['multiprocessing']:
			parallel = True
		else:
			parallel = False

		tmpdebug=False
		if debug:
			tmpdebug = True
			if debugphases != []:
				if not 'leaf' in debugphases:
					tmpdebug = False

		## First run the 'setup' hooks for the scans and pass
		## results via the environment. This should keep the
		## code cleaner.
		for sscan in scans['leafscans']:
			if not sscan.has_key('setup'):
				finalscans.append(sscan)
				continue
			setupres = runSetup(sscan, tmpdebug)
			(setuprun, newenv) = setupres
			if not setuprun:
				continue
			## 'parallel' can be used to modify whether or not the
			## scans should be run in parallel. This is right now
			## the only 'special' keyword.
			if newenv.has_key('parallel'):
				if newenv['parallel'] == False:
					parallel = False
			newenvvars = ""
			for n in newenv.keys():
				newenvvars = newenvvars + ":%s=%s" % (n, newenv[n])
			sscan['envvars'] = newenvvars[1:]
			finalscans.append(sscan)

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
		sha256leaf = {}
		for i in leaftasks:
			if sha256leaf.has_key(i[-2]):
				sha256leaf[i[-2]].append(i[0])
			else:
				sha256leaf[i[-2]] = [i[0]]
		sha256_tmp = {}
		for i in sha256leaf:
			if len(sha256leaf[i]) > 0:
				sha256_tmp[i] = sha256leaf[i][0]
		leaftasks_tmp = []
		for i in leaftasks:
			if sha256_tmp[i[-2]] == i[0]:
				leaftasks_tmp.append(i)

		## reverse sort on size: scan largest files first
		leaftasks_tmp.sort(key=lambda x: x[-1], reverse=True)
		leaftasks_tmp = map(lambda x: x[:2] + (filterScans(finalscans, x[2]),) + x[2:-1] + (topleveldir, tmpdebug, unpacktempdir), leaftasks_tmp)

		if scans['batconfig']['multiprocessing']:
			if False in map(lambda x: x['parallel'], finalscans):
				parallel = False
		else:
			parallel = False
		if debug:
			if debugphases == []:
				parallel = False
			else:
				if 'leaf' in debugphases:
					parallel = False

		if parallel:
			if scans['batconfig'].has_key('processors'):
				pool = multiprocessing.Pool(scans['batconfig']['processors'])
			else:
				pool = multiprocessing.Pool()
		else:
			pool = multiprocessing.Pool(processes=1)

		if not os.path.exists(os.path.join(topleveldir, 'filereports')):
			os.mkdir(os.path.join(topleveldir, 'filereports'))

		poolresult = pool.map(leafScan, leaftasks_tmp, 1)
		pool.terminate()

		## filter the results for the leafscans. These are the ones that
		## returned tags so need to be merged into unpackreports.
		mergetags = filter(lambda x: x[1] != [], poolresult)
		for m in mergetags:
			tagdict[m[0]] = m[1]

	dupes = []

	## the result is a list of dicts which needs to be turned into one dict
	for i in unpackreports_tmp:
		for k in i:
			if i[k].has_key('tags'):
				## the file is a duplicate, store for later 
				if 'duplicate' in i[k]['tags']:
					dupes.append(i)
					continue
			unpackreports[k] = i[k]

	for i in dupes:
		for k in i:
			dupesha256 = i[k]['sha256']
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

	for i in unpackreports.keys():
		if not unpackreports[i].has_key('sha256'):
			continue
		unpacksha256 = unpackreports[i]['sha256']
		if tagdict.has_key(unpacksha256):
			if unpackreports[i].has_key('tags'):
				unpackreports[i]['tags'] = list(set(unpackreports[i]['tags'] + tagdict[unpacksha256]))
	if debug:
		print >>sys.stderr, "LEAF END", datetime.datetime.utcnow().isoformat()

	if debug:
		print >>sys.stderr, "AGGREGATE BEGIN", datetime.datetime.utcnow().isoformat()
	if scans['aggregatescans'] != []:
		tmpdebug=False
		if debug:
			tmpdebug = True
			if debugphases != []:
				if not 'aggregate' in debugphases:
					tmpdebug = False
		aggregatescan(unpackreports, scans, scantempdir, topleveldir, os.path.basename(scan_binary), tmpdebug, unpacktempdir)
	if debug:
		print >>sys.stderr, "AGGREGATE END", datetime.datetime.utcnow().isoformat()

	for i in unpackreports:
		if unpackreports[i].has_key('tags'):
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

		dedupes = filter(lambda x: 'duplicate' not in unpackreports[x]['tags'], filter(lambda x: unpackreports[x].has_key('tags'), filter(lambda x: unpackreports[x].has_key('sha256'), unpackreports.keys())))
		postrunscans = []
		for i in dedupes:
			## results might have been changed by aggregate scans, so check if it still exists
			if unpackreports.has_key(i):
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
		if parallel:
			if scans['batconfig'].has_key('processors'):
				pool = multiprocessing.Pool(scans['batconfig']['processors'])
			else:
				pool = multiprocessing.Pool()
		else:
			pool = multiprocessing.Pool(processes=1)

		postrunresults = pool.map(postrunscan, postrunscans, 1)
		pool.terminate()
	if debug:
		print >>sys.stderr, "POSTRUN END", datetime.datetime.utcnow().isoformat()

	return (topleveldir, unpackreports)
