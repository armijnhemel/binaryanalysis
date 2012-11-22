#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to analyse binary blobs, using a "brute force" approach
and pretty print the analysis in a simple XML format.

The script has a few separate scanning phases:

1. marker scanning phase, to search for specific markers (compression, file systems,
media formats), if available. This information is later used to filter scans and to
carve files.

2. prerun phase for tagging files. This is a first big rough sweep for low hanging fruit,
so we only have to spend little or no time on useless scanning in the following phases.
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

import sys, os, os.path, magic, hashlib, subprocess, tempfile, shutil, stat, multiprocessing, cPickle, glob, tarfile
from optparse import OptionParser
import ConfigParser
import datetime
import sqlite3
import extractor
import prerun, fsmagic

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

## method to filter scans, based on the tags that were found for a
## file, plus a list of tags that the scan should skip.
## This is done to avoid scans running unnecessarily.
def filterScans(scans, tags):
	filteredscans = []
	for scan in scans:
		if scan['scanonly'] != None:
			scanonly = scan['scanonly'].split(':')
			if list(set(tags).intersection(set(scanonly))) == []:
				continue
		if scan['noscan'] != None:
			noscans = scan['noscan'].split(':')
			if list(set(noscans).intersection(set(tags))) != []:
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

## scan a single file, possibly unpack and recurse
def scan((path, filename, scans, prerunscans, magicscans, lenscandir, tempdir, debug)):
	lentempdir = len(tempdir)

	## absolute path of the file in the file system (so including temporary dir)
	filetoscan = "%s/%s" % (path, filename)

	## relative path of the file in the temporary dir
	relfiletoscan = "%s/%s" % (path[lentempdir:], filename)
	if relfiletoscan.startswith('/'):
		relfiletoscan = relfiletoscan[1:]

	## we reset the reports, blacklist, offsets and tags for each new scan
	leaftasks = []
	scantasks = []
	unpackreports = {}
	blacklist = []
	offsets = {}
	tags = []
	unpackreports[relfiletoscan] = {}
	unpackreports[relfiletoscan]['name'] = filename

	magic = ms.file(filetoscan)
	unpackreports[relfiletoscan]['magic'] = magic

	## Add both the path to indicate the position inside the file sytem
        ## or file we have unpacked, as well as the position of the files as unpacked
	## by BAT, convenient for later analysis of binaries.
	## In case of squashfs we remove the "squashfs-root" part of the temporary
	## directory too, if it is present (not always).
	storepath = path[lenscandir:].replace("/squashfs-root", "")
	unpackreports[relfiletoscan]['path'] = storepath
	unpackreports[relfiletoscan]['realpath'] = path

	if os.path.islink("%s/%s" % (path, filename)):
		return (scantasks, leaftasks, unpackreports)
	## no use checking pipes, sockets, device files, etcetera
	if not os.path.isfile("%s/%s" % (path, filename)) and not os.path.isdir("%s/%s" % (path, filename)):
		return (scantasks, leaftasks, unpackreports)

	filesize = os.lstat("%s/%s" % (path, filename)).st_size
	unpackreports[relfiletoscan]['size'] = filesize

	## empty file, not interested in further scanning
	if filesize == 0:
		return (scantasks, leaftasks, unpackreports)

	## Store the hash of the file for identification and for possibly
	## querying the knowledgebase later on.
	filehash = gethash(path, filename)
	unpackreports[relfiletoscan]['sha256'] = filehash

	## scan for markers
	(offsets, order) =  prerun.genericMarkerSearch(filetoscan, magicscans)

	## prerun scans should be run before any of the other scans
	for prerunscan in prerunscans:
		module = prerunscan['module']
		method = prerunscan['method']
		if debug:
			print >>sys.stderr, method
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if prerunscan.has_key('envvars'):
			envvars = prerunscan['envvars']
		else:
			envvars = None
		exec "from %s import %s as bat_%s" % (module, method, method)
		scantags = eval("bat_%s(filetoscan, tempdir, tags, offsets, envvars)" % (method))
		## append the tag results. These will be used later to be able to specifically filter
		## out files
		if scantags != []:
			tags = tags + scantags

	## we have all offsets with markers here, so we can filter out
	## the scans we won't need.
	## We also keep track of the "most promising" scans (offset 0) to try
	## them first.
	filterscans = []
	zerooffsets = []
	for magictype in offsets:
		if offsets[magictype] != []:
			filterscans.append(magictype)
			if offsets[magictype][0] - fsmagic.correction.get(magictype, 0) == 0:
				zerooffsets.append(magictype)

	filesize = os.stat(filetoscan).st_size
	## Based on information about offsets we should reorder the scans,
	## or at least if one scan has a match for offset 0 (after correction
	## of the offset, like for tar, gzip, iso9660, etc.) make sure it is
	## run first.
	unpackscans = []
	scanfirst = []

	## Filter scans
	filteredscans = filterScans(scans, tags)
	for unpackscan in filteredscans:
		if unpackscan['magic'] != None:
			scanmagic = unpackscan['magic'].split(':')
			if list(set(scanmagic).intersection(set(filterscans))) != []:
				if list(set(scanmagic).intersection(set(zerooffsets))) != []:
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

	for unpackscan in unpackscans:
		## the whole file has already been scanned by other scans, so we can
		## continue with the program scans.
		if extractor.inblacklist(0, blacklist) == filesize:
			break
		
		module = unpackscan['module']
		method = unpackscan['method']
		if debug:
			print >>sys.stderr, method
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if unpackscan.has_key('envvars'):
			envvars = unpackscan['envvars']
		else:
			envvars = None
		## return value is the temporary dir, plus offset in the parent file
		## plus a blacklist containing blacklisted ranges for the *original*
		## file and a hash with offsets for each marker.
		exec "from %s import %s as bat_%s" % (module, method, method)
		scanres = eval("bat_%s(filetoscan, tempdir, blacklist, offsets, envvars)" % (method))
		## result is either empty, or contains offsets and tags
		if len(scanres) == 3:
			(diroffsets, blacklist, scantags) = scanres
			tags = tags + scantags
		if len(diroffsets) == 0:
			continue
		blacklist = mergeBlacklist(blacklist)
		## each diroffset is a (path, offset) tuple
		for diroffset in diroffsets:
			report = {}
			if diroffset == None:
				continue
			scandir = diroffset[0]

			## recursively scan all files in the directory
			osgen = os.walk(scandir)
			scanreports = []
			try:
       				while True:
                			i = osgen.next()
					## make sure we can access all directories
					for d in i[1]:
						if not os.path.islink("%s/%s" % (i[0], d)):
							os.chmod("%s/%s" % (i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
                			for p in i[2]:
						try:
							if not os.path.islink("%s/%s" % (i[0], p)):
								os.chmod("%s/%s" % (i[0], p), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
							scantasks.append((i[0], p, scans, prerunscans, magicscans, len(scandir), tempdir, debug))
							relscanpath = "%s/%s" % (i[0][lentempdir:], p)
							if relscanpath.startswith('/'):
								relscanpath = relscanpath[1:]
							scanreports.append(relscanpath)
						except Exception, e:
							pass
			except StopIteration:
        			pass
			unpackreports[relfiletoscan]['scans'].append({'scanname': unpackscan['name'], 'scanreports': scanreports, 'offset': diroffset[1], 'size': diroffset[2]})
	leaftasks.append((filetoscan, magic, tags, blacklist, tempdir, filehash, filesize, debug))
	return (scantasks, leaftasks, unpackreports)

def leafScan((filetoscan, magic, scans, tags, blacklist, tempdir, filesize, debug)):
	reports = {}

	reports['tags'] = tags
	for scan in scans:

		## TODO: this code can probably go since it is done by filterScans
		if scan['noscan'] != None:
			noscans = scan['noscan'].split(':')
			if list(set(noscans).intersection(set(tags))) != []:
				continue
		report = {}
		module = scan['module']
		method = scan['method']
		if debug:
			print >>sys.stderr, method
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if scan.has_key('envvars'):
			envvars = scan['envvars']
		else:
			envvars = None
		exec "from %s import %s as bat_%s" % (module, method, method)
		res = eval("bat_%s(filetoscan, blacklist, envvars=envvars)" % (method))
		if res != None:
			reports[scan['name']] = res
	return (filetoscan, reports)

def postrunscan((filetoscan, unpackreports, leafreports, scans, scantempdir, toplevelscandir, debug)):
	sys.stdout.flush()
	for scan in scans:
		module = scan['module']
		method = scan['method']
		if debug:
			print >>sys.stderr, method
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if scan.has_key('envvars'):
			envvars = scan['envvars']
		else:
			envvars = None
		exec "from %s import %s as bat_%s" % (module, method, method)

		res = eval("bat_%s(filetoscan, unpackreports, leafreports, scantempdir, toplevelscandir ,envvars=envvars)" % (method))
		## TODO: find out what we want to do with this
		if res != None:
			pass

## arrays for storing data for the scans we have.
## unpackscans: {name, module, method, xmloutput, priority, cleanup}
## These are sorted by priority
## programscans: {name, module, method, xmloutput, cleanup}
def readconfig(config):
	unpackscans = []
	programscans = []
	prerunscans = []
	postrunscans = []
	aggregatescans = []
	batconf = {}
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
				debug = config.get(section, 'debug')
				if debug == 'yes':
					batconf['debug'] = True
				else:
					batconf['debug'] = False
			except:
				batconf['debug'] = False
			try:
				outputlite = config.get(section, 'outputlite')
				if outputlite == 'yes':
					batconf['outputlite'] = True
				else:
					batconf['outputlite'] = False
			except:
				batconf['outputlite'] = False
			continue
		
		elif config.has_option(section, 'type'):
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
				conf['cleanup'] = config.get(section, 'cleanup')
			except:
				pass
			try:
				conf['envvars'] = config.get(section, 'envvars')
			except:
				pass
			try:
				conf['magic'] = config.get(section, 'magic')
			except:
				conf['magic'] = None
			try:
				conf['noscan'] = config.get(section, 'noscan')
			except:
				conf['noscan'] = None
			try:
				conf['scanonly'] = config.get(section, 'scanonly')
			except:
				conf['scanonly'] = None
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
				## all three parameters should be there together
				conf['storedir'] = config.get(section, 'storedir')
				conf['storetarget'] = config.get(section, 'storetarget')
				conf['storetype'] = config.get(section, 'storetype')
			except:
				conf['storedir'] = None
				conf['storetarget'] = None
				conf['storetype'] = None
			try:
				conf['xmloutput'] = config.get(section, 'xmloutput')
			except:
				pass

			if config.get(section, 'type') == 'program':
				programscans.append(conf)
			elif config.get(section, 'type') == 'unpack':
				unpackscans.append(conf)
			elif config.get(section, 'type') == 'prerun':
				prerunscans.append(conf)
			elif config.get(section, 'type') == 'postrun':
				postrunscans.append(conf)
			elif config.get(section, 'type') == 'aggregate':
				aggregatescans.append(conf)
	## sort the prerun scans on priority (highest priority first)
	prerunscans = sorted(prerunscans, key=lambda x: x['priority'], reverse=True)
	return {'batconfig': batconf, 'unpackscans': unpackscans, 'programscans': programscans, 'prerunscans': prerunscans, 'postrunscans': postrunscans, 'aggregatescans': aggregatescans}

## Combine all results that we have into a format that the pretty printer can handle
## The result is a Python dictionary. In its simplest form it looks like this:
## Example:
##  {
##    'realpath': '/tmp/tmp12345678/foo/bar',
##    'magic': 'data',
##    'name': 'baz',
##    'path': '/foo/bar',
##    'sha256': 'abcdefghijkl17876546',
##    'size': 1,
##  }
##
## In case any of the "leaf scans" were successful there will be an additional
## element called 'scans'. This is a dictionary with results per leafscan
##
## Example:
## {
##  'tags': ['binary', 'elf'],
##  'architecture': 'Advanced Micro Devices X86-64',
##  'libs': ['libm.so.6', 'libselinux.so.1', 'libtinfo.so.5',
##    'libacl.so.1', 'libgpm.so.2', 'libdl.so.2', 'libperl.so',
##    'libpthread.so.0', 'libc.so.6', 'libpython2.7.so.1.0', 'libruby.so.1.8']
## }
## 
## Results of unpacking are also put in 'scans'. The name of the dictionary is the
## name of the unpacker. It can be recognized because it has an element 'offset'.
## Example:
##
##  'scans': {
##           'zip': 
##                 [
##                  {'offset': 0}, 
##                  {'realpath': '/tmp/tmpvZfamq/data/foo/bar/baz-zip-1',
##                   'magic': 'PEM certificate',
##                   'name': 'baz.crt',
##                   'path': '',
##                   'sha256': 'd206aa4b1333580e5075a6b22ce803491cc36bd40ab77dfdf4a1d98dd9caf032',
##                   'scans': {'tags': ['text']},
##                   'size': 1822
##                  }
##                 ]
##           }
##
## The 'scans' element is used to recurse.
def flatten(toplevel, unpackreports, leafreports):
	res = {}
	for i in ['realpath', 'magic', 'name', 'path', 'sha256', 'size']:
		if unpackreports[toplevel].has_key(i):
			res[i] = unpackreports[toplevel][i]
	if unpackreports[toplevel].has_key('scans') or toplevel in leafreports:
		res['scans'] = []
	if unpackreports[toplevel].has_key('scans'):
		for s in unpackreports[toplevel]['scans']:
			scanres = {}
			flattenres = []
			for i in s['scanreports']:
				flattenres.append(flatten(i, unpackreports, leafreports))
			if flattenres != []:
				scanres[s['scanname']] = []
				if s.has_key('offset'):
					scanres[s['scanname']].append({'offset': s['offset']})
				scanres[s['scanname']] = scanres[s['scanname']] + flattenres
			if scanres != {}:
				res['scans'].append(scanres)
	if toplevel in leafreports:
		for s in leafreports[toplevel]:
			res['scans'].append({s: leafreports[toplevel][s]})
	return res

def prettyprint(batconf, res, scandate, scans):
	module = batconf['module']
	method = batconf['output']
	## if there is extra information we need to pass, like locations of databases
	## we can use the environment for it
	if batconf.has_key('envvars'):
		envvars = batconf['envvars']
	else:
		envvars = None
	exec "from %s import %s as bat_%s" % (module, method, method)
	output = eval("bat_%s(res, scandate, scans, envvars)" % (method))
	return output

def dumpData(unpackreports, leafreports, scans, tempdir):
	## if we make a dump of all the result we should have:
	## * a copy of all the unpacked data
	## * whatever results from postrunscans that should be stored (defined in the config file)
	## * a pickle of all data, it saves parsing the XML report (or any other format for that matter),
	##   minus the data from the ranking scan
	## * separate pickles of the data of the ranking scan
	sha256spack = []
	for p in unpackreports:
		if unpackreports[p].has_key('sha256'):
			sha256spack.append(unpackreports[p]['sha256'])
	for i in scans['postrunscans']:
		## use parameters from configuration file. This assumes that the names of the
		## all output files of a particular scan start with the checksum of the scanned
		## file and have a common suffix.
		if i['storedir'] != None and i['storetarget'] != None and i['storetype'] != None:
			if not os.path.exists(os.path.join(tempdir, i['storetarget'])):
				os.mkdir(os.path.join(tempdir, i['storetarget']))
			target = os.path.join(tempdir, i['storetarget'])
			copyfiles = []
			## instead of using globbing we do the filtering ourselves, since we already know
			## how the file was created.
			filetypes = i['storetype'].split(':')
			for f in filetypes:
				dirlisting = filter(lambda x: x.endswith(f), os.listdir(i['storedir']))
				for s in sha256spack:
					copyfiles = copyfiles + filter(lambda x: x.startswith(s), dirlisting)
					for c in copyfiles:
						shutil.copy(os.path.join(i['storedir'], c), target)
		else:
			## nothing will be dumped if one of the three parameters is missing
			pass

	## Dump unique matches for ranking scan (if available) to separate file(s)
	## and remove the ranking data from each leafreport.
	## It is taking a lot of space in the pickle, and it is not always used:
	## the GUI for example has almost all data pregenerated.
	if not os.path.exists(os.path.join(tempdir, 'filereports')):
		os.mkdir(os.path.join(tempdir, 'filereports'))
	for l in leafreports:
		picklefile = open('%s/filereports/%s-filereport.pickle' % (tempdir,unpackreports[l]['sha256']), 'wb')
		cPickle.dump(leafreports[l], picklefile)
		picklefile.close()
		sys.stdout.flush()
		if leafreports[l].has_key('ranking'):
			(res, dynamicRes) = leafreports[l]['ranking']
			newreports = []
			for report in res['reports']:
				## We have: (rank, s, uniqueMatches.get(s,[]), percentage, packageversions.get(s, {}), packagelicenses.get(s, []))
				## We want: (rank, s, #unique matches, percentage, packageversions, packagelicenses)
				if type(report[2]) != int:
					newreports.append((report[0], report[1], len(report[2]), report[3], report[4], report[5]))
			## we should also replace nonUniqueMatches with {}
			leafreports[l]['ranking'][0]['nonUniqueMatches'] = {}
			leafreports[l]['ranking'][0]['reports'] = newreports

	picklefile = open(os.path.join(tempdir, 'scandata.pickle'), 'wb')
	cPickle.dump((unpackreports, leafreports, scans), picklefile)
	picklefile.close()

## Write everything to a dump file. A few directories that always should be
## packed are hardcoded, the other files are determined from the configuration.
## The configuration option 'lite' allows to leave out the extracted data, to
## speed up extraction of data in the GUI.
def writeDumpfile(unpackreports, leafreports, scans, outputfile, tempdir, lite=False):
	dumpData(unpackreports, leafreports, scans, tempdir)
	dumpfile = tarfile.TarFile(outputfile, 'w')
	os.chdir(tempdir)
	dumpfile.add('scandata.pickle')
	if not lite:
		dumpfile.add('data')
	try:
		os.stat('filereports')
		dumpfile.add('filereports')
	except:	pass

	for i in scans['postrunscans']:
		if i['storedir'] != None and i['storetarget'] != None and i['storetype'] != None:
			try:
				os.stat(i['storetarget'])
				dumpfile.add(i['storetarget'])
			except:	pass
	dumpfile.close()

def runscan(tempdir, scans, scan_binary):
	os.makedirs("%s/data" % (tempdir,))
	scantempdir = "%s/data" % (tempdir,)
	shutil.copy(scan_binary, scantempdir)

	magicscans = []
	for k in ["prerunscans", "unpackscans", "programscans", "postrunscans"]:
		for s in scans[k]:
			if s['magic'] != None:
				magicscans = magicscans + s['magic'].split(':')
	magicscans = list(set(magicscans))

	## Per binary scanned we get a list with results.
	## Each file system or compressed file we can unpack gives a list with
	## reports back as its result, so we have a list of lists
	## within the inner list there is a result tuple, which could contain
	## more lists in some fields, like libraries, or more result lists if
	## the file inside a file system we looked at was in fact a file system.
	leaftasks = []
	unpackreports_tmp = []
	unpackreports = {}

	scantasks = [(scantempdir, os.path.basename(scan_binary), scans['unpackscans'], scans['prerunscans'], magicscans, len(scantempdir), scantempdir, scans['batconfig']['debug'])]

	## Use multithreading to speed up scanning. Sometimes we hit http://bugs.python.org/issue9207
	## Threading can be configured in the configuration file, but
	## often it is wise to have it set to 'no'. This is because ranking writes
	## to databases and you don't want concurrent writes.
	## some categories of scans can still be run in parallel. For example
	## if only one of the program scans has a side effect, then prerun, unpack
	## and unpack scans can still be run in parallel.
	## By setting 'multiprocessing' to 'yes' and indicating that some scans should
	## not be run in parallel (which will be for the whole category of scans) it is
	## possible to have partial parallel scanning.

	if scans['batconfig']['multiprocessing'] and not scans['batconfig']['debug']:
		if False in map(lambda x: x['parallel'], scans['unpackscans'] + scans['prerunscans']):
			pool = multiprocessing.Pool(processes=1)
		else:
			pool = multiprocessing.Pool()
	else:
		pool = multiprocessing.Pool(processes=1)

	while True:
		scansplusleafs = pool.map(scan, scantasks, 1)
		scantasks = []
		for i in scansplusleafs:
			if i != None:
				scantasks = scantasks + i[0]
				leaftasks = leaftasks + i[1]
				unpackreports_tmp += [i[2]]
		if scantasks == []:
			break
	pool.terminate()

	poolresult = []
	if scans['programscans'] != []:
		## Sometimes there are duplicate files inside a blob. We
		## only want to scan them once to minimize time spent on
		## scanning. Since the results are independent anyway (the
		## unpacking phase is where unique paths are determined) we
		## can scan once for each sha256 and if there are more files
		## with the same sha256 we can simply copy the result.
		##
		## * keep a list of which sha256 have duplicates.
		## * filter out the checksums
		## * for each sha256 scan once
		## * copy results in case there are duplicates
		sha256leaf = {}
		for i in leaftasks:
			if sha256leaf.has_key(i[-3]):
				sha256leaf[i[-3]].append(i[0])
			else:
				sha256leaf[i[-3]] = [i[0]]
		sha256_tmp = {}
		for i in sha256leaf:
			if len(sha256leaf[i]) > 0:
				sha256_tmp[i] = sha256leaf[i][0]
		leaftasks_tmp = []
		for i in leaftasks:
			if sha256_tmp[i[-3]] == i[0]:
				leaftasks_tmp.append(i)
		leaftasks_tmp = map(lambda x: x[:-2] + (x[-1],), leaftasks_tmp)
		leaftasks_tmp = map(lambda x: x[:2] + (filterScans(scans['programscans'], x[2]),) + x[2:], leaftasks_tmp)

		## reverse sort on size: scan largest files first
		leaftasks_tmp.sort(key=lambda x: x[-1], reverse=True)

		if scans['batconfig']['multiprocessing'] and not scans['batconfig']['debug']:
			if False in map(lambda x: x['parallel'], scans['programscans']):
				pool = multiprocessing.Pool(processes=1)
			else:
				pool = multiprocessing.Pool()
		else:
			pool = multiprocessing.Pool(processes=1)

		poolresult = pool.map(leafScan, leaftasks_tmp, 1)
		poolresult_tmp = []
		for p in poolresult:
			pname = p[0][len(scantempdir):]
			if pname.startswith('/'):
				pname = pname[1:]
			poolresult_tmp.append((pname, p[1]))
		leafreports = dict(poolresult_tmp)
		for i in sha256leaf:
			if len(sha256leaf[i]) > 1:
				for j in sha256leaf[i][1:]:
					j_name = j[len(scantempdir):]
					if j_name.startswith('/'):
						j_name = j_name[1:]
					sha256_name = sha256leaf[i][0][len(scantempdir):]
					if sha256_name.startswith('/'):
						sha256_name = sha256_name[1:]
					leafreports[j_name] = leafreports[sha256_name]
		pool.terminate()
	else:
		leafreports = {}

	## we have a list of dicts and we just want one dict
	for i in unpackreports_tmp:
		for k in i:
			unpackreports[k] = i[k]

	## aggregate scans look at the entire result and possibly modify it.
	## The best example is JAR files: individual .class files will not be
	## very significant (or even insignificant), but combined results are.
	## Because aggregate scans have to look at the whole, these cannot be
	## run in parallel.
	if scans['aggregatescans'] != []:
		pass

	## run postrunscans here, again in parallel, if needed/wanted
	## These scans typically only have a few side effects, but don't change
	## the reporting/scanning, just process the results. Examples: generate
	## fancier reports, use microblogging to post scan results,
	## order a pizza, whatever...
	## TODO: make sure we don't process duplicates here as well, just like
	## in leaf scans.
	if scans['postrunscans'] != []:
		postrunscans = []
		for i in unpackreports:
			if leafreports.has_key(i):
				postrunscans.append((i, unpackreports[i], leafreports[i], filterScans(scans['postrunscans'], leafreports[i]['tags']), scantempdir, tempdir, scans['batconfig']['debug']))
			else:
				postrunscans.append((i, unpackreports[i], [], scans['postrunscans'], scantempdir, tempdir, scans['batconfig']['debug']))

		if scans['batconfig']['multiprocessing'] and not scans['batconfig']['debug']:
			if False in map(lambda x: x['parallel'], scans['postrunscans']):
				pool = multiprocessing.Pool(processes=1)
			else:
				pool = multiprocessing.Pool()
		else:
			pool = multiprocessing.Pool(processes=1)

		sys.stdout.flush()
		postrunresults = pool.map(postrunscan, postrunscans, 1)

	return (unpackreports, leafreports)
