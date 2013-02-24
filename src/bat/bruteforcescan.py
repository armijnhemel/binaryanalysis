#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2013 Armijn Hemel for Tjaldur Software Governance Solutions
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

import sys, os, os.path, magic, hashlib, subprocess, tempfile, shutil, stat, multiprocessing, cPickle, glob, tarfile, copy, gzip
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
			print >>sys.stderr, module, method, filename
			sys.stderr.flush()
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

	unpacked = False
	for unpackscan in unpackscans:
		## the whole file has already been scanned by other scans, so we can
		## continue with the program scans.
		if extractor.inblacklist(0, blacklist) == filesize:
			break
		
		module = unpackscan['module']
		method = unpackscan['method']
		if debug:
			print >>sys.stderr, module, method, filetoscan
			sys.stderr.flush()
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if unpackscan.has_key('envvars'):
			envvars = unpackscan['envvars'] + ":BAT_UNPACKED=%s" % unpacked
		else:
			envvars = "BAT_UNPACKED=%s" % unpacked
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
			unpacked = True
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
	unpackreports[relfiletoscan]['tags'] = tags
	if not unpacked and 'temporary' in tags:
		os.unlink(filetoscan)
		return (scantasks, leaftasks, unpackreports)
	else:
		leaftasks.append((filetoscan, magic, tags, blacklist, filehash, filesize))
	return (scantasks, leaftasks, unpackreports)

def leafScan((filetoscan, magic, scans, tags, blacklist, filehash, topleveldir, debug)):
	reports = {}
	newtags = []

	reports['tags'] = tags
	for scan in scans:
		report = {}
		module = scan['module']
		method = scan['method']
		if debug:
			print >>sys.stderr, method, filetoscan
			sys.stderr.flush()
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if scan.has_key('envvars'):
			envvars = scan['envvars']
		else:
			envvars = None
		exec "from %s import %s as bat_%s" % (module, method, method)
		res = eval("bat_%s(filetoscan, blacklist, envvars=envvars)" % (method))
		if res != None:
			(nt, leafres) = res
			reports[scan['name']] = leafres
			newtags = newtags + nt

	## write pickles with information to disk here to reduce memory usage
	try:
		os.stat('%s/filereports/%s-filereport.pickle' % (topleveldir,filehash))
	except:
		picklefile = open('%s/filereports/%s-filereport.pickle' % (topleveldir,filehash), 'wb')
		cPickle.dump(reports, picklefile)
		picklefile.close()
	return (filehash, list(set(newtags)))

def aggregatescan(unpackreports, scans, scantempdir, topleveldir, debug):
	## aggregate scans look at the entire result and possibly modify it.
	## The best example is JAR files: individual .class files will not be
	## very significant (or even insignificant), but combined results are.
	## Because aggregate scans have to look at everything as a whole, these
	## cannot be run in parallel.
	for scan in scans['aggregatescans']:
		module = scan['module']
		method = scan['method']
		if debug:
			print >>sys.stderr, module, method
			sys.stderr.flush()
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if scan.has_key('envvars'):
			envvars = scan['envvars']
		else:
			envvars = None
		exec "from %s import %s as bat_%s" % (module, method, method)

		eval("bat_%s(unpackreports, scantempdir, topleveldir, envvars=envvars)" % (method))

def postrunscan((filetoscan, unpackreports, scans, scantempdir, topleveldir, debug)):
	for scan in scans:
		module = scan['module']
		method = scan['method']
		if debug:
			print >>sys.stderr, module, method, filetoscan
			sys.stderr.flush()
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if scan.has_key('envvars'):
			envvars = scan['envvars']
		else:
			envvars = None
		exec "from %s import %s as bat_%s" % (module, method, method)

		res = eval("bat_%s(filetoscan, unpackreports, scantempdir, topleveldir, envvars=envvars)" % (method))
		## TODO: find out what we want to do with this
		if res != None:
			pass

## arrays for storing data for the scans we have.
## unpackscans: {name, module, method, xmloutput, priority}
## These are sorted by priority
## programscans: {name, module, method, xmloutput}
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
				conf['xmloutput'] = config.get(section, 'xmloutput')
			except:
				pass

			## some things only make sense in a particular context
			if config.get(section, 'type') == 'postrun':
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
	aggregatescans = sorted(aggregatescans, key=lambda x: x['priority'], reverse=True)
	return {'batconfig': batconf, 'unpackscans': unpackscans, 'programscans': programscans, 'prerunscans': prerunscans, 'postrunscans': postrunscans, 'aggregatescans': aggregatescans}

def prettyprint(batconf, res, scandate, scans, toplevelfile, topleveldir):
	module = batconf['module']
	method = batconf['output']
	## if there is extra information we need to pass, like locations of databases
	## we can use the environment for it
	if batconf.has_key('envvars'):
		envvars = batconf['envvars']
	else:
		envvars = None
	exec "from %s import %s as bat_%s" % (module, method, method)
	output = eval("bat_%s(res, scandate, scans, toplevelfile, topleveldir, envvars)" % (method))
	return output

def dumpData(unpackreports, scans, tempdir):
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
	sha256spack = list(set(sha256spack))
	oldstoredir = None
	oldlistdir = []
	for i in scans['postrunscans']:
		## use parameters from configuration file. This assumes that the names of the
		## all output files of a particular scan start with the checksum of the scanned
		## file and have a common suffix.
		if i['storedir'] != None and i['storetarget'] != None and i['storetype'] != None:
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
				dirfilter = list(set(map(lambda x: x.split('-')[0], dirlisting)))
				inter = list(set(sha256spack).intersection(set(dirfilter)))
				for s in inter:
					copyfiles = filter(lambda x: s in x, dirlisting)
					for c in copyfiles:
						dirlisting.remove(c)
					for c in list(set(copyfiles)):
						shutil.copy(os.path.join(i['storedir'], c), target)
						if i['cleanup']:
							try:
								os.unlink(os.path.join(i['storedir'],c))
							except Exception, e:
								print >>sys.stderr, "removing failed", c, e
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
			for r in list(set(removefiles)):
				try:
					os.unlink(os.path.join(i['storedir'],r))
				except Exception, e:
					print >>sys.stderr, "removing failed", r, e
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
def writeDumpfile(unpackreports, scans, outputfile, configfile, tempdir, lite=False):
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
		pool = multiprocessing.Pool()
		fnames = map(lambda x: os.path.join(tempdir, "filereports", x), filereports)
		pool.map(compressPickle, fnames)
		pool.terminate()
		dumpfile.add('filereports')
	except Exception,e:	print >>sys.stderr, e

	dumpadds = []
	for i in scans['postrunscans']:
		if i['storedir'] != None and i['storetarget'] != None and i['storetype'] != None:
			try:
				os.stat(i['storetarget'])
				dumpadds.append(i['storetarget'])
			except:	pass
	for i in list(set(dumpadds)):
		dumpfile.add(i)
	dumpfile.close()

def runscan(topleveldir, scans, scan_binary):
	os.makedirs("%s/data" % (topleveldir,))
	scantempdir = "%s/data" % (topleveldir,)
	shutil.copy(scan_binary, scantempdir)
	debug = scans['batconfig']['debug']

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

	scantasks = [(scantempdir, os.path.basename(scan_binary), scans['unpackscans'], scans['prerunscans'], magicscans, len(scantempdir), scantempdir, debug)]

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

	if scans['batconfig']['multiprocessing'] and not debug:
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
	tagdict = {}
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
		leaftasks_tmp = map(lambda x: x[:2] + (filterScans(scans['programscans'], x[2]),) + x[2:-1] + (topleveldir, debug), leaftasks_tmp)

		if scans['batconfig']['multiprocessing'] and not debug:
			if False in map(lambda x: x['parallel'], scans['programscans']):
				pool = multiprocessing.Pool(processes=1)
			else:
				pool = multiprocessing.Pool()
		else:
			pool = multiprocessing.Pool(processes=1)

		if not os.path.exists(os.path.join(topleveldir, 'filereports')):
			os.mkdir(os.path.join(topleveldir, 'filereports'))

		poolresult = pool.map(leafScan, leaftasks_tmp, 1)
		pool.terminate()

		## filter the results for the leafscans. These are the ones that
		## returned tags. These need to be merged into unpackreports.
		mergetags = filter(lambda x: x[1] != [], poolresult)
		for m in mergetags:
			tagdict[m[0]] = m[1]

	## we have a list of dicts and we just want one dict
	for i in unpackreports_tmp:
		for k in i:
			unpackreports[k] = i[k]

	for i in unpackreports.keys():
		if not unpackreports[i].has_key('sha256'):
			continue
		unpacksha256 = unpackreports[i]['sha256']
		if tagdict.has_key(unpacksha256):
			if unpackreports[i].has_key('tags'):
				unpackreports[i]['tags'] = list(set(unpackreports[i]['tags'] + tagdict[unpacksha256]))

	if scans['aggregatescans'] != []:
		aggregatescan(unpackreports, scans, scantempdir, topleveldir, debug)

	## run postrunscans here, again in parallel, if needed/wanted
	## These scans typically only have a few side effects, but don't change
	## the reporting/scanning, just process the results. Examples: generate
	## fancier reports, use microblogging to post scan results, etc.
	## We make sure we don't process duplicates here as well, just like
	## in leaf scans.
	## The assumption that is being made here is that the postrunscans only
	## really use the SHA256 values, which is right now the case.
	if scans['postrunscans'] != [] and unpackreports != {}:
		## if unpackreports != {} we know that we have done deduplication
		## already, so we can just reuse it here.
		postrunscans = []
		for i in map(lambda x: x[len(scantempdir)+1:], sha256_tmp.values()):
			## results might have been changed by aggregate scans, so check if it still exists
			if unpackreports.has_key(i):
				postrunscans.append((i, unpackreports[i], scans['postrunscans'], scantempdir, topleveldir, debug))

		if scans['batconfig']['multiprocessing'] and not debug:
			if False in map(lambda x: x['parallel'], scans['postrunscans']):
				pool = multiprocessing.Pool(processes=1)
			else:
				pool = multiprocessing.Pool()
		else:
			pool = multiprocessing.Pool(processes=1)

		postrunresults = pool.map(postrunscan, postrunscans, 1)
		pool.terminate()

	return unpackreports
