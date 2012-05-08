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

5. output phase. Using a pretty printer a report is pretty printed.

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
import bat.extractor
import bat.prerun

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
def scan((path, filename, scans, prerunscans, magicscans, lenscandir, tempdir)):
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
	(offsets, order) =  bat.prerun.genericMarkerSearch(filetoscan, magicscans)

	## prerun scans should be run before any of the other scans
	for prerunscan in prerunscans:
		module = prerunscan['module']
		method = prerunscan['method']
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
			if offsets[magictype][0] - bat.fsmagic.correction.get(magictype, 0) == 0:
				zerooffsets.append(magictype)

	filesize = os.stat(filetoscan).st_size
	## Based on information about offsets we should reorder the scans,
	## or at least if one scan has a match for offset 0 (after correction
	## of the offset, like for tar, gzip, iso9660, etc.) make sure it is
	## run first.
	unpackscans = []
	scanfirst = []

	## Filter scans
	## TODO: use filterScans
	for unpackscan in scans:
		if unpackscan['noscan'] != None:
			noscans = unpackscan['noscan'].split(':')
			if list(set(noscans).intersection(set(tags))) != []:
				continue
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
	unpackscans = sorted(unpackscans, key=lambda x: x['priority'], reverse=True)

	## prepend the most promising scans at offset 0 (if any)
	scanfirst = sorted(scanfirst, key=lambda x: x['priority'], reverse=True)
	unpackscans = scanfirst + unpackscans

	unpackreports[relfiletoscan]['scans'] = []

	for unpackscan in unpackscans:
		## the whole file has already been scanned by other scans, so we can
		## continue with the program scans.
		if bat.extractor.inblacklist(0, blacklist) == filesize:
			break
		
		module = unpackscan['module']
		method = unpackscan['method']
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
							scantasks.append((i[0], p, scans, prerunscans, magicscans, len(scandir), tempdir))
							relscanpath = "%s/%s" % (i[0][lentempdir:], p)
							if relscanpath.startswith('/'):
								relscanpath = relscanpath[1:]
							scanreports.append(relscanpath)
						except Exception, e:
							pass
			except StopIteration:
        			pass
			unpackreports[relfiletoscan]['scans'].append({'scanname': unpackscan['name'], 'scanreports': scanreports, 'offset': diroffset[1], 'size': diroffset[2]})
	leaftasks.append((filetoscan, magic, tags, blacklist, tempdir, filehash, filesize))
	return (scantasks, leaftasks, unpackreports)

def leafScan((filetoscan, magic, scans, tags, blacklist, tempdir, filesize)):
	reports = []

	reports.append({'tags': tags})
	for scan in scans:
		if scan['noscan'] != None:
			noscans = scan['noscan'].split(':')
			if list(set(noscans).intersection(set(tags))) != []:
				continue
		report = {}
		module = scan['module']
		method = scan['method']
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if scan.has_key('envvars'):
			envvars = scan['envvars']
		else:
			envvars = None
		exec "from %s import %s as bat_%s" % (module, method, method)
		res = eval("bat_%s(filetoscan, blacklist, envvars=envvars)" % (method))
		if res != None:
			report[scan['name']] = res
			reports.append(report)
	return (filetoscan, reports)

def postrunscan((filetoscan, unpackreports, leafreports, scans, scantempdir, toplevelscandir)):
	for scan in scans:
		module = scan['module']
		method = scan['method']
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
				conf['priority'] = int(config.get(section, 'priority'))
			except:
				conf['priority'] = 0
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
	## sort the prerun scans on priority (highest priority first)
	prerunscans = sorted(prerunscans, key=lambda x: x['priority'], reverse=True)
	return {'batconfig': batconf, 'unpackscans': unpackscans, 'programscans': programscans, 'prerunscans': prerunscans, 'postrunscans': postrunscans}

## combine all results that we have into a format that the pretty printer can handle
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
			res['scans'].append(s)
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

def writeDumpfile(unpackreports, leafreports, scans, outputfile, tempdir):
	## if we make a dump of all the result we should have:
	## * a copy of all the unpacked data
	## * a copy of the report
	## * a pickle of all data, it saves parsing the XML report (or any other format for that matter)
	## We dump data here. There is some hardcoded data. Too bad.
	sha256spack = []
	for p in unpackreports:
		if unpackreports[p].has_key('sha256'):
			sha256spack.append(unpackreports[p]['sha256'])
	for i in scans['postrunscans']:
		if i['name'] == 'images':
			if not os.path.exists(os.path.join(tempdir, 'images')):
				os.mkdir(os.path.join(tempdir, 'images'))
			if i.has_key('envvars'):
				envvars = i['envvars'].split(':')
				for e in envvars:
					envsplit = e.split('=')
					if envsplit[0] == 'BAT_IMAGEDIR':
						target = os.path.join(tempdir, 'images')
						copyfiles = []
						## instead of globbing all the time we do the filtering ourselves
						dirlisting = filter(lambda x: x.endswith(".png"), os.listdir(envsplit[1]))
						for s in sha256spack:
							copyfiles = copyfiles + filter(lambda x: x.startswith(s), dirlisting)
						for c in copyfiles:
							shutil.copy(os.path.join(envsplit[1], c), target)
		elif i['name'] == 'hexdump':
			if not os.path.exists(os.path.join(tempdir, 'reports')):
				os.mkdir(os.path.join(tempdir, 'reports'))
			if i.has_key('envvars'):
				envvars = i['envvars'].split(':')
				for e in envvars:
					envsplit = e.split('=')
					if envsplit[0] == 'BAT_REPORTDIR':
						target = os.path.join(tempdir, 'reports')
						copyfiles = []
						dirlisting = filter(lambda x: x.endswith("-hexdump.gz"), os.listdir(envsplit[1]))
						for s in sha256spack:
							copyfiles = copyfiles + filter(lambda x: x.startswith(s), dirlisting)
						for c in copyfiles:
							shutil.copy(os.path.join(envsplit[1], c), target)
		elif i['name'] == 'uniquehtml':
			if not os.path.exists(os.path.join(tempdir, 'reports')):
				os.mkdir(os.path.join(tempdir, 'reports'))
			if i.has_key('envvars'):
				envvars = i['envvars'].split(':')
				for e in envvars:
					envsplit = e.split('=')
					if envsplit[0] == 'BAT_REPORTDIR':
						target = os.path.join(tempdir, 'reports')
						copyfiles = []
						dirlisting = filter(lambda x: x.endswith("-unique.html"), os.listdir(envsplit[1]))
						for s in sha256spack:
							copyfiles = copyfiles + filter(lambda x: x.startswith(s), dirlisting)
						for c in copyfiles:
							shutil.copy(os.path.join(envsplit[1], c), target)

	## TODO: dump unique matches for ranking scan (if available) to separate file(s)
	## It is taking a lot of space in the pickle, and it is not always used:
	## the GUI for example has almost all data pregenerated.

	picklefile = open('%s/scandata.pickle' % (tempdir,), 'wb')
	cPickle.dump((unpackreports, leafreports, scans), picklefile)
	picklefile.close()
	## now add everything to a TAR archive
	dumpfile = tarfile.TarFile(outputfile, 'w')
	os.chdir(tempdir)
	dumpfile.add('scandata.pickle')
	dumpfile.add('data')
	try:
		os.stat('images')
		dumpfile.add('images')
	except:	pass
	try:
		os.stat('reports')
		dumpfile.add('reports')
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

	scantasks = [(scantempdir, os.path.basename(scan_binary), scans['unpackscans'], scans['prerunscans'], magicscans, len(scantempdir), scantempdir)]

	## Use multithreading to speed up scanning. Sometimes we hit http://bugs.python.org/issue9207
	## Threading can be configured in the configuration file, but
	## often it is wise to have it set to 'no'. This is because ranking writes
	## to databases and you don't want concurrent writes.

	if scans['batconfig']['multiprocessing']:
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
		leaftasks_tmp = map(lambda x: x[:-2] + (x[-1],), leaftasks_tmp)
		leaftasks_tmp = map(lambda x: x[:2] + (filterScans(scans['programscans'], x[2]),) + x[2:], leaftasks_tmp)
		leaftasks_tmp.sort(key=lambda x: x[-1], reverse=True)
		poolresult = pool.map(leafScan, leaftasks_tmp, 1)
		#poolresult = map(lambda x: (x[0][len(scantempdir):], x[1]), poolresult)
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
	else:
		leafreports = {}

	## we have a list of dicts and we just want one dict
	for i in unpackreports_tmp:
		for k in i:
			unpackreports[k] = i[k]

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
				postrunscans.append((i, unpackreports[i], leafreports[i], scans['postrunscans'], scantempdir, tempdir))
			else:
				postrunscans.append((i, unpackreports[i], [], scans['postrunscans'], scantempdir, tempdir))
		postrunresults = pool.map(postrunscan, postrunscans, 1)

	return (unpackreports, leafreports)

def main(argv):
	config = ConfigParser.ConfigParser()
        parser = OptionParser()
	parser.add_option("-b", "--binary", action="store", dest="fw", help="path to binary file", metavar="FILE")
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-o", "--outputfile", action="store", dest="outputfile", help="path to output file", metavar="FILE")
	parser.add_option("-z", "--cleanup", action="store_true", dest="cleanup", help="cleanup after analysis? (default: false)")
	(options, args) = parser.parse_args()
	if options.fw == None:
        	parser.error("Path to binary file needed")
	try:
        	scan_binary = options.fw
	except:
        	print "No file to scan found"
        	sys.exit(1)

	if options.cfg != None:
		try:
        		configfile = open(options.cfg, 'r')
		except:
			print >>sys.stderr, "Need configuration file"
			sys.exit(1)
	else:
		print >>sys.stderr, "Need configuration file"
		sys.exit(1)

	if options.outputfile == None:
        	parser.error("Path to output file needed")
		sys.exit(1)
	try:
		os.stat(options.outputfile)
		print >>sys.stderr, "output file already exists"
		sys.exit(1)
	except Exception, e:
		pass

	config.readfp(configfile)
	scans = readconfig(config)

	scandate = datetime.datetime.utcnow()

	## create temporary directory to store results in
	tempdir=tempfile.mkdtemp()

	(unpackreports, leafreports) = runscan(tempdir, scans, scan_binary)

	res = flatten("%s" % (os.path.basename(scan_binary)), unpackreports, leafreports)
	if not scans['batconfig'].has_key('output'):
		## no printing?
		pass
	else:
		output = prettyprint(scans['batconfig'], res, scandate, scans)
		print output

	writeDumpfile(unpackreports, leafreports, scans, options.outputfile, tempdir)

if __name__ == "__main__":
        main(sys.argv)
