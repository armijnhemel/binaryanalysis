#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to analyse binary blobs, using a "brute force" approach
and pretty print the analysis in a simple XML format.
'''

import sys, os, os.path, magic, hashlib, subprocess, tempfile, shutil, stat
from optparse import OptionParser
import ConfigParser
import xml.dom.minidom
import datetime
import sqlite3
import bat.extractor

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


## pretty printing for various elements
def generateNodes(elem, root, confs):
	nodes = []
	for conf in confs:
		if conf in elem:
			tmpnode = root.createElement(conf)
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = str(elem[conf])
			tmpnode.appendChild(tmpnodetext)
			nodes.append(tmpnode)
	return nodes

## This method recursively generates XML snippets. If a method for a 'program'
## has a pretty printing method defined, it will be used instead of the generic
## one.
def prettyprintresxmlsnippet(res, root, unpackscans, programscans):
	## this should always be len == 1, have more checks
	for i in res.keys():
		for confs in programscans:
			if i == confs['name']:
				try:
					module = confs['module']
					method = confs['xmloutput']
					exec "from %s import %s as bat_%s" % (module, method, method)
					xmlres = eval("bat_%s(res[i], root)" % (method))
					if xmlres != None:
                				topnode = xmlres
					else:
						topnode = None
				except Exception, e:
                			topnode = root.createElement(i)
                			tmpnodetext = xml.dom.minidom.Text()
                			tmpnodetext.data = str(res[i])
                			topnode.appendChild(tmpnodetext)
		for confs in unpackscans:
			if i == confs['name']:
                		topnode = root.createElement('unpack')
                		typenode = root.createElement('type')
                		tmpnodetext = xml.dom.minidom.Text()
                		tmpnodetext.data = str(i)
                		typenode.appendChild(tmpnodetext)
                		topnode.appendChild(typenode)
				for elem in res[i]:
					if 'offset' in elem:
                				tmpnode = root.createElement("offset")
                				tmpnodetext = xml.dom.minidom.Text()
                				tmpnodetext.data = str(elem['offset'])
                				tmpnode.appendChild(tmpnodetext)
                				topnode.appendChild(tmpnode)
					else:
                				tmpnode = root.createElement("file")
						tmpnodes = generateNodes(elem, root, ["name", "path", "realpath", "magic", "sha256", "size"])
						for tmpnode2 in tmpnodes:
                					tmpnode.appendChild(tmpnode2)

						if 'scans' in elem:
							tmpnode2 = root.createElement('scans')
							for scan in elem['scans']:
								childscannode = prettyprintresxmlsnippet(scan, root, unpackscans, programscans)
								if childscannode != None:
									tmpnode2.appendChild(childscannode)
								tmpnode.appendChild(tmpnode2)
                			topnode.appendChild(tmpnode)
	return topnode

## top level XML pretty printing, view results with xml_pp or Firefox
def prettyprintresxml(res, scandate, scans):
	root = xml.dom.minidom.Document()
	topnode = root.createElement("report")
	tmpnode = root.createElement('scandate')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = scandate.isoformat()
	tmpnode.appendChild(tmpnodetext)
	topnode.appendChild(tmpnode)

	## there are a few things we always want to know about the top level node
	tmpnodes = generateNodes(res, root, ["name", "path", "realpath", "magic", "sha256", "size"])
	for tmpnode in tmpnodes:
                topnode.appendChild(tmpnode)

	## then we recurse into the results from the individual scans
	if 'scans' in res:
		tmpnode = root.createElement('scans')
		for scan in res['scans']:
			childscannode = prettyprintresxmlsnippet(scan, root, scans['unpackscans'], scans['programscans'])
			if childscannode != None:
				tmpnode.appendChild(childscannode)
		topnode.appendChild(tmpnode)
	root.appendChild(topnode)
	return root

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

## This method returns a report snippet for inclusion in the final report. The
## report snippet is per file, but if a file has other files embedded in it, the
## it will include reports for those files as well in the 'scans' section of the
## report.
def scanfile(path, filename, scans, lentempdir=0, tempdir=None, noscan=False):
	report = {}

	report['name'] = filename

	## Add both the path to indicate the position inside the file sytem
        ## or file we have unpacked, as well as the position of the files as unpacked
	## by BAT, convenient for later analysis of binaries.
	## In case of squashfs we remove the "squashfs-root" part of the temporary
	## directory too, if it is present (not always).
	report['path'] = path[lentempdir:].replace("/squashfs-root", "")
	report['realpath'] = path
	mstype = ms.file("%s/%s" % (path, filename))
	report['magic'] = mstype

	if os.path.islink("%s/%s" % (path, filename)):
		return report
	## no use checking pipes, sockets, device files, etcetera
	if not os.path.isfile("%s/%s" % (path, filename)) and not os.path.isdir("%s/%s" % (path, filename)):
		return report

	filesize = os.lstat("%s/%s" % (path, filename)).st_size
	report['size'] = filesize

	## empty file, not interested in further scanning
	if filesize == 0:
		return report

	## Store the hash of the file for identification and for possibly
	## querying the knowledgebase later on.
	filehash = gethash(path, filename)
	report['sha256'] = filehash

	filetoscan = "%s/%s" % (path, filename)

	## and store the results per scanned file, except when explicitely
	## instructed not to scan. In that case just report some statistics
	## about the file.
	if not noscan:
		res = scan(filetoscan, mstype, scans, filehash=filehash, tempdir=tempdir)
		if res != []:
			report['scans'] = res
	return report

## scan a single file and recurse. Optionally supply a filehash for
## checking a knowledgebase, which is future work.
def scan(filetoscan, magic, scans, filehash=None, tempdir=None):
	## we reset the reports, blacklist and offsets for each new scan
	reports = []
	blacklist = []
	offsets = {}

	## prerun scans should be run before any of the other scans
	## * byteswapping
	## * scanning for markers
	for scan in scans['prerunscans']:
		module = scan['module']
		method = scan['method']
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if scan.has_key('envvars'):
			envvars = scan['envvars']
		else:
			envvars = None
		exec "from %s import %s as bat_%s" % (module, method, method)
		scanres = eval("bat_%s(filetoscan, tempdir, blacklist, offsets, envvars)" % (method))
		## result is either empty, or contains offsets
		if len(scanres) == 3:
			(diroffsets, blacklist, offsets) = scanres
		elif len(scanres) == 4:
			(diroffsets, blacklist, offsets, noscan) = scanres

	## we have all offsets with markers here, so we can filter out
	## the scans we won't need
	## TODO: only filter the scans we need, sort them by offset
	## to make sure we get it right the first time more often
	filterscans = []
	for magictype in offsets.keys():
		if offsets[magictype] != []:
			filterscans.append(magictype)

	filesize = os.stat(filetoscan).st_size
	## 'unpackscans' has been sorted in decreasing priority, so highest
	## priority scans are run first.
	for scan in scans['unpackscans']:
		## the whole file has already been scanned by other scans, so we can
		## continue with the program scans.
		if bat.extractor.inblacklist(0, blacklist) == filesize:
			break
		noscan = False
		
		## if we don't have a marker in the file, but we do have a marker
		## in the scan, we can continue with the next scan
		if scan['magic'] != None:
			scanmagic = scan['magic'].split(':')
			if list(set(scanmagic).intersection(set(filterscans))) == []:
				continue

		module = scan['module']
		method = scan['method']
		## if there is extra information we need to pass, like locations of databases
		## we can use the environment for it
		if scan.has_key('envvars'):
			envvars = scan['envvars']
		else:
			envvars = None
		## return value is the temporary dir, plus offset in the parent file
		## plus a blacklist containing blacklisted ranges for the *original*
		## file and a hash with offsets for each marker.
		exec "from %s import %s as bat_%s" % (module, method, method)
		scanres = eval("bat_%s(filetoscan, tempdir, blacklist, offsets, envvars)" % (method))
		## result is either empty, or contains offsets
		if len(scanres) == 3:
			(diroffsets, blacklist, offsets) = scanres
		elif len(scanres) == 4:
			(diroffsets, blacklist, offsets, noscan) = scanres
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
							res = scanfile(i[0], p, scans, lentempdir=len(scandir), tempdir=tempdir, noscan=noscan)
							if res != []:
								scanreports.append(res)
						except Exception, e:
							#print e
							pass
			except StopIteration:
        			pass
			if scanreports != []:
				scanreports.append({'offset': diroffset[1]})
				report[scan['name']] = scanreports
				reports.append(report)

	## list of magic file types that 'program' checks should skip
	## to avoid false positives and superfluous scanning. Does not work
	## correctly yet, for romfs for example.
	## If we use priorities we can rework this. The benefit of
	## the current approach is that it is a lot faster.
	## The drawback is that we might miss things that have been appended
	## to any of the things in this list. So for correctness we should
	## not rely on this.
	programignorelist = [ "POSIX tar archive (GNU)"
                            , "Zip archive data, at least v1.0 to extract"
                            , "romfs filesystem, version 1"
                            ]

	for scan in scans['programscans']:
		## TODO: rework this. Having blacklists is enough for this.
		skip = False
		for prog in programignorelist:
			if prog in magic:
				skip = True
				break
		if skip:
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
		## temporary stuff, this should actually be nicely wrapped in a report tuple
		res = eval("bat_%s(filetoscan, blacklist, envvars=envvars)" % (method))
		if res != None:
			report[scan['name']] = res
			reports.append(report)
	return reports

## arrays for storing data for the scans we have. Since the configuration is
## only read once and thus will not change we can easily store it globally
## unpackscans: {name, module, method, xmloutput, priority, cleanup}
## These are sorted by priority
## programscans: {name, module, method, xmloutput, cleanup}
def readconfig(config):
	unpackscans = []
	programscans = []
	prerunscans = []
	for section in config.sections():
		if config.has_option(section, 'type'):
			conf = {}
			conf['name']   = section
			conf['module'] = config.get(section, 'module')
			conf['method'] = config.get(section, 'method')

			## some scans might, or might not, have these
			try:
				conf['xmloutput'] = config.get(section, 'xmloutput')
			except:
				pass
			try:
				conf['magic'] = config.get(section, 'magic')
			except:
				conf['magic'] = None
			try:
				conf['cleanup'] = config.get(section, 'cleanup')
			except:
				pass
			try:
				conf['envvars'] = config.get(section, 'envvars')
			except:
				pass
			try:
				conf['priority'] = int(config.get(section, 'priority'))
			except:
				conf['priority'] = 0

			if config.get(section, 'type') == 'program':
				programscans.append(conf)
			elif config.get(section, 'type') == 'unpack':
				unpackscans.append(conf)
			elif config.get(section, 'type') == 'prerun':
				prerunscans.append(conf)
	## sort the unpack and prerun scans on priority (highest priority first)
	unpackscans = sorted(unpackscans, key=lambda x: x['priority'], reverse=True)
	prerunscans = sorted(prerunscans, key=lambda x: x['priority'], reverse=True)
	return {'unpackscans': unpackscans, 'programscans': programscans, 'prerunscans': prerunscans}

def main(argv):
	config = ConfigParser.ConfigParser()
        parser = OptionParser()
	parser.add_option("-a", "--always", action="store_true", dest="scanalways", help="always perform brute force scan even if results are availale in the knowledgebase (default false)")
	parser.add_option("-b", "--binary", action="store", dest="fw", help="path to binary file", metavar="FILE")
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-z", "--cleanup", action="store_true", dest="cleanup", help="cleanup after analysis? (default: false)")
	(options, args) = parser.parse_args()
	if options.fw == None:
        	parser.error("Path to binary file needed")
	try:
        	scan_binary = options.fw
	except:
        	print "No file to scan found"
        	sys.exit(1)

	global scanalways
	if options.scanalways == None:
		scanalways = False
	else:
		scanalways = options.scanalways

	if options.cfg != None:
		try:
        		configfile = open(options.cfg, 'r')
		except:
			print "Need configuration file"
			sys.exit(1)
	else:
		print "Need configuration file"
		sys.exit(1)

	config.readfp(configfile)

	scans = readconfig(config)
	scandate = datetime.datetime.utcnow()

	## Per binary scanned we get a list with results.
	## Each file system or compressed file we can unpack gives a list with
	## reports back as its result, so we have a list of lists
	## within the inner list there is a result tuple, which could contain
	## more lists in some fields, like libraries, or more result lists if
	## the file inside a file system we looked at was in fact a file system.
	tempdir=tempfile.mkdtemp()
	shutil.copy(scan_binary, tempdir)
	res = scanfile(tempdir, os.path.basename(scan_binary), scans, tempdir=tempdir)
	xml = prettyprintresxml(res, scandate, scans)
	print xml.toxml()

if __name__ == "__main__":
        main(sys.argv)
