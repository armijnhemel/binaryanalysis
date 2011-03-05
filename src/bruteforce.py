#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to analyse the firmware of a device, using a "brute force" approach
and pretty print it in a simple XML file.
'''

import sys, os, os.path, magic, hashlib, subprocess, tempfile, shutil
from optparse import OptionParser
import ConfigParser
import xml.dom.minidom
import datetime
import sqlite3

ms = magic.open(magic.MAGIC_NONE)
ms.load()

'''
This method recursively generates XML snippets. If a method for a 'program'
has a pretty printing method defined, it will be used instead of the generic
one.
'''
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
				except Exception, e:
                			topnode = root.createElement(i)
                			tmpnodetext = xml.dom.minidom.Text()
                			tmpnodetext.data = res[i]
                			topnode.appendChild(tmpnodetext)
		for confs in unpackscans:
			if i == confs['name']:
                		#topnode = root.createElement(i)
                		topnode = root.createElement('unpack')
                		typenode = root.createElement('type')
                		tmpnodetext = xml.dom.minidom.Text()
                		tmpnodetext.data = i
                		typenode.appendChild(tmpnodetext)
                		topnode.appendChild(typenode)
				for elem in res[i]:
					if 'offset' in elem:
                				tmpnode = root.createElement("offset")
                				tmpnodetext = xml.dom.minidom.Text()
                				tmpnodetext.data = elem['offset']
                				tmpnode.appendChild(tmpnodetext)
                				topnode.appendChild(tmpnode)
					else:
                				tmpnode = root.createElement("file")
        					for conf in ["name", "path", "realpath", "magic", "sha256", "size", "architecture"]:
							if conf in elem:
                						tmpnode2 = root.createElement(conf)
                						tmpnodetext = xml.dom.minidom.Text()
                						tmpnodetext.data = elem[conf]
                						tmpnode2.appendChild(tmpnodetext)
                						tmpnode.appendChild(tmpnode2)

						if 'libs' in elem:
							tmpnode2 = root.createElement('libs')
							for lib in elem['libs']:
								tmpnode3 = root.createElement('lib')
                						tmpnodetext = xml.dom.minidom.Text()
                						tmpnodetext.data = lib
                						tmpnode3.appendChild(tmpnodetext)
                						tmpnode2.appendChild(tmpnode3)
                					tmpnode.appendChild(tmpnode2)

						if 'scans' in elem:
							tmpnode2 = root.createElement('scans')
							for scan in elem['scans']:
								tmpnode2.appendChild(prettyprintresxmlsnippet(scan, root, unpackscans, programscans))
								tmpnode.appendChild(tmpnode2)
                			topnode.appendChild(tmpnode)
	return topnode

## top level XML pretty printing, view results with xml_pp or Firefox
def prettyprintresxml(res, scandate, unpackscans=[], programscans=[]):
	root = xml.dom.minidom.Document()
	topnode = root.createElement("report")
	tmpnode = root.createElement('scandate')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = scandate.isoformat()
	tmpnode.appendChild(tmpnodetext)
	topnode.appendChild(tmpnode)

	## try to get extra metadata from the knowledgebase regarding
	## vendors, devices, hardware versions of devices and firmware versions
	if conn != None:
		c = conn.cursor()
		c.execute('''select vendor, name, device.version, firmware.version from device, firmware where firmware.sha256=? and device.id == firmware.deviceid''', (res['sha256'],))
		dbres = c.fetchall()
		c.close()
		for i in dbres:
			devicenode = root.createElement('device')
			(vendor,name,version,firmwareversion) = i
			tmpnode = root.createElement('vendor')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = vendor
			tmpnode.appendChild(tmpnodetext)
			devicenode.appendChild(tmpnode)

			tmpnode = root.createElement('name')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = name
			tmpnode.appendChild(tmpnodetext)
			devicenode.appendChild(tmpnode)

			tmpnode = root.createElement('hardwareversion')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = version
			tmpnode.appendChild(tmpnodetext)
			devicenode.appendChild(tmpnode)

			tmpnode = root.createElement('firmwareversion')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = firmwareversion
			tmpnode.appendChild(tmpnodetext)
			devicenode.appendChild(tmpnode)
			topnode.appendChild(devicenode)

        for conf in ["name", "path", "magic", "sha256", "size", "architecture"]:
		if conf in res:
                	tmpnode = root.createElement(conf)
                	tmpnodetext = xml.dom.minidom.Text()
                	tmpnodetext.data = res[conf]
                	tmpnode.appendChild(tmpnodetext)
                	topnode.appendChild(tmpnode)

	if 'libs' in res:
		tmpnode = root.createElement('libs')
		for lib in res['libs']:
			tmpnode2 = root.createElement('lib')
                	tmpnodetext = xml.dom.minidom.Text()
                	tmpnodetext.data = lib
                	tmpnode2.appendChild(tmpnodetext)
                	tmpnode.appendChild(tmpnode2)
		topnode.appendChild(tmpnode)

	if 'scans' in res:
		tmpnode = root.createElement('scans')
		for scan in res['scans']:
			tmpnode.appendChild(prettyprintresxmlsnippet(scan, root, unpackscans, programscans))
		topnode.appendChild(tmpnode)
	root.appendChild(topnode)
	return root

'''
This method uses readelf to determine the architecture of the executable file.
This is necessary because sometimes leftovers from different products (and
different architectures) can be found in one firmware.
'''
def scanArchitecture(path, file):
        p = subprocess.Popen(['readelf', '-h', "%s/%s" % (path, file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (stanuit, stanerr) = p.communicate()
        if p.returncode != 0:
                return
        for line in stanuit.split('\n'):
                if "Machine:" in line:
                        return line.split(':')[1].strip()

'''
The result of this method is a list of library names that the file dynamically links
with. The path of these libraries is not given, since this is usually not recorded
in the binary (unless RPATH is used) but determined at runtime: it is dependent on
the dynamic linker configuration on the device. With some mixing and matching it is
nearly always to determine which library in which path is used, since most installations
don't change the default search paths.
'''
def scanSharedLibs(path, file):
	libs = []
        p = subprocess.Popen(['readelf', '-d', "%s/%s" % (path, file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (stanuit, stanerr) = p.communicate()
        if p.returncode != 0:
                return
        for line in stanuit.split('\n'):
                if "Shared library:" in line:
                        libs.append(line.split(': ')[1][1:-1])
	return libs

'''
This method returns a cryptographic checksum for a file using the SHA256
algorithm. This information can be used to uniquely identify a file and
perhaps reuse results for scans of this file in a later audit.
'''
def gethash(path, file):
	scanfile = open("%s/%s" % (path, file), 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	return h.hexdigest()

'''
This method returns a report snippet for inclusion in the final
report.
'''
def scanfile(path, file, lentempdir=0, tempdir=None, unpackscans=[], programscans=[]):
	report = {}

	## this will report incorrectly if we only have unpacked one file to a
	## temporary location, for example a kernel image
	report['name'] = file

	## Add both the path to indicate the position inside the file sytem
        ## or file we have unpacked, as well as the position of the files as unpacked
	## by BAT, convenient for later analysis of binaries.
	report['path'] = path[lentempdir:].replace("/squashfs-root", "")
	report['realpath'] = path
	type = ms.file("%s/%s" % (path, file))
	report['magic'] = type

        ## broken symbolic links can't be statted
        if type.find('broken symbolic link to') == 0:
        	return report
        ## don't care about symbolic links
        if type.find('symbolic link to') == 0:
        	return report
        ## no use checking a named pipe
        if type.find('fifo (named pipe)') == 0:
        	return report
	## no use checking a socket
        if type.find('socket') == 0:
        	return report
	## no use checking a block device
        if type.find('block special') == 0:
        	return report
	## no use checking a character device
        if type.find('character special') == 0:
        	return report

	report['size'] = os.lstat("%s/%s" % (path, file)).st_size

	## empty file, not interested
	if os.lstat("%s/%s" % (path, file)).st_size == 0:
		return report

	## Store the hash of the file for identification and for possibly
	## querying the knowledgebase later on.
	filehash = gethash(path, file)
	report['sha256'] = filehash

	if "ELF" in type:
		res = scanSharedLibs(path,file)
		if res != []:
			report['libs'] = res
		res = scanArchitecture(path,file)
		if res != None:
			report['architecture'] = res
	scannedfile = "%s/%s" % (path, file)

	## scan per file and store the results
	res = scan(scannedfile, type, filehash=filehash, tempdir=tempdir, unpackscans=unpackscans, programscans=programscans)
	if res != []:
		report['scans'] = res
	return report

## result is a list of result tuples, one for every file in the directory
def walktempdir(scandir, tempdir, unpackscans, programscans):
	osgen = os.walk(scandir)
	reports = []
	try:
       		while True:
                	i = osgen.next()
                	for p in i[2]:
				try:
					res = scanfile(i[0], p, lentempdir=len(scandir), tempdir=tempdir, unpackscans=unpackscans, programscans=programscans)
					if res != []:
						reports.append(res)
				except Exception, e:
					print e
	except StopIteration:
        	pass
	return reports

## scan a single file. Optionally supply a filehash for checking a knowledgebase
def scan(scanfile, magic, unpackscans=[], programscans=[], filehash=None, tempdir=None):
	reports = []
	## we reset the blacklist for each new scan we do
	blacklist = []

	## list of magic file types that 'program' checks should skip
	## to avoid false positives and superfluous scanning. Does not work
	## correctly yet, for romfs for example.
	## If we use priorities we can rework this. The benefit of
	## the current approach is that it is a lot faster.
	## The drawback is that we might miss things that have been appended
	## to any of the things in this list. So for correctness we should
	## not rely on this.
	programignorelist = [ "POSIX tar archive (GNU)"
                            , "Linux rev 0.0 ext2 filesystem data"
                            , "Linux rev 1.0 ext2 filesystem data"
                            , "Zip archive data, at least v1.0 to extract"
                            , "romfs filesystem, version 1"
                            ]

	## 'unpackscans' has been sorted in decreasing priority, so highest
	## priority scans are run first.
	for scan in unpackscans:
		noscan = False
		module = scan['module']
		method = scan['method']
		## return value is the temporary dir, plus offset in the parent file
		## plus a blacklist containing blacklisted ranges for the *original*
		## file.
		exec "from %s import %s as bat_%s" % (module, method, method)
		#(diroffsets, blacklist) = eval("bat_%s(scanfile, tempdir, blacklist)" % (method))
		scanres = eval("bat_%s(scanfile, tempdir, blacklist)" % (method))
		## result is either empty, or contains offsets
		if len(scanres) == 2:
			(diroffsets, blacklist) = scanres
		elif len(scanres) == 3:
			(diroffsets, blacklist, noscan) = scanres
		if len(diroffsets) == 0:
			continue
		## each diroffset is a (path, offset) tuple
		## TODO: optionally, there could be a 'noscan' boolean value
		for diroffset in diroffsets:
			report = {}
			if diroffset == None:
				continue
			scandir = diroffset[0]
			if noscan:
				continue
			## recursively scan all files in the directory
			res = walktempdir(scandir, tempdir, unpackscans, programscans)
			if res != []:
				res.append({'offset': diroffset[1]})
				report[scan['name']] = res
				reports.append(report)
	for scan in programscans:
		## TODO: rework this. Probably having blacklists or 'noscan' is enough is enough for this.
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
		exec "from %s import %s as bat_%s" % (module, method, method)
		## temporary stuff, this should actually be nicely wrapped in a report tuple
		res = eval("bat_%s(scanfile, blacklist)" % (method))
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
	for section in config.sections():
		if config.has_option(section, 'type'):
			conf = {}
			if config.get(section, 'type') == 'program':
				conf['name']   = section
				conf['module'] = config.get(section, 'module')
				conf['method'] = config.get(section, 'method')
				try:
					conf['xmloutput'] = config.get(section, 'xmloutput')
				except:
					pass
				try:
					conf['cleanup'] = config.get(section, 'cleanup')
				except:
					pass
				programscans.append(conf)
			elif config.get(section, 'type') == 'unpack':
				conf['name']   = section
				conf['module'] = config.get(section, 'module')
				conf['method'] = config.get(section, 'method')
				try:
					conf['priority'] = int(config.get(section, 'priority'))
				except:
					conf['priority'] = 0
				try:
					conf['xmloutput'] = config.get(section, 'xmloutput')
				except:
					pass
				try:
					conf['cleanup'] = config.get(section, 'cleanup')
				except:
					pass
				unpackscans.append(conf)
	unpackscans = sorted(unpackscans, key=lambda x: x['priority'], reverse=True)
	return (unpackscans, programscans)

def main(argv):
	config = ConfigParser.ConfigParser()
        parser = OptionParser()
	parser.add_option("-a", "--always", action="store_true", dest="scanalways", help="always perform brute force scan even if results are availale in the knowledgebase (default false)")
	parser.add_option("-b", "--binary", action="store", dest="fw", help="path to binary file", metavar="FILE")
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-d", "--database", action="store", dest="db", help="path to sqlite database (optional)", metavar="FILE")
	parser.add_option("-z", "--cleanup", action="store_true", dest="cleanup", help="cleanup after analysis? (default: false)")
	(options, args) = parser.parse_args()
	if options.fw == None:
        	parser.error("Path to binary file needed")
	try:
        	firmware_binary = options.fw
	except:
        	print "No file to scan found"
        	sys.exit(1)

	global conn
	conn = None

	if options.db != None:
		try:
			conn = sqlite3.connect(options.db)
		except:
			print "Can't open database file"
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

	(unpackscans, programscans) = readconfig(config)
	scandate = datetime.datetime.utcnow()

	## Per firmware scanned we get a list with results.
	## Each file system or compressed file we can unpack gives a list with
	## reports back as its result, so we have a list of lists
	## within the inner list there is a result tuple, which could contain
	## more lists in some fields, like libraries, or more result lists if
	## the file inside a file system we looked at was in fact a file system.
	tempdir=tempfile.mkdtemp()
	#tempdir=None
	shutil.copy(firmware_binary, tempdir)
	res = scanfile(tempdir, os.path.basename(firmware_binary), tempdir=tempdir, unpackscans=unpackscans, programscans=programscans)
	xml = prettyprintresxml(res, scandate, unpackscans=unpackscans, programscans=programscans)
	print xml.toxml()

if __name__ == "__main__":
        main(sys.argv)
