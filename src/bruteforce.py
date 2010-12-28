#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to analyse the firmware of a device, using a "brute force" approach
and pretty print it in a simple XML file.
'''

import sys, os, os.path, magic, hashlib, subprocess
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
def prettyprintresxmlsnippet(res, config, root):
	## this should always be len == 1, have more checks
	for i in res.keys():
		if config.has_option(i, 'type'):
			if config.get(i, 'type') == 'program':
				try:
					module = config.get(i, 'module')
					method = config.get(i, 'xmloutput')
					exec "from %s import %s as bat_%s" % (module, method, method)
					xmlres = eval("bat_%s(res[i], root)" % (method))
					if xmlres != None:
                				topnode = xmlres
				except Exception, e:
                			topnode = root.createElement(i)
                			tmpnodetext = xml.dom.minidom.Text()
                			tmpnodetext.data = res[i]
                			topnode.appendChild(tmpnodetext)
			elif config.get(i, 'type') == 'unpack':
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
        					for conf in ["name", "path", "magic", "sha256", "size", "architecture"]:
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
								tmpnode2.appendChild(prettyprintresxmlsnippet(scan, config, root))
								tmpnode.appendChild(tmpnode2)
                			topnode.appendChild(tmpnode)
	return topnode

## top level XML pretty printing, view results with xml_pp or Firefox
def prettyprintresxml(res, configs, scandate):
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
			tmpnode.appendChild(prettyprintresxmlsnippet(scan, configs, root))
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
report. Right now 'checks' is ignored and all checks are applied,
but we really want to be able to weed a bit.
'''
def scanfile(path, file, checks, lentempdir=0):
	report = {}

	## this will report incorrectly if we only have unpacked one file to a
	## temporary location, for example a kernel image
	report['name'] = file
	report['path'] = path[lentempdir:].replace("/squashfs-root", "")
	type = ms.file("%s/%s" % (path, file))
	report['magic'] = type

        ## broken symbolic links can't be statted, so return now
        if type.find('broken symbolic link to') == 0:
        	return report
        ## no use checking a named pipe
        if type.find('fifo (named pipe)') == 0:
        	return report
	## no use checking a socket
        if type.find('socket') == 0:
        	return report
        ## don't care about symbolic links
        elif type.find('symbolic link to') == 0:
        	return report

	report['size'] = os.lstat("%s/%s" % (path, file)).st_size

	## empty file, not interested
	if os.lstat("%s/%s" % (path, file)).st_size == 0:
		return report

	## store the hash of the file for possibly querying the
	## knowledgebase later on
	filehash = gethash(path, file)
	report['sha256'] = filehash

	## Filter out various things based on magic type.
        if type.find('ASCII text') == 0:
        	return report
        elif type.find('ASCII English text') == 0:
        	return report
        elif type.find('XML') == 0:
        	return report
        elif type.find('GIF image data') == 0:
        	return report
        elif type.find('PNG image') == 0:
        	return report
        elif type.find('JPEG image data') == 0:
        	return report
        elif type.find('PC bitmap') == 0:
        	return report
        elif type.find('MPEG') == 0:
        	return report
        elif type.find('Ogg data') == 0:
        	return report
        elif type.find('Apple QuickTime movie') == 0:
        	return report
        elif type.find('MS Windows icon resource') == 0:
        	return report
        elif type.find('Macromedia Flash Video') == 0:
        	return report
        elif type.find('tcpdump capture file') == 0:
        	return report
        elif type.find('timezone data') == 0:
        	return report
        elif type.find('LaTeX') == 0:
        	return report
        elif type.find('PDF document') == 0:
        	return report
        elif type.find('PostScript document text') == 0:
        	return report
        elif type.find('MySQL') == 0:
        	return report
        elif type.find('HTML document text') != -1:
        	return report
        elif type == 'Microsoft ICM Color Profile':
        	return report
        elif type == 'exported SGML document text':
        	return report
        elif type == 'M3U playlist text':
        	return report
        elif type == 'diff output text':
        	return report
        elif type == 'UTF-8 Unicode text':
        	return report
        elif type == 'lex description text':
        	return report
        elif type == 'OS/2 REXX batch file text':
        	return report
        elif type == 'ISO-8859 C program text':
        	return report
        elif type == 'FORTRAN program':
        	return report
        elif type == 'python script text executable':
        	return report
	# some binaries may be distributed as shell scripts that unpack them
        #elif type == 'POSIX shell script text executable':
        #	continue
	if "ELF" in type:
		res = scanSharedLibs(path,file)
		if res != []:
			report['libs'] = res
		res = scanArchitecture(path,file)
		if res != None:
			report['architecture'] = res
	scannedfile = "%s/%s" % (path, file)
	res = scan(scannedfile, checks, type, filehash)
	if res != []:
		report['scans'] = res
	return report

## result is a list of result tuples, one for every file in the directory
def walktempdir(tempdir, checks):
	osgen = os.walk(tempdir)
	reports = []
	try:
       		while True:
                	i = osgen.next()
                	for p in i[2]:
				try:
					res = scanfile(i[0], p, checks, len(tempdir))
					if res != []:
						reports.append(res)
				except Exception, e:
					print e
	except StopIteration:
        	pass
	return reports

## scan a single file. Optionally supply a filehash for checking a knowledgebase
def scan(scanfile, config, magic, filehash=None):
	reports = []

	## get stuff from the knowledgebase, but skip if we have the 'scanalways' flag set
	if not scanalways:
		if filehash == None:
			## we could not find the hash in the knowledgebase
			pass
		else:
			pass

	## list of magic file types that 'program' checks should not do
	## to avoid false positives and superfluous scanning.
	## Does not work correctly yet, for romfs for example. Solution:
	## "normalize" magic first
	programignorelist = [ "POSIX tar archive (GNU)"
                            , "Linux rev 0.0 ext2 filesystem data"
                            , "Linux rev 1.0 ext2 filesystem data"
                            , "Zip archive data, at least v1.0 to extract"
                            , "romfs filesystem, version 1"
                            ]
	for section in config.sections():
		if config.has_option(section, 'type'):
			if config.get(section, 'type') == 'program':
				skip = False
				for prog in programignorelist:
					if prog in magic:
						skip = True
						break
				if skip:
					continue
				report = {}
				module = config.get(section, 'module')
				method = config.get(section, 'method')
				exec "from %s import %s as bat_%s" % (module, method, method)
				## temporary stuff, this should actually be nicely wrapped in a report tuple
				res = eval("bat_%s(scanfile)" % (method))
				if res != None:
					report[section] = res
					reports.append(report)
			elif config.get(section, 'type') == 'unpack':
				## return value is the temporary dir, plus offset in the parent file
				module = config.get(section, 'module')
				method = config.get(section, 'method')
				exec "from %s import %s as bat_%s" % (module, method, method)
				diroffsets = eval("bat_%s(scanfile)" % (method))
				for diroffset in diroffsets:
					report = {}
					if diroffset == None:
						continue
					dir = diroffset[0]
					res = walktempdir(dir,config)
					if res != []:
						res.append({'offset': diroffset[1]})
						report[section] = res
						reports.append(report)
			else:
				pass
	return reports

def main(argv):
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

	config = ConfigParser.ConfigParser()
	config.readfp(configfile)

	scandate = datetime.datetime.utcnow()

	## Per firmware scanned we get a list with results.
	## Each file system or compressed file we can unpack gives a list with
	## reports back as its result, so we have a list of lists
	## within the inner list there is a result tuple, which could contain
	## more lists in some fields, like libraries, or more result lists if
	## the file inside a file system we looked at was in fact a file system.
	res = scanfile(os.path.dirname(firmware_binary), os.path.basename(firmware_binary), config)
	xml = prettyprintresxml(res, config, scandate)
	print xml.toxml()

if __name__ == "__main__":
        main(sys.argv)
