#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script tries to analyse the firmware of a device, using a "brute force" approach
'''

import sys, os, magic, hashlib, subprocess
from optparse import OptionParser
import ConfigParser
#import busybox, fssearch, fwunpack, wirelesstools
import xml.dom.minidom

ms = magic.open(magic.MAGIC_NONE)
ms.load()

# the result is a list of library names that the file dynamically links with
# the path of these libraries is not give, since this is not recorded in the binary
# unless RPATH is used. It is also dependent on the dynamic linker configuration
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

def gethash(path, file):
	scanfile = open("%s/%s" % (path, file), 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	return h.hexdigest()

# return a report snipped for inclusion with the final report
# right now 'checks' is ignored, but we really want to be able to weed a bit
def scanfile(path, file, checks, lentempdir):
	#print checks
	#sys.exit(0)
	report = {}
	report['hash'] = gethash(path, file)

	## this will report incorrectly if we only have unpacked one file to a
	## temporary location for example with a kernel image
	report['name'] = file
	report['path'] = path[lentempdir:].replace("/squashfs-root", "")
	report['size'] = os.lstat("%s/%s" % (path, file)).st_size
	mime = ms.file("%s/%s" % (path, file))
	report['mime'] = mime
	if "ELF" in mime:
		res = scanSharedLibs(path,file)
		if res != []:
			report['libs'] = res
	scanfile = "%s/%s" % (path, file)
	res = scan(scanfile, checks)
	if res != []:
		report['scans'] = res
	return report

## result is a list of result tuples, one for every interesting file in the directory
def walktempdir(tempdir, checks):
	osgen = os.walk(tempdir)
	reports = []
	try:
       		while True:
                	i = osgen.next()
                	for p in i[2]:
				## empty file, not interested
				if os.lstat("%s/%s" % (i[0], p)).st_size == 0:
					continue
				type = ms.file("%s/%s" % (i[0], p))
                        	## don't care about symbolic links
                        	if type.find('symbolic link to') == 0:
                                	continue
                        	## let alone broken symbolic links
                        	elif type.find('broken symbolic link to') == 0:
                                	continue

				## Filter out various things based on mime type.
                        	elif type.find('ASCII text') == 0:
                               		continue
                        	elif type.find('ASCII English text') == 0:
                               		continue
                        	elif type.find('XML') == 0:
                                	continue
                        	elif type.find('GIF image data') == 0:
                                	continue
                        	elif type.find('PNG image') == 0:
                                	continue
                        	elif type.find('JPEG image data') == 0:
                                	continue
                        	elif type.find('PC bitmap') == 0:
                                	continue
                        	elif type.find('MPEG') == 0:
                                	continue
                        	elif type.find('Ogg data') == 0:
                                	continue
                        	elif type.find('Apple QuickTime movie') == 0:
                                	continue
                        	elif type.find('MS Windows icon resource') == 0:
                                	continue
                        	elif type.find('Macromedia Flash Video') == 0:
                                	continue
                        	elif type.find('tcpdump capture file') == 0:
                                	continue
                        	elif type.find('timezone data') == 0:
                                	continue
                        	elif type.find('LaTeX') == 0:
                                	continue
                        	elif type.find('PDF document') == 0:
                                	continue
                        	elif type.find('PostScript document text') == 0:
                                	continue
                        	elif type.find('MySQL') == 0:
                                	continue
                        	elif type == 'Microsoft ICM Color Profile':
                                	continue
                        	elif type == 'M3U playlist text':
                                	continue
                        	elif type == 'diff output text':
                                	continue
                        	elif type == 'HTML document text':
                                	continue
                        	elif type == 'UTF-8 Unicode text':
                                	continue
                        	elif type == 'lex description text':
                                	continue
                        	elif type == 'OS/2 REXX batch file text':
                                	continue
                        	elif type == 'ISO-8859 C program text':
                                	continue
                        	elif type == 'FORTRAN program':
                                	continue
                        	elif type == 'python script text executable':
                                	continue
				# some binaries may be distributed as shell scripts that unpack them
                        	#elif type == 'POSIX shell script text executable':
                                #	continue
				try:
					res = scanfile(i[0], p, checks, len(tempdir))
					if res != []:
						reports.append(res)
				except Exception as e:
					print e
	except StopIteration:
        	pass
	return reports

## top level method to scan a whole firmware
def scan(scanfile, config):
	reports = []
	for section in config.sections():
		report = {}
		if config.has_option(section, 'type'):
			if config.get(section, 'type') == 'program':
				#print section
				module = config.get(section, 'module')
				method = config.get(section, 'method')
				exec "from %s import %s as %s_%s" % (module, method, module, method)
				## temporary stuff, this should actually be nicely wrapped in a report tuple
				res = eval("%s_%s(scanfile)" % (module, method))
				if res != None:
					report[section] = res
					reports.append(report)
			elif config.get(section, 'type') == 'unpack':
				## return value is a temporary dir right now, but we should offsets as well
				module = config.get(section, 'module')
				method = config.get(section, 'method')
				exec "from %s import %s as %s_%s" % (module, method, module, method)
				dir = eval("%s_%s(scanfile)" % (module, method))
				if dir != None:
					res = walktempdir(dir,config)
					if res != []:
						reports.append(res)
			else:
				pass
	return reports

def main(argv):
        parser = OptionParser()
	parser.add_option("-b", "--binary", action="store", dest="fw", help="path to firmware", metavar="FILE")
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-z", "--cleanup", action="store_true", dest="cleanup", help="cleanup after analysis? (default: false)")
	(options, args) = parser.parse_args()
	if options.fw == None:
        	parser.error("Path to firmware needed")
	try:
        	firmware_binary = options.fw
	except:
        	print "No valid firmware file"
        	sys.exit(1)
	if options.cfg != None:
		try:
        		configfile = open(options.cfg, 'r')
		except:
			configfile = None
	else:
		configfile = None

	if configfile != None:
		config = ConfigParser.ConfigParser()
        	config.readfp(configfile)
	## use default system wide config
	else:
		pass

	## Per firmware scanned we get a list with results.
	## Each file system or compressed file we can unpack gives a list with
	## reports back as its result, so we have a list of lists
	## within the inner list there is a result tuple, which could contain
	## more lists in some fields, like libraries, or more result lists if
	## the file inside a file system we looked at was in fact a file system.
	res = scan(firmware_binary, config)
	print res
	for result in res:
		for subresult in result:
			print subresult

if __name__ == "__main__":
        main(sys.argv)
