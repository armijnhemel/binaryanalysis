#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains a few methods that check for the presence of marker
strings that are likely to be found in certain programs. It is far from fool
proof and false positives are likely, so either check the results, or replace
it with your own more robust checks.
'''

import string, re, os, magic, subprocess, sys
import extractor
import xml.dom.minidom

## generic searcher for certain marker strings
def genericSearch(path, markerStrings, blacklist=[]):
        try:
		## first see if the entire file has been blacklisted
		filesize = os.stat(path).st_size
		if extractor.inblacklist(0, blacklist) == filesize:
			return None
                binary = open(path, 'rb')
                lines = binary.read()
		binary.close()
		for marker in markerStrings:
			offset = lines.find(marker)
			if offset != -1 and not extractor.inblacklist(offset, blacklist):
				return True
			else:
				return None
        except Exception, e:
                return None

## The result of this method is a list of library names that the file dynamically links
## with. The path of these libraries is not given, since this is usually not recorded
## in the binary (unless RPATH is used) but determined at runtime: it is dependent on
## the dynamic linker configuration on the device. With some mixing and matching it is
## nearly always to determine which library in which path is used, since most installations
## don't change the default search paths.
def searchDynamicLibs(path, blacklist=[], envvars=None):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(path)
	ms.close()
	if "ELF" in mstype:
		libs = []
		p = subprocess.Popen(['readelf', '-d', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
                	return
		for line in stanout.split('\n'):
			if "Shared library:" in line:
				libs.append(line.split(': ')[1][1:-1])
		if libs == []:
			return None
		else:
			return libs

def dynamicLibsPrettyPrint(res, root):
	tmpnode = root.createElement('libs')
	for lib in res:
		tmpnode2 = root.createElement('lib')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = lib
		tmpnode2.appendChild(tmpnodetext)
		tmpnode.appendChild(tmpnode2)
	return tmpnode

## This method uses readelf to determine the architecture of the executable file.
## This is necessary because sometimes leftovers from different products (and
## different architectures) can be found in one firmware.
def scanArchitecture(path, blacklist=[], envvars=None):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(path)
	ms.close()
	if "ELF" in mstype:
		p = subprocess.Popen(['readelf', '-h', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return
		for line in stanout.split('\n'):
			if "Machine:" in line:
				return line.split(':')[1].strip()

def searchLoadLin(path, blacklist=[], envvars=None):
	markerStrings = [ 'Ooops..., size of "setup.S" has become too long for LOADLIN,'
			, 'LOADLIN started from $'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchIptables(path, blacklist=[], envvars=None):
	markerStrings = [ 'iptables who? (do you need to insmod?)'
			, 'Will be implemented real soon.  I promise ;)'
			, 'can\'t initialize iptables table `%s\': %s'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchDproxy(path, blacklist=[], envvars=None):
	markerStrings = [ '# dproxy monitors this file to determine when the machine is'
			, '# If you want dproxy to log debug info specify a file here.'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchEzIpupdate(path, blacklist=[], envvars=None):
	markerStrings = [ 'ez-ipupdate Version %s, Copyright (C) 1998-'
			, '%s says that your IP address has not changed since the last update'
			, 'you must provide either an interface or an address'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchLibusb(path, blacklist=[], envvars=None):
	markerStrings = [ 'Check that you have permissions to write to %s/%s and, if you don\'t, that you set up hotplug (http://linux-hotplug.sourceforge.net/) correctly.'
			, 'usb_os_find_busses: Skipping non bus directory %s'
			, 'usb_os_init: couldn\'t find USB VFS in USB_DEVFS_PATH'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchVsftpd(path, blacklist=[], envvars=None):
	markerStrings = [ 'vsftpd: version'
			, '(vsFTPd '
			, 'VSFTPD_LOAD_CONF'
			, 'run two copies of vsftpd for IPv4 and IPv6'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchHostapd(path, blacklist=[], envvars=None):
	markerStrings = [ 'hostapd v'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchWpaSupplicant(path, blacklist=[], envvars=None):
	markerStrings = [ 'wpa_supplicant v'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchIproute(path, blacklist=[], envvars=None):
	markerStrings = [ 'Usage: tc [ OPTIONS ] OBJECT { COMMAND | help }'
			, 'tc utility, iproute2-ss%s'
			, 'Option "%s" is unknown, try "tc -help".'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchWirelessTools(path, blacklist=[], envvars=None):
	markerStrings = [ "Driver has no Wireless Extension version information."
			, "Wireless Extension version too old."
			, "Wireless-Tools version"
			, "Wireless Extension, while we are using version %d."
			, "Currently compiled with Wireless Extension v%d."
       	                ]
	return genericSearch(path, markerStrings, blacklist)

def searchRedBoot(path, blacklist=[], envvars=None):
	markerStrings = ["Display RedBoot version information"]
	return genericSearch(path, markerStrings, blacklist)

def searchUBoot(path, blacklist=[], envvars=None):
        markerStrings = [ "run script starting at addr"
			, "Hit any key to stop autoboot: %2d"
			, "## Binary (kermit) download aborted"
			, "## Ready for binary (ymodem) download "
			]
	return genericSearch(path, markerStrings, blacklist)

## What actually do these dependencies mean?
## Are they dependencies of the installer itself, or of the programs that are
## installed by the installer?
def searchWindowsDependencies(path, blacklist=[], envvars=None):
	## first determine if we are dealing with a MS Windows executable
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(path)
	ms.close()
	if not 'PE32 executable for MS Windows' in mstype and not "PE32+ executable for MS Windows" in mstype:
                return None
        binary = open(path, 'rb')
        lines = binary.read()
	binary.close()
	deps = extractor.searchAssemblyDeps(lines)
	if deps == None:
		return None
	if deps == []:
		return None
	else:
		return deps

def xmlPrettyPrintWindowsDeps(res, root):
	pass

## method to extract meta information from PDF files
def scanPDF(path, blacklist=[], envvars=None):
	## we only want to scan whole PDF files. If anything has been carved from
	## it, we don't want to see it. Blacklists are a good indicator, but we
	## should have some way to prevent other scans from analysing this file.
	if blacklist != []:
		return None
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(path)
	ms.close()
	if not 'PDF document' in mstype:
                return None
	else:
		p = subprocess.Popen(['pdfinfo', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
                	return
		else:
			pdfinfo = {}
			pdflines = stanout.rstrip().split("\n")
			for pdfline in pdflines:
				(tag, value) = pdfline.split(":", 1)
				if tag == "Title":
					pdfinfo['title'] = value.strip()
				if tag == "Author":
					pdfinfo['author'] = value.strip()
				if tag == "Creator":
					pdfinfo['creator'] = value.strip()
				if tag == "CreationDate":
					pdfinfo['creationdate'] = value.strip()
				if tag == "Producer":
					pdfinfo['producer'] = value.strip()
				if tag == "Tagged":
					pdfinfo['tagged'] = value.strip()
				if tag == "Pages":
					pdfinfo['pages'] = int(value.strip())
				if tag == "Page size":
					pdfinfo['pagesize'] = value.strip()
				if tag == "Encrypted":
					pdfinfo['encrypted'] = value.strip()
				if tag == "Optimized":
					pdfinfo['optimized'] = value.strip()
				if tag == "PDF version":
					pdfinfo['version'] = value.strip()
			return pdfinfo

def pdfPrettyPrint(res, root):
	tmpnode = root.createElement('pdfinfo')
	for key in res.keys():
		tmpnode2 = root.createElement(key)
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = str(res[key])
		tmpnode2.appendChild(tmpnodetext)
		tmpnode.appendChild(tmpnode2)
	return tmpnode

## scan for mentions of:
## * GPL
## * Apache
######################################
## !!! WARNING WARNING WARNING !!! ###
######################################
## This should only be used as an indicator for further investigation,
## never as proof that a binary is actually licensed under a license!
def scanLicenses(path, blacklist=[], envvars=None):
	results = {}
	if genericSearch(path, ["General Public License", "http://www.gnu.org/licenses/", "http://gnu.org/licenses/"]):
		results['GNU'] = True
	if genericSearch(path, ["http://gnu.org/licenses/gpl.html", "http://www.gnu.org/licenses/gpl.html",
                                "http://www.opensource.org/licenses/gpl-license.php", "http://www.gnu.org/copyleft/gpl.html"]):
		results['GPL'] = True
	if genericSearch(path, ["http://gnu.org/licenses/gpl-2.0.html", "http://www.gnu.org/licenses/old-licenses/gpl-2.0.html"]):
		results['GPLv2'] = True
	if genericSearch(path, ["http://gnu.org/licenses/old-licenses/lgpl-2.1.html"]):
		results['LGPLv2.1'] = True
	if genericSearch(path, ["http://www.apache.org/licenses/LICENSE-2.0", "http://opensource.org/licenses/apache2.0.php"]):
		results['Apache2.0'] = True
	if genericSearch(path, ["http://www.mozilla.org/MPL/"]):
		results['MPL'] = True
	if genericSearch(path, ["http://www.bittorrent.com/license/"]):
		results['BitTorrent'] = True
	if results != {}:
		return results
	else:
		return None

def licensesPrettyPrint(res, root):
	tmpnode = root.createElement('licenses')
	for key in res.keys():
		tmpnode2 = root.createElement(key)
		tmpnode.appendChild(tmpnode2)
	return tmpnode

## scan for mentions of several forges
## Some of the URLs of the forges no longer work or are redirected, but they
## might still pop up in binaries.
def scanForges(path, blacklist=[], envvars=None):
	results = {}
	if genericSearch(path, ["sourceforge.net"]):
		results['sourceforge.net'] = True
	if genericSearch(path, ["http://cvs.freedesktop.org/", "http://cgit.freedesktop.org/"]):
		results['freedesktop.org'] = True
	if genericSearch(path, ["code.google.com", "googlecode.com"]):
		results['code.google.com'] = True
	if genericSearch(path, ["savannah.gnu.org/"]):
		results['savannah.gnu.org'] = True
	if genericSearch(path, ["github.com"]):
		results['github.com'] = True
	if genericSearch(path, ["bitbucket.org"]):
		results['bitbucket.org'] = True
	if genericSearch(path, ["tigris.org"]):
		results['tigris.org'] = True
	if genericSearch(path, ["http://svn.apache.org/"]):
		results['svn.apache.org'] = True
	## various gits:
	## http://git.fedoraproject.org/git/
	## https://fedorahosted.org/
	if results != {}:
		return results
	else:
		return None

def forgesPrettyPrint(res, root):
	tmpnode = root.createElement('forges')
	for key in res.keys():
		tmpnode2 = root.createElement(key)
		tmpnode.appendChild(tmpnode2)
	return tmpnode

## experimental clamscan feature
## Always run freshclam before scanning to get the latest
## virus signatures!
def scanVirus(path, blacklist=[], envvars=None):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(path)
	ms.close()
	p = subprocess.Popen(['clamscan', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode == 0:
               	return
	else:
		## Oooh, virus found!
		viruslines = stanout.split("\n")
		## first line contains the report:
		virusname = viruslines[0].strip()[len(path) + 2:-6]
		return virusname
