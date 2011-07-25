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
def searchDynamicLibs(path, blacklist=[]):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(path)
	ms.close()
	if "ELF" in type:
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

def searchLoadLin(path, blacklist=[]):
	markerStrings = [ 'Ooops..., size of "setup.S" has become too long for LOADLIN,'
			, 'LOADLIN started from $'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchIptables(path, blacklist=[]):
	markerStrings = [ 'iptables who? (do you need to insmod?)'
			, 'Will be implemented real soon.  I promise ;)'
			, 'can\'t initialize iptables table `%s\': %s'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchDproxy(path, blacklist=[]):
	markerStrings = [ '# dproxy monitors this file to determine when the machine is'
			, '# If you want dproxy to log debug info specify a file here.'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchEzIpupdate(path, blacklist=[]):
	markerStrings = [ 'ez-ipupdate Version %s, Copyright (C) 1998-'
			, '%s says that your IP address has not changed since the last update'
			, 'you must provide either an interface or an address'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchLibusb(path, blacklist=[]):
	markerStrings = [ 'Check that you have permissions to write to %s/%s and, if you don\'t, that you set up hotplug (http://linux-hotplug.sourceforge.net/) correctly.'
			, 'usb_os_find_busses: Skipping non bus directory %s'
			, 'usb_os_init: couldn\'t find USB VFS in USB_DEVFS_PATH'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchVsftpd(path, blacklist=[]):
	markerStrings = [ 'vsftpd: version'
			, '(vsFTPd '
			, 'VSFTPD_LOAD_CONF'
			, 'run two copies of vsftpd for IPv4 and IPv6'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchHostapd(path, blacklist=[]):
	markerStrings = [ 'hostapd v'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchWpaSupplicant(path, blacklist=[]):
	markerStrings = [ 'wpa_supplicant v'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchIproute(path, blacklist=[]):
	markerStrings = [ 'Usage: tc [ OPTIONS ] OBJECT { COMMAND | help }'
			, 'tc utility, iproute2-ss%s'
			, 'Option "%s" is unknown, try "tc -help".'
			]
	return genericSearch(path, markerStrings, blacklist)

def searchWirelessTools(path, blacklist=[]):
	markerStrings = [ "Driver has no Wireless Extension version information."
			, "Wireless Extension version too old."
			, "Wireless-Tools version"
			, "Wireless Extension, while we are using version %d."
			, "Currently compiled with Wireless Extension v%d."
       	                ]
	return genericSearch(path, markerStrings, blacklist)

def searchRedBoot(path, blacklist=[]):
	markerStrings = ["Display RedBoot version information"]
	return genericSearch(path, markerStrings, blacklist)

def searchUBoot(path, blacklist=[]):
        markerStrings = [ "run script starting at addr"
			, "Hit any key to stop autoboot: %2d"
			, "## Binary (kermit) download aborted"
			, "## Ready for binary (ymodem) download "
			]
	return genericSearch(path, markerStrings, blacklist)

## What actually do these dependencies mean?
## Are they dependencies of the installer itself, or of the programs that are
## installed by the installer?
def searchWindowsDependencies(path, blacklist=[]):
	## first determine if we are dealing with a MS Windows executable
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(path)
	ms.close()
	if not 'PE32 executable for MS Windows' in type:
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
