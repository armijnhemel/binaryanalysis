#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains a few methods that check for the presence of marker
strings that are likely to be found in certain programs. It is far from fool
proof and false positives are likely, so either check the results, or replace
it with your own more robust checks.
'''

import string, re, os
import extractor

## generic searcher for certain marker strings
def genericSearch(path, markerStrings, blacklist=[]):
        try:
		## first see if the entire file has been blacklisted
		filesize = os.stat(path).st_size
		if extractor.inblacklist(0, blacklist) == filesize:
			return None
                binary = open(path, 'rb')
                lines = binary.read()
		for marker in markerStrings:
			offset = lines.find(marker)
			if offset != -1 and not extractor.inblacklist(offset, blacklist):
				return True
			else:
				return None
        except Exception, e:
                return None

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
