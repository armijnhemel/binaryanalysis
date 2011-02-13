#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import string, re
import extractor

def searchLoadLin(path, blacklist=[]):
	markerStrings = [ 'Ooops..., size of "setup.S" has become too long for LOADLIN,'
			, 'LOADLIN started from $'
			]
        try:
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

def searchIptables(path, blacklist=[]):
	markerStrings = [ 'iptables who? (do you need to insmod?)'
			, 'Will be implemented real soon.  I promise ;)'
			, 'can\'t initialize iptables table `%s\': %s'
			]
        try:
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

def searchDproxy(path, blacklist=[]):
	markerStrings = [ '# dproxy monitors this file to determine when the machine is'
			, '# If you want dproxy to log debug info specify a file here.'
			]
        try:
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

def searchEzIpupdate(path, blacklist=[]):
	markerStrings = [ 'ez-ipupdate Version %s, Copyright (C) 1998-'
			, '%s says that your IP address has not changed since the last update'
			, 'you must provide either an interface or an address'
			]
        try:
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

def searchLibusb(path, blacklist=[]):
	markerStrings = [ 'Check that you have permissions to write to %s/%s and, if you don\'t, that you set up hotplug (http://linux-hotplug.sourceforge.net/) correctly.'
			, 'usb_os_find_busses: Skipping non bus directory %s'
			, 'usb_os_init: couldn\'t find USB VFS in USB_DEVFS_PATH'
			]
        try:
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

def searchVsftpd(path, blacklist=[]):
	markerStrings = [ 'vsftpd: version'
			, '(vsFTPd '
			, 'VSFTPD_LOAD_CONF'
			, 'run two copies of vsftpd for IPv4 and IPv6'
			]
        try:
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

def searchHostapd(path, blacklist=[]):
	markerStrings = [ 'hostapd v'
			]
        try:
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

def searchWpaSupplicant(path, blacklist=[]):
	markerStrings = [ 'wpa_supplicant v'
			]
        try:
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

def searchIproute(path, blacklist=[]):
	markerStrings = [ 'Usage: tc [ OPTIONS ] OBJECT { COMMAND | help }'
			, 'tc utility, iproute2-ss%s'
			, 'Option "%s" is unknown, try "tc -help".'
			]
        try:
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

def searchWirelessTools(path, blacklist=[]):
	markerStrings = [ "Driver has no Wireless Extension version information."
			, "Wireless Extension version too old."
			, "Wireless-Tools version"
			, "Wireless Extension, while we are using version %d."
			, "Currently compiled with Wireless Extension v%d."
       	                ]
        try:
                wireless_binary = open(path, 'rb')
                lines = wireless_binary.read()
		for marker in markerStrings:
			offset = lines.find(marker)
			if offset != -1 and not extractor.inblacklist(offset, blacklist):
				return True
			else:
				return None
        except Exception, e:
                return None

def searchRedBoot(path, blacklist=[]):
	markerStrings = ["Display RedBoot version information"]
        try:
                redboot_binary = open(path, 'rb')
                lines = redboot_binary.read()
		for marker in markerStrings:
                	offset = lines.find(marker)
			if offset != -1 and not extractor.inblacklist(offset, blacklist):
                       		return True
                	else:
                        	return None
        except Exception, e:
                return None

def searchUBoot(path, blacklist=[]):
        markerStrings = [ "run script starting at addr"
			, "Hit any key to stop autoboot: %2d"
			, "## Binary (kermit) download aborted"
			, "## Ready for binary (ymodem) download "
			]
        try:
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
