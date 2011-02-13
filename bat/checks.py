#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import string, re
import extractor

def searchLoadLin(path, blacklist=[]):
        try:
                binary = open(path, 'rb')
                lines = binary.read()
                offset = extractLoadLin(lines)
		if offset != -1 and not extractor.inblacklist(offset, blacklist):
			return True
		else:
			return None
        except Exception, e:
                return None

def extractLoadLin(lines):
	markerStrings = [ 'Ooops..., size of "setup.S" has become too long for LOADLIN,'
			, 'LOADLIN started from $'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1

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

def extractIptables(lines):
	markerStrings = [ 'iptables who? (do you need to insmod?)'
			, 'Will be implemented real soon.  I promise ;)'
			, 'can\'t initialize iptables table `%s\': %s'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1

def searchDproxy(path, blacklist=[]):
        try:
                binary = open(path, 'rb')
                lines = binary.read()
                offset = extractDproxy(lines)
		if offset != -1 and not extractor.inblacklist(offset, blacklist):
			return True
		else:
			return None
        except Exception, e:
                return None

def extractDproxy(lines):
	markerStrings = [ '# dproxy monitors this file to determine when the machine is'
			, '# If you want dproxy to log debug info specify a file here.'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1

def searchEzIpupdate(path, blacklist=[]):
        try:
                binary = open(path, 'rb')
                lines = binary.read()
                offset = extractEzIpupdate(lines)
		if offset != -1 and not extractor.inblacklist(offset, blacklist):
			return True
		else:
			return None
        except Exception, e:
                return None

def extractEzIpupdate(lines):
	markerStrings = [ 'ez-ipupdate Version %s, Copyright (C) 1998-'
			, '%s says that your IP address has not changed since the last update'
			, 'you must provide either an interface or an address'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1

def searchLibusb(path, blacklist=[]):
        try:
                binary = open(path, 'rb')
                lines = binary.read()
                offset = extractLibusb(lines)
		if offset != -1 and not extractor.inblacklist(offset, blacklist):
			return True
		else:
			return None
        except Exception, e:
                return None

def extractLibusb(lines):
	markerStrings = [ 'Check that you have permissions to write to %s/%s and, if you don\'t, that you set up hotplug (http://linux-hotplug.sourceforge.net/) correctly.'
			, 'usb_os_find_busses: Skipping non bus directory %s'
			, 'usb_os_init: couldn\'t find USB VFS in USB_DEVFS_PATH'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1

def searchVsftpd(path, blacklist=[]):
        try:
                binary = open(path, 'rb')
                lines = binary.read()
                offset = extractVsftpd(lines)
		if offset != -1 and not extractor.inblacklist(offset, blacklist):
			return True
		else:
			return None
        except Exception, e:
                return None

def extractVsftpd(lines):
	markerStrings = [ 'vsftpd: version'
			, '(vsFTPd '
			, 'VSFTPD_LOAD_CONF'
			, 'run two copies of vsftpd for IPv4 and IPv6'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1

def searchHostapd(path, blacklist=[]):
        try:
                binary = open(path, 'rb')
                lines = binary.read()
                offset = extractHostapd(lines)
		if offset != -1 and not extractor.inblacklist(offset, blacklist):
			return True
		else:
			return None
        except Exception, e:
                return None

def extractHostapd(lines):
	markerStrings = [ 'hostapd v'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1

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

def extractWpaSupplicant(lines):
	markerStrings = [ 'wpa_supplicant v'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1

def searchIproute(path, blacklist=[]):
        try:
                binary = open(path, 'rb')
                lines = binary.read()
                offset = extractIproute(lines)
		if offset != -1 and not extractor.inblacklist(offset, blacklist):
			return True
		else:
			return None
        except Exception, e:
                return None

def extractIproute(lines):
	markerStrings = [ 'Usage: tc [ OPTIONS ] OBJECT { COMMAND | help }'
			, 'tc utility, iproute2-ss%s'
			, 'Option "%s" is unknown, try "tc -help".'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1
