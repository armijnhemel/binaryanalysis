#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import string, re
import extractor

# marker strings that can be found in wireless-tools
# add more to make it more robust
wirelessMarkerStrings = [ "Driver has no Wireless Extension version information."
			, "Wireless Extension version too old."
			, "Wireless-Tools version"
			, "Wireless Extension, while we are using version %d."
			, "Currently compiled with Wireless Extension v%d."
                        ]

def searchWirelessTools(path):
        try:
                wireless_binary = open(path, 'rb')
                wireless_lines = wireless_binary.read()
                if extractWireless(wireless_lines) != -1:
			return True
		else:
			return None
        except Exception, e:
                return None

def extractWireless(lines):
	for marker in wirelessMarkerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1
