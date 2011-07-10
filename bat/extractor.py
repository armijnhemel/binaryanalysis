#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains a few convenience functions that are used throughout the code.
'''

import string
from xml.dom import minidom

## Helper method to replace unprintable characters with spaces.
## This is useful for doing regular expressions to extract the BusyBox
## version, while retaining all offsets in the file.
def extract_printables(lines):
        printables = ""
        for i in lines:
                if i in string.printable:
                        printables += i
                else:
                        printables += " "
        return printables

## check if a word is surrounded by non-printable characters
def check_nonprintable(lines, offset, word):
        if lines[offset-1] not in string.printable:
                if lines[offset+len(word)] not in string.printable:
                        return True
        return False

## convenience method to check if the offset we find is in a blacklist
## Blacklists are composed of tuples (lower, upper) which mark a region
## in the parent file(!) as a no go area.
## This method returns the upperbound from the tuple for which
## lower <= offset < upper is True
def inblacklist(offset, blacklist):
	for bl in blacklist:
		if offset >= bl[0] and offset < bl[1]:
			return bl[1]

###
## The helper method below is to specifically analyse Microsoft Windows binaries
## and extract the XML that can usually be found in those installers. Based on
## that information we might be able to get a better scan, since many well
## known installers have default values for the descriptive strings
###

## 1. search '<?xml'
## 2. search for '<assembly' open tag
## 3. search for </assembly> close tag
## 4. see if there is no junk in between (using XML parsing)
## 5. extract information from the assembly, such info from <assemblyIdentity>
##    like architecture and the packager that was used to pack and information
##    about dependencies
## 6. repeat, because there might be more than one XML assembly file included
##    (ignored for now)
## Returns a tuple with:
## * hash with name, version, architecture, platform
## * list of dependencies

def searchAssembly(data):
	xmloffset = data.find('<?xml')
	if xmloffset == -1:
		return None
	offset = data.find('<assembly', xmloffset)
	if offset == -1:
		return None
	traileroffset = data.find('</assembly>', offset)
	if traileroffset == -1:
		return None
	assembly = data[xmloffset:traileroffset + 11]
	try:
		dom = minidom.parseString(assembly)
		assemblyNodes = dom.getElementsByTagName('assembly')
		if len(assemblyNodes) != 1:
			return None
		else:
			deps = []
			assemblyattrs = {}
			for ch in assemblyNodes[0].childNodes:
				if ch.localName == "assemblyIdentity":
					for attr in xrange(0, ch.attributes.length):
						assemblyattrs[ch.attributes.item(attr).name] = ch.attributes.item(attr).value
				if ch.localName == "dependency":
					assemblyId = ch.getElementsByTagName('assemblyIdentity')
					for assembly in assemblyId:
						depsattrs = {}
						for attr in xrange(0, assembly.attributes.length):
							depsattrs[assembly.attributes.item(attr).name] = assembly.attributes.item(attr).value
						deps.append(depsattrs)

			return (assemblyattrs, deps)
	except Exception, e:
		return None
	return None

## used in unpack scans
def searchAssemblyAttrs(data):
	res = searchAssembly(data)
	if res != None:
		return res[0]
	return {}


## used in leaf scans
def searchAssemblyDeps(data):
	res = searchAssembly(data)
	if res != None:
		return res[1]
	return {}
