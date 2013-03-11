#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, sys, string, re, subprocess
import extractor
import magic
import xml.dom.minidom

ms = magic.open(magic.MAGIC_NONE)
ms.load()

def xmlprettyprint(res, root, envvars=None):
	topnode = root.createElement("kernelchecks")
	for i in res.keys():
		tmpnode = root.createElement(i)
		if i == 'version':
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = res[i]
			tmpnode.appendChild(tmpnodetext)
		topnode.appendChild(tmpnode)
	return topnode

def kernelChecks(path, tags, blacklist=[], envvars=None):
	results = {}
        try:
                kernelbinary = open(path, 'rb')
                kernel_lines = kernelbinary.read()
        except Exception, e:
                return None
	## sanity check
	res = extractKernelVersion(kernel_lines)
	if res != None:
		results['version'] = res
	else:
		return None
	if findALSA(kernel_lines) != -1:
		results['alsa'] = True
	if findMtd(kernel_lines) != -1:
		results['mtd'] = True
	if findFAT(kernel_lines) != -1:
		results['fat'] = True
	if findNetfilter(kernel_lines) != -1:
		results['netfilter'] = True
	if findRedBoot(kernel_lines) != -1:
		results['redboot'] = True
	if findSysfs(kernel_lines) != -1:
		results['sysfs'] = True
	if findSquashfs(kernel_lines) != -1:
		results['squashfs'] = True
	return (['kernelchecks'], results)

## Helper method that extracts the kernel version using a regular
## expression. It needs printable characters for this.
## If it can't be found, it will return 'None' instead.
def extractKernelVersion(lines):
	offset = lines.find("Linux version ")
	if offset == -1:
		return
        ## kernel version numbers should fit within 100 characters
        printables = extractor.extract_printables(lines[offset:offset+100])
        res = re.search("Linux version ([\d\.\d\w-]+) \(", printables)
        if res != None:
                return res.groups(0)[0]
        else:
                return

def findALSA(lines):
	markerlines = [ "ALSA-PCM%d-%d%c%d"
                      , "ALSA client number %d"
                      , "ALSA receiver port %d"
                      , "[%s] ALSA port %d:%d"
                      , "ALSA device list:"
                      , "ALSA card file remove problem (%p)"
                      , "Sound Driver:3.8.1a-980706 (ALSA v1.0.14 emulation code)"
                      , "For more details, read ALSA-Configuration.txt."
                      ]

	for i in markerlines:
		res = lines.find(i)
		if res != -1:
			return res
	return -1

def findFAT(lines):
	markerlines = [ "Directory bread(block %llu) failed"
		   , "Couldn't remove the long name slots"
		   , "Corrupted directory (i_pos %lld)"
		   , "invalid access to FAT (entry 0x%08x)"
		   , "%s: deleting FAT entry beyond EOF"
		   , "FAT read failed (blocknr %llu)"
		   , "unable to read inode block for updating (i_pos %lld)"
		   , "corrupted file size (i_pos %lld, %lld)"
		   , "\"%s\" option is obsolete, not supported now"
		   , "Unrecognized mount option \"%s\" or missing value"
		   , "utf8 is not a recommended IO charset for FAT filesystems, filesystem will be case sensitive!"
		   , "bogus number of FAT structure"
		   , "bread failed, FSINFO block (sector = %lu)"
                   ]

	for i in markerlines:
		res = lines.find(i)
		if res != -1:
			return res
	return -1

def findMtd(lines):
	markerlines = [ "add_mtd_device"
                   , "Can't allocate major number %d for Memory Technology Devices."
                   ]
	for i in markerlines:
		res = lines.find(i)
		if res != -1:
			return res
	return -1

def findNetfilter(lines):
	return lines.find("Netfilter core team")

def findSquashfs(lines):
	return lines.find("squashfs: version")

def findSysfs(lines):
	return lines.find("sysfs: could not get root inode")

def findRedBoot(lines):
	return lines.find("No RedBoot partition table detected in %s")

## analyse a kernel module. Requires that the modinfo program from module-init-tools has been installed
def analyseModuleLicense(path, tags, blacklist=[], envvars=[]):
	if not "relocatable" in ms.file(path):
		return None
	p = subprocess.Popen(['/sbin/modinfo', "-F", "license", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (stanout, stanerr) = p.communicate()
        if p.returncode != 0:
                return None
	if stanout == "":
		return None
        else:
                return (['modulelicense'], stanout.strip())

##
def analyseELF(path, tags, blacklist=[], envvars=[]):
	pass
