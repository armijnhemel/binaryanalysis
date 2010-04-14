#!/usr/bin/python

import os, sys, string
import re, subprocess
import extractor, fssearch

## Helper method that extracts the kernel version using a regular
## expression. It needs printable characters for this.
## If it can't be find, it will return 'None' instead.
def extractKernelVersion(lines):
        printables = extractor.extract_printables(lines)
        res = re.search("Linux version ([\d\.\d\w-]+) \(", printables)
        if res != None:
                return res.groups(0)[0]
        else:
                return

def findALSA(lines):
	markerlines = [ "Directory bread(block %llu) failed"
		      , "ALSA-PCM%d-%d%c%d"
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

def findInitFs(lines):
	return fssearch.findGzip(lines)

## analyse a kernel module. Requires that the modinfo program from module-init-tools has been installed
def analyseModule(module, tmpdir):
	p = subprocess.Popen(['/sbin/modinfo', "-F", "license", module], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
        (stanuit, stanerr) = p.communicate()
        if p.returncode != 0:
                return
        else:
                return stanuit
