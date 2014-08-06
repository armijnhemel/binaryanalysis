#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, sys, string, re, subprocess, cPickle
import extractor
import xml.dom.minidom

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

def kernelChecks(path, tags, blacklist=[], scandebug=False, envvars=None, unpacktempdir=None):
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
	return (['kernelchecks', 'linuxkernel'], results)

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

## extract the kernel version from the module
## TODO: merge with module license extraction
def analyseModuleVersion(path, tags, blacklist=[], scandebug=False, envvars=[], unpacktempdir=None):
	if not 'elfrelocatable' in tags:
		return
	## 2.6 and later Linux kernel
	p = subprocess.Popen(['/sbin/modinfo', "-F", "vermagic", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return None
	if stanout == "":
		## 2.4 kernel
		p = subprocess.Popen(['/sbin/modinfo', "-F", "kernel_version", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return None
		if stanout != "":
			return (['linuxkernel', 'modulekernelversion'], stanout.split()[0])
	else:
		return (['linuxkernel', 'modulekernelversion'], stanout.split()[0])

## analyse a kernel module. Requires that the modinfo program from module-init-tools has been installed
def analyseModuleLicense(path, tags, blacklist=[], scandebug=False, envvars=[], unpacktempdir=None):
	if not "elfrelocatable" in tags:
		return None
	p = subprocess.Popen(['/sbin/modinfo', "-F", "license", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (stanout, stanerr) = p.communicate()
        if p.returncode != 0:
                return None
	if stanout == "":
		return None
        else:
		licenses = set(stanout.strip().split('\n'))
		return (['modulelicense'], licenses)

## match versions of kernel modules and linux kernels inside a firmware
## This is not a fool proof method. There are situations possible where the kernel
## and modules are not the same on purpose, for example if the kernel is used for
## upgrading a flash partition that contains modules meant for another, different
## kernel residing on another flash partition which is not upgraded.
## Also match the architectures of the modules: they should be for the same architecture
## but sometimes modules for an entirely different architecture pop up, which is a
## sign that something is wrong.
def kernelmodulecheck(unpackreports, scantempdir, topleveldir, processors, scandebug=False, envvars=None, unpacktempdir=None):
	kernelversions = set()
	moduleversions = {}
	modulearchitectures = {}
	for i in unpackreports:
		## sanity checks
		if not unpackreports[i].has_key('tags'):
			continue
		if not unpackreports[i].has_key('sha256'):
			continue

		if not ('linuxkernel' in unpackreports[i]['tags'] or 'kernelchecks' in unpackreports[i]['tags']):
			continue

		filehash = unpackreports[i]['sha256']

		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue

		## read pickle file
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		## record versions of Linux kernel images and modules
		if leafreports.has_key('kernelmoduleversion'):
			moduleversions[filehash] = leafreports['kernelmoduleversion']
		elif leafreports.has_key('kernelchecks'):
			if leafreports['kernelchecks'].has_key('version'):
				kernelversions.add(leafreports['kernelchecks']['version'])

		if leafreports.has_key('architecture'):
			modulearchitectures[filehash] = leafreports['architecture']

	architectures = set(modulearchitectures.values())

	res = {}

	## if there is more than one architecture then there is probably
	## something fishy going on, like leftover modules from an earlier device
	## with a different architecture.
	if len(architectures) > 1:
		res['kernelmodulearchitecturemismatch'] = True

	## check for each module if its version can be found in any
	## of the found Linux kernel versions.
	## If there are no kernel versions in the firmware, then assume a kernel
	## (or multiple kernels) are already on the device and nothing should be
	## assumed.
	if kernelversions != set():
		for m in moduleversions.keys():
			if not moduleversions[m] in kernelversions:
				res['kernelmoduleversionmismatch'] = True
				return res
	return res
