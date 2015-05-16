#!/usr/bin/python
#-*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2014-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, multiprocessing

'''
During scanning BAT tags duplicate files (same checksums) and only processes a
single file later on. Which file is marked as the 'original' and which as the
duplicate depends on the scanning order, which is non-deterministic.

In some situations there is more information available to make a better choice
about the 'original' and the duplicate.

This module is to fix these situations.

1. In ELF shared libraries the SONAME and RPATH attributes can be used.
'''

def fixduplicates(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):
	## First deal with ELF files
	## store names of all ELF files present in scan archive
	elffiles = set()
	dupefiles = set()

	seendupe = False

	for i in unpackreports:
		if not unpackreports[i].has_key('checksum'):
			continue
		filehash = unpackreports[i]['checksum']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue

		if not 'elf' in unpackreports[i]['tags']:
			continue

		## This makes no sense for for example statically linked libraries and, Linux kernel
		## images and Linux kernel modules, so skip.
		if 'static' in unpackreports[i]['tags']:
			continue
		if 'linuxkernel' in unpackreports[i]['tags']:
			continue
		if 'duplicate' in unpackreports[i]['tags']:
			seendupe = True
			dupefiles.add(i)
		else:
			elffiles.add(i)

	## only process if there actually are duplicate files
	if seendupe:
		dupehashes = {}
		for i in dupefiles:
			filehash = unpackreports[i]['checksum']
			if dupehashes.has_key(filehash):
				dupehashes[filehash].append(i)
			else:
				dupehashes[filehash] = [i]
		dupekeys = dupehashes.keys()
		for i in elffiles:
			filehash = unpackreports[i]['checksum']
			if filehash in dupekeys:
				realpath = unpackreports[i]['realpath']
				filename = unpackreports[i]['name']

				## extract dynamic section
				p = subprocess.Popen(['readelf', '-Wd', "%s" % os.path.join(realpath, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					continue

				## determine if a library might have a soname
				sonames = set()
				for line in stanout.split('\n'):
					if "(SONAME)" in line:
						soname_split = line.split(': ')
						if len(soname_split) < 2:
							continue
						soname = line.split(': ')[1][1:-1]
						sonames.add(soname)
				## there should be only one SONAME
				if len(sonames) != 1:
					continue

				soname = sonames.pop()
				if soname == filename:
					## no need for fixing
					continue
				if unpackreports[i]['scans'] != []:
					## if any unpack scans were successful then renaming might have
					## to be done recursively which needs more thought
					continue
				unpackreports[i]['tags'].append('duplicate')
				for j in dupehashes[filehash]:
					if soname == os.path.basename(j):
						unpackreports[j]['tags'].remove('duplicate')
						break
