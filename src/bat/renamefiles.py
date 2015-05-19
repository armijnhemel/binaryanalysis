#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, shutil, os.path, copy

'''
This aggregate scan traverses the unpackreports an tries to rename certain files based on properties of
unpacked files. For example:

* if a file is carved out of a larger file that contains a Linux kernel,
  rename it to something like "unpacked-linux-kernel"
* if a gzip CPIO archive is extracted from a Linux kernel and contains
  files/directories, like /root or /dev it is likely an initramfs
'''

def renamefiles(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):
	## only focus on initramfs that is also compressed for now
	kernelfiles = set()
	## known compressions for initramfs
	initramfscompressions = ['gzip']
	for r in unpackreports.keys():
		if unpackreports[r].has_key('checksum'):
			if 'linuxkernel' in unpackreports[r]['tags']:
				if 'modulekernelversion' in unpackreports[r]['tags']:
					continue
				if 'duplicate' in unpackreports[r]['tags']:
					continue
				kernelfiles.add(r)

	if 'TEMPLATE' in scanenv:
		template = scanenv['TEMPLATE']
		if template != None:
			templatecutoff = template.find('%')
			template = template[:templatecutoff]

	cpiotemplate = "initramfs"
	for r in kernelfiles:
		if unpackreports[r]['scans'] != []:
			for s in unpackreports[r]['scans']:
				if len(s['scanreports']) != 1:
					continue
				renamefiles = set()
				origcpio = ''
				targetcpio = ''
				process = False
				if s['scanname'] in initramfscompressions:
					unpackfile = s['scanreports'][0]
					if unpackreports[unpackfile]['name'].startswith('tmp'):
						process = True
					else:
						if template != None:
							if unpackreports[unpackfile]['name'].startswith(template):
								process = True
					if not process:
						continue
					if unpackreports[unpackfile]['scans'] != []:
						if len(unpackreports[unpackfile]['scans']) != 1:
							continue
						if unpackreports[unpackfile]['scans'][0]['scanname'] == 'cpio':
							## it is an initramfs, so it is possible to rename the file
							## Rename on disk:
							## 1. file
							## 2. unpacking directory
							## Then rename in unpackreports
							## 1. original file
							## 2. any paths in scanreports (path, realpath)
							## 3. references in parent file
							origname = os.path.join(unpackreports[unpackfile]['realpath'], unpackreports[unpackfile]['name'])
							targetname = os.path.join(unpackreports[unpackfile]['realpath'], cpiotemplate)
							if not os.path.exists(targetname):
								## on disk
								shutil.move(origname, targetname)
								if not "duplicate" in unpackreports[unpackfile]['tags']:
									origcpio = "%s-cpio-1" % origname
									targetcpio = "%s-cpio-1" % targetname
									shutil.move(origcpio, targetcpio)
								## in unpackreports
								unpackreports[unpackfile]['name'] = cpiotemplate
								newunpackreportsname = os.path.join(os.path.dirname(unpackfile), cpiotemplate)
								unpackreports[r]['scans'][0]['scanreports'][0] = newunpackreportsname
								renamefiles.add(unpackfile)

				while len(renamefiles) != 0:
					newrenamefiles = set()
					for re in renamefiles:
						origcpio = '/%s' % os.path.basename(origcpio)
						targetcpio = '/%s' % os.path.basename(targetcpio)
						newr = re.replace(origcpio, targetcpio)

						realpath = copy.deepcopy(unpackreports[re]['realpath'])
						newrealpath = realpath.replace(origcpio, targetcpio)
						unpackreports[re]['realpath'] = newrealpath
						## recurse into files, if any
						if 'scans' in unpackreports[re]:
							for sc in unpackreports[re]['scans']:
								if 'scanreports' in sc:
									newrenamefiles.update(sc['scanreports'])
									newscanreports = []
									for scr in sc['scanreports']:
										newscanreports.append(scr.replace(origcpio, targetcpio))
										sc['scanreports'] = newscanreports

						## then rename and delete the old value
						unpackreports[newr] = copy.deepcopy(unpackreports[re])
						del unpackreports[re]
					renamefiles = newrenamefiles
