## Binary Analysis Tool
## Copyright 2009-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, subprocess, tempfile

'''
Module to 'unpack' an ext2 file system. We are taking a shortcut. We're using
e2cp to copy files, but we're recreating the directories in the file system
ourselves. We can get this information from the output of el2s.

The second column displays the Ext2/linux mode flags which can be found in
<ext2fs/ext2fs.h> from e2fsprogs.

We are mostly interested in regular files and directories:

#define LINUX_S_IFREG  0100000
#define LINUX_S_IFDIR  0040000
'''

def copyext2fs(source, target=None):
	if target == None:
		targetdir = tempfile.mkdtemp()
	else:
		targetdir = target

	## now walk each directory and copy files
	scandirs = [""]
	while len(scandirs) != 0:
		newscandirs = set()
		for scandir in scandirs:
			p = subprocess.Popen(['e2ls', '-l', source + ":" + scandir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        		(stanout, stanerr) = p.communicate()
        		if p.returncode != 0:
				## This could happen is for example the file system is corrupted
				## and inodes are damaged
				continue
			if stanout.strip() == "No files found!":
				continue
			for i in stanout.strip().split("\n"):
				if i.startswith(">"):
					continue
				isplits = i.split()
				if len(isplits[1]) < 5:
					## bogus file system, so continue
					return None
				modeflag = int(isplits[1][0:-3])
				if len(isplits) < 8:
					continue
				else:
					filename = isplits[7]
				if modeflag == 40:
					newscandirs.add(scandir + "/" + filename)
					os.mkdir(target + "/" + scandir + "/" + filename)
				## also take sticky bit, suid, sgid, etc. into account
				elif modeflag >= 100 and modeflag < 120:
					copypath = source + ":" + scandir + "/" + filename
					p = subprocess.Popen(['e2cp', copypath, "-d", os.path.normpath(target + "/" + scandir)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        				(stanout, stanerr) = p.communicate()
        				if p.returncode != 0:
						continue
		scandirs = newscandirs
	return targetdir
