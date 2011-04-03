#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains helper functions to unpack archives or file systems.
Most of the commands are pretty self explaining. The result of the wrapper
functions is a list of tuples, which contain the name of a temporary directory
with the unpacked contents of the archive, and the offset of the archive or
file system in the parent file.

Optionally, we return a range of bytes that should be excluded in same cases
where we want to prevent other scans from (re)scanning (part of) the data.

TODO: merge many of the searchUnpack and unpack methods, so we only have to
suck in the data once in the unpack part.
'''

import sys, os, subprocess, os.path
import tempfile, bz2, re, magic, tarfile
import fsmagic, fssearch, extractor, ext2
import rpm

## TODO: rewrite this to like how we do other searches: first
## look for markers, then unpack.
## This method should return a blacklist.
def searchUnpackTar(filename, tempdir=None, blacklist=[]):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(filename)
	ms.close()

	tarmagic = ['POSIX tar archive (GNU)'
		   , 'tar archive'
		   ]

	## search for first magic marker that matches
	for tm in tarmagic:
		if tm in type:
			tarsize = 0
        		if tempdir == None:
        		       	tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "tar", 1)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			tar = tarfile.open(filename, 'r')
                	tartmpdir = tempfile.mkdtemp(dir=tmpdir)
			tar.extractall(path=tartmpdir)
			for t in tar:
				tarsize = tarsize + t.size
			tar.close()
			blacklist.append((0,tarsize))
			return ([(tartmpdir, 0)], blacklist)
	return ([], blacklist)

## yaffs2 is used frequently in Android and various mediaplayers based on
## Realtek chipsets (RTD1261/1262/1073/etc.)
## yaffs2 does not have a magic header, so it is really hard to recognize.
## This is why, for now, we will only try to unpack at offset 0.
## For this you will need the unyaffs program from
## http://code.google.com/p/unyaffs/
def searchUnpackYaffs2(filename, tempdir=None, blacklist=[]):
        if tempdir == None:
               	tmpdir = tempfile.mkdtemp()
	else:
		try:
			tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "yaffs", 1)
			os.makedirs(tmpdir)
		except Exception, e:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
	p = subprocess.Popen(['unyaffs', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		if tempdir == None:
			os.rmdir(tmpdir)
		return ([], blacklist)
	## unfortunately unyaffs also returns 0 when it fails
	if len(stanerr) != 0:
		if tempdir == None:
			os.rmdir(tmpdir)
		return ([], blacklist)
	return ([(tmpdir,0)], blacklist)

## Windows executables can be unpacked in many ways.
## We should try various methods:
## * 7z
## * unshield
## * cabextract
## * unrar
## * unzip
## Sometimes one or both will give results.
## We should probably blacklist the whole file after one method has been successful.
## Some Windows executables can only be unpacked interactively using Wine :-(
def searchUnpackExe(filename, tempdir=None, blacklist=[]):
	## first determine if we are dealing with a MS Windows executable
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(filename)
	ms.close()

	if not 'PE32 executable for MS Windows' in type:
		return ([], blacklist)

	## apparently we have a MS Windows executable, so continue
	diroffsets = []
	execounter = 1
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	## first search for ZIP. Do this by searching for:
	## * PKBAC (seems to give the best results)
	## * WinZip Self-Extractor
	## 7zip gives better results than unzip
	offset = data.find("PKBAC")
	if offset != -1:
		if tempdir == None:
			tmpdir = tempfile.mkdtemp()
		else:
			try:
				tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "exe", execounter)
				os.makedirs(tmpdir)
			except Exception, e:
				tmpdir = tempfile.mkdtemp(dir=tempdir)
		res = unpack7z(data, 0, tmpdir)
		if res != None:
			diroffsets.append((res, 0))
			blacklist.append((0, os.stat(filename).st_size))
			return (diroffsets, blacklist)
		else:
			if tempdir == None:
				os.rmdir(tmpdir)
	## then search for RAR by searching for:
	## WinRAR
	## and unpack with unrar
	offset = data.find("WinRAR")
	if offset != -1:
		if tempdir == None:
			tmpdir = tempfile.mkdtemp()
		else:
			try:
				tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "exe", execounter)
				os.makedirs(tmpdir)
			except Exception, e:
				tmpdir = tempfile.mkdtemp(dir=tempdir)
		res = unpackRar(data, 0, tmpdir)
		if res != None:
			(endofarchive, rardir) = res
			diroffsets.append((rardir, 0))
			## add the whole binary to the blacklist
			blacklist.append((0, os.stat(filename).st_size))
			execounter = execounter + 1
			return (diroffsets, blacklist)
		else:
			if tempdir == None:
				os.rmdir(tmpdir)
	## else try other methods
	## 7zip gives better results than cabextract
	## Ideally we should also do something with innounp
	return (diroffsets, blacklist)

## unpacker for Microsoft InstallShield
def searchUnpackInstallShield(filename, tempdir=None, blacklist=[]):
	return ([], blacklist)

## unpacker for Microsoft Cabinet Archive files.
def searchUnpackCab(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findCab(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		cabcounter = 1
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findCab(data, blacklistoffset)
			if offset == -1:
				break
			if tempdir == None:
				tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "cab", cabcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			res = unpackCab(data, offset, tmpdir)
			if res != None:
				(cabdir, cabsize) = res
				diroffsets.append((cabdir, offset))
				blacklist.append((offset, offset + cabsize))
				offset = fssearch.findCab(data, offset+cabsize)
				cabcounter = cabcounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
				offset = fssearch.findCab(data, offset+1)
	return (diroffsets, blacklist)

def unpackCab(data, offset, tempdir=None):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	## copied from the python-magic examples
	cab = file(tmpfile[1], "r")
	buffer = cab.read(100)
	cab.close()

	mstype = ms.buffer(buffer)
	if "Microsoft Cabinet archive data" not in mstype:
		ms.close()
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	p = subprocess.Popen(['cabextract', '-d', tmpdir, tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		## The size of the CAB archive can be determined from the
		## output from magic, which we already have.
		## We should do more sanity checks here
		cabsize = re.search("(\d+) bytes", mstype)
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return (tmpdir, int(cabsize.groups()[0]))

## temporary unpacker for Microsoft Windows Executables.
## This is actually *not* correct and should be replaced with the generic EXE unpacker.
## This method should be reworked to unpack 7z compressed files only.
def searchUnpack7z(filename, tempdir=None, blacklist=[]):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(filename)
	ms.close()

	exemagic = ['PE32 executable for MS Windows'
		   ]

	for exe in exemagic:
		if exe in type:
        		if tempdir == None:
        		       	tmpdir = tempfile.mkdtemp()
			else:
				tmpdir = tempdir
                	zztmpdir = tempfile.mkdtemp(dir=tmpdir)
			param = "-o%s" % zztmpdir
			p = subprocess.Popen(['7z', param, '-l', '-y', 'x', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0:
				try:
					## cleanup
					os.rmdir(zztmpdir)
        				if tempdir == None:
						os.rmdir(tmpdir)
				except:
					pass
				continue
			else:
				blacklist.append((0, os.stat(filename).st_size))
				return ([(zztmpdir, 0)], blacklist)
	return ([], blacklist)

def unpack7z(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzip is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	param = "-o%s" % tmpdir
	p = subprocess.Popen(['7z', param, '-l', '-y', 'x', tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

## unpack lzip archives.
## This method returns a blacklist.
def searchUnpackLzip(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findLzip(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		lzipcounter = 1
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findLzip(data, blacklistoffset)
			if offset == -1:
				break
			if tempdir == None:
				tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "lzip", lzipcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			(res, lzipsize) = unpackLzip(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				blacklist.append((offset, offset+lzipsize))
				offset = fssearch.findLzip(data, offset+lzipsize)
				lzipcounter = lzipcounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
				offset = fssearch.findLzip(data, offset+1)
	return (diroffsets, blacklist)

def unpackLzip(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzip is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['lzip', "-d", "-c", tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanout)
	#os.fdopen(outtmpfile[0]).flush()
	os.fsync(outtmpfile[0])
	if os.stat(outtmpfile[1]).st_size == 0:
		os.fdopen(outtmpfile[0]).close()
		os.unlink(outtmpfile[1])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	## determine the size of the archive we unpacked, so we can skip a lot
	p = subprocess.Popen(['lzip', '-vvvt', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		## something weird happened here: we can unpack, but not test the archive?
		os.fdopen(outtmpfile[0]).close()
		os.unlink(outtmpfile[1])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	lzipsize = int(re.search("member size\s+(\d+)", stanerr).groups()[0])
	os.fdopen(outtmpfile[0]).close()
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (tmpdir, lzipsize)

## To unpack XZ we need to find a header and a footer.
## The trailer is actually very generic and a lot more common than the header,
## so it is likely that we need to search for the trailer a lot more than
## for the header.
def searchUnpackXZ(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findXZ(data)
	if offset == -1:
		return ([], blacklist)
	else:
		## record the original offset
		origoffset = offset
		diroffsets = []
		xzcounter = 1
		## remember the offsets of the XZ footer, search for all trailers once
		traileroffsets = []
		trailer = fssearch.findXZTrailer(data)
		## why bother if we can't find a trailer?
		if trailer == -1:
			return []
		while(trailer != -1):
			trailer = fssearch.findXZTrailer(data,trailer+1)
			if trailer != -1:
				traileroffsets.append(trailer)
		## remember all offsets of the XZ header in the file
		offsets = [offset]
		while(offset != -1):
			offset = fssearch.findXZ(data,offset+1)
			if offset != -1:
				offsets.append(offset)
		for trail in traileroffsets:
			## check if the trailer is in the blacklist
			blacklistoffset = extractor.inblacklist(trail, blacklist)
			if blacklistoffset != None:
				## remove trailer from traileroffsets?
				continue
			for offset in offsets:
				## only check offsets that make sense
				if offset >= trail:
					continue
				blacklistoffset = extractor.inblacklist(offset, blacklist)
				if blacklistoffset != None:
					## remove offset from offsets?
					continue
				else:
					if tempdir == None:
						tmpdir = tempfile.mkdtemp()
					else:
						try:
							tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "xz", xzcounter)
							os.makedirs(tmpdir)
						except Exception, e:
							tmpdir = tempfile.mkdtemp(dir=tempdir)
					res = unpackXZ(data, offset, trail, tmpdir)
					if res != None:
						diroffsets.append((res, offset))
						xzcounter = xzcounter + 1
					else:
						## cleanup
						os.rmdir(tmpdir)
	return (diroffsets, blacklist)

def unpackXZ(data, offset, trailer, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that xz is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	## trailer has size of 2. Add 1 because [lower, upper)
	os.write(tmpfile[0], data[offset:trailer+3])
	## test integrity of the file
	p = subprocess.Popen(['xz', '-t', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return None
	## unpack
	p = subprocess.Popen(['xzcat', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanout)
	#os.fdopen(outtmpfile[0]).flush()
	os.fsync(outtmpfile[0])
	if os.stat(outtmpfile[1]).st_size == 0:
		os.fdopen(outtmpfile[0]).close()
		os.unlink(outtmpfile[1])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.fdopen(outtmpfile[0]).close()
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

## Not sure how cpio works if we have a cpio archive within a cpio archive
## especially with regards to locating the proper cpio trailer.
## This method should return a blacklist.
def searchUnpackCpio(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findCpio(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		cpiocounter = 1
		trailer = fssearch.findCpioTrailer(data)
		if trailer == -1:
			## no trailer found, so no use to continue checking
			return ([], blacklist)
		while(offset != -1 and trailer != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findCpio(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "cpio", cpiocounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			## length of 'TRAILER!!!' plus 1 to include the whole trailer
			## and cpio archives are always rounded to blocks of 512 bytes
			trailercorrection = (512 - len(data[offset:trailer+10])%512)
			res = unpackCpio(data[offset:trailer+10 + trailercorrection], 0, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				blacklist.append((offset, trailer))
				offset = fssearch.findCpio(data, offset + trailer)
				trailer = fssearch.findCpioTrailer(data, offset + trailer)
				cpiocounter = cpiocounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
				offset = fssearch.findCpio(data, offset+1)
			## there is a logic flow here. We should actually check for
			## all (offset, trailer) pairs where offset < trailer
			while offset < trailer and offset != -1:
				offset = fssearch.findCpio(data, offset+1)
			#trailer = fssearch.findCpioTrailer(data, offset)
		return (diroffsets, blacklist)

## tries to unpack stuff using cpio. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
## This one needs to stay separate, since it is also used by RPM unpacking
def unpackCpio(data, offset, tempdir=None):
        if tempdir == None:
                tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	## write data to a temporary location first so we can check
	## the magic.
	## Also use cpio -t to test if we actually have a valid archive
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(tmpfile[1])
	ms.close()
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	if 'cpio' not in type:
		if tempdir == None:
			os.rmdir(tmpdir)
		return
	p = subprocess.Popen(['cpio', '-t'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate(data[offset:])
	if p.returncode != 0:
		## we don't have a valid archive according to cpio -t
		if tempdir == None:
			os.rmdir(tmpdir)
		return
	p = subprocess.Popen(['cpio', '-i', '-d', '--no-absolute-filenames'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate(data[offset:])
	return tmpdir

## This method should return a blacklist.
def searchUnpackCramfs(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findCramfs(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		cramfscounter = 1
        	if tempdir == None:
        	       	tmpdir = tempfile.mkdtemp()
		else:
			try:
				tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "cramfs", cramfscounter)
				os.makedirs(tmpdir)
			except Exception, e:
				tmpdir = tempfile.mkdtemp(dir=tempdir)
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findCramfs(data, blacklistoffset)
			if offset == -1:
				break
			res = unpackCramfs(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				cramfscounter = cramfscounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
			offset = fssearch.findCramfs(data, offset+1)
		if len(diroffsets) == 0:
			os.rmdir(tmpdir)
		return (diroffsets, blacklist)

## tries to unpack stuff using fsck.cramfs. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackCramfs(data, offset, tempdir=None):
        if tempdir == None:
                tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	## fsck.cramfs needs to unpack in a separate directory. So, create a new temporary
	## directory to avoid name clashes
        tmpdir2 = tempfile.mkdtemp()
	## since fsck.cramfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	## right now this is a path to a specially adapted fsck.cramfs that ignores special inodes
	## create a new path to unpack all stuff
	p = subprocess.Popen(['bat-fsck.cramfs', '-x', tmpdir2 + "/cramfs", tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
			os.rmdir(tmpdir2)
		return
	else:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		os.rmdir(tmpdir)
		return tmpdir2

## Search and unpack a squashfs file system. Since there are so many flavours
## of squashfs available we have to do some extra work here, and possibly have
## some extra tools (squashfs variants) installed.
## Use the output of 'file' to determine the size of squashfs and use it for the
## blacklist.
def searchUnpackSquashfs(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findSquashfs(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		squashcounter = 1
		while(offset != -1):
			## check if the offset we find is in a blacklist
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findSquashfs(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "squashfs", squashcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			retval = unpackSquashfsWrapper(data, offset, tmpdir)
			if retval != None:
				(res, squashsize) = retval
				diroffsets.append((res, offset))
				blacklist.append((offset,offset+squashsize))
				squashcounter = squashcounter + 1
				offset = fssearch.findSquashfs(data, offset+squashsize)
			else:
				## cleanup
				os.rmdir(tmpdir)
				offset = fssearch.findSquashfs(data, offset+1)
		return (diroffsets, blacklist)

## wrapper around all the different squashfs types
def unpackSquashfsWrapper(data, offset, tempdir=None):
	## first try normal Squashfs unpacking
	retval = unpackSquashfs(data, offset, tempdir)
	if retval != None:
		return retval
	'''
	## then try other flavours
	else:
		## first OpenWrt variant
		retval = unpackSquashfsOpenWrtLZMA(data,offset,tempdir)
		if retval != None:
			return retval

		else:
			## then Broadcom variant
			retval = unpackSquashfsBroadcomLZMA(data,offset,tempdir)
			if retval != None:
				return retval
	'''
	return None

## tries to unpack stuff using 'normal' unsquashfs. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackSquashfs(data, offset, tempdir=None):
        if tempdir == None:
                tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	## squashfs is not always in the same path, so we need to make a few different invocations
	## Fedora uses /usr/sbin, Ubuntu users /usr/bin
	## Below there is an extremely ugly hack to differentiate between the two
	try:
		os.stat('/usr/sbin/unsquashfs')
		distro = 'sbin'
	except:
		try:
			os.stat('/usr/bin/unsquashfs')
			distro = 'bin'
		except:
			return None

	if distro == 'sbin':
		p = subprocess.Popen(['/usr/sbin/unsquashfs', '-d', tmpdir, '-f', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	elif distro == 'bin':
		p = subprocess.Popen(['/usr/bin/unsquashfs', '-d', tmpdir, '-f', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		squashsize = 0
		p = subprocess.Popen(['file', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.fdopen(tmpfile[0]).close()
			os.unlink(tmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None
		else:
			squashsize = int(re.search(", (\d+) bytes", stanout).groups()[0])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return (tmpdir, squashsize)

## squashfs variant from OpenWrt, with LZMA
def unpackSquashfsOpenWrtLZMA(data, offset, tempdir=None):
        if tempdir == None:
                tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	## this is just a temporary path for now
	p = subprocess.Popen(['/home/armijn/gpltool/trunk/external/squashfs-openwrt/unsquashfs-lzma', '-d', tmpdir, '-f', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		## like with 'normal' squashfs we can use 'file' to determine the size
		squashsize = 0
		p = subprocess.Popen(['file', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.fdopen(tmpfile[0]).close()
			os.unlink(tmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None
		else:
			squashsize = int(re.search(", (\d+) bytes", stanout).groups()[0])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return (tmpdir, squashsize)

## squashfs variant from Broadcom, with LZMA
def unpackSquashfsBroadcomLZMA(data, offset, tempdir=None):
        if tempdir == None:
                tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	## this is just a temporary path for now
	p = subprocess.Popen(['/home/armijn/gpltool/trunk/external/squashfs-broadcom/unsquashfs', '-d', tmpdir, '-f', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		## unlike with 'normal' squashfs we can't use 'file' to determine the size
		squashsize = 1
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return (tmpdir, squashsize)

## We use tune2fs to get the size of the file system so we know what to
## blacklist.
## This method should return a blacklist.
def searchUnpackExt2fs(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findExt2fs(data)
	if offset == -1:
		return ([], blacklist)
	## according to /usr/share/magic the magic header starts at 0x438
	if offset < 0x438:
		return ([], blacklist)
	else:
		diroffsets = []
		ext2counter = 1
		while(offset != -1 and offset >= 0x438):
			## check if the offset we find is in a blacklist
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findExt2fs(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "ext2", ext2counter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			## we should actually scan the data starting from offset - 0x438
			if not checkExt2fs(data[offset - 0x438:offset - 0x438 + 4096], 0, tmpdir):
				os.rmdir(tmpdir)
				offset = fssearch.findExt2fs(data, offset+1)
				continue
			res = unpackExt2fs(data[offset - 0x438:], 0, tmpdir)
			if res != None:
				diroffsets.append((res, offset - 0x438))
				## this needs to be moved to unpackExt2fs, since it fails if 'filename' contains
				## an ext2 file system, but has data prepended.
				p = subprocess.Popen(['tune2fs', '-l', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode == 0:
					if len(stanerr) == 0:
						blockcount = 0
						blocksize = 0
						## we want block count and block size
						for line in stanout.split("\n"):
							if 'Block count' in line:
								blockcount = int(line.split(":")[1].strip())
							if 'Block size' in line:
								blocksize = int(line.split(":")[1].strip())
						blacklist.append((offset - 0x438, offset - 0x438 + blockcount * blocksize))
						ext2counter = ext2counter + 1
					else:
						os.rmdir(tmpdir)
				else:
					os.rmdir(tmpdir)
			else:
				os.rmdir(tmpdir)
			offset = fssearch.findExt2fs(data, offset+1)
	return (diroffsets, blacklist)

def checkExt2fs(data, offset, tempdir=None):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	## for a quick sanity check we only need a tiny bit of data
	if len(data[offset:]) >= 4096:
		os.write(tmpfile[0], data[offset:offset+4096])
	else:
		os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['tune2fs', '-l', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return False
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return True

## Unpack an ext2 file system using e2tools and some custom written code from our own ext2 module
def unpackExt2fs(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	ext2.copyext2fs(tmpfile[1], tmpdir)
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

## tries to unpack stuff using zcat. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackGzip(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that zcat is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['zcat', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanout)
	#os.fdopen(outtmpfile[0]).flush()
	os.fsync(outtmpfile[0])
	if os.stat(outtmpfile[1]).st_size == 0:
		os.fdopen(outtmpfile[0]).close()
		os.unlink(outtmpfile[1])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.fdopen(outtmpfile[0]).close()
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

def searchUnpackGzip(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findGzip(data)
	if offset == -1:
		return ([], blacklist)
	else:
		## counter to remember how many gzip file systems we have
		## discovered, so we can use this to append to the directory
		## name containing the unpacked contents.
		gzipcounter = 1
		diroffsets = []
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findGzip(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "gzip", gzipcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			res = unpackGzip(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				gzipcounter = gzipcounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
			offset = fssearch.findGzip(data, offset+1)
		return (diroffsets, blacklist)

## tries to unpack stuff using bzcat. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
## We use bzcat instead of the bz2 module because that can't handle trailing
## data very well.
def unpackBzip2(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that bzcat is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['bzcat', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanout)
	#os.fdopen(outtmpfile[0]).flush()
	os.fsync(outtmpfile[0])
	if os.stat(outtmpfile[1]).st_size == 0:
		os.fdopen(outtmpfile[0]).close()
		os.unlink(outtmpfile[1])
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.fdopen(outtmpfile[0]).close()
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

def searchUnpackBzip2(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findBzip2(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		bzip2counter = 1
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findBzip2(data, blacklistoffset)
			if offset == -1:
				break
			if tempdir == None:
				tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "bzip2", bzip2counter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			res = unpackBzip2(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				bzip2counter = bzip2counter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
			offset = fssearch.findBzip2(data, offset+1)
		return (diroffsets, blacklist)

def unpackZip(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that zipinfo and unzip are in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	## Use information from zipinfo -v to extract the right offsets (or at least the last offset)
	p = subprocess.Popen(['zipinfo', '-v', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	res = re.search("Actual[\w\s]*end-(?:of-)?cent(?:ral)?-dir record[\w\s]*:\s*(\d+) \(", stanout)
	if res != None:
		endofcentraldir = int(res.groups(0)[0])
	else:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)
	p = subprocess.Popen(['unzip', '-o', tmpfile[1], '-d', tmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0 and p.returncode != 1:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (endofcentraldir, tmpdir)

def searchUnpackZip(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findZip(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		endofcentraldir = 0
		zipcounter = 1
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findZip(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "zip", zipcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			(endofcentraldir, res) = unpackZip(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				zipcounter = zipcounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
			if endofcentraldir == None:
				offset = fssearch.findZip(data, offset+1)
			else:
				offset = fssearch.findZip(data, endofcentraldir+1)
		return (diroffsets, blacklist)

def searchUnpackRar(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findRar(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		rarcounter = 1
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findRar(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "rar", rarcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			res = unpackRar(data, offset, tmpdir)
			if res != None:
				(endofarchive, rardir) = res
				diroffsets.append((rardir, offset))
				offset = fssearch.findRar(data, endofarchive)
				rarcounter = rarcounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
				offset = fssearch.findRar(data, offset+1)
		return (diroffsets, blacklist)

def unpackRar(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that unrar is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	# inspect the rar archive, and retrieve the end of archive
	# this way we won't waste too many resources when we don't need to
	p = subprocess.Popen(['unrar', 'vt', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	rarstring = stanout.strip().split("\n")[-1]
	res = re.search("\s*\d+\s*\d+\s+(\d+)\s+\d+%", rarstring)
	if res != None:
		endofarchive = int(res.groups(0)[0])
	else:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	p = subprocess.Popen(['unrar', 'x', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	## oh the horror, we really need to check if unzip actually was successful
	#outtmpfile = tempfile.mkstemp(dir=tmpdir)
	#os.write(outtmpfile[0], stanout)
	#if os.stat(outtmpfile[1]).st_size == 0:
		#os.unlink(outtmpfile[1])
		#os.unlink(tmpfile[1])
		#return None
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (endofarchive, tmpdir)

def searchUnpackLZMA(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findLZMA(data)
	if offset == -1:
		return ([],blacklist)
	else:
		diroffsets = []
		lzmacounter = 1
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findLZMA(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "lzma", lzmacounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			res = unpackLZMA(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				lzmacounter = lzmacounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
			offset = fssearch.findLZMA(data, offset+1)
		return (diroffsets, blacklist)

## tries to unpack stuff using lzma -cd. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackLZMA(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzma is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['lzma', '-cd', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(outtmpfile[0], stanout)
        if os.stat(outtmpfile[1]).st_size == 0:
                os.fdopen(outtmpfile[0]).close()
                os.unlink(outtmpfile[1])
                os.fdopen(tmpfile[0]).close()
                os.unlink(tmpfile[1])
		if tempdir == None:
                	os.rmdir(tmpdir)
                return None
	os.fdopen(outtmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

def unpackRPM(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that rpm2cpio is in the path
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	## first use rpm2cpio to unpack the rpm data
	p = subprocess.Popen(['rpm2cpio', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if len(stanout) != 0:
		## cleanup first
                os.fdopen(tmpfile[0]).close()
                os.unlink(tmpfile[1])
		if tempdir == None:
                	os.rmdir(tmpdir)
		## then use unpackCpio() to unpack the RPM
		return unpackCpio(stanout, 0, tempdir)
	else:
                os.fdopen(tmpfile[0]).close()
                os.unlink(tmpfile[1])
		if tempdir == None:
                	os.rmdir(tmpdir)
		return None

## RPM is basically a header, plus some compressed files, so we are getting
## duplicates at the moment. We can defeat this easily by setting the blacklist
## upperbound to the start of compression.
## This method should return a blacklist.
def searchUnpackRPM(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findRPM(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		rpmcounter = 1
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findRPM(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "rpm", rpmcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			res = unpackRPM(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				rpmcounter = rpmcounter + 1
				## determine which compression is used, so we can
				## find the right offset. Code from the RPM examples
				tset = rpm.TransactionSet()
        			fdno = os.open(filename, os.O_RDONLY)
        			header = tset.hdrFromFdno(fdno)
        			os.close(fdno)
				## first some sanity checks. payload format should
				## always be 'cpio' according to LSB 3
				if header[rpm.RPMTAG_PAYLOADFORMAT] == 'cpio':
					## compression should always be 'gzip' according to LSB 3
					if header[rpm.RPMTAG_PAYLOADCOMPRESSOR] == 'gzip':
						payloadoffset = fssearch.findGzip(data, offset)
						blacklist.append((offset, payloadoffset))
			else:
				## cleanup
				os.rmdir(tmpdir)
			offset = fssearch.findRPM(data, offset+1)
		return (diroffsets, blacklist)

## Search and unpack Ubifs. Since we can't easily determine the length of the
## file system by using ubifs we will have to use a different measurement to
## measure the size of ubifs. A good start is the sum of the size of the
## volumes that were unpacked.
## This method should return a blacklist.
def searchUnpackUbifs(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	## We can use the values of offset and ubisize where offset != -1
	## to determine the ranges for the blacklist.
	offset = fssearch.findUbifs(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		ubicounter = 1
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findUbifs(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "ubifs", ubicounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			res = unpackUbifs(data, offset, tmpdir)
			if res != None:
				(ubitmpdir, ubisize) = res
				diroffsets.append((ubitmpdir, offset))
				offset = fssearch.findUbifs(data, offset+ubisize)
				ubicounter = ubicounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
				offset = fssearch.findUbifs(data, offset+1)
		return (diroffsets, blacklist)

def unpackUbifs(data, offset, tempdir=None):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	## use unubi to unpack the data
	p = subprocess.Popen(['unubi', '-d', tmpdir, tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()

	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		## clean up the temporary files
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		## determine the sum of the size of the unpacked files
		osgen = os.walk(tempdir)
		ubisize = 0
		try:
			while True:
				i = osgen.next()
				for p in i[2]:
					ubisize = ubisize + os.stat("%s/%s" % (i[0], p)).st_size
        	except StopIteration:
                	pass
		if ubisize == 0:
			if tempdir == None:
				os.rmdir(tmpdir)
			return None
		return (tmpdir, ubisize)

## unpacking for ARJ. The file format is described at:
## http://www.fileformat.info/format/arj/corion.htm
## Although there is no trailer we can use the arj program to at least give
## us some information about the uncompressed size of the archive.
## Please note: these files can also be unpacked with 7z, which could be
## a little bit faster. Since 7z is "smart" and looks ahead we would lose
## blacklisting and getting the right offset.
## ARJ should therefore have priority over 7z (TODO)
def searchUnpackARJ(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	offset = fssearch.findARJ(data)
	if offset == -1:
		return ([], blacklist)
	else:
		diroffsets = []
		arjcounter = 1
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findARJ(data, blacklistoffset)
			if offset == -1:
				break
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "arj", arjcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
			res = unpackARJ(data, offset, tmpdir)
			if res != None:
				(arjtmpdir, arjsize) = res
				diroffsets.append((arjtmpdir, offset))
				blacklist.append((offset, arjsize))
				offset = fssearch.findARJ(data, offset+arjsize)
				arjcounter = arjcounter + 1
			else:
				## cleanup
				os.rmdir(tmpdir)
				offset = fssearch.findARJ(data, offset+1)
		return (diroffsets, blacklist)

def unpackARJ(data, offset, tempdir=None):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	tmpfile = tempfile.mkstemp(dir=tmpdir, suffix=".arj")
	os.write(tmpfile[0], data[offset:])
	## first check archive integrity
	p = subprocess.Popen(['arj', 't', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		## this is not an ARJ archive
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		p = subprocess.Popen(['arj', 'x', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.fdopen(tmpfile[0]).close()
			os.unlink(tmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None
	## everything has been unpacked, so we can get the size.
	p = subprocess.Popen(['arj', 'v', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	stanoutlines = stanout.strip().split("\n")
	## we should do more sanity checks here
	arjsize = int(stanoutlines[-1].split()[-2])
	## always clean up the old temporary files
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (tmpdir, arjsize)

###
## The scans below are scans that are used to extract files from bigger binary
## blobs, but they should not be recursively applied to their own results,
## because that results in endless loops.
###

## http://en.wikipedia.org/wiki/Graphics_Interchange_Format
## 1. search for a GIF header
## 2. search for a GIF trailer
## 3. check the data with gifinfo
def searchUnpackGIF(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	header = fssearch.findGIF(data)
	if header == -1:
		return ([], blacklist)
	trailer = data.find(';', header)
	if trailer == -1:
		return ([], blacklist)
	traileroffsets = []
	traileroffsets.append(trailer)
	while(trailer != -1):
		trailer = data.find(';',trailer+1)
		if trailer != -1:
			traileroffsets.append(trailer)
	headeroffsets = []
	headeroffsets.append(header)
	while (header != -1):
		header = fssearch.findGIF(data, header+1)
		if header != -1:
			headeroffsets.append(header)
	diroffsets = []
	gifcounter = 1
	for i in range (0,len(headeroffsets)):
		offset = headeroffsets[i]
		if i < len(headeroffsets) - 1:
			nextoffset = headeroffsets[i+1]
		else:
			nextoffset = len(data)
		## first check if we're not blacklisted for the offset
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		for trail in traileroffsets:
			if trail <= offset:
				continue
			if trail >= nextoffset:
				break
			## check if we're not blacklisted for the trailer
			blacklistoffset = extractor.inblacklist(trail, blacklist)
			if blacklistoffset != None:
				continue
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "gif", gifcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
				tmpfile = tempfile.mkstemp(prefix='unpack-', suffix=".gif", dir=tmpdir)
				os.write(tmpfile[0], data[offset:trail+1])
				p = subprocess.Popen(['gifinfo', tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					os.fdopen(tmpfile[0]).close()
					os.unlink(tmpfile[1])
					os.rmdir(tmpdir)
				else:
					os.fdopen(tmpfile[0]).close()
					## basically we have a copy of the original
					## image here, so why bother?
					if offset == 0 and trail == len(data) - 1:
						os.unlink(tmpfile[1])
						os.rmdir(tmpdir)
					else:
						diroffsets.append((tmpdir, offset))
						gifcounter = gifcounter + 1
						break
	return (diroffsets, blacklist)

## JPEG extraction can be tricky according to /usr/share/magic, so this is
## not fool proof.
def searchUnpackJPEG(filename, tempdir=None, blacklist=[]):
	## first search for JFIF, then search for Exif, then search for plain
	## JPEG and take the minimum value.
	## Only do JFIF for now
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	#print fssearch.findJFIF(data,0)
	return ([], blacklist)

## PNG extraction is similar to GIF extraction, except there is a way better
## defined trailer.
def searchUnpackPNG(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	header = fssearch.findPNG(data)
	if header == -1:
		return ([], blacklist)
	trailer = fssearch.findPNGTrailer(data, header)
	if trailer == -1:
		return ([], blacklist)
	traileroffsets = []
	traileroffsets.append(trailer)
	while(trailer != -1):
		trailer = fssearch.findPNGTrailer(data,trailer+1)
		if trailer != -1:
			traileroffsets.append(trailer)
	headeroffsets = []
	headeroffsets.append(header)
	while (header != -1):
		header = fssearch.findPNG(data, header+1)
		if header != -1:
			headeroffsets.append(header)
	diroffsets = []
	pngcounter = 1
	for i in range (0,len(headeroffsets)):
		offset = headeroffsets[i]
		if i < len(headeroffsets) - 1:
			nextoffset = headeroffsets[i+1]
		else:
			nextoffset = len(data)
		## first check if we're not blacklisted for the offset
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		for trail in traileroffsets:
			if trail <= offset:
				continue
			if trail >= nextoffset:
				break
			## check if we're not blacklisted for the trailer
			blacklistoffset = extractor.inblacklist(trail, blacklist)
			if blacklistoffset != None:
				continue
        		if tempdir == None:
        	       		tmpdir = tempfile.mkdtemp()
			else:
				try:
					tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), "png", pngcounter)
					os.makedirs(tmpdir)
				except Exception, e:
					tmpdir = tempfile.mkdtemp(dir=tempdir)
				tmpfile = tempfile.mkstemp(prefix='unpack-', suffix=".png", dir=tmpdir)
				os.write(tmpfile[0], data[offset:trail+8])
				p = subprocess.Popen(['webpng', '-d', tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					os.fdopen(tmpfile[0]).close()
					os.unlink(tmpfile[1])
					os.rmdir(tmpdir)
				else:
					os.fdopen(tmpfile[0]).close()
					## basically we have a copy of the original
					## image here, so why bother?
					if offset == 0 and trail == len(data) - 8:
						os.unlink(tmpfile[1])
						os.rmdir(tmpdir)
						blacklist.append((0,len(data)))
					else:
						diroffsets.append((tmpdir, offset))
						pngcounter = pngcounter + 1
						break
	return (diroffsets, blacklist)

## EXIF is (often) prepended to the actual image data
## Having access to EXIF data can also (perhaps) get us useful data
def searchUnpackEXIF(filename, tempdir=None, blacklist=[]):
	return ([],blacklist)

## sometimes Ogg audio files are embedded into binary blobs
def searchUnpackOgg(filename, tempdir=None, blacklist=[]):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	return ([], blacklist)

## sometimes MP3 audio files are embedded into binary blobs
def searchUnpackMP3(filename, tempdir=None, blacklist=[]):
	return ([], blacklist)
