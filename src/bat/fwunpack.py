#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains helper functions to unpack archives or file systems.
Most of the commands are pretty self explaining. The result of the wrapper
functions is a list of tuples, which contain the name of a temporary directory
with the unpacked contents of the archive, and the offset of the archive or
file system in the parent file.

Optionally, we return a range of bytes that should be excluded in same cases
where we want to prevent other scans from (re)scanning (part of) the data.
'''

import sys, os, subprocess, os.path, shutil, stat
import tempfile, bz2, re, magic, tarfile, zlib
import fsmagic, fssearch, extractor, ext2, jffs2
from xml.dom import minidom

## generic method to create temporary directories, with the correct filenames
## which is used throughout the code.
def dirsetup(tempdir, filename, marker, counter):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		try:
			tmpdir = "%s/%s-%s-%s" % (os.path.dirname(filename), os.path.basename(filename), marker, counter)
			os.makedirs(tmpdir)
		except Exception, e:
			tmpdir = tempfile.mkdtemp(dir=tempdir)
	return tmpdir

def unpacksetup(tempdir):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir
	return tmpdir

## method to search for all the markers we have in fsmagic
## TODO: since most/all scans use results from this method we can rewrite this and
## always run it, but after other pre-run scans, such as byteswapping
def genericMarkerSearch(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	datafile = open(filename, 'rb')
	databuffer = []
	offsets = {}
	offset = 0
	datafile.seek(offset)
	databuffer = datafile.read(100000)
        marker_keys = fsmagic.fsmagic.keys()
	for key in marker_keys:
		offsets[key] = []
	while databuffer != '':
		for key in marker_keys:
			res = databuffer.find(fsmagic.fsmagic[key])
			if res == -1:
				continue
			else:
				while res != -1:
					## we should return this differently, so we can sort per offset and
					## do a possibly better scan
					#offsets[key].append((offset + res, key))
					offsets[key].append(offset + res)
					res = databuffer.find(fsmagic.fsmagic[key], res+1)
		## move the offset 99950
		datafile.seek(offset + 99950)
		## read 100000 bytes with a 50 bytes overlap
		## overlap with the previous read
		databuffer = datafile.read(100000)
		if len(databuffer) >= 50:
			offset = offset + 99950
		else:
			offset = offset + len(databuffer)
	datafile.close()
	return ([], blacklist, offsets)

## There are certain routers that have all bytes swapped, because they use 16
## bytes NOR flash instead of 8 bytes SPI flash. This is an ugly hack to first
## rearrange the data. This is mostly for Realtek RTL8196C based routers.
def searchUnpackByteSwap(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	datafile = open(filename, 'rb')
	offset = 0
	datafile.seek(offset)
	swapped = False
	databuffer = datafile.read(100000)
	## "Uncompressing Linux..."
	while databuffer != '':
		datafile.seek(offset + 99950)
		if databuffer.find("nUocpmerssni giLun.x..") != -1:
			swapped = True
			break
		databuffer = datafile.read(100000)
		if len(databuffer) >= 50:
			offset = offset + 99950
		else:
			offset = offset + len(databuffer)

	if swapped:
		tmpdir = dirsetup(tempdir, filename, "byteswap", 1)
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		## reset pointer into file
		datafile.seek(0)
		data = datafile.read()
		counter = 0
		for i in xrange(0,len(data)):
        		if counter == 0:
                		os.write(tmpfile[0], data[i+1])
        		else:
                		os.write(tmpfile[0], data[i-1])
        		counter = (counter+1)%2
		return ([(tmpdir, 0)], blacklist, offsets)
	datafile.close()
	return ([], blacklist, offsets)

## unpack base64 files
def searchUnpackBase64(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	## first determine if we are dealing with ASCII text
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(filename)
	ms.close()

	## Since this only works on complete files the blacklist should be empty
	if not 'ASCII' in mstype or blacklist != []:
		return ([], blacklist, offsets)
	counter = 1
	diroffsets = []
	tmpdir = dirsetup(tempdir, filename, "base64", counter)
	p = subprocess.Popen(['base64', '-d', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.rmdir(tmpdir)
		return ([], blacklist, offsets)
	else:
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		os.write(tmpfile[0], stanout)
		## the whole file is blacklisted
		blacklist.append((0, os.stat(filename).st_size))
		diroffsets.append((tmpdir, 0))
		return (diroffsets, blacklist, offsets)

## decompress executables that have been compressed with UPX.
def searchUnpackUPX(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	p = subprocess.Popen(['upx', '-t', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return ([], blacklist, offsets)
	counter = 1
	diroffsets = []
	tmpdir = dirsetup(tempdir, filename, "upx", counter)
	p = subprocess.Popen(['upx', '-d', filename, '-o', os.path.basename(filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.rmdir(tmpdir)
		return ([], blacklist, offsets)
	else:
		## the whole file is blacklisted
		blacklist.append((0, os.stat(filename).st_size))
		diroffsets.append((tmpdir, 0))
	return (diroffsets, blacklist, offsets)

## unpack Java serialized data
def searchUnpackJavaSerialized(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['java_serialized'] == []:
		return ([], blacklist, offsets)
	counter = 1
	diroffsets = []
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	for offset in offsets['java_serialized']:
		## check if the offset we find is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "java_serialized", counter)
		res = unpackJavaSerialized(data, offset, tmpdir)
		if res != None:
			(serdir, size) = res
			diroffsets.append((serdir, offset))
			blacklist.append((offset, offset + size))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackJavaSerialized(data, offset, tempdir=None):

	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	os.fdopen(tmpfile[0]).close()
	## TODO: remove hardcoded path
	p = subprocess.Popen(['java', '-jar', '/home/armijn/gpltool/trunk/bat-extratools/jdeserialize/bat-jdeserialize.jar', '-blockdata', 'deserialize', tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
        (stanout, stanerr) = p.communicate()
        if p.returncode != 0 or 'file version mismatch!' in stanerr:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	if os.stat("%s/%s" % (tmpdir, "deserialize")).st_size == 0:
		os.unlink("%s/%s" % (tmpdir, "deserialize"))
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	serialized_size = os.stat(tmpfile[1]).st_size
	os.unlink(tmpfile[1])
	return (tmpdir, serialized_size)


## unpacking SWF files is easy, but for later processing we definitely would
## need to give some hints to other scanners about what file we have unpacked,
## so we can search more effectively.
## We are assuming that the whole file is an SWF file.
def searchUnpackSwf(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['swf'] == []:
		return ([], blacklist, offsets)
	## right now we are dealing only with entire files. This might change in
	## the future.
	if offsets['swf'][0] != 0:
		return ([], blacklist, offsets)
	counter = 1
	diroffsets = []
	data = open(filename).read()
	tmpdir = dirsetup(tempdir, filename, "swf", counter)
	res = unpackSwf(data, tmpdir)
	if res != None:
		diroffsets.append((res, 0))
		blacklist.append((0, os.stat(filename).st_size))
	else:
		os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackSwf(data, tempdir=None):
	## skip first 8 bytes, then decompress with zlib
	tmpdir = unpacksetup(tempdir)
	try:
		unzswf = zlib.decompress(data[8:])
	except Exception, e:
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], unzswf)
	os.fdopen(tmpfile[0]).close()
	return tmpdir

## unpacking jffs2 files is tricky
def searchUnpackJffs2(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	## first determine if we are dealing with ASCII text
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(filename)
	ms.close()
	## for now we're just working on whole file systems. This could change in the future.
	if not 'jffs2' in mstype or blacklist != []:
		return ([], blacklist, offsets)

	counter = 1
	diroffsets = []
	tmpdir = dirsetup(tempdir, filename, "jffs2", counter)
	res = unpackJffs2(filename, tmpdir)
	if res != None:
		diroffsets.append((res, 0))
		blacklist.append((0, os.stat(filename).st_size))
	else:
		os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackJffs2(filename, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	return jffs2.unpackJFFS2(filename, tmpdir)

def searchUnpackAr(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['ar'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	counter = 1
	data = datafile.read()
	datafile.close()
	diroffsets = []
	for offset in offsets['ar']:
		## check if the offset we find is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "ar", counter)
		res = unpackAr(data, offset, tmpdir)
		if res != None:
			(ardir, size) = res
			diroffsets.append((ardir, offset))
			blacklist.append((offset, offset + size))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackAr(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['ar', 'tv', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	## ar only works on complete files, so we can set the size to len(data)
	p = subprocess.Popen(['ar', 'x', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	if tempdir == None:
		os.rmdir(tmpdir)
	return (tmpdir, len(data))

## 1. search ISO9660 file system
## 2. mount it using FUSE
## 3. copy the contents
## 4. make sure all permissions are correct (so use chmod)
## 5. unmount file system
def searchUnpackISO9660(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['iso9660'] == []:
		return ([], blacklist, offsets)
	diroffsets = []
	counter = 1
	for offset in offsets['iso9660']:
		## according to /usr/share/magic the magic header starts at 0x438
		if offset < 32769:
			continue
		## check if the offset we find is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "iso9660", counter)
		res = unpackISO9660(filename, offset, tmpdir)
		if res != None:
			(isooffset, size) = res
			diroffsets.append((isooffset, offset - 32769))
			blacklist.append((offset - 32769, offset - 32769 + size))
			counter = counter + 1
		else:
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackISO9660(filename, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)

	if offset != 32769:
		p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile[1],), 'bs=%s' % (offset - 32769,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	## if we need to the whole file we might as well just copy it directly
	else:
		shutil.copy(filename, tmpfile[1])

	## create a mountpoint
	mountdir = tempfile.mkdtemp()
	p = subprocess.Popen(['fuseiso', tmpfile[1], mountdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.rmdir(mountdir)
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	## first we create *another* temporary directory, because of the behaviour of shutil.copytree()
	tmpdir2 = tempfile.mkdtemp()
	## then copy the contents to a subdir
	shutil.copytree(mountdir, tmpdir2 + "/bla")
	## then change all the permissions
	osgen = os.walk(tmpdir2 + "/bla")
	try:
		while True:
			i = osgen.next()
			os.chmod(i[0], stat.S_IRWXU)
			for p in i[2]:
				os.chmod("%s/%s" % (i[0], p), stat.S_IRWXU)
	except Exception, e:
		pass
	## then we move all the contents using shutil.move()
	mvfiles = os.listdir(tmpdir2 + "/bla")
	for f in mvfiles:
		shutil.move(tmpdir2 + "/bla/" + f, tmpdir)
	## then we cleanup the temporary dir
	shutil.rmtree(tmpdir2)
	
	## determine size
	p = subprocess.Popen(['du', '-scb', mountdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		## this should not happen
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	size = int(stanout.strip().split("\n")[-1].split()[0])
	## unmount the ISO image using fusermount
	p = subprocess.Popen(['fusermount', "-u", mountdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	## TODO: check exit codes
	os.rmdir(mountdir)
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (tmpdir, size)

def searchUnpackTar(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	taroffsets = []
	for marker in fsmagic.tar:
		taroffsets = taroffsets + offsets[marker]
	if taroffsets == []:
		return ([], blacklist, offsets)

	diroffsets = []
	counter = 1
	for offset in taroffsets:
		## according to /usr/share/magic the magic header starts at 0x101
		if offset < 0x101:
			continue

		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "tar", counter)
		(res, tarsize) = unpackTar(filename, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset - 0x101))
			counter = counter + 1
			blacklist.append((offset - 0x101, offset - 0x101 + tarsize))
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)


def unpackTar(filename, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)

	if offset != 0x101:
		p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile[1],), 'bs=%s' % (offset - 0x101,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	## if we need to the whole file we might as well just copy it directly
	else:
		shutil.copy(filename, tmpfile[1])

	tarsize = 0

	try:
		tar = tarfile.open(tmpfile[1], 'r')
		tarmembers = tar.getmembers()
		## assume that the last member is also the last in the file
		tarsize = tarmembers[-1].offset_data + tarmembers[-1].size
		for i in tarmembers:
			if not i.isdev():
				tar.extract(i, path=tmpdir)
		tar.close()
	except Exception, e:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (tmpdir, tarsize)

## yaffs2 is used frequently in Android and various mediaplayers based on
## Realtek chipsets (RTD1261/1262/1073/etc.)
## yaffs2 does not have a magic header, so it is really hard to recognize.
## This is why, for now, we will only try to unpack at offset 0.
## For this you will need the unyaffs program from
## http://code.google.com/p/unyaffs/
def searchUnpackYaffs2(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	tmpdir = dirsetup(tempdir, filename, "yaffs", 1)
	p = subprocess.Popen(['bat-unyaffs', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.rmdir(tmpdir)
		return ([], blacklist, offsets)
	## unfortunately unyaffs also returns 0 when it fails
	if len(stanerr) != 0:
		os.rmdir(tmpdir)
		return ([], blacklist, offsets)
	## we need to check if there was actually any data unpacked.
	if os.listdir(tmpdir) == []:
		os.rmdir(tmpdir)
		return ([], blacklist, offsets)
	blacklist.append((0, os.stat(filename).st_size))
	return ([(tmpdir,0)], blacklist, offsets)

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
def searchUnpackExe(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	## first determine if we are dealing with a MS Windows executable
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(filename)
	ms.close()

	if not 'PE32 executable for MS Windows' in mstype and not "PE32+ executable for MS Windows" in mstype:
		return ([], blacklist, offsets)

	## apparently we have a MS Windows executable, so continue
	diroffsets = []
	counter = 1
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	assembly = extractor.searchAssemblyAttrs(data)
	## if we were able to extract the assembly XML file we could get some useful
	## information from it. Although there are some vanity entries that we can
	## easily skip (and just bruteforce) there are a few that we really need to
	## recognize. TODO: refactor
	if assembly != {}:
		## we are pretty much out of luck with this one.
		if assembly['name'] == "NOSMicrosystems.iNOSSO":
			return ([], blacklist, offsets)
		## if we see this we can probably directly go to unrar
		elif assembly['name'] == "WinRAR SFX":
			pass
		elif assembly['name'] == "WinZipComputing.WinZip.WZSEPE32":
			pass
		elif assembly['name'] == "WinZipComputing.WinZip.WZSFX":
			pass
		elif assembly['name'] == "JR.Inno.Setup":
			pass
		elif assembly['name'] == "Nullsoft.NSIS.exehead":
			pass
		elif assembly['name'] == "7zS.sfx.exe":
			pass
		## IExpress WExtract
		elif assembly['name'] == "wextract":
			pass
		elif assembly['name'] == "InstallShield.Setup":
			pass
		## self extracting cab, use either cabextract or 7z
		elif assembly['name'] == "sfxcab":
			pass
		## Setup Factory
		elif assembly['name'] == "setup.exe":
			pass
		## dunno this one, seems to be misspelled
		elif assembly['name'] == "Squeez-SFX":
			pass
	## after all the special cases we can just bruteforce our way through
	## like before, although if we find some strings we could already skip
	## some checks. Needs refactoring.
	## first search for ZIP. Do this by searching for:
	## * PKBAC (seems to give the best results)
	## * WinZip Self-Extractor
	## 7zip gives better results than unzip
	offset = data.find("PKBAC")
	if offset != -1:
		tmpdir = dirsetup(tempdir, filename, "exe", counter)
		res = unpack7z(data, 0, tmpdir)
		if res != None:
			diroffsets.append((res, 0))
			blacklist.append((0, os.stat(filename).st_size))
			return (diroffsets, blacklist, offsets)
		else:
			if tempdir == None:
				os.rmdir(tmpdir)
	## then search for RAR by searching for:
	## WinRAR
	## and unpack with unrar
	offset = data.find("WinRAR")
	if offset != -1:
		tmpdir = dirsetup(tempdir, filename, "exe", counter)
		res = unpackRar(data, 0, tmpdir)
		if res != None:
			(endofarchive, rardir) = res
			diroffsets.append((rardir, 0))
			## add the whole binary to the blacklist
			blacklist.append((0, os.stat(filename).st_size))
			counter = counter + 1
			return (diroffsets, blacklist, offsets)
		else:
			if tempdir == None:
				os.rmdir(tmpdir)
	## else try other methods
	## 7zip gives better results than cabextract
	## Ideally we should also do something with innounp
	## As a last resort try 7-zip
	tmpdir = dirsetup(tempdir, filename, "exe", counter)
	res = unpack7z(data, 0, tmpdir)
	if res != None:
		diroffsets.append((res, 0))
		blacklist.append((0, os.stat(filename).st_size))
		return (diroffsets, blacklist, offsets)
	else:
		if tempdir == None:
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

## unpacker for Microsoft InstallShield
## We're using unshield for this. Unfortunately the released version of
## unshield (0.6) does not support newer versions of InstallShield files, so we
## can only unpack a (shrinking) subset of files.
##
## Patches for support of newer versions have been posted at:
## http://sourceforge.net/tracker/?func=detail&aid=3163039&group_id=30550&atid=399603
## but unfortunately there has not been a new release yet.
def searchUnpackInstallShield(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['installshield'] == []:
		return ([], blacklist, offsets)
	diroffsets = []
	counter = 1
	## To successfully unpack we need:
	## * installshield cabinet (.cab)
	## * header file (.hdr)
	## * possibly (if available) <filename>2.cab
	##
	## To successfully unpack the filenames need to be formatted as <filename>1.<extension>
	## so we will only consider files that end in "1.cab"
	if offsets['installshield'][0] != 0:
		return ([], blacklist, offsets)
	## Check the filenames first, if we don't have <filename>1.cab, or <filename>1.hdr we return
	## This should prevent that data2.cab is scanned.
	if not filename.endswith("1.cab"):
		return ([], blacklist, offsets)
	try:
		os.stat(filename[:-4] + ".hdr")
	except Exception, e:
		return ([], blacklist, offsets)
	blacklistoffset = extractor.inblacklist(0, blacklist)
	if blacklistoffset != None:
		return ([], blacklist, offsets)
	tmpdir = dirsetup(tempdir, filename, "installshield", counter)

	p = subprocess.Popen(['unshield', 'x', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.rmdir(tmpdir)
	else:
		## Ideally we add data1.cab, data1.hdr and (if present) data2.cab to the blacklist.
		## For this we need to be able to supply more information to the parent process
		diroffsets.append((tmpdir, 0))
	return (diroffsets, blacklist, offsets)

## unpacker for Microsoft Cabinet Archive files.
def searchUnpackCab(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['cab'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	diroffsets = []
	counter = 1
	## only read data when we have found an offset
	data = datafile.read()
	datafile.close()
	for offset in offsets['cab']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "cab", counter)
		res = unpackCab(data, offset, tmpdir)
		if res != None:
			(cabdir, cabsize) = res
			diroffsets.append((cabdir, offset))
			blacklist.append((offset, offset + cabsize))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

## This method will not work when the CAB is embedded in a bigger file, such as
## a MINIX file system. We need to use more data from the metadata and perhaps
## adjust for certificates.
def unpackCab(data, offset, tempdir=None):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	tmpdir = unpacksetup(tempdir)
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

def searchUnpack7z(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['7z'] == []:
		return ([], blacklist, offsets)

	## for now only try to unpack if 7z starts at offset 0
	if offsets['7z'][0] != 0:
		return ([], blacklist, offsets)

	datafile = open(filename, 'rb')
	## counter to remember how many gzip file systems we have
	## discovered, so we can use this to append to the directory
	## name containing the unpacked contents.
	counter = 1
	diroffsets = []
	data = datafile.read()
	datafile.close()
	for offset in offsets['7z']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "7z", counter)
		res = unpack7z(data, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset))
			counter = counter + 1
			break
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)


def unpack7z(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that 7z is in the path
	tmpdir = unpacksetup(tempdir)
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
def searchUnpackLzip(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['lzip'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	diroffsets = []
	counter = 1
	data = datafile.read()
	datafile.close()
	for offset in offsets['lzip']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "lzip", counter)
		(res, lzipsize) = unpackLzip(data, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset))
			blacklist.append((offset, offset+lzipsize))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackLzip(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzip is in the path
	tmpdir = unpacksetup(tempdir)
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
		return (None, None)
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
		return (None, None)
	lzipsize = int(re.search("member size\s+(\d+)", stanerr).groups()[0])
	os.fdopen(outtmpfile[0]).close()
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (tmpdir, lzipsize)

## unpack lzo archives.
def searchUnpackLzo(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['lzo'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	diroffsets = []
	counter = 1
	for offset in offsets['lzo']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "lzo", counter)
		(res, lzosize) = unpackLzo(data, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset))
			blacklist.append((offset, offset+lzosize))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackLzo(data, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzop is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['lzop', "-d", "-P", "-p%s" % (tmpdir,), tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)
	## determine the size of the archive we unpacked, so we can skip a lot in future scans
	p = subprocess.Popen(['lzop', '-t', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	## file could be two lzop files concatenated, which would unpack just fine
	## but which would give a returncode != 0 when tested. This will do for now though.
	if p.returncode != 0:
		lzopsize = 0
	else:
		## the whole file is the lzop archive
		lzopsize = len(data)
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (tmpdir, lzopsize)

## To unpack XZ we need to find a header and a footer.
## The trailer is actually very generic and a lot more common than the header,
## so it is likely that we need to search for the trailer a lot more than
## for the header.
def searchUnpackXZ(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['xz'] == []:
		return ([], blacklist, offsets)
	if offsets['xztrailer'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	## record the original offset
	diroffsets = []
	counter = 1
	## only read the data when we know we can continue
	data = datafile.read()
	datafile.close()
	for trail in offsets['xztrailer']:
		## check if the trailer is in the blacklist
		blacklistoffset = extractor.inblacklist(trail, blacklist)
		if blacklistoffset != None:
			continue
		for offset in offsets['xz']:
			## only check offsets that make sense
			if offset >= trail:
				continue
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				continue
			else:
				tmpdir = dirsetup(tempdir, filename, "xz", counter)
				res = unpackXZ(data, offset, trail, tmpdir)
				if res != None:
					diroffsets.append((res, offset))
					counter = counter + 1
				else:
					## cleanup
					os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackXZ(data, offset, trailer, tempdir=None):
	## first unpack the data, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that xz is in the path
	tmpdir = unpacksetup(tempdir)
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
def searchUnpackCpio(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	cpiooffsets = []
	for marker in fsmagic.cpio:
		cpiooffsets = cpiooffsets + offsets[marker]
	if cpiooffsets == []:
		return ([], blacklist, offsets)

	if offsets['cpiotrailer'] == []:
		return ([], blacklist, offsets)

	datafile = open(filename, 'rb')
	diroffsets = []
	counter = 1
	## only read data when we actually have offsets
	data = datafile.read()
	datafile.close()
	for offset in cpiooffsets:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		for trailer in offsets['cpiotrailer']:
			blacklistoffset = extractor.inblacklist(trailer, blacklist)
			if blacklistoffset != None:
				continue
			if trailer < offset:
				continue
			tmpdir = dirsetup(tempdir, filename, "cpio", counter)
			## length of 'TRAILER!!!' plus 1 to include the whole trailer
			## and cpio archives are always rounded to blocks of 512 bytes
			trailercorrection = (512 - len(data[offset:trailer+10])%512)
			res = unpackCpio(data[offset:trailer+10 + trailercorrection], 0, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				blacklist.append((offset, trailer))
				counter = counter + 1
				## success with unpacking, no need to continue with
				## the next trailer for this offset
				break
			else:
				## cleanup
				os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

## tries to unpack stuff using cpio. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
## This one needs to stay separate, since it is also used by RPM unpacking
def unpackCpio(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	## write data to a temporary location first so we can check the magic.
	## Also use cpio -t to test if we actually have a valid archive
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(tmpfile[1])
	ms.close()
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	if 'cpio' not in mstype:
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

## unpacking cramfs file systems. This will file on file systems from some
## devices most notably from Sigma Designs, since they seem to have tweaked
## the file system.
def searchUnpackCramfs(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['cramfs'] == []:
		return ([], blacklist, offsets)

	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	diroffsets = []
	counter = 1
	for offset in offsets['cramfs']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "cramfs", counter)
		retval = unpackCramfs(data, offset, tmpdir)
		if retval != None:
			(res, cramfssize) = retval
			if cramfssize != 0:
				blacklist.append((offset,offset+cramfssize))
			diroffsets.append((res, offset))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

## tries to unpack stuff using fsck.cramfs. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackCramfs(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	## fsck.cramfs needs to unpack in a separate directory. So, create a new temporary
	## directory to avoid name clashes
        tmpdir2 = tempfile.mkdtemp()
	## since fsck.cramfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp()
	os.write(tmpfile[0], data[offset:])

	## right now this is a path to a specially adapted fsck.cramfs that ignores special inodes
	## We actually need to create a new subdirectory inside tmpdir, otherwise the tool will complain
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
		## first copy all the contents from the temporary dir to tmpdir
		mvfiles = os.listdir(tmpdir2 + "/cramfs")
		for f in mvfiles:
			shutil.move(tmpdir2 + "/cramfs/" + f, tmpdir)
		## determine if the whole file actually is the cramfs file. Do this by running bat-fsck.cramfs again with -v and check stderr.
		## If there is no warning or error on stderr, we know that the entire file is the cramfs file and it can be blacklisted.
		p = subprocess.Popen(['bat-fsck.cramfs', '-v', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if len(stanerr) != 0:
			cramfssize = 0
		else:
			cramfssize = len(data)
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		shutil.rmtree(tmpdir2)
		return (tmpdir, cramfssize)

## Search and unpack a squashfs file system. Since there are so many flavours
## of squashfs available we have to do some extra work here, and possibly have
## some extra tools (squashfs variants) installed.
## Use the output of 'file' to determine the size of squashfs and use it for the
## blacklist.
def searchUnpackSquashfs(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	squashoffsets = []
	for marker in fsmagic.squashtypes:
		squashoffsets = squashoffsets + offsets[marker]
	if squashoffsets == []:
		return ([], blacklist, offsets)

	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	diroffsets = []
	counter = 1
	for offset in squashoffsets:
		## check if the offset we find is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "squashfs", counter)
		retval = unpackSquashfsWrapper(data, offset, tmpdir)
		if retval != None:
			(res, squashsize) = retval
			diroffsets.append((res, offset))
			blacklist.append((offset,offset+squashsize))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

## wrapper around all the different squashfs types
def unpackSquashfsWrapper(data, offset, tempdir=None):
	## first try normal Squashfs unpacking
	retval = unpackSquashfs(data, offset, tempdir)
	if retval != None:
		return retval
	## then try other flavours
	## first SquashFS 4.2
	retval = unpackSquashfs42(data,offset,tempdir)
	if retval != None:
		return retval

	## OpenWrt variant
	retval = unpackSquashfsOpenWrtLZMA(data,offset,tempdir)
	if retval != None:
		return retval

	## Broadcom variant
	## WARNING!!
	## Sometimes, for example when the OpenWrt version from above
	## can't unpack a file, this scan will pick it up and eat
	## 100% CPU for a long long long time, without producing any
	## result. This is not a bug in BAT, but in this version of
	## unsquashfs!
	retval = unpackSquashfsBroadcomLZMA(data,offset,tempdir)
	if retval != None:
		return retval

	## Ralink variant
	retval = unpackSquashfsRalinkLZMA(data,offset,tempdir)
	if retval != None:
		return retval

	## Atheros variant
	retval = unpackSquashfsAtherosLZMA(data,offset,tempdir)
	if retval != None:
		return retval
	return None

## tries to unpack stuff using 'normal' unsquashfs. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackSquashfs(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	## squashfs is not always in the same path:
	## Fedora uses /usr/sbin, Ubuntu uses /usr/bin
	## Just to be sure we add /usr/sbin to the path and set the environment

	unpackenv = os.environ
	unpackenv['PATH'] = unpackenv['PATH'] + ":/usr/sbin"

	p = subprocess.Popen(['unsquashfs', '-d', tmpdir, '-f', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=unpackenv)
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
	tmpdir = unpacksetup(tempdir)
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	## squashfs 1.0 with lzma from OpenWrt can't unpack to an existing directory
	## so we use a workaround using an extra temporary directory
	tmpdir2 = tempfile.mkdtemp()

	p = subprocess.Popen(['bat-unsquashfs-openwrt', '-dest', tmpdir2 + "/squashfs-root", '-f', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	## Return code is not reliable enough, since even after successful unpacking the return code could be 16 (related to creating inodes as non-root)
	## we need to filter out messages about creating inodes. Right now we do that by counting how many
	## error lines we have for creating inodes and comparing them with the total number of lines in stderr
	## If they match we know all errors are for creating inodes, so we can safely ignore them.
	stanerrlines = stanerr.strip().split("\n")
	inode_error = 0
	for stline in stanerrlines:
		if "create_inode: could not create" in stline:
			inode_error = inode_error + 1
	if stanerr != "" and len(stanerrlines) != inode_error:
		shutil.rmtree(tmpdir2)
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		## move all the contents using shutil.move()
		mvfiles = os.listdir(tmpdir2 + "/squashfs-root")
		for f in mvfiles:
			shutil.move(tmpdir2 + "/squashfs-root/" + f, tmpdir)
		## then we cleanup the temporary dir
		shutil.rmtree(tmpdir2)
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

## squashfs 4.2, various compression methods
def unpackSquashfs42(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	p = subprocess.Popen(['bat-unsquashfs42', '-d', tmpdir, '-f', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		## unlike with 'normal' squashfs we can't always use 'file' to determine the size
		squashsize = 1
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return (tmpdir, squashsize)

## generic function for all kinds of squashfs+lzma variants that were copied
## from slax.org and then adapted and that are slightly different, but not that
## much.
def unpackSquashfsWithLZMA(data, offset, command, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	p = subprocess.Popen([command, '-d', tmpdir, '-f', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		## unlike with 'normal' squashfs we can't use 'file' to determine the size
		## This could lead to duplicate scanning with LZMA, so we might need to implement
		## a top level "pruning" script :-(
		squashsize = 1
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return (tmpdir, squashsize)
	pass

## squashfs variant from Atheros, with LZMA
def unpackSquashfsAtherosLZMA(data, offset, tempdir=None):
	return unpackSquashfsWithLZMA(data, offset, "bat-unsquashfs-atheros", tempdir)

## squashfs variant from Ralink, with LZMA
def unpackSquashfsRalinkLZMA(data, offset, tempdir=None):
	return unpackSquashfsWithLZMA(data, offset, "bat-unsquashfs-ralink", tempdir)

## squashfs variant from Broadcom, with LZMA
def unpackSquashfsBroadcomLZMA(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	## since unsquashfs can't deal with data via stdin first write it to
	## a temporary location
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	p = subprocess.Popen(['bat-unsquashfs-broadcom', '-d', tmpdir, '-f', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	else:
		## we first need to check the contents of stderr to see if uncompression actually worked
		## This could lead to duplicate scanning with LZMA, so we might need to implement
		## a top level "pruning" script :-(
		if "LzmaUncompress: error" in stanerr:
			os.fdopen(tmpfile[0]).close()
			os.unlink(tmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return None
		## unlike with 'normal' squashfs we can't use 'file' to determine the size
		squashsize = 1
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		return (tmpdir, squashsize)

## We use tune2fs to get the size of the file system so we know what to
## blacklist.
def searchUnpackExt2fs(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['ext2'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	diroffsets = []
	counter = 1

	## set path for Debian
	unpackenv = os.environ
	unpackenv['PATH'] = unpackenv['PATH'] + ":/sbin"

	for offset in offsets['ext2']:
		## according to /usr/share/magic the magic header starts at 0x438
		if offset < 0x438:
			continue
		## check if the offset we find is in a blacklist
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "ext2", counter)
		## we should actually scan the data starting from offset - 0x438
		datafile.seek(offset - 0x438)
		ext2checkdata = datafile.read(4096)
		if not checkExt2fs(ext2checkdata, 0, tmpdir):
			os.rmdir(tmpdir)
			continue
		res = unpackExt2fs(filename, offset - 0x438, tmpdir)
		if res != None:
			(ext2tmpdir, ext2size) = res
			diroffsets.append((ext2tmpdir, offset - 0x438))
			## this needs to be moved to unpackExt2fs, since it fails if 'filename' contains
			## an ext2 file system, but has data prepended.
			p = subprocess.Popen(['tune2fs', '-l', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=unpackenv)
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
					counter = counter + 1
				else:
					os.rmdir(tmpdir)
			else:
				os.rmdir(tmpdir)
		else:
			os.rmdir(tmpdir)
	datafile.close()
	return (diroffsets, blacklist, offsets)

def checkExt2fs(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
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
def unpackExt2fs(filename, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	if offset != 0:
		p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile[1],), 'bs=%s' % (offset,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	## if we need to the whole file we might as well just copy it directly
	else:
		shutil.copy(filename, tmpfile[1])
	ext2.copyext2fs(tmpfile[1], tmpdir)
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	ext2size = 0
	return (tmpdir, ext2size)

## tries to unpack stuff using zcat. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
def unpackGzip(filename, offset, tempdir=None):
	## Assumes (for now) that zcat is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.fdopen(tmpfile[0]).close()
	## use dd. This really pays off when using large files.
	if offset != 0:
		p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile[1],), 'bs=%s' % (offset,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	## if we need to the whole file we might as well just copy it directly
	else:
		shutil.copy(filename, tmpfile[1])

	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	p = subprocess.Popen(['zcat', tmpfile[1]], stdout=outtmpfile[0], stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if os.stat(outtmpfile[1]).st_size == 0:
		os.unlink(outtmpfile[1])
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	os.unlink(tmpfile[1])
	return tmpdir

def searchUnpackGzip(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['gzip'] == []:
		return ([], blacklist, offsets)

	## counter to remember how many gzip file systems we have
	## discovered, so we can use this to append to the directory
	## name containing the unpacked contents.
	counter = 1
	diroffsets = []
	for offset in offsets['gzip']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "gzip", counter)
		res = unpackGzip(filename, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

## tries to unpack stuff using bzcat. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
## We use bzcat instead of the bz2 module because that can't handle trailing
## data very well.
def unpackBzip2(filename, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that bzcat is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)

	if offset != 0:
		p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile[1],), 'bs=%s' % (offset,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	## if we need to the whole file we might as well just copy it directly
	else:
		shutil.copy(filename, tmpfile[1])

	#p = subprocess.Popen(['bzcat', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	p = subprocess.Popen(['bzcat', tmpfile[1]], stdout=outtmpfile[0], stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
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

def searchUnpackBzip2(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['bz2'] == []:
		return ([], blacklist, offsets)

	diroffsets = []
	counter = 1
	for offset in offsets['bz2']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "bzip2", counter)
		res = unpackBzip2(filename, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackZip(data, offset, filename, tempdir=None):
	tmpdir = unpacksetup(tempdir)

	tmpfile = tempfile.mkstemp(dir=tempdir)

	os.write(tmpfile[0], data[offset:])
	os.fdopen(tmpfile[0]).close()

	## First we do some sanity checks

	## Use information from zipinfo -v to extract the right offset (or at least the last offset,
	## which is the only one we are interested in)
	p = subprocess.Popen(['zipinfo', '-v', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()

	## check if the file is encrypted, if so, we need to bail out
	res = re.search("file security status:\s+(\w*)\sencrypted", stanout)
	if res == None:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)

	if res.groups(0)[0] != 'not':
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)

	## we have a non-encrypted file, so we can continue processing it
	res = re.search("Actual[\w\s]*end-(?:of-)?cent(?:ral)?-dir record[\w\s]*:\s*(\d+) \(", stanout)
	if res != None:
		endofcentraldir = int(res.groups(0)[0])
	else:
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return (None, None)

	if "extra bytes at beginning or within zipfile" in stanerr:
		multidata = data[offset:]
		multicounter = 1
		## first unpack the original file.
		multitmpdir = "/%s/%s-multi-%s" % (tmpdir, os.path.basename(filename), multicounter)
		os.makedirs(multitmpdir)
		p = subprocess.Popen(['unzip', '-o', tmpfile[1], '-d', multitmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanoutzip, stanerrzip) = p.communicate()
		if p.returncode != 0 and p.returncode != 1:
			## this is just weird! We were told that we have a zip file by zipinfo, but we can't unzip?
			#shutil.rmtree(multitmpdir)
			pass
		multicounter = multicounter + 1
		zipoffset = int(re.search("(\d+) extra bytes at beginning or within zipfile", stanerr).groups()[0])
		while zipoffset != 0:
			multitmpdir = "/%s/%s-multi-%s" % (tmpdir, os.path.basename(filename), multicounter)
			os.makedirs(multitmpdir)
			multitmpfile = tempfile.mkstemp(dir=tmpdir)
			os.write(multitmpfile[0], multidata[:zipoffset])
			os.fdopen(multitmpfile[0]).close()
			p = subprocess.Popen(['unzip', '-o', multitmpfile[1], '-d', multitmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanoutzip, stanerrzip) = p.communicate()
			if p.returncode != 0 and p.returncode != 1:
				## this is just weird! We were told that we have a zip file by zipinfo, but we can't unzip?
				## hackish workaround: get 'end of central dir', add 100 bytes, and try to unpack. Actually
				## we should do this in a loop until we can either successfully unpack or reach the end of
				## the file.
				p2 = subprocess.Popen(['zipinfo', '-v', multitmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanoutzip, stanerrzip) = p2.communicate()
				res = re.search("Actual[\w\s]*end-(?:of-)?cent(?:ral)?-dir record[\w\s]*:\s*(\d+) \(", stanoutzip)
				if res != None:
					tmpendofcentraldir = int(res.groups(0)[0])
					newtmpfile = open(multitmpfile[1], 'w')
					newtmpfile.write(multidata[:tmpendofcentraldir+100])
					newtmpfile.close()
					p3 = subprocess.Popen(['unzip', '-o', newtmpfile.name, '-d', multitmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
					(stanoutzip, stanerrzip) = p3.communicate()
				else:
					## need to do something here, unsure yet what
					pass
			p = subprocess.Popen(['zipinfo', '-v', multitmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanoutzip, stanerrzip) = p.communicate()
			if not "extra bytes at beginning or within zipfile" in stanerrzip:
				os.unlink(multitmpfile[1])
				break
			zipoffset = int(re.search("(\d+) extra bytes at beginning or within zipfile", stanerrzip).groups()[0])
			os.unlink(multitmpfile[1])
			multicounter = multicounter + 1
	else:
		p = subprocess.Popen(['unzip', '-o', tmpfile[1], '-d', tmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0 and p.returncode != 1:
			os.unlink(tmpfile[1])
			if tempdir == None:
				os.rmdir(tmpdir)
			return (None, None)
	os.unlink(tmpfile[1])
	return (endofcentraldir, tmpdir)

def searchUnpackZip(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['zip'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	diroffsets = []
	counter = 1
	data = datafile.read()
	datafile.close()
	endofcentraldir_offset = 0
	for offset in offsets['zip']:
		if offset < endofcentraldir_offset:
			continue
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "zip", counter)
		(endofcentraldir, res) = unpackZip(data, offset, filename, tmpdir)
		if res != None:
			diroffsets.append((res, offset))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
		if endofcentraldir != None:
			endofcentraldir_offset = endofcentraldir
			blacklist.append((offset, offset + endofcentraldir))
	return (diroffsets, blacklist, offsets)

def searchUnpackRar(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['rar'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	diroffsets = []
	counter = 1
	data = datafile.read()
	datafile.close()
	for offset in offsets['rar']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "rar", counter)
		res = unpackRar(data, offset, tmpdir)
		if res != None:
			(endofarchive, rardir) = res
			diroffsets.append((rardir, offset))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackRar(data, offset, tempdir=None):
	## Assumes (for now) that unrar is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])

	# inspect the rar archive, and retrieve the end of archive
	# this way we won't waste too many resources when we don't need to
	p = subprocess.Popen(['unrar', 'vt', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	rarstring = stanout.strip().split("\n")[-1]
	res = re.search("\s*\d+\s*\d+\s+(\d+)\s+\d+%", rarstring)
	if res != None:
		endofarchive = int(res.groups(0)[0]) + offset
	else:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	p = subprocess.Popen(['unrar', 'x', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
	(stanout, stanerr) = p.communicate()
	## oh the horror, we really need to check if unrar actually was successful
	#outtmpfile = tempfile.mkstemp(dir=tmpdir)
	#os.write(outtmpfile[0], stanout)
	#if os.stat(outtmpfile[1]).st_size == 0:
		#os.unlink(outtmpfile[1])
		#os.unlink(tmpfile[1])
		#return None
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return (endofarchive, tmpdir)

def searchUnpackLZMA(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	lzmaoffsets = []
	for marker in fsmagic.lzmatypes:
		lzmaoffsets = lzmaoffsets + offsets[marker]
	if lzmaoffsets == []:
		return ([], blacklist, offsets)
	diroffsets = []
	counter = 1
	for offset in lzmaoffsets:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "lzma", counter)
		res = unpackLZMA(filename, offset, tmpdir)
		if res != None:
			diroffsets.append((res, offset))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

## tries to unpack stuff using lzma -cd. If it is successful, it will
## return a directory for further processing, otherwise it will return None.
## With XZ Utils >= 5.0.0 we should be able to use the -l option for integrity
## testing. It will not be faster, but probably more accurate.
## This would require Fedora 15 or later (not sure about which Ubuntu).
def unpackLZMA(filename, offset, tempdir=None):
	## first unpack things, write things to a file and return
	## the directory if the file is not empty
	## Assumes (for now) that lzma is in the path
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
        ## use dd. This really pays off when using large files.
	if offset != 0:
		p = subprocess.Popen(['dd', 'if=%s' % (filename,), 'of=%s' % (tmpfile[1],), 'bs=%s' % (offset,), 'skip=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	## if we need to the whole file we might as well just copy it directly
	else:
		shutil.copy(filename, tmpfile[1])
	outtmpfile = tempfile.mkstemp(dir=tmpdir)
	p = subprocess.Popen(['lzma', '-cd', tmpfile[1]], stdout=outtmpfile[0], stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
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

## Search and unpack Ubifs. Since we can't easily determine the length of the
## file system by using ubifs we will have to use a different measurement to
## measure the size of ubifs. A good start is the sum of the size of the
## volumes that were unpacked.
def searchUnpackUbifs(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['ubifs'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	## We can use the values of offset and ubisize where offset != -1
	## to determine the ranges for the blacklist.
	diroffsets = []
	counter = 1
	data = datafile.read()
	datafile.close()
	for offset in offsets['ubifs']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "ubifs", counter)
		res = unpackUbifs(data, offset, tmpdir)
		if res != None:
			(ubitmpdir, ubisize) = res
			diroffsets.append((ubitmpdir, offset))
			## TODO use ubisize to make set the blacklist correctly
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackUbifs(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
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
## useful information like the actual offset that is used for reporting and
## blacklisting.
## WARNING: this method is very costly. Since ARJ is not used on many Unix
## systems it is advised to not enable it when scanning binaries intended for
## these systems.
def searchUnpackARJ(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['arj'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	diroffsets = []
	counter = 1
	data = datafile.read()
	datafile.close()
	for offset in offsets['arj']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "arj", counter)
		res = unpackARJ(data, offset, tmpdir)
		if res != None:
			(arjtmpdir, arjsize) = res
			diroffsets.append((arjtmpdir, offset))
			blacklist.append((offset, arjsize))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackARJ(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
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

## extraction of Windows .ICO files. The identifier for .ICO files is very
## common, so on large files this will have a rather big performance impact
## with relatively little gain. In the default distribution of BAT this scan
## is therefore disabled.
def searchUnpackIco(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['ico'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	diroffsets = []
	counter = 1
	data = datafile.read()
	datafile.close()
	for offset in offsets['ico']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		tmpdir = dirsetup(tempdir, filename, "ico", counter)
		res = unpackIco(data, offset, tmpdir)
		if res != None:
			icotmpdir = res
			diroffsets.append((icotmpdir, offset))
			counter = counter + 1
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, offsets)

def unpackIco(data, offset, tempdir=None):
	tmpdir = unpacksetup(tempdir)
	tmpfile = tempfile.mkstemp(dir=tmpdir)
	os.write(tmpfile[0], data[offset:])
	p = subprocess.Popen(['icotool', '-x', '-o', tmpdir, tmpfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()

	if p.returncode != 0 or "no images matched" in stanerr:
		os.fdopen(tmpfile[0]).close()
		os.unlink(tmpfile[1])
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	## clean up the temporary files
	os.fdopen(tmpfile[0]).close()
	os.unlink(tmpfile[1])
	return tmpdir

###
## The scans below are scans that are used to extract files from bigger binary
## blobs, but they should not be recursively applied to their own results,
## because that results in endless loops.
###

## http://en.wikipedia.org/wiki/Graphics_Interchange_Format
## 1. search for a GIF header
## 2. search for a GIF trailer
## 3. check the data with gifinfo
def searchUnpackGIF(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	gifoffsets = []
	for marker in fsmagic.gif:
		gifoffsets = gifoffsets + offsets[marker]
	if gifoffsets == []:
		return ([], blacklist, offsets)

	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()

	## GIF files have a trailer. We search for them here, since it is very very
	## generic character. It would cost too many resources to also for these
	## in all cases.
	traileroffsets = []
	trailer = data.find(';', gifoffsets[0])
	while(trailer != -1):
		traileroffsets.append(trailer)
		trailer = data.find(';',trailer+1)
	if traileroffsets == []:
		return ([], blacklist, offsets)

	diroffsets = []
	counter = 1

	for i in range (0,len(gifoffsets)):
		offset = gifoffsets[i]
		if i < len(gifoffsets) - 1:
			nextoffset = gifoffsets[i+1]
		else:
			nextoffset = len(data)
		## first check if we're not blacklisted for the header
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		## we're only interested in the trailers that are bigger than the offset
		traileroffsets = filter(lambda x: x>=offset, traileroffsets)
		for trail in traileroffsets:
			if trail <= offset:
				continue
			## There is no trailer before the next header, so this can't be correct.
			## This breaks apart if by any chance one of the identifiers is in the 
			## file as normal data. Chances for that are very very low.
			if trail >= nextoffset:
				break
			## check if we're not blacklisted for the trailer
			blacklistoffset = extractor.inblacklist(trail, blacklist)
			if blacklistoffset != None:
				continue
			tmpdir = dirsetup(tempdir, filename, "gif", counter)
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
					blacklist.append((0, os.stat(filename).st_size))
					return (diroffsets, blacklist, offsets)
				else:
					diroffsets.append((tmpdir, offset))
					counter = counter + 1
					## go to the next header
					break
	return (diroffsets, blacklist, offsets)

## JPEG extraction can be tricky according to /usr/share/magic, so this is
## not fool proof.
def searchUnpackJPEG(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	## first search for JFIF, then search for Exif, then search for plain
	## JPEG and take the minimum value.
	## Only do JFIF for now
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	#print fssearch.findJFIF(data,0)
	return ([], blacklist, offsets)

## PNG extraction is similar to GIF extraction, except there is a way better
## defined trailer.
def searchUnpackPNG(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	if offsets['png'] == []:
		return ([], blacklist, offsets)
	if offsets['pngtrailer'] == []:
		return ([], blacklist, offsets)
	datafile = open(filename, 'rb')
	diroffsets = []
	headeroffsets = offsets['png']
	traileroffsets = offsets['pngtrailer']
	counter = 1
	data = datafile.read()
	datafile.close()
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
			tmpdir = dirsetup(tempdir, filename, "png", counter)
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
					counter = counter + 1
					break
	return (diroffsets, blacklist, offsets)

## EXIF is (often) prepended to the actual image data
## Having access to EXIF data can also (perhaps) get us useful data
def searchUnpackEXIF(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	return ([],blacklist, offsets)

## sometimes Ogg audio files are embedded into binary blobs
def searchUnpackOgg(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	datafile = open(filename, 'rb')
	data = datafile.read()
	datafile.close()
	return ([], blacklist, offsets)

## sometimes MP3 audio files are embedded into binary blobs
def searchUnpackMP3(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	return ([], blacklist, offsets)
