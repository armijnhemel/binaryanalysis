#!/usr/bin/python
# -*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Program to process a whole directory full of compressed source code archives
to create simple manifest files that list checksums of every individual file
in an archive. This is to speed up scanning of archives when rebuilding the
BAT database.

Needs a file LIST in the directory it is passed as a parameter, which has the
following format:

package version filename origin

separated by whitespace

Compression is determined using magic
'''

import sys, os, magic, string, re, subprocess, shutil, stat
import tempfile, bz2, tarfile, gzip, hashlib, zlib
from optparse import OptionParser
from multiprocessing import Pool

tarmagic = ['POSIX tar archive (GNU)'
           , 'tar archive'
           ]

ms = magic.open(magic.MAGIC_NONE)
ms.load()

## unpack the directories to be scanned.
def unpack(directory, filename, unpackdir):
	try:
		os.stat(os.path.join(directory, filename))
	except:
		print >>sys.stderr, "Can't find %s" % filename
		return None

        filemagic = ms.file(os.path.realpath(os.path.join(directory, filename)))

        ## Assume if the files are bz2 or gzip compressed they are compressed tar files
        if 'bzip2 compressed data' in filemagic:
		if unpackdir != None:
       			tmpdir = tempfile.mkdtemp(dir=unpackdir)
		else:
       			tmpdir = tempfile.mkdtemp()
		## for some reason the tar.bz2 unpacking from python doesn't always work, like
		## aeneas-1.0.tar.bz2 from GNU, so use a subprocess instead of using the
		## Python tar functionality.
 		p = subprocess.Popen(['tar', 'jxf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			shutil.rmtree(tmpdir)
			return
		return tmpdir
	elif 'LZMA compressed data, streamed' in filemagic:
		if unpackdir != None:
       			tmpdir = tempfile.mkdtemp(dir=unpackdir)
		else:
       			tmpdir = tempfile.mkdtemp()
		p = subprocess.Popen(['tar', 'ixf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		return tmpdir
        elif 'XZ compressed data' in filemagic:
		if unpackdir != None:
       			tmpdir = tempfile.mkdtemp(dir=unpackdir)
		else:
       			tmpdir = tempfile.mkdtemp()
 		p = subprocess.Popen(['tar', 'Jxf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		return tmpdir
        elif 'gzip compressed data' in filemagic:
		if unpackdir != None:
       			tmpdir = tempfile.mkdtemp(dir=unpackdir)
		else:
       			tmpdir = tempfile.mkdtemp()
 		p = subprocess.Popen(['tar', 'zxf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		return tmpdir
	elif 'Zip archive data' in filemagic:
		try:
			if unpackdir != None:
       				tmpdir = tempfile.mkdtemp(dir=unpackdir)
			else:
       				tmpdir = tempfile.mkdtemp()
			p = subprocess.Popen(['unzip', "-B", os.path.join(directory, filename), '-d', tmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0 and p.returncode != 1:
				print >>sys.stderr, "unpacking ZIP failed for", filename, stanerr
				shutil.rmtree(tmpdir)
				pass
			else:
				return tmpdir
		except Exception, e:
			print >>sys.stderr, "unpacking ZIP failed", e

def grabhash(filedir, filename, filehash, pool, extrahashes, temporarydir):
	## unpack the archive. If it fails, cleanup and return.
	temporarydir = unpack(filedir, filename, temporarydir)
	if temporarydir == None:
		return None

	print "processing", filename
	sys.stdout.flush()

	## add 1 to deal with /
	lenunpackdir = len(temporarydir) + 1

	osgen = os.walk(temporarydir)

	try:
		scanfiles = []
		while True:
			i = osgen.next()
			## make sure all directories can be accessed
			for d in i[1]:
				if not os.path.islink(os.path.join(i[0], d)):
					os.chmod(os.path.join(i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			for p in i[2]:
				scanfiles.append((i[0], p, extrahashes))
	except Exception, e:
		if str(e) != "":
			print >>sys.stderr, e

	## compute the hashes in parallel
	scanfile_result = filter(lambda x: x != None, pool.map(computehash, scanfiles, 1))
	cleanupdir(temporarydir)
	scanfile_result = map(lambda x: (x[0][lenunpackdir:],) +  x[1:], scanfile_result)
	return scanfile_result

def cleanupdir(temporarydir):
	osgen = os.walk(temporarydir)
	try:
		while True:
			i = osgen.next()
			## make sure all directories can be accessed
			for d in i[1]:
				if not os.path.islink(os.path.join(i[0], d)):
					os.chmod(os.path.join(i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			for p in i[2]:
				try:
					if not os.path.islink(os.path.join(i[0], p)):
						os.chmod(os.path.join(i[0], p), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
				except Exception, e:
					#print e
					pass
	except StopIteration:
		pass
	try:
		shutil.rmtree(temporarydir)
	except:
		## nothing that can be done right now, so just give up
		pass

def computehash((path, filename, extrahashes)):
	resolved_path = os.path.join(path, filename)
	if not os.path.isfile(resolved_path):
		## filter out fifo and pipe
		return None
	try:
		if not os.path.islink(resolved_path):
			os.chmod(resolved_path, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
	except Exception, e:
		pass
	## skip links
	if os.path.islink(resolved_path):
        	return None
	filehashes = {}
	scanfile = open(resolved_path, 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	filehashes['sha256'] = h.hexdigest()
	for i in extrahashes:
		scanfile = open(resolved_path, 'r')
		if i == 'crc32':
			crcdata = scanfile.read()
			filehashes[i] = zlib.crc32(crcdata) & 0xffffffff
		else:
			h = hashlib.new(i)
			h.update(scanfile.read())
			filehashes[i] = h.hexdigest()
		scanfile.close()
	return (path, filename, filehashes)

def checkalreadyscanned((filedir, filename, checksum)):
	resolved_path = os.path.join(filedir, filename)
	try:
		os.stat(resolved_path)
	except:
		print >>sys.stderr, "Can't find %s" % filename
		return None
	if checksum != None:
		filehash = checksum
	else:
		scanfile = open(resolved_path, 'r')
		h = hashlib.new('sha256')
		h.update(scanfile.read())
		scanfile.close()
		filehash = h.hexdigest()
	return (filename, filehash)

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-u", "--update", action="store_true", dest="update", help="only create manifest files for new archives")
	parser.add_option("-t", "--temporarydir", action="store", dest="unpackdir", help="set unpacking directory (default: /tmp)", metavar="DIR")

	(options, args) = parser.parse_args()
	if options.filedir == None:
		parser.error("Specify dir with files")
	else:
		try:
			filelist = open(os.path.join(options.filedir,"LIST")).readlines()
		except:
			parser.error("'LIST' not found in file dir")

	if options.unpackdir != None:
		if not os.path.exists(options.unpackdir):
			parser.error("temporary unpacking directory '%s' does not exist" % options.unpackdir)

	options.unpackdir = '/ramdisk'

	pool = Pool()

	pkgmeta = []

	checksums = {}
	if os.path.exists(os.path.join(options.filedir, "SHA256SUM")):
		checksumlines = open(os.path.join(options.filedir, "SHA256SUM")).readlines()
		for c in checksumlines[1:]:
			checksumsplit = c.strip().split()
			if len(checksumsplit) < 2:
				continue
			archivefilename = checksumsplit[0]
			archivechecksum = checksumsplit[1]
			checksums[archivefilename] = archivechecksum

	extrahashes = ['md5', 'sha1', 'crc32']

	for unpackfile in filelist:
		try:
			unpacks = unpackfile.strip().split()
			if len(unpacks) == 4:
				(package, version, filename, origin) = unpacks
				batarchive = False
			else:
				(package, version, filename, origin, bat) = unpacks
				if bat == 'batarchive':
					batarchive = True
				else:
					batarchive = False
			pkgmeta.append((options.filedir, filename, checksums[filename]))
		except Exception, e:
			# oops, something went wrong
			print >>sys.stderr, e
	res = filter(lambda x: x != None, pool.map(checkalreadyscanned, pkgmeta, 1))

	processed_hashes = set()
	manifestdir = os.path.join(options.filedir, "MANIFESTS")
	if os.path.exists(manifestdir) and os.path.isdir(manifestdir):
		outputdir = manifestdir
	else:
		outputdir = "/tmp"

	print "outputting hashes to %s" % outputdir
	sys.stdout.flush()

	uniquehashes = set()
	for r in res:
		(filename, filehash) = r
		if filehash in uniquehashes:
			continue
		uniquehashes.add(filehash)
		if options.update and os.path.exists(os.path.join(outputdir, "%s.bz2" % filehash)):
			continue
		unpackres = grabhash(options.filedir, filename, filehash, pool, extrahashes, options.unpackdir)
		if unpackres == None:
			continue
		## first write the scanned/supported hashes, in the order in which they
		## appear for each file
		manifest = os.path.join(outputdir, "%s.bz2" % filehash)
		manifestfile = bz2.BZ2File(manifest, 'w')
		if extrahashes == []:
			manifestfile.write("sha256\n")
		else:
			hashesstring = "sha256"
			for h in extrahashes:
				hashesstring += "\t%s" % h
			manifestfile.write("%s\n" % hashesstring)
		for u in unpackres:
			if extrahashes == []:
				manifestfile.write("%s\t%s\n" % (os.path.join(u[0], u[1]), u[2]['sha256']))
			else:
				hashesstring = "%s" % u[2]['sha256']
				for h in extrahashes:
					hashesstring += "\t%s" % u[2][h]
				manifestfile.write("%s\t%s\n" % (os.path.join(u[0], u[1]), hashesstring))
		manifestfile.close()
	pool.terminate()
	print "%d hashes were written to %s" % (len(uniquehashes), outputdir)
	sys.stdout.flush()

if __name__ == "__main__":
    main(sys.argv)
