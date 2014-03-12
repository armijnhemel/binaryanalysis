#!/usr/bin.python

## Binary Analysis Tool
## Copyright 2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Script to test integrity of archives. TODO: properly handle ZIP archives
'''

import sys, os, magic, multiprocessing, subprocess
import tempfile, bz2, tarfile, gzip
from optparse import OptionParser

tarmagic = ['POSIX tar archive (GNU)'
           , 'tar archive'
           ]

ms = magic.open(magic.MAGIC_NONE)
ms.load()

## unpack the directories to be scanned.
def unpack((directory, filename)):
	try:
		os.stat(os.path.join(directory, filename))
	except:
		print >>sys.stderr, "Can't find %s" % filename
		return None

	filemagic = ms.file(os.path.realpath(os.path.join(directory, filename)))

	## Assume if the files are bz2 or gzip compressed they are compressed tar files
	if 'bzip2 compressed data' in filemagic:
		## for some reason the tar.bz2 unpacking from python doesn't always work, like
		## aeneas-1.0.tar.bz2 from GNU, so use a subprocess instead of using the
		## Python tar functionality.
		p = subprocess.Popen(['tar', 'jtf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	elif 'LZMA compressed data, streamed' in filemagic:
		p = subprocess.Popen(['tar', 'itf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	elif 'XZ compressed data' in filemagic:
		p = subprocess.Popen(['tar', 'itf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	elif 'gzip compressed data' in filemagic:
		p = subprocess.Popen(['tar', 'ztf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	elif 'compress\'d data 16 bits' in filemagic:
		p = subprocess.Popen(['tar', 'ztf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	elif 'Minix filesystem' in filemagic and filename.endswith('.gz'):
		## sometimes libmagic gets it wrong
		p = subprocess.Popen(['tar', 'ztf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
	else:
		return None
	if p.returncode != 0:
		return (filename, False)
	else:
		return (filename, True)
	'''
	elif 'Zip archive data' in filemagic:
		try:
			tmpdir = tempfile.mkdtemp(dir=unpackdir)
			p = subprocess.Popen(['unzip', "-B", os.path.join(directory, filename), '-d', tmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0 and p.returncode != 1:
				print >>sys.stderr, "unpacking ZIP failed for", filename, stanerr
				shutil.rmtree(tmpdir)
			else:
				return tmpdir
		except Exception, e:
			print >>sys.stderr, "unpacking ZIP failed", e
	'''

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")

	(options, args) = parser.parse_args()
	if options.filedir == None:
		parser.error("Specify dir with files")
	else:
		try:
			filelist = open(os.path.join(options.filedir, "LIST")).readlines()
		except:
			parser.error("'LIST' not found in file dir")

	## first process the LIST file
	pkgmeta = []
	for unpackfile in filelist:
		try:
			unpacks = unpackfile.strip().split()
			if len(unpacks) == 3:
				origin = "unknown"
				(package, version, filename) = unpacks
			else:
				(package, version, filename, origin) = unpacks
			pkgmeta.append((options.filedir, filename))
		except Exception, e:
			# oops, something went wrong
			print >>sys.stderr, e

	pool = multiprocessing.Pool()
	unpackresults = pool.map(unpack, pkgmeta)
	pool.terminate()
	for i in unpackresults:
		if i != None:
			(filename, result) = i
			if not result:
				print "corrupt archive: %s" % filename

if __name__ == "__main__":
	main(sys.argv)
