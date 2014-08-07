#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Script to copy BAT archive files efficiently. Takes three arguments:

1. directory with 'original' archives (used to create the BAT archives)
2. directory with BAT archives
3. target directory where to copy BAT archives to

It is very important that 1. is the same directory as used to generate the BAT archives
'''

import sys, os, re, subprocess, shutil, stat
from optparse import OptionParser
from multiprocessing import Pool

def main(argv):
	parser = OptionParser()
	parser.add_option("-a", "--archivedir", action="store", dest="archivedir", help="path to directory with BAT archives", metavar="DIR")
	parser.add_option("-o", "--origdir", action="store", dest="origdir", help="directory with original archives", metavar="DIR")
	parser.add_option("-t", "--targetdir", action="store", dest="targetdir", help="target directory", metavar="DIR")
	(options, args) = parser.parse_args()

	if options.archivedir == None:
		parser.error("specify archivedir")
	else:
		try:
			archivelist = open(os.path.join(options.archivedir,"ARCHIVELIST")).readlines()
		except:
			parser.error("'ARCHIVELIST' not found in file dir")
	if options.origdir == None:
		parser.error("specify origdir")
	else:
		try:
			filelist = open(os.path.join(options.origdir,"LIST")).readlines()
		except:
			parser.error("'LIST' not found in file dir")


	archives = os.listdir(options.archivedir)
	archivenames = set()
	for a in archives:
		asplits = a.rsplit('.', 2)
		if len(asplits) != 3:
			continue
		if asplits[2] != 'bz2':
			continue
		if asplits[1] != 'tar':
			continue
		if not 'bat' in asplits[0]:
			continue
		archivenames.add(a)
		
	if options.targetdir == None:
		parser.error("specify targetdir")
	else:
		if not os.path.exists(options.targetdir):
			parser.error("targetdir does not exist")

	copyfromarchives = set()
	copyfromorig = set()
	archivetometa = {}

	for unpackfile in filelist:
		try:
			unpacks = unpackfile.strip().split()
			if len(unpacks) == 4:
				(package, version, filename, origin) = unpacks
				if '%s-%s-%s-bat.tar.bz2' % (package, version, origin) in archivenames:
					copyfromarchives.add('%s-%s-%s-bat.tar.bz2' % (package, version, origin))
					archivetometa['%s-%s-%s-bat.tar.bz2' % (package, version, origin)] = (version, origin)
				else:
					copyfromorig.add(filename)
		except:
			pass

	print "copying %d archives" % len(copyfromarchives)
	for i in copyfromarchives:
		shutil.copy(os.path.join(options.archivedir, i), options.targetdir)
	print "copying %d original files" % len(copyfromorig)
	for i in copyfromorig:
		shutil.copy(os.path.join(options.origdir, i), options.targetdir)
	print "copying manifests"
	if os.path.exists(os.path.join(options.origdir, 'MANIFESTS')):
		os.mkdir(os.path.join(options.targetdir, 'MANIFESTS'))
		manifests = os.listdir(os.path.join(options.origdir, 'MANIFESTS'))
		for i in manifests:
			shutil.copy(os.path.join(options.origdir, 'MANIFESTS', i), os.path.join(options.targetdir, 'MANIFESTS'))
	if os.path.exists(os.path.join(options.archivedir, 'MANIFESTS')):
		manifests = os.listdir(os.path.join(options.archivedir, 'MANIFESTS'))
		for i in manifests:
			shutil.copy(os.path.join(options.archivedir, 'MANIFESTS', i), os.path.join(options.targetdir, 'MANIFESTS'))
	print "copying checksums"
	if os.path.exists(os.path.join(options.origdir, 'SHA256SUM')):
		shutil.copy(os.path.join(options.origdir, 'SHA256SUM'), options.targetdir)
	#if os.path.exists(os.path.join(options.origdir, 'SHA256SUM')):
		#sha256sums = open(os.path.join(options.origdir, 'SHA256SUM')).readlines()
	#if os.path.exists(os.path.join(options.archivedir, 'SHA256SUM')):
		#sha256sums = open(os.path.join(options.archivedir, 'SHA256SUM')).readlines()

	print "writing LIST"
	newlistfile = open(os.path.join(options.targetdir, "LIST"), 'wb')
	## walk the original LIST file and write lines for the files for which there are no archives
	for f in filelist:
		unpacks = f.strip().split()
		filename = unpacks[2]
		if filename in copyfromorig:
			newlistfile.write(f)
	## then walk the list for archives
	for f in archivelist:
		archivename = f.strip()
		if archivename in copyfromarchives:
			(version, origin) = archivetometa[archivename]
			newlistfile.write("%s\t%s\t%s\t%s\tbatarchive\n" % (archivename[:-12], version, origin, archivename))
	newlistfile.close()

if __name__ == "__main__":
	main(sys.argv)
