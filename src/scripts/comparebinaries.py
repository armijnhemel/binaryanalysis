#!/usr/bin/python

import sys, os, os.path, hashlib, subprocess, tempfile, magic, multiprocessing
from optparse import OptionParser
try:
	import tlsh
	tlshscanning = True
except:
	tlshscanning = False

## Binary Analysis Tool
## Copyright 2013-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This program compares two binaries (firmwares, files, etc.) in various ways to
see how close they are.

There are a few scenarios where this program can be used:

1. comparing an old firmware (that is already known and which has been verified)
to a new firmware (update) and see if there are any big differences.
2. comparing a firmware to a rebuild of a firmware as part of compliance
engineering
3. comparing two binaries to see if a certain security bug might be present

A few assumptions are made:

1. both firmwares were unpacked using the Binary Analysis Tool
2. files that are in the original firmware, but not in the new firmware, are
not reported (example: removed binaries). This might change in a future version.
3. files that are in the new firmware but not not in the original firmware are
reported, since this would mean additions to the firmware, possibly with
license conditions or security concerns.
4. files that appear in both firmwares but which are not identical are checked
using bsdiff and, if available, tlsh.

With just checksums it is easy to find the files that are different. Using BSDIFF
and tlsh it becomes easier to see how big the difference really is.

Low values are probably not interesting at all:
* time stamps (BusyBox, Linux kernel, etc. record a time stamp in the binary)
* slightly different compiler settings

If the diffs get larger there are of course bigger changes.

This approach will make it easier to make a baseline scan of a firmware, then
find, prioritize and scan only the differences in an update of the firmware.
'''

## copied from bruteforce.py
def gethash(path, filename):
	scanfile = open("%s/%s" % (path, filename), 'r')
	h = hashlib.new('sha256')
	scanfile.seek(0)
	hashdata = scanfile.read(10000000)
	while hashdata != '':
		h.update(hashdata)
		hashdata = scanfile.read(10000000)
	scanfile.close()
	return h.hexdigest()

## method to compare binaries. Returns the amount of bytes that differ
## according to bsdiff, or 0 if the files are identical
def comparebinaries(path1, path2):
	basepath1 = os.path.basename(path1)
	dirpath1 = os.path.dirname(path1)
	basepath2 = os.path.basename(path2)
	dirpath2 = os.path.dirname(path2)
	## binaries are identical
	if gethash(dirpath1, basepath1) == gethash(dirpath2, basepath2):
		return 0
	difftmp = tempfile.mkstemp()
	os.fdopen(difftmp[0]).close()
	p = subprocess.Popen(["bsdiff", path1, path2, difftmp[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	## cleanup
	(stanout, stanerr) = p.communicate()
	diffsize = os.stat(difftmp[1]).st_size
	os.unlink(difftmp[1])
	return diffsize

def main(argv):
	parser = OptionParser()
	parser.add_option("-n", "--new", action="store", dest="newdir", help="path to BAT results of new binary", metavar="DIR")
	parser.add_option("-o", "--original", action="store", dest="olddir", help="path to BAT results of original binary", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.olddir == None or options.newdir == None:
		parser.error("Supply paths to both directories")

	if not os.path.exists(options.olddir):
		parser.error("Directory \"%s\" does not exist" % (options.olddir,))

	if not os.path.exists(options.newdir):
		parser.error("Directory \"%s\" does not exist" % (options.newdir,))

	ms = magic.open(magic.MAGIC_NONE)
	ms.load()

	## The goal is to check the files from the new binary and
	## compare them with files from the old binary
	## First build a list of files in the original binary
	## Then do the same for the new binary and check:
	## * does a file with the same name exist in the original binary
	## * do the files differ
	## and report about it
	checkfiles = {}
	osgen = os.walk(options.olddir)
	try:
		while True:
			i = osgen.next()
			for p in i[2]:
				if os.path.islink(os.path.join(i[0], p)):
					continue
				if not os.path.isfile(os.path.join(i[0], p)):
					continue
				if not checkfiles.has_key(p):
					checkfiles[p] = [os.path.join(i[0], p)]
				else:
					checkfiles[p].append(os.path.join(i[0],p))
	except StopIteration:
		pass
	notfoundnewdir = []
	notfoundorigdir = []
	## now loop over the new binary
	osgen = os.walk(options.newdir)
	try:
		while True:
			i = osgen.next()
			for p in i[2]:
				if os.path.islink(os.path.join(i[0], p)):
					continue
				if not os.path.isfile(os.path.join(i[0], p)):
					continue
				## name of this file can't be found in old scan tree, so report
				if not checkfiles.has_key(p):
					notfoundnewdir.append(p)
				else:
					for j in checkfiles[p]:
						diff = comparebinaries(j, os.path.join(i[0], p))
						## bsdiff between two identical files is 143 bytes
						if diff <= 143 :
							continue
						else:
							print "* %s and %s differ %d bytes according to bsdiff" % ("%s/%s" % (i[0], p), j, diff)
	except StopIteration:
		pass

	if notfoundnewdir != []:
		print "\nThe following files from the new binary were not found in the original binary:"
		for i in notfoundnewdir:
			print "* %s" % i

	## TODO: check for files in the original directory as well, although
	## removal of files might not be as interesting
	if notfoundorigdir != []:
		print "\nThe following files from the original binary were not found in the new binary:"
		for i in notfoundorigdir:
			print "* %s" % i

if __name__ == "__main__":
        main(sys.argv)
