#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script is to update the SHA256SUM file in a directory that contains sha256 checksums 
for each file, that speeds up database creation.
'''

import os, os.path, sys, hashlib, multiprocessing, zlib
from optparse import OptionParser

def computehash((filedir, filename, extrahashes)):
	filehashes = {}
	resolved_path = os.path.join(filedir, filename)
	scanfile = open(resolved_path, 'r')
	filedata = scanfile.read()
	scanfile.close()
	h = hashlib.new('sha256')
	h.update(filedata)
	filehashes['sha256'] = h.hexdigest()

	if 'crc32' in extrahashes:
		try:
			filehashes['crc32'] = zlib.crc32(filedata) & 0xffffffff
		except:
			return None

	## first remove 'crc32' from extrahashes
	extrahashesset = set(extrahashes)
	try:
		extrahashesset.remove('crc32')
	except KeyError:
		pass

	temphashes = {}
	for i in extrahashesset:
		temphashes[i] = hashlib.new(i)
	for i in extrahashesset:
		temphashes[i].update(filedata)
	for i in extrahashesset:
		filehashes[i] = temphashes[i].hexdigest()
        return (filename, filehashes)

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory with files", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.filedir == None:
		parser.error("No directory defined")
	if not os.path.exists(options.filedir):
		parser.error("No directory found")
	dirlist = os.listdir(options.filedir)
	dirlist = filter(lambda x: x != 'LIST' and x != 'SHA256SUM', dirlist)
	dirlist = filter(lambda x: os.path.isfile(os.path.join(options.filedir, x)), dirlist)

	## no files, so exit
	if len(dirlist) == 0:
		sys.exit(0)

	extrahashes = ['md5', 'sha1', 'crc32']

	filetohash = {}
	if os.path.exists(os.path.join(options.filedir, "SHA256SUM")):
		sha256file = os.path.join(options.filedir, "SHA256SUM")
		sha256lines = open(sha256file, 'r').readlines()
		## first line should have the supported hashes

		checksumsused = sha256lines[0].strip().split()
		## first line is always a list of supported hashes.
		process = True
		if set(checksumsused).intersection(set(extrahashes)) != set(extrahashes):
			process = False
		if process:
			for i in sha256lines[1:]:
				entries = i.strip().split()
				filename = entries[0]
				if filename == 'SHA256SUM':
					continue
				if filename == 'LIST':
					continue
				if filename == 'DOWNLOADURL':
					continue
				## sha256 is always the first hash and second entry
				hashentry = entries[1]
				filetohash[filename] = {}
				filetohash[filename]['sha256'] = hashentry
				counter = 2
				for c in checksumsused[1:]:
					## only record results for hashes that are in 'extrahashes'
					if c in extrahashes:
						filetohash[filename][c] = entries[counter]
					counter += 1

	## determine which files need to be scanned
	diffset = set(dirlist).difference(set(filetohash))
	if len(diffset) == 0:
		sys.exit(0)

	## find hashes in parallel
	shatasks = map(lambda x: (options.filedir, x, extrahashes), diffset)
	pool = multiprocessing.Pool()
	sharesults = filter(lambda x: x != None, pool.map(computehash, shatasks, 1))
	pool.terminate()

	for i in sharesults:
		(filename, filehashes) = i
		filetohash[filename] = filehashes

	## write results
	filenameskeys = filetohash.keys()
	filenameskeys.sort()
	sha256file = open(os.path.join(options.filedir, "SHA256SUM"), 'w')
	## first write a line with the hashes that are supported
	if extrahashes == []:
		sha256file.write("sha256\n")
	else:
		hashesstring = "sha256"
		for h in extrahashes:
			hashesstring += "\t%s" % h
		sha256file.write("%s\n" % hashesstring)
	for i in filenameskeys:
		## first hashes, since file names could contain spaces
		hashesstring = filetohash[i]['sha256']
		for h in extrahashes:
			hashesstring += "\t%s" % filetohash[i][h]
		sha256file.write("%s  %s\n" % (i, hashesstring))
	sha256file.close()

if __name__ == "__main__":
	main(sys.argv)
