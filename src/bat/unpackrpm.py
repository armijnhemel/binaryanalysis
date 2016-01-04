#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains only code specific to RPM unpacking. This is so it can be
disabled on systems that don't have the Python RPM bindings installed.
'''

import sys, os, subprocess, os.path, struct
import tempfile, magic, rpm
import extractor, fwunpack

## RPM is basically a header, plus some compressed files, so we might get
## duplicates at the moment. We can defeat this easily by setting the blacklist
## upperbound to the start of compression + 1. This is ugly and should actually
## be fixed.
def searchUnpackRPM(filename, tempdir=None, blacklist=[], offsets={}, scanenv={}, debug=False):
	hints = {}
	if not 'rpm' in offsets:
		return ([], blacklist, [], hints)
	if offsets['rpm'] == []:
		return ([], blacklist, [], hints)

	## sanity checks for payload compressors before even trying to process headers
	## TODO: LZMA
	compressorfound = False
	compressors = ['gzip', 'xz', 'bz2', 'lzip']
	for compressor in compressors:
		if compressor in offsets:
			compressorfound = True
			break

	if not compressorfound:
		return ([], blacklist, [], hints)

	offsetsfound = False
	for compressor in compressors:
		if offsets[compressor] != []:
			offsetsfound = True
			break

	if not offsetsfound:
		return ([], blacklist, [], hints)

	diroffsets = []
	rpmcounter = 1
	for offset in offsets['rpm']:
		blacklistoffset = extractor.inblacklist(offset, blacklist)
		if blacklistoffset != None:
			continue
		rpmfile = open(filename, 'rb')
		rpmfile.seek(offset+4)
		rpmversionbyte = rpmfile.read(1)
		rpmfile.close()
		rpmmajorversion = struct.unpack('<B', rpmversionbyte)[0]
		if rpmmajorversion > 3 or rpmmajorversion == 0:
			continue

		## now first check the header
		headervalid = False
		tset = rpm.TransactionSet()
		tset.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
		sizeofheader = 0
		## search all compressors, sorted by prevalence
		#for compressor in ['gzip', 'xz', 'bz2', 'lzip', 'lzma']:
		for compressor in ['gzip', 'xz', 'bz2', 'lzip']:
			if not compressor in offsets:
				continue
			for compressoroffset in offsets[compressor]:
				if compressoroffset < offset:
					continue
				try:
					tmprpm = tempfile.mkstemp()
					rpmfile = open(filename, 'rb')
					rpmfile.seek(offset)
					rpmdata = rpmfile.read(compressoroffset - offset)
					rpmfile.close()
					os.write(tmprpm[0], rpmdata)
					os.fsync(tmprpm[0])
					os.close(tmprpm[0])
        				fdno = os.open(tmprpm[1], os.O_RDONLY)
        				header = tset.hdrFromFdno(fdno)
        				os.close(fdno)
					os.unlink(tmprpm[1])
					headervalid = True
					sizeofheader = compressoroffset - offset
					break
				except Exception, e:
					if os.path.exists(tmprpm[1]):
						os.close(fdno)
						os.unlink(tmprpm[1])
			if headervalid:
				break

		if not headervalid:
			## no valid header was found so continue with the next RPM file
			continue

		## The RPM file format is heavily underdocumented, so scrape bits and pieces
		## of docs from various sources.
		## http://www.rpm.org/max-rpm/s1-rpm-file-format-rpm-file-format.html
		## https://docs.fedoraproject.org/ro/Fedora_Draft_Documentation/0.1/html/RPM_Guide/ch-package-structure.html

		## payload format always has to be cpio
		if header[rpm.RPMTAG_PAYLOADFORMAT] != 'cpio':
			continue

		## possibly good statistic to have
		#compressor = header[rpm.RPMTAG_PAYLOADCOMPRESSOR]

		## the size of the headers and payload, but not of the lead and any signatures
		bl = header[rpm.RPMTAG_SIGSIZE]
		filesize = os.stat(filename).st_size

		## after the header checks are done carve the possible RPM file from
		## the bigger archive (right now just removing all leading bytes) and
		## use rpm2cpio to unpack the RPM file.
		tmpdir = fwunpack.dirsetup(tempdir, filename, "rpm", rpmcounter)
		tmpfile = tempfile.mkstemp(dir=tmpdir)
		os.fdopen(tmpfile[0]).close()

		fwunpack.unpackFile(filename, offset, tmpfile[1], tmpdir)

		## first use rpm2cpio to unpack the rpm data
		p = subprocess.Popen(['rpm2cpio', tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if len(stanout) != 0:
			## cleanup first
                	os.unlink(tmpfile[1])
			if tempdir == None:
                		os.rmdir(tmpdir)
			## then use unpackCpio() to unpack the RPM
			res = fwunpack.unpackCpio(stanout, tmpdir)
		else:
                	os.unlink(tmpfile[1])
			if tempdir == None:
                		os.rmdir(tmpdir)

		if res != None:
			rpmcounter = rpmcounter + 1
			try:
				## this header describes the size of headers +
				## compressed payload size. It might be a few bytes off
				## with the actual size of the file.
				bl = header[rpm.RPMTAG_SIGSIZE]
				filesize = os.stat(filename).st_size
				## sanity check. It should not happen with a properly
				## formatted RPM file, but you never know.
				if bl > filesize:
					bl = payloadoffset + 1
			except Exception, e:
				bl = payloadoffset + 1
			diroffsets.append((res, offset, bl))
			blacklist.append((offset, bl))
		else:
			## cleanup
			os.rmdir(tmpdir)
	return (diroffsets, blacklist, [], hints)
