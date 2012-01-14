#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This module contains only the RPM specific parts. This is so we don't get
failures in the systems that don't have Python RPM bindings.
'''

import sys, os, subprocess, os.path
import tempfile, magic, rpm
import fsmagic, fssearch, extractor, fwunpack

def unpackRPM(data, offset, tempdir=None):
	## Assumes (for now) that rpm2cpio is in the path
	tmpdir = fwunpack.unpacksetup(tempdir)
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
		return fwunpack.unpackCpio(stanout, 0, tempdir)
	else:
                os.fdopen(tmpfile[0]).close()
                os.unlink(tmpfile[1])
		if tempdir == None:
                	os.rmdir(tmpdir)
		return None

## RPM is basically a header, plus some compressed files, so we are getting
## duplicates at the moment. We can defeat this easily by setting the blacklist
## upperbound to the start of compression.
def searchUnpackRPM(filename, tempdir=None, blacklist=[], offsets={}, envvars=None):
	datafile = open(filename, 'rb')
	offset = fssearch.findRPM(datafile)
	if offset == -1:
		datafile.close()
		return ([], blacklist, offsets)
	else:
		diroffsets = []
		rpmcounter = 1
		data = datafile.read()
		while(offset != -1):
			blacklistoffset = extractor.inblacklist(offset, blacklist)
			if blacklistoffset != None:
				offset = fssearch.findRPM(datafile, blacklistoffset)
			if offset == -1:
				break
			tmpdir = fwunpack.dirsetup(tempdir, filename, "rpm", rpmcounter)
			res = unpackRPM(data, offset, tmpdir)
			if res != None:
				diroffsets.append((res, offset))
				rpmcounter = rpmcounter + 1
				## determine which compression is used, so we can
				## find the right offset. Code from the RPM examples
				tset = rpm.TransactionSet()
				tset.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
        			fdno = os.open(filename, os.O_RDONLY)
        			header = tset.hdrFromFdno(fdno)
        			os.close(fdno)
				## first some sanity checks. payload format should
				## always be 'cpio' according to LSB 3
				if header[rpm.RPMTAG_PAYLOADFORMAT] == 'cpio':
					## compression should always be 'gzip' according to LSB 3
					if header[rpm.RPMTAG_PAYLOADCOMPRESSOR] == 'gzip':
						payloadoffset = fssearch.findGzip(datafile, offset)
						blacklist.append((offset, payloadoffset))
			else:
				## cleanup
				os.rmdir(tmpdir)
			offset = fssearch.findRPM(datafile, offset+1)
		datafile.close()
		return (diroffsets, blacklist, [])
