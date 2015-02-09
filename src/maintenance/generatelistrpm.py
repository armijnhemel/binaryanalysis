#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Helper script to generate the LIST files for the string extraction scripts. While this script is not foolproof, it will save lots of typing :-)

This variant is specifically for processing a directory full of SRPM files.

1. files are converted to CPIO archives using rpm2cpio
2. files are unpacked using cpio
3. archives (ZIP, tar.gz, tar.bz, tgz, etc.) are moved to a temporary directory. TODO: Any patches are put in a special patch
directory.
4.
5. LIST file for temporary directory is created
'''

import sys, os, os.path, subprocess, tempfile, shutil, stat, sqlite3
from optparse import OptionParser
import multiprocessing

## spec file scanner to process any patches that are actually applied
## extract the following:
## * name
## * version
## * release
## * source inputs
## * any applied patches
## * any unapplied patches
## * possibly license and URL
def scanspec(specfile):
	result = {}
	patches = {}
	appliedpatches = set()
	speclines = map(lambda x: x.strip(), open(specfile, 'r').readlines())
	for s in speclines:
		if line.startswith('Name:'):
			pass
		elif line.startswith('Release:'):
			pass
		elif line.startswith('Version:'):
			pass
		elif line.startswith('URL:'):
			url = line.split(':',1)[1].strip()
			result['url'] = url
		elif line.startswith('License:'):
			license = line.split(':',1)[1].strip()
			result['license'] = license
		elif line.startswith('Source'):
			## possibly subsitute version and other variables
			## possibly remove URLs and other things, so just the
			## name of the source code file is kept
			pass
		elif line.startswith('Patch'):
			patchsplit = line.split(':', 1)
			patches[patchsplit[0].lower()] = patchsplit[1]
		elif line.startswith('%patch'):
			## check if patch is known. If so, apply it
			appliedpatch = line[1:].split('', 1)[0]
			if appliedpatch in patches:
				appliedpatches.add(patches[appliedpatch]
	return result

def parallel_unpack((rpmfile, target, copyfiles, unpacktmpdir, cutoff)):
	## cutoff is at 200 MiB
	## TODO: make configurable
	cutoff = 209715200
	## make a temporary directory
	if os.stat(rpmfile).st_size < cutoff:
		cpiodir = tempfile.mkdtemp(dir=unpacktmpdir)
	else:
		cpiodir = tempfile.mkdtemp()

	cpiotmp = tempfile.mkstemp(dir=cpiodir)

	p1 = subprocess.Popen(['rpm2cpio', rpmfile], stdin=subprocess.PIPE, stdout=cpiotmp[0], stderr=subprocess.PIPE, close_fds=True, cwd=cpiodir)
	(cpiostanout, cpiostanerr) = p1.communicate()
	os.fsync(cpiotmp[0])
	os.fdopen(cpiotmp[0]).close()

	p2 = subprocess.Popen(['cpio', '-i', '-d', '--no-absolute-filenames', '-F', cpiotmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=cpiodir)
	(cpiostanout, cpiostanerr) = p2.communicate()
	for f in copyfiles:
		shutil.copy(os.path.join(cpiodir, f), target)
		os.chmod(os.path.join(target, f), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
	shutil.rmtree(cpiodir)

## it's either in the form of:
##   package-version.extension
##   package_version.extension
## where extension is tar.gz, tar.bz2, tar.xz, tgz, zip, tbz2, etc.
def generatelist(filedir, origin):
	files = os.walk(filedir)
	try:
        	while True:
			i = files.next()
			for p in i[2]:
				if p == "LIST":
					continue
				## first determine things like the extension
				res = p.rsplit('.', 1)
				if len(res) == 1:
					print >>sys.stderr, "can't split %s -- add manually" % (p,)
					continue
				(packageversion, extension) = res
				if extension in ["tgz", "tbz2", "tar"]:
					pass
				elif extension in ["jar", "zip"]:
					pass
				else:
					try:
						(packageversion, extension, compression) = p.rsplit('.', 2)
					except:
						continue
					if not (extension in ["tar"] and compression in ["gz", "bz2", "bz", "lz", "lzma", "xz", "Z"]):
						continue
				## exceptions go here
				if "wireless_tools" in packageversion:
					res = packageversion.rsplit(".", 1)
				## first try package-version
				else:
					res = packageversion.rsplit("-", 1)
					if len(res) == 1:
						## then try package_version
						res = packageversion.rsplit("_", 1)
						if len(res) == 1:
							print >>sys.stderr, "can't split %s -- add manually" % (p,)
							continue
				(package, version) = res
				print "%s\t%s\t%s\t%s" % (package, version, p, origin)
				
	except Exception, e:
		pass

## scan each RPM file and see if there are any source code archives inside.
## This check is based on conventions on how source code archives are named and
## might miss things.
## TODO: collect patches as well
def scanrpm((filedir, filepath)):
	extensions = [".tar.gz", ".tar.bz2", ".tar.bz", ".tar.xz", ".tgz", ".tbz2", ".tar.Z", "tar.lz", "tar.lzma"]
	p2 = subprocess.Popen(['rpm', '-qpl', '--dump', "%s/%s" % (filedir, filepath)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p2.communicate()
	rpmfiles = stanout.strip().rsplit("\n")
	copyfiles = []
	for fs in rpmfiles:
		## the interesting data from '--dump' are md5sum and the size (not used at the moment)
		(f, size, mtime, md5sum, rest) = fs.split(' ', 4)
		fsplit = f.lower().rsplit('.', 1)
		if len(fsplit) == 1:
			continue
		(packageversion, extension) = fsplit
		if extension in ["tgz", "tbz2", "tar"]:
			copyfiles.append((f, md5sum))
			continue
		elif extension in ["jar", "zip"]:
			copyfiles.append((f, md5sum))
			continue
		else:
			try:
				(packageversion, extension, compression) = f.lower().rsplit('.', 2)
			except:
				continue
			if not (extension in ["tar"] and compression in ["gz", "bz2", "bz", "lz", "lzma", "xz", "Z"]):
				continue
			else:
				copyfiles.append((f,md5sum))
	return (filedir, filepath, copyfiles)

def unpacksrpm(filedir, target, unpacktmpdir):
	files = os.walk(filedir)
	uniquefiles = set()
	uniquerpms = set()
	nonuniquerpms = set()
	rpm2copyfiles = {}

	rpmscans = set()

	try:
        	while True:
			i = files.next()
			for p in i[2]:
				## first filter out files that are likely no source rpm, just by
				## looking at the extension.
				res = p.rsplit('.', 2)
				if len(res) != 3:
					continue
				if res[-1] != 'srpm' and (res[-1] != 'rpm' and res[-2] != 'src'):
					ccontinue
				else:
					rpmscans.add((i[0], p))
	except Exception, e:
		pass
		#print >>sys.stderr, e
		#sys.stderr.flush()

	pool = multiprocessing.Pool()
	rpmres = pool.map(scanrpm, rpmscans, 1)

	uniquemd5s = set()

	for r in rpmres:
		(filedir, filepath, copyfiles) = r
		unique = True
		for fs in copyfiles:
			(f, md5sum) = fs
			if md5sum in uniquemd5s:
				unique = False
				break
			if f in uniquefiles:
				#print "files with different checksums and same name", f, filedir, filepath, md5sum
				unique = False
				break
		if unique:
			uniquefiles.update(set(map(lambda x: x[0], copyfiles)))
			uniquemd5s.update(set(map(lambda x: x[1], copyfiles)))
			uniquerpms.add(os.path.join(filedir, filepath))
		else:
			nonuniquerpms.add(os.path.join(filedir, filepath))
		rpm2copyfiles[os.path.join(filedir, filepath)] = map(lambda x: x[0], copyfiles)

	## unique RPMs can be unpacked in parallel, non-uniques cannot
	## first process the unique RPMS in parallel
	## cutoff is at 200 MiB
	## TODO: make configurable
	cutoff = 209715200
	tasks = map(lambda x: (x, target, rpm2copyfiles[x], unpacktmpdir, cutoff), uniquerpms)
	pool.map(parallel_unpack, tasks,1)
	pool.terminate()

	## ... then unpack the non-unique RPMS, possibly overwriting already unpacked data
	## And yes, probably there is a more efficient way to do this.
	for n in nonuniquerpms:
		## first check if for all the 'copyfiles' a file with the same name already exists. If so,
		## then don't unpack.
		unique = False
		for f in rpm2copyfiles[n]:
			if not os.path.exists(os.path.join(target, f)):
				unique = True
				break
		if not unique:
			continue
		## make a temporary directory
		cpiodir = tempfile.mkdtemp()
		cpiotmp = tempfile.mkstemp(dir=cpiodir)
		p1 = subprocess.Popen(['rpm2cpio', n], stdin=subprocess.PIPE, stdout=cpiotmp[0], stderr=subprocess.PIPE, close_fds=True, cwd=cpiodir)
		(cpiostanout, cpiostanerr) = p1.communicate()
		os.fsync(cpiotmp[0])
		os.fdopen(cpiotmp[0]).close()
		p2 = subprocess.Popen(['cpio', '-i', '-d', '--no-absolute-filenames', '-F', cpiotmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=cpiodir)
		(cpiostanout, cpiostanerr) = p2.communicate()
		for f in rpm2copyfiles[n]:
			shutil.copy(os.path.join(cpiodir, f), target)
			os.chmod(os.path.join(target, f), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
		shutil.rmtree(cpiodir)
	return target

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-o", "--origin", action="store", dest="origin", help="origin of packages (default: unknown)", metavar="ORIGIN")
	parser.add_option("-t", "--target-directory", action="store", dest="target", help="target directory where files are stored (default: generated temporary directory)", metavar="DIR")
	(options, args) = parser.parse_args()

	## TODO: sanity checks for unpacktmpdir
	unpacktmpdir = '/ramdisk'

	if options.filedir == None:
		parser.error("Specify dir with files")
	if options.origin == None:
		origin = "unknown"
	else:
		origin = options.origin

	if options.target == None:
		target = tempfile.mkdtemp()[1]
	else:
		try:
			os.mkdir(options.target)
		except Exception, e:
			#print e.args, type(e.args)
			#if e.args.startswith("[Errno 17] File exists:"):
			#	pass
			pass
		target = options.target
	unpacksrpm(options.filedir, target, unpacktmpdir)
	generatelist(target, origin)

if __name__ == "__main__":
	main(sys.argv)
