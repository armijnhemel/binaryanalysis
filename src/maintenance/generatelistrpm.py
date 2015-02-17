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

import sys, os, os.path, subprocess, tempfile, shutil, stat, sqlite3, re
from optparse import OptionParser
import multiprocessing
import hashlib

## spec file scanner to process any patches that are actually applied
## extract the following:
## * name
## * version
## * release
## * source inputs
## * any applied patches
## * any unapplied patches
## * possibly license and URL
## TODO: also process if, undefine, etc. and verify what patches exist
def scanspec(specfile, specdir):
	result = {}
	patches = {}
	appliedpatches = set()
	speclines = map(lambda x: x.rstrip(), open(os.path.join(specdir, specfile), 'r').readlines())
	defines = {}
	globaldefines = {}
	defines['nil'] = ''
	globaldefines['nil'] = ''
	unresolvedpatches = set()
	missingpatches = set()
	filelist = os.listdir(specdir)
	for line in speclines:
		if line.startswith('Name:'):
			name = line.split(':',1)[1].strip()
			if not '%{' in name:
				result['name'] = name
				continue
			specreplaces = re.findall("%{([\w\d]+)}", name)
			for s in specreplaces:
				if s in result:
					name = name.replace("%{" + s + "}", result[s])
				elif s in defines:
					name = name.replace("%{" + s + "}", defines[s])
				elif s in globaldefines:
					name = name.replace("%{" + s + "}", globaldefines[s])
			if not '%{'in name:
				result['name'] = name
		elif line.startswith('%define'):
			definesplit = line.strip()[1:].split()
			if len(definesplit) != 3:
				continue
			if '%' in definesplit[1]:
				continue
			specreplaces = re.findall("%{([\w\d]+)}", definesplit[2])
			for s in specreplaces:
				if s in globaldefines:
					definesplit[2] = definesplit[2].replace("%{" + s + "}", globaldefines[s])
				elif s in defines:
					definesplit[2] = definesplit[2].replace("%{" + s + "}", defines[s])
			if '%' in definesplit[2]:
				continue
			defines[definesplit[1]] = definesplit[2]
		elif line.startswith('%global'):
			definesplit = line.strip()[1:].split()
			if len(definesplit) != 3:
				continue
			if '%' in definesplit[1]:
				continue
			specreplaces = re.findall("%{([\w\d]+)}", definesplit[2])
			for s in specreplaces:
				if s in globaldefines:
					definesplit[2] = definesplit[2].replace("%{" + s + "}", globaldefines[s])
				elif s in result:
					definesplit[2] = definesplit[2].replace("%{" + s + "}", result[s])
			if '%' in definesplit[2]:
				continue
			globaldefines[definesplit[1]] = definesplit[2]
		elif line.startswith('Release:'):
			pass
		elif line.startswith('Version:'):
			if 'version' in result:
				continue
			version = line.split(':',1)[1].strip()
			if not '%{' in version:
				result['version'] = version
			specreplaces = re.findall("%{([\w\d]+)}", version)
			for s in specreplaces:
				if s in result:
					version = version.replace("%{" + s + "}", result[s])
				elif s in defines:
					version = version.replace("%{" + s + "}", defines[s])
				elif s in globaldefines:
					version = version.replace("%{" + s + "}", globaldefines[s])
			if not ('%{' in version or '%(' in version):
				result['version'] = version
		elif line.startswith('URL:'):
			url = line.split(':',1)[1].strip()
			if not '%{' in url:
				result['url'] = url
				continue
			specreplaces = re.findall("%{([\w\d]+)}", url)
			for s in specreplaces:
				if s in result:
					url = url.replace("%{" + s + "}", result[s])
				elif s in defines:
					url = url.replace("%{" + s + "}", defines[s])
				elif s in globaldefines:
					url = url.replace("%{" + s + "}", globaldefines[s])
			if not '%{' in url:
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
			if len(patchsplit) == 1:
				continue
			if re.match('Patch\d+', patchsplit[0]) == None:
				if not line.startswith('Patch:'):
					continue
			patchname = patchsplit[1].strip()
			if "%{" in patchname:
				specreplaces = re.findall("%{([\w\d_?]+)}", patchname)
				for s in specreplaces:
					optional = False
					if s.startswith('?'):
						s = s[1:]
						optional = True
					if not s in patchname:
						continue
					if s in result:
						if optional:
							patchname = patchname.replace("%{?" + s + "}", result[s])
						else:
							patchname = patchname.replace("%{" + s + "}", result[s])
					elif s in defines:
						if optional:
							patchname = patchname.replace("%{?" + s + "}", defines[s])
						else:
							patchname = patchname.replace("%{" + s + "}", defines[s])
					elif s in globaldefines:
						if optional:
							patchname = patchname.replace("%{?" + s + "}", globaldefines[s])
						else:
							patchname = patchname.replace("%{" + s + "}", globaldefines[s])
			patches[patchsplit[0].lower()] = os.path.basename(patchname)
		elif line.startswith('%patch'):
			## check if patch is known. If so, add it to the applied patches
			appliedpatch = line[1:].split(' ', 1)[0]
			if appliedpatch in patches:
				if '%{' in patches[appliedpatch]:
					unresolvedpatches.add(patches[appliedpatch])
					## if it is unresolved try to do a fuzzy match
					## * split patches[appliedpatch] and look in filelist
				else:
					if os.path.exists(os.path.join(specdir, patches[appliedpatch])):
						appliedpatches.add(patches[appliedpatch])
					else:
						missingpatches.add(patches[appliedpatch])
	if len(appliedpatches) != 0:
		result['appliedpatches'] = appliedpatches
	if len(unresolvedpatches) != 0:
		result['unresolvedpatches'] = unresolvedpatches
	if len(missingpatches) != 0:
		result['missingpatches'] = missingpatches
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

	p1 = subprocess.Popen(['rpm2cpio', rpmfile], stdin=subprocess.PIPE, stdout=cpiotmp[0], stderr=subprocess.PIPE, cwd=cpiodir)
	(cpiostanout, cpiostanerr) = p1.communicate()
	os.fsync(cpiotmp[0])
	os.fdopen(cpiotmp[0]).close()

	p2 = subprocess.Popen(['cpio', '-i', '-d', '--no-absolute-filenames', '-F', cpiotmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cpiodir)
	(cpiostanout, cpiostanerr) = p2.communicate()
	os.unlink(cpiotmp[1])
	## first analyse the spec file
	res = []
	'''
	unpackedfiles = os.listdir(cpiodir)
	specfiles = filter(lambda x: x.endswith('.spec'), unpackedfiles)
	for f in specfiles:
		res.append(scanspec(f, cpiodir))
	'''
	## copy the source code files
	for f in copyfiles:
		shutil.copy(os.path.join(cpiodir, f), target)
		os.chmod(os.path.join(target, f), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
	shutil.rmtree(cpiodir)
	return res

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
## TODO: extract the spec file
def scanrpm((filedir, filepath)):
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

def unpacksrpm(filedir, target, unpacktmpdir, rpmdatabase):
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
					continue
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
	res = pool.map(parallel_unpack, tasks,1)
	pool.terminate()
	for r in res:
		print r

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
		p2 = subprocess.Popen(['cpio', '-i', '-d', '--no-absolute-filenames', '-F', cpiotmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cpiodir)
		(cpiostanout, cpiostanerr) = p2.communicate()
		os.unlink(cpiotmp[1])
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

	rpmdatabase = '/tmp/rpmdb.sqlite3'
	#conn = sqlite3.connect(rpmdatabase)
	#cursor = conn.cursor()
	#cursor.execute('''create table if not exists rpm(rpmname text, checksum text, downloadurl text)''')
	#cursor.execute('''create index if not exists rpm_checksum_index on rpm(checksum)''')
	#cursor.execute('''create index if not exists rpm_rpmname_index on rpm(rpmname)''')
	#cursor.close()
	#conn.close()

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
	unpacksrpm(options.filedir, target, unpacktmpdir, rpmdatabase)
	generatelist(target, origin)

if __name__ == "__main__":
	main(sys.argv)
