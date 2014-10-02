#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Program to process a whole directory full of compressed source code archives and
create a BAT archive.

BAT archive files are pre-processed source code archive files that are created
after an initial database run.

A BAT archive consists of:

* files that are unique to this specific version of the package
* all other files that were not processed (in case they need to be processed later)
* a list of all checksums of all files inside the *original* archive
* a list of all non-unique checksums and a version number of a package
where these files can be found
* a list of all extensions that can be found in the package

This is useful to reduce spending time on packing/unpacking source code
archives and scanning all files, before picking out a handful that are new. In
some cases (Linux kernel) the differences between kernel versions are so small
that a big reduction in runtime of unpacking/scanning can be achieved.

Needs a file LIST in the directory it is passed as a parameter, which has the
following format:

package version filename origin

separated by whitespace

Compression is determined using magic

Also needed is a current database with processed packages.
'''

import sys, os, magic, string, re, subprocess, shutil, stat, multiprocessing
import tempfile, bz2, tarfile, gzip, datetime
from optparse import OptionParser
import sqlite3, hashlib
import batextensions

extensions = batextensions.extensions

## extensions, without leading .
extensionskeys = set(map(lambda x: x[1:], extensions.keys()))

tarmagic = ['POSIX tar archive (GNU)'
           , 'tar archive'
           ]

ms = magic.open(magic.MAGIC_NONE)
ms.load()


def packfile((packfile, packdir, lenunpackdir, version, seennotscanned_files)):
	(origpath, origfile, checksum, extension, process) = packfile
	modorigpath = os.path.join(packdir, origpath[lenunpackdir:])
	shutil.copy(os.path.join(origpath, origfile), modorigpath)

def findversion((dbpath, s, package, processed_versions, scanned_files_version, seennotscanned_files_version)):
	packfiles = set()
	skipfiles = set()
	(filepath, filename, checksum, extension, process) = s
	if scanned_files_version != None:
		firstoccur = scanned_files_version
		skipfiles.add(s + (firstoccur,))
		return (packfiles, skipfiles)
	elif seennotscanned_files_version != None:
		firstoccur = seennotscanned_files_version
		skipfiles.add(s + (firstoccur,))
		return (packfiles, skipfiles)
	## look up checksum in database
	conn = sqlite3.connect(dbpath)
	cursor = conn.cursor()
	cursor.execute("select package, version from processed_file where sha256=?", (checksum,))
	res = cursor.fetchall()
	versions = set(map(lambda x: x[1], filter(lambda x: x[0] == package, res)))
	foundversions = set(processed_versions).intersection(versions)
	if foundversions == set():
		packfiles.add((filepath, filename, checksum, extension, process))
	else:
		for v in processed_versions:
			if v in foundversions:
				firstoccur = v
				break
		skipfiles.add(s + (firstoccur,))
	cursor.close()
	conn.close()
	return (packfiles, skipfiles)

def computehash((path, filename, filehash)):
	resolved_path = os.path.join(path, filename)
	if filehash == None:
		if not os.path.islink(resolved_path):
			try:
				os.chmod(resolved_path, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			except Exception, e:
				pass
		else:
			return None
		## nothing to determine about an empty file, so skip
		if os.stat(resolved_path).st_size == 0:
			return None
	## some filenames might have uppercase extensions, so lowercase them first
	p_nocase = filename.lower()
	process = False
	ext = p_nocase.split('.')[-1]
	if ext != p_nocase:
		if ext in extensionskeys:
			process = True
	if process:
		## this check only makes sense if 'process' is set to True
		filemagic = ms.file(os.path.realpath(resolved_path))
		if filemagic == "AppleDouble encoded Macintosh file":
			process = False
	if filehash == None:
		scanfile = open(resolved_path, 'r')
		h = hashlib.new('sha256')
		h.update(scanfile.read())
		scanfile.close()
		filehash = h.hexdigest()
	return (path, filename, filehash, ext, process)

## unpack the directories to be scanned. For speed improvements it might be
## wise to use a ramdisk or tmpfs for this.
def unpack(directory, filename, unpackdir=None):
	try:
		os.stat(os.path.join(directory, filename))
	except:
		print >>sys.stderr, "Can't find %s" % filename
		return None

	filemagic = ms.file(os.path.realpath(os.path.join(directory, filename)))

	## Assume if the files are bz2 or gzip compressed they are compressed tar files
	if 'bzip2 compressed data' in filemagic:
		tmpdir = tempfile.mkdtemp(dir=unpackdir)
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
		tmpdir = tempfile.mkdtemp(dir=unpackdir)
		p = subprocess.Popen(['tar', 'ixf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		return tmpdir
	elif 'XZ compressed data' in filemagic:
		tmpdir = tempfile.mkdtemp(dir=unpackdir)
		p = subprocess.Popen(['tar', 'ixf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		return tmpdir
	elif 'gzip compressed data' in filemagic:
		tmpdir = tempfile.mkdtemp(dir=unpackdir)
		p = subprocess.Popen(['tar', 'zxf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		return tmpdir
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

def computehasharchive((filedir, checksums, version, filename)):
	resolved_path = os.path.join(filedir, filename)
	try:
		os.stat(resolved_path)
	except:
		print >>sys.stderr, "Can't find %s" % filename
		return None
	if checksums.has_key(filename):
		filehash = checksums[filename]
	else:
		scanfile = open(resolved_path, 'r')
		h = hashlib.new('sha256')
		h.update(scanfile.read())
		scanfile.close()
		filehash = h.hexdigest()
	return (filename, version, filehash)

## per package:
## 1. unpack archive
## 2. scan all files and compute hashes
## 3. lookup what is available in the database from the same package and origin
## 4. copy unique and unscanned files to new archive dir 
## 5. create text file with metadata
## 6. pack archive
## 7. pack archive + metadata into BAT archive
def packagewrite(dbpath, filedir, outdir, pool, package, versionfilenames, origin, outfile, shaoutfile, unpacktempdir):
	## keep a dictionary of checksum + version to avoid lookups
	scanned_files = {}
	seennotscanned_files = {}
	## first sanity check: is there actually more than one version so a proper diff can be made?
	if len(versionfilenames) == 1:
		return None
	conn = sqlite3.connect(dbpath)
	cursor = conn.cursor()
	## second sanity check: is there actually anything useful in the database?
	cursor.execute("select * from processed where package=? and origin=? LIMIT 1", (package, origin))
	res = cursor.fetchall()
	if res == []:
		cursor.close()
		conn.close()
		return res

	## grab the versions. The first version will be used as the base version,
	## which will always be stored in full. The prime use case is the Linux kernel.
	versions = map(lambda x: x[0], versionfilenames)

	checksums = {}
	if os.path.exists(os.path.join(filedir, "SHA256SUM")):
		checksumlines = open(os.path.join(filedir, "SHA256SUM")).readlines()
		for c in checksumlines[1:]:
			checksumsplit = c.strip().split()
			if len(checksumsplit) < 2:
				continue
			archivefilename = checksumsplit[0]
			archivechecksum = checksumsplit[1]
			checksums[archivefilename] = archivechecksum

	res = filter(lambda x: x != None, pool.map(computehasharchive, map(lambda x: (filedir,checksums) + x, versionfilenames),1))

	## keep a list of versions that have already been processed. Use a list to keep order when they were processed
	processed_versions = []
	for r in res:
		(archivefilename, version, archivechecksum) = r
		## to determine the version that is used as a 'base' first check if it is in the database
		cursor.execute("select version from processed where sha256=?", (archivechecksum,))
		versionres = cursor.fetchall()
		if versionres != []:
			## extra sanity check to see if it is the expected version
			if versionres[0][0] != version:
				continue
			processed_versions.append(versionres[0][0])
			break

	manifests = False
	manifestdir = os.path.join(filedir, "MANIFESTS")
	if os.path.exists(manifestdir):
		if os.path.isdir(manifestdir):
			manifests = True
	for r in res:
		(archivefilename, version, archivechecksum) = r
		if version in processed_versions:
			continue

		print "processing: %s" % version
		sys.stdout.flush()
		## unpack the archive in a temporary directory
		unpackdir = unpack(filedir, archivefilename, unpacktempdir)
		if unpackdir == None:
			continue

		## add 1 to deal with /
		lenunpackdir = len(unpackdir) + 1
		## walk the files, get all the interesting ones
		osgen = os.walk(unpackdir)

		filetohash = {}

		if manifests:
			manifestfile = os.path.join(manifestdir, "%s.bz2" % archivechecksum)
			if os.path.exists(manifestfile):
				manifest = bz2.BZ2File(manifestfile, 'r')
				manifestlines = manifest.readlines()
				manifest.close()
				tmpextrahashes = manifestlines[0].strip().split()
				for c in manifestlines[1:]:
					archivechecksums = {}
					checksumsplit = c.strip().split()
					fileentry = checksumsplit[0]
					## sha256 is always the first hash
					archivechecksums['sha256'] = checksumsplit[1]
					counter = 2
					for h in tmpextrahashes:
						if h == 'sha256':
							continue
						archivechecksums[h] = checksumsplit[counter]
						counter += 1
						checksums[fileentry] = archivechecksums
					filetohash[fileentry] = archivechecksums['sha256']

		try:
			scanfiles = set()
			while True:
				i = osgen.next()
				## make sure all directories can be accessed
				for d in i[1]:
					if not os.path.islink(os.path.join(i[0], d)):
						os.chmod(os.path.join(i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
				for p in i[2]:
					normpath = os.path.join(i[0][lenunpackdir:], p)
					if filetohash.has_key(normpath):
						scanfiles.add((i[0], p, filetohash[normpath]))
					else:
						scanfiles.add((i[0], p, None))

		except Exception, e:
			if str(e) != "":
				print >>sys.stderr, package, version, e

		packfiles = set()
		skipfiles = set()

		print "computing hashes"
		sys.stdout.flush()
		scanfile_res = pool.map(computehash, scanfiles)
		scanfile_result = filter(lambda x: x != None, scanfile_res)
		## scanfile_result: (path, filename, filehash, ext, process)

		print "scanning"
		sys.stdout.flush()
		## scanned_files and seennotscanned_files get larger and larger
		tasks = map(lambda x: (dbpath, x, package, processed_versions, scanned_files.get(x[2], None), seennotscanned_files.get(x[2], None)), scanfile_result)
		res = pool.map(findversion, tasks)
		for r in res:
			(respackfiles, resskipfiles) = r
			packfiles.update(respackfiles)
			skipfiles.update(resskipfiles)
		## add the files that were scanned in this version to scanned_files
		for s in packfiles:
			(origpath, origfile, checksum, extension, process) = s
			if process != False:
				scanned_files[checksum] = version
			elif process == False:
				seennotscanned_files[checksum] = version

		if len(skipfiles) == 0:
			print "no files skipped, use original file when generating database\n"
			sys.stdout.flush()
			## Nothing to optimize, so just cleanup and continue to the next file
			shutil.rmtree(unpackdir)
			processed_versions.append(version)
			continue

		print "skipping %s packing %s for version %s" % (len(skipfiles), len(packfiles), version)
		sys.stdout.flush()

		## there are some files that need to be packed.
		## first, create a temporary directory
		## TODO: allow this to be set to for example a ramdisk
		packdir = tempfile.mkdtemp(dir='/ramdisk')

		if len(packfiles) != 0:
			## copy all files. First create all directories
			packdirs = set(map(lambda x: x[lenunpackdir:], map(lambda x: x[0], packfiles)))
			for i in packdirs:
				try:
					os.makedirs(os.path.join(packdir, i))
				except Exception, e:
					pass
					#print e

			## keep a list of lower case extensions for all remaining files
			storeexts = set(map(lambda x: x[3], packfiles))

			print "copying %d files" % len(packfiles)
			sys.stdout.flush()
			tasks = map(lambda x: (x, packdir, lenunpackdir, version, seennotscanned_files), packfiles)
			pool.map(packfile, tasks)
		else:
			storeexts = []

		print "creating BAT manifest"
		sys.stdout.flush()

		## create a BAT manifest file
		batfile = open(os.path.join(packdir, "MANIFEST.BAT"), 'w')

		## First add a section with the name, version, origin, SHA256sum of the original archive
		batfile.write("## META INFORMATION OF PACKAGE\n")
		batfile.write("## START META\n")
		batfile.write("package: %s\n" % package)
		batfile.write("version: %s\n" % version)
		batfile.write("filename: %s\n" % archivefilename)
		batfile.write("origin: %s\n" % origin)
		batfile.write("sha256: %s\n" % archivechecksum)
		batfile.write("## END META\n")
		batfile.write("\n")

		## then add a line for each skipped file, plus in which version they can be found
		batfile.write("## FILES THAT CAN BE FOUND IN OTHER PACKAGES\n")
		batfile.write("## PATH CHECKSUM VERSION\n")
		batfile.write("## START DUPLICATE_FILES\n")
		for i in skipfiles:
			(origpath, origfile, checksum, extension, process, firstoccur) = i
			if not scanned_files.has_key(checksum):
				scanned_files[checksum] = firstoccur
			if process:
				batfile.write("%s\t%s\t%s\n" % (os.path.join(origpath[lenunpackdir:], origfile), checksum, firstoccur))
		batfile.write("## END DUPLICATE_FILES\n")
		batfile.write("\n")
		batfile.write("## FILES THAT CAN BE FOUND IN OTHER PACKAGES BUT ARE NOT SCANNED\n")
		batfile.write("## PATH CHECKSUM VERSION\n")
		batfile.write("## START UNSCANNED_DUPLICATE_FILES\n")
		for i in skipfiles:
			(origpath, origfile, checksum, extension, process, firstoccur) = i
			if not process:
				batfile.write("%s\t%s\t%s\n" % (os.path.join(origpath[lenunpackdir:], origfile), checksum, firstoccur))
		batfile.write("## END UNSCANNED_DUPLICATE_FILES\n")
		batfile.write("\n")
		## TODO: add checksums of packfiles
		batfile.write("## START EXTENSIONS\n")
		batfile.write("## EXTENSIONS OF UNPROCESSED FILES (LOWER CASED)\n")
		if len(storeexts) != 0:
			batfile.write(reduce(lambda x,y: "%s %s" %(x, y), storeexts))
			batfile.write("\n")
			batfile.write("## END EXTENSIONS\n")
		batfile.close()

		print "packing"
		sys.stdout.flush()
		## now pack the archive
		outputfile = os.path.join(outdir, '%s-%s-%s-bat.tar.bz2' % (package,version,origin))
		filestopack = os.listdir(packdir)
		dumpfile = tarfile.open(outputfile, 'w:bz2')
		os.chdir(packdir)
		for i in filestopack:
			dumpfile.add(i)
		dumpfile.close()

		## cleanup
		print "cleanup\n"
		sys.stdout.flush()
		shutil.rmtree(packdir)
		shutil.rmtree(unpackdir)
		processed_versions.append(version)
		outfile.write('%s-%s-%s-bat.tar.bz2' % (package,version,origin))
		outfile.write("\n")
		shaoutfile.write('%s-%s-%s-bat.tar.bz2\t%s\t%s' % (package,version,origin, archivechecksum, archivefilename))
		shaoutfile.write("\n")
	cursor.close()
	conn.close()
	return res

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="db", help="path to database", metavar="FILE")
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-o", "--outdir", action="store", dest="outdir", help="path to directory to write BAT archive files", metavar="DIR")
	parser.add_option("-t", "--tempdir", action="store", dest="tempdir", help="path to temporary directory to unpack archives", metavar="DIR")

	(options, args) = parser.parse_args()
	if options.filedir == None:
		parser.error("Specify dir with files")
	else:
		try:
			filelist = open(os.path.join(options.filedir, "LIST")).readlines()
		except:
			parser.error("'LIST' not found in file dir")

	if options.db == None:
		parser.error("Specify path to database")

	if options.outdir == None:
		parser.error("Specify output dir")
	else:
		if not os.path.exists(options.outdir):
			parser.error("output dir does not exist")

	unpackdir = None
	## check if the temporary directory exists and is writable
	if options.tempdir != None:
		if os.path.exists(options.tempdir):
			try:
				tmptest = tempfile.mkstemp(dir=options.tempdir)
				os.unlink(tmptest[1])
				unpackdir = options.tempdir
			except Exception, e:
				pass

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
			pkgmeta.append((package, version, filename, origin))
		except Exception, e:
			# oops, something went wrong
			print >>sys.stderr, e

	## sort everything per origin, then per package.
	origins = {}
	for p in pkgmeta:
		(package, version, filename, origin) = p
		if origins.has_key(origin):
			origins[origin].append(tuple(p[0:3]))
		else:
			origins[origin] = [tuple(p[0:3])]

	scandate = datetime.datetime.utcnow()
	pool = multiprocessing.Pool()
	outputfile = os.path.join(options.outdir, 'ARCHIVELIST-%s' % scandate.isoformat())
	outfile = open(outputfile, 'w')
	shaoutputfile = os.path.join(options.outdir, 'SHA256SUM-ARCHIVE')
	shaoutfile = open(shaoutputfile, 'w')
	for o in origins.keys():
		packages = {}
		for p in origins[o]:
			(package, version, filename) = p
			if packages.has_key(package):
				packages[package].append((version, filename))
			else:
				packages[package] = [(version,filename)]
		for p in packages.keys():
			packagewrite(options.db, options.filedir, options.outdir, pool, p, packages[p], o, outfile, shaoutfile, unpackdir)
	pool.terminate()
	outfile.close()
	shaoutfile.close()

if __name__ == "__main__":
	main(sys.argv)
