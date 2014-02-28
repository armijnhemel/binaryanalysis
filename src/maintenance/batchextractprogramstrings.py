#!/usr/bin/python
# -*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2009-2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Program to process a whole directory full of compressed source code archives
to create a knowledgebase. Needs a file LIST in the directory it is passed as
a parameter, which has the following format:

package version filename origin

separated by whitespace

Compression is determined using magic
'''

import sys, os, magic, string, re, subprocess, shutil, stat
import tempfile, bz2, tarfile, gzip, ConfigParser
from optparse import OptionParser
from multiprocessing import Pool
import sqlite3, hashlib

tarmagic = ['POSIX tar archive (GNU)'
           , 'tar archive'
           ]

ms = magic.open(magic.MAGIC_NONE)
ms.load()

kernelexprs = []

## lots of things with _ATTR, like DEVICE_ATTR and friends. This list should be expanded.
kernelexprs.append(re.compile("__ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("__ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("__ATTR_RW\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("__ATTR_IGNORE_LOCKDEP\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("BRPORT_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("BUS_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("CLASS_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DEVICE_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("HYPERVISOR_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("KSM_ATTR_RO\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("MODINFO_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EP_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_INFO_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_RO_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_RW_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_RW_ATTR_SBI_UI\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("EXT4_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DMI_SYSFS_SEL_FIELD\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("^TRACE_EVENT\s*\(\s*(\w+),", re.MULTILINE))
kernelexprs.append(re.compile("^\s*PARAM\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("SCHED_FEAT\(\s*(\w+),", re.MULTILINE))
kernelexprs.append(re.compile("DECLARE_STATS_COUNTER\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("power_attr\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_WRITEBACK_WORK_EVENT\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_DEV_ATTRIBUTE\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_LINK_ATTRIBUTE\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_PORT_ATTRIBUTE\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("KERNEL_ATTR_RO\(\s*(\w+)\)", re.MULTILINE))
kernelexprs.append(re.compile("INTEL_UNCORE_EVENT_DESC\(\s*(\w+),", re.MULTILINE))
kernelexprs.append(re.compile("scsi_msgbyte_name\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("scsi_opcode_name\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("scsi_statusbyte_name\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("VMCOREINFO_LENGTH\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("VMCOREINFO_NUMBER\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("POWER_SUPPLY_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_CONN_RD_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("SETUP_SESSION_RD_ATTR\s*\((\w+)", re.MULTILINE))
kernelexprs.append(re.compile("DEFINE_EVENT\s*\(\w+,\s*(\w+)", re.MULTILINE))
#SYSCALL_DEFINE + friends go here
#COMPAT_SYSCALL_DEFINE

## some more precompiled regex
recopyright = re.compile('^\[(\d+):\d+:(\w+)] \'(.*)\'')
recopyright2 = re.compile('^\[(\d+):\d+:(\w+)] \'(.*)')

oldallowedvals= ["b", "c", "h", "i", "l", "s"]

reoldallowedexprs = []

for v in oldallowedvals:
	reoldallowedexprs.append(re.compile("\d+%s" % v))
	reoldallowedexprs.append(re.compile("\d+\-\d+%s+" % v))

rechar = re.compile("c\d+")

## list of extensions, plus what language they should be mapped to
## This is not necessarily correct, but right now it suffices. Ideally a parser
## would be run on each file to see what kind of file it is.
extensions = {'.c'      : 'C',
              '.cc'     : 'C',
              '.cpp'    : 'C',
              '.cxx'    : 'C',
              '.c++'    : 'C',
              '.h'      : 'C',
              '.hh'     : 'C',
              '.hpp'    : 'C',
              '.hxx'    : 'C',
              '.l'      : 'C',
              '.qml'    : 'C',
              '.s'      : 'C',
              '.txx'    : 'C',
              '.y'      : 'C',
              '.cs'     : 'C#',
              '.groovy' : 'Java',
              '.java'   : 'Java',
              '.jsp'    : 'Java',
              '.scala'  : 'Java',
              '.as'     : 'ActionScript',
              '.js'     : 'JavaScript',
              '.php'    : 'PHP',
              '.py'     : 'Python',
              '.patch'  : 'patch',
              '.diff'   : 'patch',
             }

languages = set(extensions.values())

## a list of characters that 'strings' will split on when processing a binary file
splitcharacters = map(lambda x: chr(x), range(0,9) + range(14,32) + [127])

## process the contents of list with rewrites
## The file has per line the following fields, separated by spaces or tabs:
## * package name
## * version
## * filename
## * origin
## * sha256
## * new package name
## * new version name
def readrewritelist(rewritelist):
	## rewrite is a hash. Key is sha256 of the file.
	rewrite = {}
	try:
		rewritefile = open(rewritelist, 'r')
		rewritelines = rewritefile.readlines()
		rewritefile.close()
		for r in rewritelines:
			rs = r.strip().split()
			## format error, bail out
			if len(rs) != 7:
				return {}
			else:
				(package, version, filename, origin, sha256, newp, newv) = rs
				## dupe, skip
				if rewrite.has_key(sha256):
					continue
				else:
					rewrite[sha256] = {'package': package, 'version': version, 'filename': filename, 'origin': origin, 'newpackage': newp, 'newversion': newv}
	except:
		return {}
	return rewrite

## split on the special characters, plus remove special control characters that are
## at the beginning and end of the string in escaped form.
## Return a list of strings.
def splitSpecialChars(s):
	splits = [s]
	final_splits = []
	splitchars = []
	for i in splitcharacters:
		if i in s:
			splitchars.append(i)
	if splitchars != []:
		for i in splitchars:
			splits = filter(lambda x: x != '', reduce(lambda x, y: x + y, map(lambda x: x.split(i), splits), []))
	## Now make sure to get rid of leading control characters.
	## The reason to remove them only at the beginning and end
	## (for now) is because it is a lot easier. In the future try to
	## split on them mid-string.
	remove_chars = ["\\a", "\\b", "\\v", "\\f", "\\n", "\\r", "\\e", "\\0"]
	for i in splits:
		processed = False
		lensplit = len(i)
		while not processed and lensplit != 0:
			for c in remove_chars:
				if i.startswith(c):
					i = i[2:]
					break
				if i.endswith(c) and len(i) > 3:
					if i[-3] != "\\":
						i = i[:-2]
						break
			if lensplit == len(i):
				processed = True
				final_splits.append(i)
				break
			else:
				lensplit = len(i)
	return final_splits

## unpack the directories to be scanned. For speed improvements it might be
## wise to use a ramdisk or tmpfs for this, although when using Ninka and
## FOSSology it is definitely not I/O bound...
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

def unpack_verify(filedir, filename):
	try:
		os.stat(os.path.join(filedir, filename))
	except:
		print >>sys.stderr, "Can't find %s" % filename

## get strings plus the license. This method should be renamed to better
## reflect its true functionality...
def unpack_getstrings(filedir, package, version, filename, origin, filehash, dbpath, cleanup, license, copyrights, pool, ninkacomments, licensedb, oldpackage, oldsha256, rewrites, batarchive):
	## unpack the archive. If it fails, cleanup and return.
	## TODO: make temporary dir configurable
	temporarydir = unpack(filedir, filename, '/gpl/tmp')
	if temporarydir == None:
		c.close()
		conn.close()
		return None

	if batarchive:
		## override the data for package, version, filename, origin, filehash
		## first unpack
		## first extract the MANIFEST.BAT file from the BAT archive
		if not os.path.exists(os.path.join(temporarydir, "MANIFEST.BAT")):
			return
		manifest = os.path.join(temporarydir, "MANIFEST.BAT")
		manifestfile = open(manifest)
		manifestlines = manifestfile.readlines()
		manifestfile.close()
		inheader = False
		infiles = False
		inextensions = False
		for i in manifestlines:
			if "START META" in i:
				inheader = True
				continue
			if "END META" in i:
				inheader = False
				continue
			if "START FILES" in i:
				infiles = True
				continue
			if "END FILES" in i:
				infiles = False
				continue
			if "START EXTENSIONS" in i:
				inextensions = True
				continue
			if "END EXTENSIONS" in i:
				inextensions = False
				continue
			if inheader:
				if i.startswith('package'):
					package = i.split(':')[1].strip()
				elif i.startswith('version'):
					version = i.split(':')[1].strip()
				elif i.startswith('origin'):
					origin = i.split(':')[1].strip()
				elif i.startswith('filename'):
					filename = i.split(':')[1].strip()
				elif i.startswith('sha256'):
					filehash = i.split(':')[1].strip()
	print >>sys.stdout, "processing", filename
	sys.stdout.flush()

        conn = sqlite3.connect(dbpath, check_same_thread = False)
	c = conn.cursor()
	c.execute('PRAGMA synchronous=off')

	## First see if this exact version is in the rewrite list. If so, rewrite.
	if rewrites.has_key(filehash):
		if origin == rewrites[filehash]['origin']:
			if filename == rewrites[filehash]['filename']:
				if package == rewrites[filehash]['package']:
					if version == rewrites[filehash]['version']:
						package = rewrites[filehash]['newpackage']
						version = rewrites[filehash]['newversion']

	## Then check if version exists in the database.
	c.execute('''select sha256 from processed where package=? and version=? LIMIT 1''', (package, version))
	checkres = c.fetchall()
	if len(checkres) == 0:
		## If the version is not in 'processed' check if there are already any strings
		## from program + version. If so, first remove the results before adding to
		## avoid unnecessary duplication.
		c.execute('''select sha256 from processed_file where package=? and version=? LIMIT 1''', (package, version))
		if len(c.fetchall()) != 0:
			c.execute('''delete from processed_file where package=? and version=?''', (package, version))
			conn.commit()
	else:
		## If the version is in 'processed' then it should be checked if every file is in processed_file
		## If they are, then the versions are equivalent and no processing is needed.
		## If not, one of the versions should be renamed.
		## TODO: support for batarchive
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
					scanfiles.append((i[0], p))
		except Exception, e:
			if str(e) != "":
				print >>sys.stderr, package, version, e

		## first filter out the uninteresting files
		scanfiles = filter(lambda x: x != None, pool.map(filterfiles, scanfiles, 1))
		## compute the hashes in parallel
		scanfile_result = filter(lambda x: x != None, pool.map(computehash, scanfiles, 1))
		identical = True
		## compare amount of checksums for this version and the one recorded in the database.
		## If they are not equal the package is not identical.
		origlen = len(conn.execute('''select sha256 from processed_file where package=? and version=?''', (package, version)).fetchall())
		if len(scanfile_result) == origlen:
			tasks = map(lambda x: (dbpath, package, version, x[2]), scanfile_result)
			nonidenticals = filter(lambda x: x[1] == False, pool.map(grabhash, tasks, 1))
			if len(nonidenticals) != 0:
				identical = False
		else:
			identical = False

		if not identical:
			## rewrite the version number and process further
			version = "%s-%s-%s" % (version, origin, filehash)
			## If the version is not in 'processed' check if there are already any strings
			## from program + version. If so, first remove the results before adding to
			## avoid unnecessary duplication.
			c.execute('''select sha256 from processed_file where package=? and version=? LIMIT 1''', (package, version))
			if len(c.fetchall()) != 0:
				c.execute('''delete from processed_file where package=? and version=?''', (package, version))
				conn.commit()
		else:
			if cleanup:
				cleanupdir(temporarydir)
			return

	filetohash = {}

	if not batarchive:
		manifestdir = os.path.join(filedir, "MANIFESTS")
		if os.path.exists(manifestdir):
			if os.path.isdir(manifestdir):
				manifestfile = os.path.join(manifestdir, "%s.bz2" % filehash)
				if os.path.exists(manifestfile):
					manifest = bz2.BZ2File(manifestfile, 'r')
					manifestlines = manifest.readlines()
					manifest.close()
					for i in manifestlines:
						(fileentry, hashentry) = i.strip().split()
						filetohash[fileentry] = hashentry

	sqlres = traversefiletree(temporarydir, conn, c, package, version, license, copyrights, pool, ninkacomments, licensedb, oldpackage, oldsha256, batarchive, filetohash)
	if sqlres != []:
		## Add the file to the database: name of archive, sha256, packagename and version
		## This is to be able to just update the database instead of recreating it.
		c.execute('''insert into processed (package, version, filename, origin, sha256) values (?,?,?,?,?)''', (package, version, filename, origin, filehash))
		conn.commit()
	c.close()
	conn.close()
	if cleanup:
		cleanupdir(temporarydir)
	return sqlres

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

def grabhash((db, package, version, checksum)):
	conn = sqlite3.connect(db)
	c = conn.cursor()
	c.execute('''select sha256 from processed_file where package=? and version=? and sha256=?''', (package, version, checksum))
	cres = c.fetchall()
	if len(cres) == 0:
		identical = False
	else:
		identical = True
	c.close()
	conn.close()
	return (checksum, identical)

## Compute the SHA256 for a single file.
def filterfiles((filedir, filename)):
	resolved_path = os.path.join(filedir, filename)
	try:
		if not os.path.islink(resolved_path):
			os.chmod(resolved_path, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
	except Exception, e:
		pass
	## skip links
	if os.path.islink(resolved_path):
        	return None
	## nothing to determine about an empty file, so skip
	if os.stat(resolved_path).st_size == 0:
		return None
	## some filenames might have uppercase extensions, so lowercase them first
	p_nocase = filename.lower()
	process = False
	for extension in extensions.keys():
		if (p_nocase.endswith(extension)) and not p_nocase == extension:
			process = True
			break

	if not process:
		return None
	return (filedir, filename, extension)

def computehash((filedir, filename, extension)):
	resolved_path = os.path.join(filedir, filename)
	filemagic = ms.file(os.path.realpath(resolved_path))
	if filemagic == "AppleDouble encoded Macintosh file":
		return None
	scanfile = open(resolved_path, 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	filehash = h.hexdigest()
	return (filedir, filename, filehash, extension)

def traversefiletree(srcdir, conn, cursor, package, version, license, copyrights, pool, ninkacomments, licensedb, oldpackage, oldsha256, batarchive, filetohash):
	osgen = os.walk(srcdir)

	try:
		scanfiles = []
		while True:
			i = osgen.next()
			for p in i[2]:
				if batarchive:
					if p == 'MANIFEST.BAT':
						continue
				scanfiles.append((i[0], p))
			## make sure all directories can be accessed
			for d in i[1]:
				if not os.path.islink(os.path.join(i[0], d)):
					os.chmod(os.path.join(i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
	except Exception, e:
		if str(e) != "":
			print >>sys.stderr, package, version, e
			return
		pass

	srcdirlen = len(srcdir)+1

	## first filter out the uninteresting files
	scanfiles = filter(lambda x: x != None, pool.map(filterfiles, scanfiles, 1))
	## compute the hashes in parallel, or if available, use precomputed SHA256 from the MANIFEST file
	if filetohash != {}:
		scanfile_result = []
		new_scanfiles = []
		for i in scanfiles:
			(scanfilesdir, scanfilesfile, scanfileextension) = i
			if filetohash.has_key(os.path.join(scanfilesdir[srcdirlen:], scanfilesfile)):
				scanhash = filetohash[(os.path.join(scanfilesdir[srcdirlen:], scanfilesfile))]
				scanfile_result.append((scanfilesdir, scanfilesfile, scanhash, scanfileextension))
			else:
				new_scanfiles.append((scanfilesdir, scanfilesfile, scanfileextension))
		## sanity checks in case the MANIFEST file is incomplete
		if new_scanfiles != []:
			scanfile_result += filter(lambda x: x != None, pool.map(computehash, new_scanfiles, 1))
	else:
		scanfile_result = filter(lambda x: x != None, pool.map(computehash, scanfiles, 1))

	#ninkaversion = "b84eee21cb"
	ninkaversion = "1.1"
	insertfiles = set()
	tmpsha256s = []
	filehashes = {}
	filestoscan = []

	## loop through the files to see which files should be scanned.
	## A few assumptions are made:
	## * all tables are in a consistent state
	## * all tables are generated at the same time
	## So this is not robust if one of the databases (say, licenses)
	## is modified by another tool, or deleted and needs to be
	## regenerated.
	for s in scanfile_result:
		(path, filename, filehash, extension) = s
		insertfiles.add((os.path.join(path[srcdirlen:],filename), filehash))

		## if many versions of a single package are processed there is likely going to be
		## overlap. Avoid hitting the disk by remembering the SHA256 from a previous run.
		## This only really helps if the files are scanned in release order to decrease
		## the deltas.
		if package == oldpackage:
			if s[2] in oldsha256:
				continue
		if filehash in tmpsha256s:
			continue
		cursor.execute("select * from processed_file where sha256=? LIMIT 1", (filehash,))
		testres = cursor.fetchall()
		if len(testres) != 0:
			continue
		tmpsha256s.append(filehash)
		cursor.execute('''select * from extracted_file where sha256=? LIMIT 1''', (filehash,))
		if len(cursor.fetchall()) != 0:
			#print >>sys.stderr, "duplicate %s %s: %s/%s" % (package, version, i[0], p)
			continue
		filestoscan.append((package, version, path, filename, extensions[extension], filehash, ninkaversion))
		if filehashes.has_key(filehash):
			filehashes[filehash].append((path, filename))
		else:
			filehashes[filehash] = [(path, filename)]

	## first check licenses, since we do sometimes manipulate some source code files
	if license:
		ninkaconn = sqlite3.connect(ninkacomments, check_same_thread = False)
		ninkacursor = ninkaconn.cursor()

		licenseconn = sqlite3.connect(licensedb, check_same_thread = False)
		licensecursor = licenseconn.cursor()
		licensecursor.execute('PRAGMA synchronous=off')

		if 'patch' in languages:
			## patch files should not be scanned for license information
			comments_results = pool.map(extractcomments, filter(lambda x: x[4] != 'patch', filestoscan), 1)
		else:
			comments_results = pool.map(extractcomments, filestoscan, 1)
		commentshash = {}
		commentshash2 = {}
		for c in comments_results:
			if commentshash.has_key(c[0]):
				continue
			else:
				commentshash[c[0]] = c[1]
			if commentshash2.has_key(c[1]):
				commentshash2[c[1]].append(c[0])
			else:
				commentshash2[c[1]] = [c[0]]

		licensefilestoscan = []
		for c in commentshash2:
			ninkacursor.execute('''select license, version from ninkacomments where sha256=?''', (c,))
			res = ninkacursor.fetchall()
			if len(res) > 0:
				## store all the licenses that are already known for this comment
				for r in res:
					(filelicense, scannerversion) = r
					for f in commentshash2[c]:
						## only use this if there actually are duplicates
						#licensecursor.execute('''delete from licenses where sha256 = ? and license = ? and scanner = ? and version = ?''', (f, filelicense, "ninka", scannerversion))
						licensecursor.execute('''insert into licenses (sha256, license, scanner, version) values (?,?,?,?)''', (f, filelicense, "ninka", scannerversion))
			else:
				licensefilestoscan.append(commentshash2[c][0])
		licenseconn.commit()

		licensescanfiles = []

		for l in licensefilestoscan:
			licensescanfiles.append((filehashes[l][0][0], filehashes[l][0][1], l, ninkaversion))
		license_results = pool.map(runfullninka, licensescanfiles, 1)

		## we now know the licenses for files we didn't know before. So:
		## 1. find the corresponding commentshash
		## 2. store the licenses for this file, plus for the commentshash
		## 3. for each file that has the same commentshash, store the license as well
		for l in license_results:
			licenses = l[1]
			for license in licenses:
				ninkacursor.execute('''insert into ninkacomments (sha256, license, version) values (?,?,?)''', (commentshash[l[0]], license, ninkaversion))
				for f in commentshash2[commentshash[l[0]]]:
					licensecursor.execute('''insert into licenses (sha256, license, scanner, version) values (?,?,?,?)''', (f, license, "ninka", ninkaversion))
		licenseconn.commit()
		ninkaconn.commit()

		## cleanup
		ninkacursor.close()
		ninkaconn.close()

		## TODO: sync names of licenses as found by FOSSology and Ninka
		fossology_chunksize = 10
		fossology_filestoscan = []
		if 'patch' in languages:
			fossyfiles = filter(lambda x: x[4] != 'patch', filestoscan)
		else:
			fossyfiles = filestoscan
		for i in range(0,len(fossyfiles),fossology_chunksize):
			fossology_filestoscan.append((fossyfiles[i:i+fossology_chunksize]))
		fossology_res = filter(lambda x: x != None, pool.map(licensefossology, fossology_filestoscan, 1))
		## this requires FOSSology 2.3.0 or later
		p2 = subprocess.Popen(["/usr/share/fossology/nomos/agent/nomos", "-V"], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
		(stanout, stanerr) = p2.communicate()
		res = re.match("nomos build version: ([\d\.]+) ", stanout)
		if res != None:
			fossology_version = res.groups()[0]
		else:
			## hack for not working version number in 2.4.0
			fossology_version = '2.4.0'

		for f in fossology_res:
			for ff in f:
				(filehash, fres) = ff
				for license in fres:

					#licensecursor.execute('''delete from licenses where sha256 = ? and license = ? and scanner = ? and version = ?''', (filehash, license, "fossology", fossology_version))
					licensecursor.execute('''insert into licenses (sha256, license, scanner, version) values (?,?,?,?)''', (filehash, license, "fossology", fossology_version))
		licenseconn.commit()
		licensecursor.close()
		licenseconn.close()


	## extract copyrights
	if copyrights:
		if 'patch' in languages:
			## patch files should not be scanned for copyright information
			copyrightsres = pool.map(extractcopyrights, filter(lambda x: x[4] != 'patch', filestoscan), 1)
		else:
			copyrightsres = pool.map(extractcopyrights, filestoscan, 1)
		if copyrightsres != None:
			licenseconn = sqlite3.connect(licensedb, check_same_thread = False)
			licensecursor = licenseconn.cursor()
			licensecursor.execute('PRAGMA synchronous=off')

			for c in filter(lambda x: x != None, copyrightsres):
				(filehash, cres) = c
				for cr in cres:
					## OK, this delete is *really* stupid because we don't have an index for this
					## combination of parameters.
					#licensecursor.execute('''delete from extracted_copyright where sha256 = ? and copyright = ? and type = ? and offset = ?''', (filehash, cr[1], cr[0], cr[2]))
					licensecursor.execute('''insert into extracted_copyright (sha256, copyright, type, offset) values (?,?,?,?)''', (filehash, cr[1], cr[0], cr[2]))
			licenseconn.commit()
			licensecursor.close()
			licenseconn.close()

	## process the files to scan in parallel, then process the results
	extracted_results = pool.map(extractstrings, filestoscan, 1)

	for extractres in extracted_results:
		(filehash, language, sqlres, moduleres, results) = extractres
		for res in sqlres:
			(pstring, linenumber) = res
			cursor.execute('''insert into extracted_file (programstring, sha256, language, linenumber) values (?,?,?,?)''', (pstring, filehash, language, linenumber))
		if moduleres.has_key('parameters'):
			for res in moduleres['parameters']:
				(pstring, ptype) = res
				cursor.execute('''insert into kernelmodule_parameter (sha256, modulename, paramname, paramtype) values (?,?,?,?)''', (filehash, None, pstring, ptype))
		if moduleres.has_key('alias'):
			for res in moduleres['alias']:
				cursor.execute('''insert into kernelmodule_alias (sha256, modulename, alias) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('author'):
			for res in moduleres['author']:
				cursor.execute('''insert into kernelmodule_author (sha256, modulename, author) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('descriptions'):
			for res in moduleres['descriptions']:
				cursor.execute('''insert into kernelmodule_description (sha256, modulename, description) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('firmware'):
			for res in moduleres['firmware']:
				cursor.execute('''insert into kernelmodule_firmware (sha256, modulename, firmware) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('license'):
			for res in moduleres['license']:
				cursor.execute('''insert into kernelmodule_license (sha256, modulename, license) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('versions'):
			for res in moduleres['versions']:
				cursor.execute('''insert into kernelmodule_version (sha256, modulename, version) values (?,?,?)''', (filehash, None, res))
		if moduleres.has_key('param_descriptions'):
			for res in moduleres['param_descriptions']:
				cursor.execute('''insert into kernelmodule_parameter_description (sha256, modulename, paramname, description) values (?,?,?, ?)''', (filehash, None) + res)

		if language == 'C':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'function':
					cursor.execute('''insert into extracted_function (sha256, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
				elif nametype == 'kernelfunction':
					cursor.execute('''insert into extracted_function (sha256, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, 'linuxkernel', linenumber))
				else:
					cursor.execute('''insert into extracted_name (sha256, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, language, linenumber))
		elif language == 'C#':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'method':
					cursor.execute('''insert into extracted_function (sha256, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
		elif language == 'Java':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'method':
					cursor.execute('''insert into extracted_function (sha256, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
				else:
					cursor.execute('''insert into extracted_name (sha256, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, language, linenumber))

		elif language == 'PHP':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'function':
					cursor.execute('''insert into extracted_function (sha256, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
				else:
					cursor.execute('''insert into extracted_name (sha256, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, language, linenumber))

		elif language == 'Python':
			for res in results:
				(cname, linenumber, nametype) = res
				if nametype == 'function' or nametype == 'member':
					cursor.execute('''insert into extracted_function (sha256, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, language, linenumber))
				else:
					cursor.execute('''insert into extracted_name (sha256, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, language, linenumber))
	conn.commit()

	for i in insertfiles:
		cursor.execute('''insert into processed_file (package, version, filename, sha256) values (?,?,?,?)''', (package, version, i[0], i[1]))
	conn.commit()

	if not os.path.exists(os.path.join(srcdir, "MANIFEST.BAT")):
		return
	manifest = os.path.join(srcdir, "MANIFEST.BAT")
	manifestfile = open(manifest)
	manifestlines = manifestfile.readlines()
	manifestfile.close()
	inheader = False
	infiles = False
	inextensions = False
	for i in manifestlines:
		if "START META" in i:
			inheader = True
			continue
		if "END META" in i:
			inheader = False
			continue
		if "START FILES" in i:
			infiles = True
			continue
		if "END FILES" in i:
			infiles = False
			continue
		if "START EXTENSIONS" in i:
			inextensions = True
			continue
		if "END EXTENSIONS" in i:
			inextensions = False
			continue
		if infiles:
			(archivepath, archivechecksum, archiveversion) = i.strip().split('\t')
			cursor.execute('''insert into processed_file (package, version, filename, sha256) values (?,?,?,?)''', (package, version, archivepath, archivechecksum))
	conn.commit()
	return (scanfile_result)

## extract comments in parallel
def extractcomments((package, version, i, p, language, filehash, ninkaversion)):
	## first generate a .comments file with Ninka and see if it is already
	## known. This is because often license headers are identical, and
	## there is no need to rescan the files if the headers are identical.
	## For gtk+ 2.20.1 scanning time dropped with about 25%.
	ninkaenv = os.environ.copy()
	ninkabasepath = '/gpl/ninka/ninka-%s' % ninkaversion
	ninkaenv['PATH'] = ninkaenv['PATH'] + ":%s/comments" % ninkabasepath

	p1 = subprocess.Popen(["%s/ninka.pl" % ninkabasepath, "-c", os.path.join(i, p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ninkaenv)
	(stanout, stanerr) = p1.communicate()
	scanfile = open("%s/%s.comments" % (i, p), 'r')
	ch = hashlib.new('sha256')
	ch.update(scanfile.read())
	scanfile.close()
	commentshash = ch.hexdigest()
	return (filehash, commentshash)

def runfullninka((i, p, filehash, ninkaversion)):
	ninkaenv = os.environ.copy()
	ninkabasepath = '/gpl/ninka/ninka-%s' % ninkaversion
	ninkaenv['PATH'] = ninkaenv['PATH'] + ":%s/comments" % ninkabasepath

	ninkares = set()

	p2 = subprocess.Popen(["%s/ninka.pl" % ninkabasepath, os.path.join(i, p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ninkaenv)
	(stanout, stanerr) = p2.communicate()
	ninkasplit = stanout.strip().split(';')[1:]
	## filter out the licenses that can't be determined.
	if ninkasplit[0] == '':
		ninkares = set(['UNKNOWN'])
	else:
		licenses = ninkasplit[0].split(',')
		ninkares = set(licenses)
	return (filehash, ninkares)

def extractcopyrights((package, version, i, p, language, filehash, ninkaversion)):
	copyrightsres = []
	p2 = subprocess.Popen(["/usr/share/fossology/copyright/agent/copyright", "-C", os.path.join(i, p)], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
	(stanout, stanerr) = p2.communicate()
	if "FATAL" in stanout:
		## TODO: better error handling
		return None
	else:
		clines = stanout.split("\n")
		continuation = True
		bufstr = ""
		buftype = ""
		offset = 0
		for c in clines[1:]:
			## Extract copyright information, like URLs, e-mail
			## addresses and copyright statements.
			## Copyright statements and URLs are not very accurate.
			## URLs extracted from BusyBox for example contain links
			## to standards, RFCs, other project's bug trackers, and
			## so on. It is not a good indicator of anything
			## unless some extra filtering is added, like searching for
			## URLs that point to licenses that were not included in
			## the binary.
			res = recopyright.match(c.strip())
			if res != None:
				if continuation:
					if bufstr != "" and buftype != "":
						copyrightsres.append((buftype, bufstr, offset))
				continuation = False
				bufstr = ""
				buftype = ""
				offset = res.groups()[0]
				## e-mail addresses are never on multiple lines
				if res.groups()[1] == 'email':
					copyrightsres.append(('email', res.groups()[2], offset))
				## urls should are never on multiple lines
				elif res.groups()[1] == 'url':
					copyrightsres.append(('url', res.groups()[2], offset))
				## copyright statements can be on multiple lines, but this is
				## the start of a new statement
				elif res.groups()[1] == 'statement':
					continuation = True
					buftype = "statement"
					bufstr = res.groups()[2]
			else:
				res = recopyright2.match(c.strip())
				if res != None:
					if res.groups()[1] == 'statement':
						continuation = True
						buftype = "statement"
						bufstr = res.groups()[2]
						offset = res.groups()[0]
				else:
					bufstr = bufstr + "\n" + c.strip()
					continuation = True
		## perhaps some lingering data
		if continuation:
			if bufstr != "" and buftype != "":
				copyrightsres.append((buftype, bufstr, offset))
		## TODO: clean up 'statement' and 'url', since there is quite a
		## bit of bogus data present.
	return (filehash, copyrightsres)

def licensefossology((packages)):
	## Also run FOSSology. This requires that the user has enough privileges to actually connect to the
	## FOSSology database, for example by being in the correct group.
	fossologyres = []
	fossscanfiles = map(lambda x: os.path.join(x[2], x[3]), packages)
	scanargs = ["/usr/share/fossology/nomos/agent/nomos"] + fossscanfiles
	p2 = subprocess.Popen(scanargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	(stanout, stanerr) = p2.communicate()
	if "FATAL" in stanout:
		## TODO: better error handling
		return None
	else:
		fosslines = stanout.strip().split("\n")
		for j in range(0,len(fosslines)):
			fossysplit = fosslines[j].strip().rsplit(" ", 1)
			licenses = fossysplit[-1].split(',')
			fossologyres.append((packages[j][5], set(licenses)))
	return fossologyres

## TODO: get rid of ninkaversion before we call this method
## TODO: process more files at once to reduce overhead of calling ctags
def extractstrings((package, version, i, p, language, filehash, ninkaversion)):
	if language == 'patch':
		## The file is a patch/diff file. Take the following steps to deal with it:
		## 1. find out what kind of diff file it is. Stick to dealing with a unified diff file for now
		## 2. find out how many files are inside the diff
		## 3. find out which files these manipulate and if these would have been processed
		## 4. find out which lines are added to the files
		patchfile = open(os.path.join(i,p))
		patchcontent = patchfile.read()
		patchfile.close()
		patchlines = patchcontent.split('\n')

		unified = False

		## keep track of how many patches are in the file
		unifiedpatches = 0
		addlines = []
		unifiedmin = False
		unifiedplus = False
		skippatch = False
		oldfile = ""
		newfile = ""

		## keep track of how many lines are in the patch
		linecounter = 0
		for l in patchlines:
			linecounter += 1
			if unifiedmin and unifiedplus:
				## at least one patch in the file seems to be valid
				unified = True
			if l.startswith('---'):
				if unifiedmin:
					## this should not happen, malformed patch
					## unclear what to do with this so ignore for now
					pass
				unifiedmin = True
				## reset some values
				skippatch = False
				unifiedplus = False
				patchsplits = l.split()
				if len(patchsplits) < 2:
					## this should not happen, malformed patch
					skippatch = True
					continue
				oldfile = os.path.basename(patchsplits[1])
				continue
			if l.startswith('+++'):
				if not unifiedmin:
					## this should not happen, malformed patch
					skippatch = True
					continue
				## TODO: the line starting with '+++' should follow the line with '---' immediately
				## assume for now that this happens
				patchsplits = l.split()
				if len(patchsplits) < 2:
					## this should not happen, malformed patch
					skippatch = True
					continue

				process = False
				newfile = os.path.basename(patchsplits[1])
				if newfile == oldfile:
					## easy case since both file names have the same name.
					p_nocase = oldfile.lower()
					for extension in extensions.keys():
						if (p_nocase.endswith(extension)) and not p_nocase == extension:
							process = True
							break
				else:
					## either oldfile or newfile needs to match
					p_nocase = oldfile.lower()
					for extension in extensions.keys():
						if (p_nocase.endswith(extension)) and not p_nocase == extension:
							process = True
							break
					if not process:
						p_nocase = newfile.lower()
						for extension in extensions.keys():
							if (p_nocase.endswith(extension)) and not p_nocase == extension:
								process = True
								break

				if not process:
					skippatch = True
					continue
				unifiedplus = True
			if not unifiedmin:
				## first few lines of the patch
				continue
			if skippatch:
				continue
			## now process the lines
			if l.startswith ('-'):
				continue
			if l.startswith (' '):
				continue
			## store the current line number in a list of lines that start with '+'
			addlines.append(linecounter)

		if not unified:
			sqlres = []
			moduleres = {}
		else:
			## TODO: clean up
			(patchsqlres, moduleres) = extractsourcestrings(p, i, language, package)
			sqlres = []
			for sql in patchsqlres:
				(res, linenumber) = sql
				if linenumber in addlines:
					sqlres.append(sql)
	else:
		(sqlres, moduleres) = extractsourcestrings(p, i, language, package)

	results = set()

	## extract function names using ctags, except functions from
	## the Linux kernel, since it will never be dynamically linked
	## but variable names are sometimes stored in a special ELF
	## section called __ksymtab__strings
	# (name, linenumber, type)

	if (language in ['C', 'C#', 'Java', 'PHP', 'Python']):

		p2 = subprocess.Popen(["ctags", "-f", "-", "-x", os.path.join(i, p)], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
		(stanout2, stanerr2) = p2.communicate()
		if p2.returncode != 0:
			pass
		elif stanout2.strip() == "":
			pass
		else:
			stansplit = stanout2.strip().split("\n")
			for res in stansplit:
				csplit = res.strip().split()
				if filter(lambda x: x not in string.printable, csplit[0]) != "":
					continue
				if language == 'C':
					if package == 'linux':
						## for the Linux kernel the variable names are sometimes
						## stored in a special ELF section __ksymtab_strings
						if csplit[1] == 'variable':
							if "EXPORT_SYMBOL_GPL" in csplit[4]:
								results.add((csplit[0], int(csplit[2]), 'gplkernelsymbol'))
							elif "EXPORT_SYMBOL" in csplit[4]:
								results.add((csplit[0], int(csplit[2]), 'kernelsymbol'))
						elif csplit[1] == 'function':
							results.add((csplit[0], int(csplit[2]), 'kernelfunction'))
					else:
						if csplit[1] == 'variable':
							if len(csplit) < 5:
								results.add((csplit[0], int(csplit[2]), 'variable'))
							else:
								if "EXPORT_SYMBOL_GPL" in csplit[4]:
									results.add((csplit[0], int(csplit[2]), 'gplkernelsymbol'))
								elif "EXPORT_SYMBOL" in csplit[4]:
									results.add((csplit[0], int(csplit[2]), 'kernelsymbol'))
								else:
									results.add((csplit[0], int(csplit[2]), 'variable'))
						elif csplit[1] == 'function':
							results.add((csplit[0], int(csplit[2]), 'function'))
				if language == 'C#':
					for i in ['method']:
						if csplit[1] == i:
							results.add((csplit[0], int(csplit[2]), i))
				if language == 'Java':
					for i in ['method', 'class', 'field']:
						if csplit[1] == i:
							results.add((csplit[0], int(csplit[2]), i))
				if language == 'PHP':
					## ctags does not nicely handle comments, so sometimes there are
					## false positives.
					for i in ['variable', 'function', 'class']:
						if csplit[1] == i:
							results.add((csplit[0], int(csplit[2]), i))
				if language == 'Python':
					## TODO: would be nice to store members with its surrounding class
					for i in ['variable', 'member', 'function', 'class']:
						if csplit[0] == '__init__':
							break
						if csplit[1] == i:
							results.add((csplit[0], int(csplit[2]), i))
							break

	return (filehash, language, sqlres, moduleres, results)

## Extract strings using xgettext. Apparently this does not always work correctly. For example for busybox 1.6.1:
## $ xgettext -a -o - fdisk.c
##  xgettext: Non-ASCII string at fdisk.c:203.
##  Please specify the source encoding through --from-code.
## We fix this by rerunning xgettext with --from-code=utf-8
## The results might not be perfect, but they are acceptable.
## TODO: use version from bat/extractor.py
## TODO: process more files at once to reduce overhead of calling xgettext
def extractsourcestrings(filename, filedir, language, package):
	remove_chars = ["\\a", "\\b", "\\v", "\\f", "\\e", "\\0"]
	sqlres = []

	## moduleres is only used for storing information about Linux kernel module
	moduleres = {}
	## for files that we think are in the 'C' family we first check for unprintable
	## characters like \0. xgettext doesn't like these and will stop as soon as it
	## encounters one of these characters, possibly missing out on some very significant
	## strings that we *do* want to see because they end up in the binary. We replace
	## them with \n, then run xgettext.
	## TODO: fix for octal values, like \010
	if language == 'C':
		changed = False
		scanfile = open(os.path.join(filedir, filename))
		filecontents = scanfile.read()
		scanfile.close()

		## suck in the file and look for __ATTR and friends, since the
		## first parameter is given to stringify(). __ATTR was gradually
		## introduced in kernel 2.6.8.
		if package == 'linux':
			paramres = []
			licenseres = []
			aliasres = []
			authorres = []
			descriptionres = []
			regresults = []
			firmwareres = []
			versionres = []
			paramdescriptionres = []
			for ex in kernelexprs:
				regexres = ex.findall(filecontents)
				if regexres != []:
					regresults = regresults + regexres
			if regresults != []:
				## first filter 'name' and '_name' since those are frequently
				## used in the #define statements for __ATTR etc.
				## The linenumber is set to 0 since using regular expressions
				## it is not easy to find that out unless an extra step is performed.
				## This is something for a future TODO.
				sqlres += map(lambda x: (x, 0), filter(lambda x: x != '_name' and x != 'name', list(set(regresults))))
			## Extract a whole bunch of information relating to modules. Using regular expressions is
			## actually not the right way to do it since some of the information is hidden in macros
			## and #defines and what not, so actually the source tree needs to be properly preprocessed
			## first. However, this will do for now.
			## TODO: partially replace with call to xgettext and grep -n for weird accents

			## Both module_param and MODULE_PARM formats were in use at the same time
			## include/linux/moduleparam.h in Linux kernel sources documents various types
			allowedvals= ["bool", "byte", "charp", "int", "uint", "string", "short", "ushort", "long", "ulong"]
			oldallowedvals= ["b", "c", "h", "i", "l", "s"]
			if "module_param" in filecontents:
				## first try module_param()
				regexres = re.findall("module_param\s*\(([\w\d]+),\s*(\w+)", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in allowedvals, regexres)
					for p in parres:
						paramres.append(p)

				## then module_param_named()
				regexres = re.findall("module_param_named\s*\(([\w\d]+),\s*[\w\d]+,\s*(\w+)", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in allowedvals, regexres)
					for p in parres:
						paramres.append(p)

				## then module_param_array()
				regexres = re.findall("module_param_array\s*\(([\w\d]+),\s*(\w+)", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in allowedvals, regexres)
					## oh, this is ugly...does this even work correctly with localised versions?
					parres = map(lambda x: (x[0], "array of %s" % x[1]), parres)
					for p in parres:
						paramres.append(p)

				## then module_param_array_named()
				regexres = re.findall("module_param_array_named\s*\(([\w\d]+),\s*[\w\d]+,\s*(\w+)", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in allowedvals, regexres)
					## oh, this is ugly...does this even work correctly with localised versions?
					parres = map(lambda x: (x[0], "array of %s" % x[1]), parres)
					for p in parres:
						paramres.append(p)

				## finally module_param_string()
				regexres = re.findall("module_param_string\s*\(([\w\d]+),", filecontents, re.MULTILINE)
				if regexres != []:
					parres = map(lambda x: (x, "string"), regexres)
					for p in parres:
						paramres.append(p)

			if "MODULE_PARM" in filecontents:
				regexres = re.findall("MODULE_PARM\s*\(([\w\d]+),\s*\"([\w\d\-]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					parres = filter(lambda x: x[1] in oldallowedvals, regexres)
					parres2 = filter(lambda x: x[1] not in oldallowedvals, regexres)
					for p in parres:
						paramres.append(p)
					for p in parres2:
						for v in reoldallowedexprs:
							if v.search(p[1]) != None:
								paramres.append(p)
								break
						## and special case for characters
						#if re.search("c\d+", p[1]) != None:
						if rechar.search(p[1]) != None:
							paramres.append(p)
			moduleres['parameters'] = paramres

			## extract information from the MODULE_ALIAS field
			if "MODULE_ALIAS" in filecontents:
				regexres = re.findall("MODULE_ALIAS\s*\(\s*\"([\w\d:,\-\_\s/\[\]\*]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in regexres:
						aliasres.append(p)
			moduleres['alias'] = aliasres

			## extract information from the MODULE_AUTHOR field
			## TODO: this does not work well with accents and characters from various languages
			## TODO: combine with extracted strings to increase quality
			if "MODULE_AUTHOR" in filecontents:
				regexres = re.findall("MODULE_AUTHOR\s*\(\s*\"([\w\d/\s,\.\-:<>@\(\)[\]\+&;'~\\\\]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in regexres:
						authorres.append(p)
			moduleres['author'] = authorres

			## extract information from the MODULE_DESCRIPTION field
			## Although these are already stored as generic strings it makes sense to also store them
			## separately with more module information
			## TODO: combine with extracted strings to increase quality
			if "MODULE_DESCRIPTION" in filecontents:
				regexres = re.findall("MODULE_DESCRIPTION\s*\(\s*\"([\w\d/_\(\)\[\]\\\\\!\?;#$%^\*&<>\{\}\':+=\|\-\.,\s]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in regexres:
						descriptionres.append(p)
			moduleres['descriptions'] = descriptionres

			## extract information from the MODULE_FIRMWARE field
			if "MODULE_FIRMWARE" in filecontents:
				regexres = re.findall("MODULE_FIRMWARE\s*\(\s*\"([\w\d/_\-\.]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in regexres:
						firmwareres.append(p)
			moduleres['firmware'] = firmwareres

			## extract information from the MODULE_LICENSE field
			if "MODULE_LICENSE" in filecontents:
				regexres = re.findall("MODULE_LICENSE\s*\(\s*\"([\w\d/\s]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in regexres:
						licenseres.append(p)
			moduleres['license'] = licenseres

			## extract information from the MODULE_VERSION field
			if "MODULE_VERSION" in filecontents:
				regexres = re.findall("MODULE_VERSION\s*\(\s*\"([\w\d/_\-\.\s]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in regexres:
						versionres.append(p)
			moduleres['versions'] = versionres

			if "MODULE_PARM_DESC" in filecontents:
				regexres = re.findall("MODULE_PARM_DESC\s*\(\s*([\w\d]+),\s*\"([\w\d/_\(\)\[\]\\\\\!\?;#$%^\*&<>\{\}\':+=\|\-\.,\s]+)\"\s*\)\s*;", filecontents, re.MULTILINE)
				if regexres != []:
					for p in regexres:
						paramdescriptionres.append(p)
			moduleres['param_descriptions'] = paramdescriptionres

		for r in remove_chars:
			if r in filecontents:
				changed = True
				filecontents = filecontents.replace(r, '\\n')
		if changed:
			scanfile = open(os.path.join(filedir, filename), 'w')
			scanfile.write(filecontents)
			scanfile.close()

	p1 = subprocess.Popen(['xgettext', '-a', "--omit-header", "--no-wrap", os.path.join(filedir, filename), '-o', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p1.communicate()
	if p1.returncode != 0:
		## analyze stderr first
		if "Non-ASCII" in stanerr:
			## rerun xgettext with a different encoding
			p2 = subprocess.Popen(['xgettext', '-a', "--omit-header", "--no-wrap", "--from-code=utf-8", os.path.join(filedir, filename), '-o', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			## overwrite stanout
			(stanout, pstanerr) = p2.communicate()
			if p2.returncode != 0:
				return (sqlres, moduleres)
	source = stanout 
	lines = []
	linenumbers = []

	## escape just once to speed up extraction of filenumbers
	filename_escape = re.escape(filename)

	for l in stanout.split("\n"):
		## skip comments and hints
		if l.startswith("#, "):
			continue
		if l.startswith("#: "):
			## there can actually be more than one entry on a single line
			res = re.findall("%s:(\d+)" % (filename_escape,), l[3:])
			if res != None:
				linenumbers = linenumbers + map(lambda x: int(x), res)
			else:
				linenumbers.append(0)

		if l.startswith("msgid "):
			lines = []
			lines.append(l[7:-1])
		## when we see msgstr "" we have reached the end of a block and we can start
		## processing
		elif l.startswith("msgstr \"\""):
			count = len(linenumbers)
			for xline in lines:
				splits=splitSpecialChars(xline)
				if splits == []:
					continue
				for splitline in splits:
					for line in splitline.split("\\r\\n"):
						for sline in line.split("\\n"):
							## is this really needed?
							sline = sline.replace("\\\n", "")

							## unescape a few values
							sline = sline.replace("\\\"", "\"")
							sline = sline.replace("\\t", "\t")
							sline = sline.replace("\\\\", "\\")
	
							## don't store empty strings, they won't show up in binaries
							## but they do make the database a lot larger
							if sline == '':
								continue
							for i in range(0, len(linenumbers)):
								sqlres.append((sline, linenumbers[i]))
			linenumbers = []
		## the other strings are added to the list of strings we need to process
		else:
			lines.append(l[1:-1])
	return (sqlres, moduleres)

def checkalreadyscanned((filedir, package, version, filename, origin, batarchive, dbpath, checksums)):
	resolved_path = os.path.join(filedir, filename)
	try:
		os.stat(resolved_path)
	except:
		print >>sys.stderr, "Can't find %s" % filename
		return None
	if batarchive:
		## first extract the MANIFEST.BAT file from the BAT archive
		## TODO: add support for unpackdir
		archivedir = tempfile.mkdtemp()
		tar = tarfile.open(resolved_path, 'r')
		tarmembers = tar.getmembers()
		for i in tarmembers:
			## TODO: sanity check to see if there is a MANIFEST.BAT
			if i.name.endswith('MANIFEST.BAT'):
				tar.extract(i, path=archivedir)
		manifest = os.path.join(archivedir, "MANIFEST.BAT")
		manifestfile = open(manifest)
		manifestlines = manifestfile.readlines()
		manifestfile.close()
		shutil.rmtree(archivedir)
		for i in manifestlines:
			## for later checks the package and filehash are important
			## The rest needs to be overriden later anyway
			if i.startswith('package'):
				package = i.split(':')[1].strip()
			elif i.startswith('sha256'):
				filehash = i.split(':')[1].strip()
				break
	else:
		if checksums.has_key(filename):
			filehash = checksums[filename]
		else:
			scanfile = open(resolved_path, 'r')
			h = hashlib.new('sha256')
			h.update(scanfile.read())
			scanfile.close()
			filehash = h.hexdigest()

	conn = sqlite3.connect(dbpath, check_same_thread = False)
	c = conn.cursor()
	## Check if we've already processed this file. If so, we can easily skip it and return.
	c.execute('''select * from processed where sha256=?''', (filehash,))
	if len(c.fetchall()) != 0:
		res = None
	else:
		res = (package, version, filename, origin, filehash, batarchive)
	c.close()
	conn.close()

	return res

def main(argv):
	config = ConfigParser.ConfigParser()

	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")

	## the following options are provided on the commandline
	parser.add_option("-b", "--blacklist", action="store", dest="blacklist", help="path to blacklist file", metavar="FILE")
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-t", "--rewritelist", action="store", dest="rewritelist", help="path to rewrite list", metavar="FILE")
	parser.add_option("-v", "--verify", action="store_true", dest="verify", help="verify files, don't process (default: false)")
	(options, args) = parser.parse_args()


	if options.cfg == None:
		parser.error("Specify configuration file")
	else:
		if not os.path.exists(options.cfg):
			parser.error("Configuration file does not exist")
		try:
			configfile = open(options.cfg, 'r')
		except:
			parser.error("Configuration file not readable")
		config.readfp(configfile)
		configfile.close()

	if options.filedir == None:
		parser.error("Specify dir with files")
	else:
		try:
			filelist = open(os.path.join(options.filedir,"LIST")).readlines()
		except:
			parser.error("'LIST' not found in file dir")

	if options.blacklist != None:
		try:
			blacklistlines = open(options.blacklist).readlines()
		except:
			parser.error("blacklist defined but not found/accessible")
	else:
		blacklistlines = []

	## TODO: fix format for blacklist
	## package version filename origin sha256sum
	## with sha256sum being decisive 
	blacklistsha256sums = []
	for i in blacklistlines:
		try:
			unpacks = i.strip().split()
			(package, version, filename, origin, sha256sum) = unpacks
			blacklistsha256sums.append(sha256sum)
		except Exception, e:
			# oops, something went wrong
			print >>sys.stderr, e

	## search configuration to see if it is correct and/or not malformed
	## first search for a section called 'extractconfig' with configtype = global
	for section in config.sections():
		if section == "extractconfig":
			try:
				sec = config.get(section, 'scancopyright')
				if sec == 'yes':
					scancopyright = True
				else:
					scancopyright = False
			except:
				scancopyright = False
			try:
				sec = config.get(section, 'scanlicense')
				if sec == 'yes':
					scanlicense = True
				else:
					scanlicense = False
			except:
				scanlicense = False
			try:
				masterdatabase = config.get(section, 'database')
			except:
				print >>sys.stderr, "Database location not defined in configuration file. Exiting..."
				sys.exit(1)
			try:
				sec = config.get(section, 'cleanup')
				if sec == 'yes':
					cleanup = True
				else:
					cleanup = False
			except:
				cleanup = False
			try:
				sec = config.get(section, 'wipe')
				if sec == 'yes':
					wipe = True
				else:
					wipe = False
			except:
				wipe = False
			try:
				licensedb = config.get(section, 'licensedb')
			except:
				licensedb = None
			try:
				ninkacomments = config.get(section, 'ninkacommentsdb')
			except:
				ninkacomments = None
	if scanlicense:
		license = True
		## check if FOSSology is actually running
		p2 = subprocess.Popen(["/usr/share/fossology/nomos/agent/nomos", "-h"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stanout, stanerr) = p2.communicate()
		if "FATAL" in stanerr:
			print >>sys.stderr, "ERROR: license scanning enabled, but FOSSology not running"
			sys.exit(1)
		if licensedb == None:
			parser.error("License scanning enabled, but no path to licensing database supplied")
		if ninkacomments == None:
			parser.error("License scanning enabled, but no path to ninkacomments database supplied")
		if ninkacomments == masterdatabase:
			parser.error("Database and ninkacomments database cannot be the same")
	else:
		license = False

	if scancopyright != None:
		copyrights = True
		p2 = subprocess.Popen(["/usr/share/fossology/copyright/agent/copyright", "-h"], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
		(stanout, stanerr) = p2.communicate()
		if "FATAL" in stanout:
			print >>sys.stderr, "ERROR: copyright extraction enabled, but FOSSology not running"
			sys.exit(1)
		if licensedb == None:
			parser.error("Copyright scanning enabled, but no path to copyright database supplied")
	else:
		copyrights = False

	## optionally rewrite files
	if options.rewritelist != None:
		if not os.path.exists(options.rewritelist):
			parser.error("rewrite list specified, but does not exist")
		if not (os.path.isfile(options.rewritelist) or os.path.islink(options.rewritelist)):
			parser.error("rewrite list specified, but is not a file")
		rewrites = readrewritelist(options.rewritelist)
	else:
		rewrites = {}

	if (scanlicense or scancopyright) and licensedb == None:
		print >>sys.stderr, "Specify path to licenses/copyrights database"
		sys.exit(1)

	conn = sqlite3.connect(masterdatabase, check_same_thread = False)
	c = conn.cursor()
	#c.execute('PRAGMA synchronous=off')

	if scanlicense:
		ninkaconn = sqlite3.connect(ninkacomments, check_same_thread = False)
		ninkac = ninkaconn.cursor()

	if scanlicense or scancopyright:
		licenseconn = sqlite3.connect(licensedb, check_same_thread = False)
		licensec = licenseconn.cursor()

	if wipe:
		try:
			c.execute('''drop table extracted''')
		except:
			pass
		try:
			c.execute('''drop table processed''')
		except:
			pass
		try:
			c.execute('''drop table processed_file''')
		except:
			pass
		try:
			c.execute('''drop table extracted_file''')
		except:
			pass
		try:
			licensec.execute('''drop table licenses''')
			licensec.execute('''drop table extracted_copyright''')
			licenseconn.commit()
		except:
			pass
		try:
			ninkac.execute('''drop table ninkacomments''')
			ninkaconn.commit()
		except:
			pass

		conn.commit()
        try:
		## Keep an archive of which packages and archive files (tar.gz, tar.bz2, etc.) we've already
		## processed, so we don't repeat work.
		c.execute('''create table if not exists processed (package text, version text, filename text, origin text, sha256 text)''')
		c.execute('''create index if not exists processed_index on processed(package, version)''')
		c.execute('''create index if not exists processed_checksum on processed(sha256)''')
		c.execute('''create index if not exists processed_origin on processed(origin)''')

		## Keep an archive of which packages are blacklisted. This is useful during database creation,
		## or during database expansion.
		#c.execute('''create table if not exists blacklist (package text, version text, filename text, origin text, sha256 text)''')
		#c.execute('''create index if not exists blacklist_index on blacklist(package, version)''')

		## Since there is a lot of duplication inside source packages we store strings per checksum
		## which we can later link with files
		c.execute('''create table if not exists processed_file (package text, version text, filename text, sha256 text)''')
		c.execute('''create index if not exists processedfile_index on processed_file(sha256)''')
		c.execute('''create index if not exists processedfile_package_index on processed_file(package)''')
		c.execute('''create unique index if not exists processedfile_package_index_unique on processed_file(package, version, filename, sha256)''')

		## Store the extracted strings per checksum, not per (package, version, filename).
		## This saves a lot of space in the database
		## The field 'language' denotes what 'language' (family) the file the string is extracted from
		## is in. Possible values: extensions.values()
		c.execute('''create table if not exists extracted_file (programstring text, sha256 text, language text, linenumber int)''')
		c.execute('''create index if not exists programstring_index on extracted_file(programstring)''')
		c.execute('''create index if not exists extracted_hash on extracted_file(sha256)''')
		c.execute('''create index if not exists extracted_language on extracted_file(language);''')

		## Store the function names extracted, per checksum
		c.execute('''create table if not exists extracted_function (sha256 text, functionname text, language text, linenumber int)''')
		c.execute('''create index if not exists function_index on extracted_function(sha256);''')
		c.execute('''create index if not exists functionname_index on extracted_function(functionname)''')
		c.execute('''create index if not exists functionname_language on extracted_function(language);''')

		## Store different information extracted with ctags
		c.execute('''create table if not exists extracted_name (sha256 text, name text, type text, language text, linenumber int)''')
		c.execute('''create index if not exists name_checksum_index on extracted_name(sha256);''')
		c.execute('''create index if not exists name_name_index on extracted_name(name)''')
		c.execute('''create index if not exists name_type_index on extracted_name(type)''')
		c.execute('''create index if not exists name_language_index on extracted_name(language);''')

		## Store information about Linux kernel modules
		c.execute('''create table if not exists kernelmodule_alias(sha256 text, modulename text, alias text)''')
		c.execute('''create table if not exists kernelmodule_author(sha256 text, modulename text, author text)''')
		c.execute('''create table if not exists kernelmodule_description(sha256 text, modulename text, description text)''')
		c.execute('''create table if not exists kernelmodule_firmware(sha256 text, modulename text, firmware text)''')
		c.execute('''create table if not exists kernelmodule_license(sha256 text, modulename text, license text)''')
		c.execute('''create table if not exists kernelmodule_parameter(sha256 text, modulename text, paramname text, paramtype text)''')
		c.execute('''create table if not exists kernelmodule_parameter_description(sha256 text, modulename text, paramname text, description text)''')
		c.execute('''create table if not exists kernelmodule_version(sha256 text, modulename text, version text)''')

		c.execute('''create index if not exists kernelmodule_alias_index on kernelmodule_alias(alias)''')
		c.execute('''create index if not exists kernelmodule_author_index on kernelmodule_author(author)''')
		c.execute('''create index if not exists kernelmodule_description_index on kernelmodule_description(description)''')
		c.execute('''create index if not exists kernelmodule_firmware_index on kernelmodule_firmware(firmware)''')
		c.execute('''create index if not exists kernelmodule_license_index on kernelmodule_license(license)''')
		c.execute('''create index if not exists kernelmodule_parameter_index on kernelmodule_parameter(paramname)''')
		c.execute('''create index if not exists kernelmodule_parameter_description_index on kernelmodule_parameter_description(description)''')
		c.execute('''create index if not exists kernelmodule_version_index on kernelmodule_version(version)''')

		c.execute('''create index if not exists kernelmodule_alias_sha256index on kernelmodule_alias(sha256)''')
		c.execute('''create index if not exists kernelmodule_author_sha256index on kernelmodule_author(sha256)''')
		c.execute('''create index if not exists kernelmodule_description_sha256index on kernelmodule_description(sha256)''')
		c.execute('''create index if not exists kernelmodule_firmware_sha256index on kernelmodule_firmware(sha256)''')
		c.execute('''create index if not exists kernelmodule_license_sha256index on kernelmodule_license(sha256)''')
		c.execute('''create index if not exists kernelmodule_parameter_sha256index on kernelmodule_parameter(sha256)''')
		c.execute('''create index if not exists kernelmodule_parameter_description_sha256index on kernelmodule_parameter_description(sha256)''')
		c.execute('''create index if not exists kernelmodule_version_sha256index on kernelmodule_version(sha256)''')
		conn.commit()

		if scanlicense or scancopyright:
			## Store the extracted licenses per checksum.
			licensec.execute('''create table if not exists licenses (sha256 text, license text, scanner text, version text)''')
			licensec.execute('''create index if not exists license_index on licenses(sha256);''')

			## Store the copyrights extracted by FOSSology, per checksum
			## type can be:
			## * email
			## * statement
			## * url
			licensec.execute('''create table if not exists extracted_copyright (sha256 text, copyright text, type text, offset int)''')
			licensec.execute('''create index if not exists copyright_index on extracted_copyright(sha256);''')
			licensec.execute('''create index if not exists copyright_type_index on extracted_copyright(copyright, type);''')
			licenseconn.commit()
			licensec.close()
			licenseconn.close()

		if scanlicense:
			## Store the comments extracted by Ninka per checksum.
			ninkac.execute('''create table if not exists ninkacomments (sha256 text, license text, version text)''')
			ninkac.execute('''create index if not exists comments_index on ninkacomments(sha256);''')

			ninkaconn.commit()
			ninkac.close()
			ninkaconn.close()
	except Exception, e:
		print >>sys.stderr, e

	c.close()
	conn.close()

	pool = Pool()

	pkgmeta = []

	checksums = {}
	if os.path.exists(os.path.join(options.filedir, "SHA256SUM")):
		checksumlines = open(os.path.join(options.filedir, "SHA256SUM")).readlines()
		for c in checksumlines:
			checksumsplit = c.strip().split()
			if len(checksumsplit) != 2:
				continue
			(archivechecksum, archivefilename) = checksumsplit
			checksums[archivefilename] = archivechecksum
	## TODO: do all kinds of checks here
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
			pkgmeta.append((options.filedir, package, version, filename, origin, batarchive, masterdatabase, checksums))
		except Exception, e:
			# oops, something went wrong
			print >>sys.stderr, e
	res = filter(lambda x: x != None, pool.map(checkalreadyscanned, pkgmeta, 1))

	oldpackage = ""
	oldres = []
	processed_hashes = set()

	batarchives = []
	resordered = []

	## first loop through everything to filter out all the files that don't
	## need processing, plus moving any batarchives to the end of the queue
	for i in res:
		(package, version, filename, origin, filehash, batarchive) = i
		if filehash in blacklistsha256sums:
			continue
		## no need to process some files twice, even if they
		## are under a different name.
		if filehash in processed_hashes:
			continue
		if batarchive:
			batarchives.append(i)
		else:
			resordered.append(i)
		processed_hashes.add(filehash)

	res = resordered + batarchives
	for i in res:
		try:
			(package, version, filename, origin, filehash, batarchive) = i
			if package != oldpackage:
				oldres = []
			unpackres = unpack_getstrings(options.filedir, package, version, filename, origin, filehash, masterdatabase, cleanup, license, copyrights, pool, ninkacomments, licensedb, oldpackage, oldres, rewrites, batarchive)
			if unpackres != None:
				oldres = map(lambda x: x[2], unpackres)
				oldpackage = package
		except Exception, e:
				# oops, something went wrong
				print >>sys.stderr, e

if __name__ == "__main__":
    main(sys.argv)
