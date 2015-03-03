#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under GPL 2

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
import multiprocessing, ConfigParser
import hashlib, zlib, urllib
import rpm

## backup method that uses the RPM module's built in functionality to expamd
## macros
## WARNING WARNING WARNING: this is dangerous as commands from the RPM spec file
## that could invoke external commands will run!
## Never run this on a machine where it could do harm!
def scanspec2(specfile, specdir):
	spec = os.path.join(specdir, specfile)
	try:
		parsedspec = rpm.spec(spec)
	except Exception, e:
		return None
	patches = filter(lambda x: x[2] == 2, parsedspec.sources)
	return patches
	
## homebrew spec file scanner. This is to avoid to use the RPM python bindings
## due to security concerns.
## extract the following:
## * name
## * version
## * release
## * source inputs
## * any applied patches
## * any unapplied patches
## * possibly license and URL
## TODO: also process if, undefine, etc.
def scanspec(specfile, specdir, insecurerpm):
	result = {}
	patches = {}
	sources = set()
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
			## release usually has %{?dist} in it, which is dependent
			## on the machine. This is not really reliable for matching.
			release = line.split(':',1)[1].strip()
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
			sourcesplit = line.split(':',1)
			if len(sourcesplit) != 2:
				continue
			source = sourcesplit[1].strip()
			source = os.path.basename(source)
			if not '%{' in source:
				if os.path.exists(os.path.join(specdir, source)):
					sources.add(source)
			specreplaces = re.findall("%{([\w\d]+)}", source)
			for s in specreplaces:
				if s in result:
					source = source.replace("%{" + s + "}", result[s])
				elif s in defines:
					source = source.replace("%{" + s + "}", defines[s])
				elif s in globaldefines:
					source = source.replace("%{" + s + "}", globaldefines[s])
			if '%{' in source:
				continue
			if os.path.exists(os.path.join(specdir, source)):
				sources.add(source)
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
	if len(sources) != 0:
		result['sources'] = sources
	return result

def parallel_unpack((rpmfile, target, copyfiles, unpacktmpdir, cutoff, insecurerpm, extrahashes)):
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

	filechecksums = {}
	unpackedfiles = os.listdir(cpiodir)
	for f in unpackedfiles:
		filechecksums[f] = scanhashes(os.path.join(cpiodir, f), extrahashes)
	## then analyse the spec file
	specfiles = filter(lambda x: x.endswith('.spec'), unpackedfiles)
	## there should only be one spec file
	if len(specfiles) != 1:
		shutil.rmtree(cpiodir)
		return
	f = specfiles[0]
	specres = scanspec(f,cpiodir,insecurerpm)
	if "unresolvedpatches" in specres and insecurerpm:
		extrapatches = scanspec2(f,cpiodir)
	if "missingpatches" in specres and insecurerpm:
		extrapatches = scanspec2(f,cpiodir)
	specres['rpmname'] = os.path.basename(rpmfile)
	specres['filechecksums'] = filechecksums
	'''
	## copy the source code files
	for f in copyfiles:
		shutil.copy(os.path.join(cpiodir, f), target)
		os.chmod(os.path.join(target, f), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
	## copy the patches
	for f in copyfiles:
		shutil.copy(os.path.join(cpiodir, f), target)
		os.chmod(os.path.join(target, f), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
	'''
	shutil.rmtree(cpiodir)
	return specres

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

def scanhashes(resolved_path, extrahashes):
	filehashes = {}
	scanfile = open(resolved_path, 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	filehashes['sha256'] = h.hexdigest()

	## TODO: sanity checks for crc32 for really big files
	for i in extrahashes:
		scanfile = open(resolved_path, 'r')
		if i == 'crc32':
			crcdata = scanfile.read()
			filehashes[i] = zlib.crc32(crcdata) & 0xffffffff
		else:
			h = hashlib.new(i)
			h.update(scanfile.read())
			filehashes[i] = h.hexdigest()
		scanfile.close()
	return filehashes

## scan each RPM file and see if there are any source code archives inside.
## This check is based on conventions on how source code archives are named and
## might miss things.
## TODO: store patches as well
def scanrpm((filedir, filepath, filehashes, extrahashes)):

	## running rpm -qpl --dump is a lot faster than using the RPM Python module
	resolved_path = os.path.join(filedir, filepath)
	p2 = subprocess.Popen(['rpm', '-qpl', '--dump', resolved_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p2.communicate()
	rpmfiles = stanout.strip().rsplit("\n")
	copyfiles = []
	rpmchecksums = set()
	for fs in rpmfiles:
		## the interesting data from '--dump' are md5sum and the size (not used at the moment)
		splitresults = fs.split(' ', 4)
		if len(splitresults) < 5:
			continue
		(f, size, mtime, md5sum, rest) = splitresults
		rpmchecksums.add((f, md5sum))
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
			except Exception, e:
				continue
			if not (extension in ["tar"] and compression in ["gz", "bz2", "bz", "lz", "lzma", "xz", "Z"]):
				continue
			else:
				copyfiles.append((f,md5sum))
	if filehashes == None:
		filehashes = scanhashes(resolved_path, extrahashes)
	return (filedir, filepath, copyfiles, filehashes, rpmchecksums)

def unpacksrpm(filedir, target, unpacktmpdir, origin, rpmdatabase, insecurerpm):
	files = os.walk(filedir)
	uniquefiles = set()
	uniquerpms = set()
	nonuniquerpms = set()
	rpm2copyfiles = {}

	## hardcode for now
	extrahashes = ['md5', 'sha1', 'crc32']
	checksums = {}
	if os.path.exists(os.path.join(filedir, 'SHA256SUM')):
		checksumlines = open(os.path.join(filedir, "SHA256SUM")).readlines()
		tmpextrahashes = checksumlines[0].strip().split()
		for c in checksumlines[1:]:
			archivechecksums = {}
			checksumsplit = c.strip().split()
			archivefilename = checksumsplit[0]
			## sha256 is always the first hash
			archivechecksums['sha256'] = checksumsplit[1]
			counter = 2
			for h in tmpextrahashes:
				if h == 'sha256':
					continue
				if h not in extrahashes:
					continue
				archivechecksums[h] = checksumsplit[counter]
				counter += 1
			checksums[archivefilename] = archivechecksums

	rpmscans = []
	try:
        	while True:
			i = files.next()
			for p in i[2]:
				## first filter out files that are likely no source rpm, just by
				## looking at the extension.
				res = p.rsplit('.', 2)
				if len(res) != 3:
					continue
				if res[-1] == 'srpm':
					rpmscans.append((i[0], p, checksums.get(p, None), extrahashes))
				elif res[-1] == 'rpm' and res[-2] == 'src':
					rpmscans.append((i[0], p, checksums.get(p, None), extrahashes))
	except Exception, e:
		pass
		#print >>sys.stderr, e
		#sys.stderr.flush()

	pool = multiprocessing.Pool()
	rpmres = pool.map(scanrpm, rpmscans, 1)

	uniquemd5s = set()

	conn = sqlite3.connect(rpmdatabase)
	cursor = conn.cursor()
	insertrpms = []

	for r in rpmres:
		(filedir, filepath, copyfiles, filehashes, rpmchecksums) = r
		if not filepath in checksums:
			checksums[filepath] = filehashes
		downloadurl = None
		cursor.execute("select rpmname, origin, downloadurl from rpm where checksum=?", (filehashes['sha256'],))
		res = cursor.fetchall()
		if len(res) != 0:
			process = True
			for r in res:
				(dbrpmname, dborigin, dbdownloadurl) = r
				if dbrpmname == filepath and dborigin == origin and dbdownloadurl == downloadurl:
					process = False
					break
			if not process:
				continue
		insertrpms.append(r)
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
	conn.commit()

	## unique RPMs can be unpacked in parallel, non-uniques cannot
	## first process the unique RPMS in parallel
	## cutoff is at 200 MiB
	## TODO: make configurable
	cutoff = 209715200
	tasks = map(lambda x: (x, target, rpm2copyfiles[x], unpacktmpdir, cutoff, insecurerpm, extrahashes), uniquerpms)
	res = pool.map(parallel_unpack, tasks,1)
	pool.terminate()

	for r in res:
		version = r.get('version', None)
		name = r.get('name', None)
		rpmname = r.get('rpmname', None)
		license = r.get('license', None)
		url = r.get('url', None)
		rpmname = r.get('rpmname', None)
		rpmchecksum = checksums[rpmname]['sha256']
		cursor.execute("insert into rpm_info(checksum, name, version, url, license) values (?,?,?,?,?)", (rpmchecksum, name, version, url, license))
		filechecksums = r.get('filechecksums', {})
		for f in filechecksums:
			filetype = None
			if f.endswith('.spec'):
				filetype = 'spec'
			else:
				if 'appliedpatches' in r:
					if f in r['appliedpatches']:
						filetype = 'patch'
				if 'sources' in r:
					if f in r['sources']:
						filetype = 'source'
			cursor.execute("insert into rpm_contents(filename, type, checksum, rpmchecksum) values (?,?,?,?)", (f, filetype, filechecksums[f]['sha256'], rpmchecksum))

	## ... then unpack the non-unique RPMS, possibly overwriting already unpacked data
	## And yes, probably there is a more efficient way to do this.
	for rpmfile in nonuniquerpms:
		## first check if for all the 'copyfiles' a file with the same name already exists. If so,
		## then don't unpack.
		unique = False
		for f in rpm2copyfiles[rpmfile]:
			if not os.path.exists(os.path.join(target, f)):
				unique = True
				break
		if not unique:
			continue

		filechecksums = {}

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
		p2 = subprocess.Popen(['cpio', '-i', '-d', '--no-absolute-filenames', '-F', cpiotmp[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cpiodir)
		(cpiostanout, cpiostanerr) = p2.communicate()
		os.unlink(cpiotmp[1])

		## first analyse the spec file

		unpackedfiles = os.listdir(cpiodir)
		for f in unpackedfiles:
			filechecksums[f] = scanhashes(os.path.join(cpiodir, f), extrahashes)
		specfiles = filter(lambda x: x.endswith('.spec'), unpackedfiles)
		if len(specfiles) != 1:
			shutil.rmtree(cpiodir)
			continue
		f = specfiles[0]
		specres = scanspec(f,cpiodir,insecurerpm)
		if "unresolvedpatches" in specres and insecurerpm:
			extrapatches = scanspec2(f,cpiodir)
		if "missingpatches" in specres and insecurerpm:
			extrapatches = scanspec2(f,cpiodir)
		rpmname = os.path.basename(rpmfile)

		version = specres.get('version', None)
		name = specres.get('name', None)
		license = specres.get('license', None)
		url = specres.get('url', None)
		rpmchecksum = checksums[rpmname]['sha256']
		cursor.execute("insert into rpm_info(checksum, name, version, url, license) values (?,?,?,?,?)", (rpmchecksum, name, version, url, license))
		for f in filechecksums:
			filetype = None
			if f.endswith('.spec'):
				filetype = 'spec'
			else:
				if 'appliedpatches' in specres:
					if f in specres['appliedpatches']:
						filetype = 'patch'
			cursor.execute("insert into rpm_contents(filename, type, checksum, rpmchecksum) values (?,?,?,?)", (f, filetype, filechecksums[f]['sha256'], rpmchecksum))

		'''
		for f in rpm2copyfiles[n]:
			shutil.copy(os.path.join(cpiodir, f), target)
			os.chmod(os.path.join(target, f), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
		'''
		shutil.rmtree(cpiodir)

	## finally add everything about the RPM file itself to the database
	for r in insertrpms:
		(filedir, filepath, copyfiles, filehashes, rpmchecksums) = r
		cursor.execute("insert into rpm (rpmname, checksum, origin, downloadurl) values (?,?,?,?)", (filepath, filehashes['sha256'], origin, downloadurl))
	conn.commit()
	cursor.close()
	conn.close()

	return target

def main(argv):
	config = ConfigParser.ConfigParser()

	parser = OptionParser()
	parser.add_option("-c", "--configuration", action="store", dest="cfg", help="path to configuration", metavar="FILE")
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-o", "--origin", action="store", dest="origin", help="origin of packages (default: unknown)", metavar="ORIGIN")
	parser.add_option("-t", "--target-directory", action="store", dest="target", help="target directory where files are stored (default: generated temporary directory)", metavar="DIR")
	(options, args) = parser.parse_args()

	## read the configuration file. This should be the same as
	## the configuration file used for createdb.py
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
	if options.origin == None:
		origin = "unknown"
	else:
		origin = options.origin

	## search configuration to see if it is correct and/or not malformed
	## first search for a section called 'extractconfig' with configtype = global
	for section in config.sections():
		if section == "extractconfig":
			try:
				unpackdir = config.get(section, 'unpackdir')
			except:
				unpackdir = None

	## TODO: sanity checks for unpackdir

	## TODO: make configurable
	rpmdatabase = '/tmp/rpmdb.sqlite3'
	patchesdir = '/tmp/patches'

	## This setting is to instruct the unpacking whether or not to use the RPM module's
	## built-in functionality to do expansion of various macros. This is dangerous
	## as it would execute scripts that could come from untrusted resources.
	## TODO: make configurable.
	insecurerpm = False

	conn = sqlite3.connect(rpmdatabase)
	cursor = conn.cursor()
	cursor.execute('''create table if not exists rpm(rpmname text, checksum text, origin text, downloadurl text)''')
	cursor.execute('''create index if not exists rpm_checksum_index on rpm(checksum)''')
	cursor.execute('''create index if not exists rpm_rpmname_index on rpm(rpmname)''')
	cursor.execute('''create table if not exists rpm_info(checksum text, name text, version text, url text, license text)''')
	cursor.execute('''create index if not exists rpm_info_checksum_index on rpm_info(checksum)''')
	cursor.execute('''create index if not exists rpm_info_name_index on rpm_info(name)''')
	cursor.execute('''create index if not exists rpm_info_version_index on rpm_info(version)''')
	cursor.execute('''create table if not exists rpm_contents(filename text, type text, checksum text, rpmchecksum text)''')
	cursor.execute('''create index if not exists rpm_contents_checksum_index on rpm_contents(checksum)''')
	cursor.execute('''create index if not exists rpm_contents_rpmchecksum_index on rpm_contents(rpmchecksum)''')
	cursor.close()
	conn.close()

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
	unpacksrpm(options.filedir, target, unpackdir, origin, rpmdatabase, insecurerpm)
	#generatelist(target, origin)

if __name__ == "__main__":
	main(sys.argv)
