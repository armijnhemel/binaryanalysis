#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This program analyses result files of the Binary Analysis Tool. Its purpose is
to check source code archives for completeness of the source code.

In the ranking scan for each unique file that was reported per package the following
information is retrieved from the pickle:

* the unique string itself
* package
* checksums of all source code files in a package that contain the unique string
* name of all source code files in a package that contain the unique string

Per unique string the following data should be dumped:

1. first check for presence of SHA256.
2. check for unique string and verify in which file name it occurs in
'''

import os, os.path, sys, cPickle, sqlite3, multiprocessing, tempfile
import stat, hashlib, subprocess, magic, string, gzip, re
from optparse import OptionParser

tarmagic = ['POSIX tar archive (GNU)'
           , 'tar archive'
           ]

ms = magic.open(magic.MAGIC_NONE)
ms.load()

## list of extensions, plus what language they should be mapped to
## This is not necessarily correct, but right now it suffices. Ideally a parser
## would be run on each file to see what kind of file it is.
## This list should be kept in sync with the list in batchextractprogramstrings.py
extensions = {'c'      : 'C',
              'cc'     : 'C',
              'cpp'    : 'C',
              'cxx'    : 'C',
              'c++'    : 'C',
              'h'      : 'C',
              'hh'     : 'C',
              'hpp'    : 'C',
              'hxx'    : 'C',
              'l'      : 'C',
              'qml'    : 'C',
              's'      : 'C',
              'txx'    : 'C',
              'y'      : 'C',
              'cs'     : 'C#',
              'groovy' : 'Java',
              'java'   : 'Java',
              'jsp'    : 'Java',
              'scala'  : 'Java',
              'as'     : 'ActionScript',
              'js'     : 'JavaScript',
             }

splitcharacters = map(lambda x: chr(x), range(0,9) + range(14,32) + [127])

## unpack the file in its own directory
def unpack(directory, filename, filemagic, lentempdir):
	unpackdir = None
	if os.path.exists("%s-unpack" % os.path.join(directory, filename)):
		unpackdir = tempfile.mkdtemp(prefix="%s-" % os.path.join(directory, filename))
	else:
		unpackdir = "%s-unpack" % os.path.join(directory, filename)
		os.mkdir(unpackdir)

	## Assume if the files are bz2 or gzip compressed they are compressed tar files
	if 'bzip2 compressed data' in filemagic:
		## for some reason the tar.bz2 unpacking from python doesn't always work, like
		## aeneas-1.0.tar.bz2 from GNU, so use a subprocess instead of using the
		## Python tar functionality.
		p = subprocess.Popen(['tar', 'jxf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=unpackdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.rmdir(unpackdir)
			return
	elif 'XZ compressed data' in filemagic:
		p = subprocess.Popen(['tar', 'Jxf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=unpackdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.rmdir(unpackdir)
			return
	elif 'gzip compressed data' in filemagic:
		p = subprocess.Popen(['tar', 'zxf', os.path.join(directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=unpackdir)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			os.rmdir(unpackdir)
			return
	elif 'Zip archive data' in filemagic:
		try:
			p = subprocess.Popen(['unzip', "-B", os.path.join(directory, filename), '-d', tmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0 and p.returncode != 1:
				print >>sys.stderr, "unpacking ZIP failed for", filename, stanerr
				shutil.rmtree(unpackdir)
				return
		except Exception, e:
			print >>sys.stderr, "unpacking ZIP failed", e
			return

	## walk the temporary dir to make sure all files are readable
	## and recurse.
	return walkunpacksources(unpackdir, lentempdir)

## walk and unpack a source archive. This means
## * unpack any top level archives
## * make sure permissions are correct
## * analyse each file, and unpack archives, and prepare those as well
def walkunpacksources(sourcepath, lentempdir):
	filepaths = []
	try:
		osgen = os.walk(sourcepath, topdown=True)
		while True:
			i = osgen.next()
			for d in i[1]:
				## make sure all directories can be accesssed
				if not os.path.islink(os.path.join(i[0], d)):
					os.chmod(os.path.join(i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			for filename in i[2]:
				resolved_path = os.path.realpath(os.path.join(i[0], filename))
				## make sure all files can be accessed
				try:
					if not os.path.islink(resolved_path):
						os.chmod(resolved_path, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
				except Exception, e:
					#print e
					pass

				filemagic = ms.file(resolved_path)
				if 'bzip2 compressed data' in filemagic or 'XZ compressed data' in filemagic or 'gzip compressed data' in filemagic or 'Zip archive data' in filemagic:
					fileres = unpack(i[0], filename, filemagic, lentempdir)
					if fileres != None:
						filepaths += fileres
				else:
					if i[0][lentempdir:].startswith('/'):
						filepaths.append((i[0][lentempdir+1:], filename))
					else:
						filepaths.append((i[0][lentempdir:], filename))
	except StopIteration:
		pass

	return filepaths

def computehash((topdir, filepath, filename)):
	resolved_path = os.path.join(topdir, filepath, filename)
	try:
		if not os.path.islink(resolved_path):
			os.chmod(resolved_path, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
	except Exception, e:
		return

	## skip links
	if os.path.islink(resolved_path):
		return None
	## nothing to determine about an empty file, so skip
	if os.stat(resolved_path).st_size == 0:
		return None
	## some filenames might have uppercase extensions, so lowercase them first
	p_nocase = filename.lower()

	## TODO: handle patch and diff files as well
	languagesplit = resolved_path.rsplit('.', 1)
	if len(languagesplit) == 1:
		return
	if extensions.has_key(languagesplit[-1].lower()):
		#language = extensions[languagesplit[-1].lower()]
		extension = languagesplit[-1].lower()
	else:
		return

	filemagic = ms.file(os.path.realpath(resolved_path))
	if filemagic == "AppleDouble encoded Macintosh file":
		return None
	scanfile = open(resolved_path, 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	filehash = h.hexdigest()
	return (topdir, filepath, filename, filehash, extension)

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

## Extract strings using xgettext. Apparently this does not always work correctly. For example for busybox 1.6.1:
## $ xgettext -a -o - fdisk.c
##  xgettext: Non-ASCII string at fdisk.c:203.
##  Please specify the source encoding through --from-code.
## We fix this by rerunning xgettext with --from-code=utf-8
## The results might not be perfect, but they are acceptable.
## TODO: use version from bat/extractor.py
## TODO: process more files at once to reduce overhead of calling xgettext
def extractsourcestrings(filedir, filename, language):
	remove_chars = ["\\a", "\\b", "\\v", "\\f", "\\e", "\\0"]
	sqlres = []
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
				return sqlres
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
	return sqlres


## walk and process the unpacked source archive. This means:
## * scan each individual source code file and extract string constants,
##   function names, etc. and store these in a temporary sqlite database
## * store information about each file in the temporary database.
def walkscansources((topdir, filepath, filename, filehash, extension)):
	cresults = []
	javaresults = []
	language = extensions[extension]
	sqlres = extractsourcestrings(os.path.join(topdir, filepath), filename, language)
	if (language == 'C' or language == 'Java'):

		p2 = subprocess.Popen(["ctags", "-f", "-", "-x", os.path.join(topdir, filepath, filename)], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
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
					## for the Linux kernel the variable names are sometimes
					## stored in a special ELF section __ksymtab_strings
					if csplit[1] == 'variable':
						if len(csplit) < 5:
							cresults.append((csplit[0], int(csplit[2]), 'variable'))
						else:
							if "EXPORT_SYMBOL" in csplit[4]:
								cresults.append((csplit[0], int(csplit[2]), 'kernelsymbol'))
							else:
								cresults.append((csplit[0], int(csplit[2]), 'variable'))
					elif csplit[1] == 'function':
						cresults.append((csplit[0], int(csplit[2]), 'function'))
				if language == 'Java':
					for i in ['method', 'class', 'field']:
						if csplit[1] == i:
							javaresults.append((csplit[0], int(csplit[2]), i))

        return (filepath, filename, filehash, language, sqlres, cresults, javaresults)


def main(argv):
	parser = OptionParser()
	parser.add_option("-s", "--sourcedir", action="store", dest="sourcedir", help="path to directory with sources", metavar="DIR")
	parser.add_option("-p", "--pickledir", action="store", dest="pickledir", help="path to directory with pickles", metavar="DIR")
	parser.add_option("-d", "--database", action="store", dest="db", help="path to temporary database", metavar="FILE")

	(options, args) = parser.parse_args()

	## sanity checks for source dir
	if options.sourcedir == None:
		parser.error("Location source directory not supplied")
	if not os.path.exists(options.sourcedir):
		parser.error("Source directory does not exist")

	## sanity checks for temporary database
	if options.db == None:
		parser.error("Location temporary database not supplied")
	if os.path.exists(options.db):
		parser.error("Temporary database already exists")

	## sanity checks for the pickle dir:
	## 1. are there actually any pickles
	## 2. are the files valid Python pickles
	if options.pickledir == None:
		parser.error("Location pickle directory not supplied")
	if not os.path.exists(options.pickledir):
		parser.error("Pickle directory does not exist")
	picklelist = os.listdir(options.pickledir)
	if picklelist == []:
		print >>sys.stderr, "Pickle directory empty"
		sys.exit(1)

	## First, check if it actually makes sense to walk and unpack the archive
	## by checking the scan results if anything was found by 'ranking'.
	## Then, unpack and walk the sources and create a temporary database for
	## quick lookups.
	## Check the markers from the binary scan with markers in the temporary
	## database and report if anything is missing.
	walkdir = os.path.normpath(options.sourcedir)
	lentempdir = len(walkdir)
	scanres = map(lambda x: (walkdir,) + x, walkunpacksources(walkdir, lentempdir))
	pool = multiprocessing.Pool()
	scanres = filter(lambda x: x != None, pool.map(computehash, scanres))
	extracted_results = pool.map(walkscansources, scanres)
	pool.terminate()

	conn = sqlite3.connect(options.db)
	c = conn.cursor()

	## The database is a reduced version of the BAT database
	c.execute('''create table if not exists processed_file (filename text, sha256 text)''')
	c.execute('''create index if not exists processedfile_index on processed_file(sha256)''')

	## add tables and indexes
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
	conn.commit()

	for extractres in extracted_results:
		(filepath, filename, filehash, language, sqlres, cresults, javaresults) = extractres
		for res in sqlres:
			(pstring, linenumber) = res
			c.execute('''insert into extracted_file (programstring, sha256, language, linenumber) values (?,?,?,?)''', (pstring, filehash, language, linenumber))
		for res in list(set(cresults)):
			(cname, linenumber, nametype) = res
			if nametype == 'function':
				c.execute('''insert into extracted_function (sha256, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, 'C', linenumber))
			elif nametype == 'kernelfunction':
				c.execute('''insert into extracted_function (sha256, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, 'linuxkernel', linenumber))
			else:
				c.execute('''insert into extracted_name (sha256, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, 'C', linenumber))
		for res in list(set(javaresults)):
			(cname, linenumber, nametype) = res
			if nametype == 'method':
				c.execute('''insert into extracted_function (sha256, functionname, language, linenumber) values (?,?,?,?)''', (filehash, cname, 'Java', linenumber))
			else:
				c.execute('''insert into extracted_name (sha256, name, type, language, linenumber) values (?,?,?,?,?)''', (filehash, cname, nametype, 'Java', linenumber))
		resolved_path = os.path.join(filepath, filename)
		c.execute('''insert into processed_file (filename, sha256) values (?,?)''', (resolved_path, filehash))
	conn.commit()

	for l in picklelist:
		packages = []
		picklefile = gzip.open(os.path.join(options.pickledir, l), 'r')
		leaf_scan = cPickle.load(picklefile)
		picklefile.close()
		if not leaf_scan.has_key('ranking'):
			continue
		(stringmatches, dynamicres, varfunmatches) = leaf_scan['ranking']
		language = varfunmatches['language']

		## for each package: check per string whether or not a file with the same
		## checksum can be found, most likely version first. If none is found check
		## if the string can be found in the database and see if the name of the package
		## and possibly the version can be found in the path of the file and if the
		## filename matches.
		## If there is no match report it.

		print "checking for %d unique function name matches" % dynamicres['uniquematches']
		matched_functions = dynamicres['uniquepackages']
		notfoundfuncs = []
		for package in matched_functions:
			for f in matched_functions[package]:
				res = c.execute('select * from extracted_function where functionname=?', (f,)).fetchall()
				if res == []:
					notfoundfuncs.append(f)
				for r in res:
					if r[2] != language:
						continue
					fileres = c.execute('select * from processed_file where sha256=?', (r[0],)).fetchall()
					for fr in fileres:
						#print fr, package, package in fr[0]
						pass
		print
		print "NOT FOUND UNIQUE FUNCTIONS", notfoundfuncs
		print

		notfoundstrings = []
		if stringmatches['reports'] != []:
 			for j in stringmatches['reports']:
				(rank, packagename, uniquematches, percentage, packageversions, licenses) = j
				if len(uniquematches) == 0:
					continue
				for u in uniquematches:
					(uniquestring, matches) = u
					res = c.execute('select * from extracted_file where programstring=?', (uniquestring,)).fetchall()
					if res == []:
						notfoundstrings.append(uniquestring)
					for r in res:
						if r[2] != language:
							continue
						fileres = c.execute('select * from processed_file where sha256=?', (r[0],)).fetchall()
						for fr in fileres:
							#print fr, package, package in fr[0]
							pass
		print "NOT FOUND UNIQUE STRINGS", notfoundstrings
		print
				

	c.close()
	conn.close()


if __name__ == "__main__":
	main(sys.argv)
