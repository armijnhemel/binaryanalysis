#!/usr/bin/python
#-*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2011-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains the ranking algorithm as described in the paper
"Finding Software License Violations Through Binary Code Clone Detection"
by Armijn Hemel, Karl Trygve Kalleberg, Eelco Dolstra and Rob Vermaas, as
presented at the Mining Software Repositories 2011 conference.

Configuration parameters for databases are:

BAT_SQLITE_DB :: location of database containing extracted strings

Per language:
BAT_SQLITE_AVG_$LANGUAGE          :: location of database containing average strings in $LANGUAGE per package
BAT_SQLITE_STRINGSCACHE_$LANGUAGE :: location of database that caches strings in $LANGUAGE per package future lookups
'''

import string, re, os, os.path, magic, sys, tempfile, shutil, copy
import sqlite3
import subprocess
import xml.dom.minidom
import extractor

ms = magic.open(magic.MAGIC_NONE)
ms.load()

## mapping of names for databases per language
avgdbperlanguage = { 'C':              'BAT_SQLITE_AVG_C'
                   , 'Java':           'BAT_SQLITE_AVG_Java'
                   , 'C#':             'BAT_SQLITE_AVG_C#'
                   , 'ActionScript':   'BAT_SQLITE_AVG_ActionScript'
                   }

stringsdbperlanguage = { 'C':              'BAT_SQLITE_STRINGSCACHE_C'
                       , 'Java':           'BAT_SQLITE_STRINGSCACHE_Java'
                       , 'C#':             'BAT_SQLITE_STRINGSCACHE_C#'
                       , 'ActionScript':   'BAT_SQLITE_STRINGSCACHE_ActionScript'
                       }

## extract the strings using 'strings' and only consider strings >= 5,
## although this should be configurable
## Then run it through extractGeneric, that queries the database and does
## funky statistcs as described in our paper.
## Original code (in Perl) was written by Eelco Dolstra.
## Reimplementation in Python done by Armijn Hemel.
def searchGeneric(path, blacklist=[], offsets={}, envvars=None):
	## Only consider strings that are len(stringcutoff) or larger
	stringcutoff = 5
	## we want to use extra information for a few file types
	## * ELF files
	## * bFLT files
	## * Java class files + Dalvik VM files
	## * Windows executables and libraries
	## * Mono/.NET files
	## * Flash/ActionScript
	## Focus is on ELF
        mstype = ms.file(path)
        if "ELF" in mstype:
		language = 'C'
	elif "bFLT" in mstype:
		language = 'C'
	elif "compiled Java" in mstype:
		language = 'Java'
	elif "Dalvik dex file" in mstype:
		language = 'Java'
	else:
		## first check the filename extension. If it is .js we will treat it as
		## JavaScript.
		## Else we will just consider it as 'C'.
		language='C'

	if blacklist == []:
		scanfile = path
	else:
		filesize = filesize = os.stat(path).st_size
		## whole file is blacklisted, so no need to scan
		if extractor.inblacklist(0, blacklist) == filesize:
			return None
		## we have already scanned parts of the file
		## we need to carve the right parts from the file first
		datafile = open(path, 'rb')
		data = datafile.read()
		datafile.close()
		lastindex = 0
		databytes = ""
		for i in blacklist:
			if i[0] > lastindex:
				## just concatenate the bytes
				databytes = databytes + data[lastindex:i[0]]
				## set lastindex to the next
				lastindex = i[1] - 1
		tmpfile = tempfile.mkstemp()
		os.write(tmpfile[0], databytes)
		os.fdopen(tmpfile[0]).close()
		scanfile = tmpfile[1]
        try:
		lines = []
		if language == 'C':
			## For ELF binaries we can concentrate on just a few sections of the
			## binary, namely the .rodata and .data sections.
			## The .rodata section might also contain other data, so we can expect
			## false positives until we have found a way to get only the string
			## constants :-(

        		if "ELF" in mstype and blacklist == []:
				#extractDynamic(path, envvars)
				#print >>sys.stderr, path
				#return
				datafile = open(path, 'rb')
				data = datafile.read()
				datafile.close()
				elfscanfiles = []
				## first we need to determine the size and offset of .data and .rodata and carve it from the file
        			p = subprocess.Popen(['readelf', '-SW', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        			(stanout, stanerr) = p.communicate()
				## TODO: check if we actually get sections. On some systems the
				## binary is somewhat corrupted and does not have section headers
				st = stanout.strip().split("\n")
				for s in st[3:]:
					for section in [".data", ".rodata"]:
						if section in s:
							elfsplits = s[8:].split()
							if section == "." + elfsplits[0]:
								elfoffset = int(elfsplits[3], 16)
								elfsize = int(elfsplits[4], 16)
								elftmp = tempfile.mkstemp(suffix=section)
								os.write(elftmp[0], data[elfoffset:elfoffset+elfsize])
								os.fdopen(elftmp[0]).close()
								elfscanfiles.append(elftmp[1])

				for i in elfscanfiles:
					## run strings to get rid of weird characters that we don't even want to scan
					## TODO: check if we need -Tbinary or not
        				p = subprocess.Popen(['strings', '-n', str(stringcutoff), i], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        				(stanout, stanerr) = p.communicate()

        				st = stanout.split("\n")

        				for s in st:
                        			printstring = s
                				if len(printstring) >= stringcutoff:
                        				lines.append(printstring)
					os.unlink(i)


			else:
				## extract all strings from the binary. Only look at strings
				## that are a certain amount of characters or longer. This is
				## configurable through "stringcutoff" although the gain will be relatively
				## low by also scanning strings < 5.
				p = subprocess.Popen(['strings', '-n', str(stringcutoff), scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					if blacklist != []:
						## cleanup the tempfile
						os.unlink(tmpfile[1])
					return None
				lines = stanout.split("\n")
		elif language == 'Java':
			lines = []
			## we really should think about whether or not we want to do this per class file,
			## or per JAR file.
        		if "compiled Java" in mstype and blacklist == []:
				p = subprocess.Popen(['jcf-dump', '--print-constants', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					if blacklist != []:
						## cleanup the tempfile
						os.unlink(tmpfile[1])
				## we process each line of stanout, looking for lines that look like this:
				## #13: String 45="/"
				for l in stanout.split("\n"):
					if re.match("#\d+: String \d+=\"", l) != None:
						printstring = l.split("=", 1)[1][1:-1]
        					if len(printstring) >= stringcutoff:
							lines.append(printstring)
			elif "Dalvik dex" in mstype and blacklist == []:
				## Using dedexer http://dedexer.sourceforge.net/ we can extract string constants from Dalvik files
				## java -jar ~/Downloads/ddx1.15.jar -d $tmpdir classes.dex
				## then process each file in $tmpdir and search file for lines containing "const-string"
				## alternatively, use code from here http://code.google.com/p/smali/
				dalvikdir = tempfile.mkdtemp()
				p = subprocess.Popen(['java', '-jar', '/usr/share/java/bat-ddx.jar', '-d', dalvikdir, scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode == 0:
					osgen = os.walk(dalvikdir)
					try:
						while True:
							ddxfiles = osgen.next()
							for ddx in ddxfiles[2]:
								ddxlines = open("%s/%s" % (ddxfiles[0], ddx)).readlines()
								for d in ddxlines:
									reres = re.match("\s+const-string\s+v\d+", d)
									if reres != None:
										printstring = d.strip().split(',', 1)[1][1:-1]
        									if len(printstring) >= stringcutoff:
											lines.append(printstring)
					except StopIteration:
						pass
				## cleanup
				shutil.rmtree(dalvikdir)
		elif language == 'JavaScipt':
			## JavaScript can be minified, but using xgettext we
			## can still extract the strings from it
			## results = extractor.extractStrings(os.path.dirname(path), os.path.basename(path))
			## for r in results:
			##	lines.append(r[0])
			lines = []
		else:
			lines = []

		res = extractGeneric(lines, path, language, envvars)
		if res != None:
			if blacklist != []:
				## we made a tempfile because of blacklisting, so cleanup
				os.unlink(tmpfile[1])
			return res
		else:
			if blacklist != []:
				## we made a tempfile because of blacklisting, so cleanup
				os.unlink(tmpfile[1])
			return None
        except Exception, e:
                print >>sys.stderr, "string scan failed for:", path, e, type(e)
		if blacklist != []:
			## cleanup the tempfile
			os.unlink(tmpfile[1])
                return None

def extractDynamic(scanfile, envvars):
	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass
	## sometimes we can extract useful information from the dynamic symbols
	## but mostly they lead to false positives.
 	p = subprocess.Popen(['readelf', '-W', '--dyn-syms', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return

	st = stanout.strip().split("\n")

	if st == '':
		return

	## open the database containing all the strings that were extracted
	## from source code.
	conn = sqlite3.connect(scanenv.get('BAT_SQLITE_DB', '/tmp/master'))
	## we have byte strings in our database, not utf-8 characters...I hope
	conn.text_factory = str
	c = conn.cursor()

	## keep a list of versions per sha256, since source files often contain more than one line
	scanstr = []
	mangles = []
	for i in st[3:]:
		dynstr = i.split()
		if dynstr[6] == 'UND':
			continue
		if dynstr[3] != 'FUNC':
			continue
		## every program has 'main', so skip
		if dynstr[7] == 'main':
			continue
		## _init _fini _start are in the ELF standard and/or added by GCC to everything, so skip
		if dynstr[7] == '_init' or dynstr[7] == '_fini' or dynstr[7] == '_start':
			continue
		## __libc_csu_init __libc_csu_fini are in the ELF standard and/or added by GCC to everything, so skip
		if dynstr[7] == '__libc_csu_init' or dynstr[7] == '__libc_csu_fini':
			continue
		## C++ string, needs to be demangled first
		if dynstr[7].startswith("_Z"):
			mangles.append(dynstr[7])
		else:
			funcname = dynstr[7]
			scanstr.append(funcname)

	step = 100
	if mangles != []:
		for i in range(0, len(mangles), step):
			offset = i
			args = ['c++filt'] + mangles[offset:offset+step]
			offset = offset + step
			p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0:
				continue
			for f in stanout.strip().split('\n'):
				funcname = f.split('(', 1)[0].rsplit('::', 1)[-1].strip()
				scanstr.append(funcname)

	sha256_packages = {}
	pkgcnt = {}
	uniquepackages = []
	namesmatched = 0

	## demangling can lead to identical results, so we prune first
	for funcname in list(set(scanstr)):
		matched = False
		c.execute('select sha256 from extracted_function where functionname=?', (funcname,))
		res = c.fetchall()
		pkgs = []
		for r in res:
			if sha256_packages.has_key(r[0]):
				pkgs = pkgs + copy.copy(sha256_packages[r[0]])
				matched = True
				continue
			c.execute('select package, version from processed_file where sha256=?', r)
			s = c.fetchall()
			if s != []:
				matched = True
			pkgs = pkgs + s
			sha256_packages[r[0]] = s
		differentpackages = map(lambda x: x[0], pkgs)
		if len(list(set(differentpackages))) == 1:
			uniquepackages = uniquepackages + pkgs
		if matched:
			namesmatched += 1
	for i in list(set(uniquepackages)):
		print >>sys.stderr, i, uniquepackages.count(i), namesmatched

## Look up strings in the database and determine which packages/versions/licenses were used
def extractGeneric(lines, path, language='C', envvars=None):
	lenStringsFound = 0
	uniqueMatches = {}
	allMatches = {}
	uniqueScore = {}
	nonUniqueScore = {}
	nrUniqueMatches = 0
	stringsLeft = {}
	sameFileScore = {}
	alpha = 5.0
	gaincutoff = 1
	nonUniqueMatches = {}
	nonUniqueMatchLines = []
	nonUniqueAssignments = {}

	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass
		
	## open the database containing all the strings that were extracted
	## from source code.
	conn = sqlite3.connect(scanenv.get('BAT_SQLITE_DB', '/tmp/master'))
	## we have byte strings in our database, not utf-8 characters...I hope
	conn.text_factory = str
	c = conn.cursor()

	## create extra tables and attach them to the current database connection
	## These databases should be wiped and/or recreated when the database with
	## strings has been changed!!
	avgdb = scanenv.get(avgdbperlanguage[language], '/tmp/avg')
	c.execute("attach ? as avg", (avgdb,))
	c.execute("create table if not exists avg.avgstringscache (package text, avgstrings real, primary key (package))")

	stringscache = scanenv.get(stringsdbperlanguage[language], '/tmp/stringscache')
	c.execute("attach ? as stringscache", (stringscache,))
	c.execute("create table if not exists stringscache.stringscache (programstring text, package text, filename text)")
	c.execute("create index if not exists stringscache.programstring_index on stringscache(programstring)")
	conn.commit()

	rankingfull = False
	if scanenv.get('BAT_RANKING_FULLCACHE', 0) == '1':
		rankingfull = True

	determineversion = False
	if scanenv.get('BAT_RANKING_VERSION', 0) == '1':
		determineversion = True

	determinelicense = False
	if scanenv.get('BAT_RANKING_LICENSE', 0) == '1':
		## TODO: if extracted_file does not exist we should always set this to False
		determinelicense = True

	## keep a list of versions per package we found
	packageversions = {}

	## keep a list of licenses per package we found
	## WARNING WARNING WARNING
	## Just because a license is reported, it does not necessarily
	## mean that the package is under that license!
	## There are very likely false positives and false negatives and
	## the information is for informative purposes only!
	packagelicenses = {}

	## keep a list of versions per sha256, since source files often contain more than one line
	sha256_versions = {}

	## keep a list of versions per sha256, since source files often contain more than one line
	sha256_licenses = {}

	## sort the lines first, so we can easily skip duplicates
	lines.sort()

	lenlines = len(lines)

	print >>sys.stderr, "total extracted strings for %s: %d" %(path, lenlines)

	res = []
	matchedlines = 0
	oldline = None
	matched = False
	for line in lines:
		#print >>sys.stderr, "processing <|%s|>" % line
		## speedup if the lines happen to be the same as the old one
		## This does *not* alter the score in any way, but perhaps
		## it should: having a very significant string a few times
		## is a strong indication.
		if line == oldline:
			if matched:
				matchedlines = matchedlines + 1
			continue
		matched = False
		oldline = line
		newmatch = False
		## skip empty lines
                if line == "": continue

		## first see if we have anything in the cache at all
		res = conn.execute('''select package, filename FROM stringscache.stringscache WHERE programstring=?''', (line,)).fetchall()

		## nothing in the cache
		if len(res) == 0 and not rankingfull:
			## do we actually have a result?
			checkres = conn.execute('''select sha256, language from extracted_file WHERE programstring=? LIMIT 1''', (line,)).fetchall()
			res = []
			if len(checkres) == 0:
				print >>sys.stderr, "no matches found for <(|%s|)> in %s" % (line, path)
				continue
			else:
				## now fetch *all* sha256 checksums
				checkres = conn.execute('''select sha256, language from extracted_file WHERE programstring=?''', (line,)).fetchall()
				checkres = list(set(checkres))
				for (checksha, checklan) in checkres:
					if checklan != language:
						continue
					else:
						## overwrite 'res' here
						res = conn.execute('''select package, filename FROM processed_file p WHERE sha256=?''', (checksha,)).fetchall()
			newmatch = True
		if len(res) != 0:
			## We are assuming:
			## * database has no duplicates
			## * filenames in the database have been processed using os.path.basename()
			## If not, uncomment the following few lines:
			#res = map(lambda (x,y): (x, os.path.basename(y)), res)
			#res = list(set(res))

			## Add the length of the string to lenStringsFound.
			## We're not really using it, except for reporting.
			lenStringsFound = lenStringsFound + len(line)
			matched = True

			## for statistics it's nice to see how many lines we matched
			matchedlines = matchedlines + 1

			print >>sys.stderr, "\n%d matches found for <(|%s|)> in %s" % (len(res), line, path)

			pkgs = {}    ## {package name: [filenames without path]}

			## For each string we determine in how many packages (without version) the string
			## is found.
			## If the string is only found in one package the string is unique to the package
			## and we record it as such and add its length to a score.
			for result in res:
				(package, filename) = result
				## in case we don't know this match yet record it in the database
				if newmatch and not rankingfull:
					c.execute('''insert into stringscache.stringscache values (?, ?, ?, ?)''', (line, package, filename))
				if not pkgs.has_key(package):
					pkgs[package] = [filename]
				else:
					pkgs[package].append(filename)
			if len(pkgs) == 1:
				## the string is unique to this package and this package only
				uniqueScore[package] = uniqueScore.get(package, 0) + len(line)

				if not allMatches.has_key(package):
					allMatches[package] = {}

				allMatches[package][line] = allMatches[package].get(line,0) + len(line)

				nrUniqueMatches = nrUniqueMatches + 1

				## We should store the version number with the license.
				## There are good reasons for this: files are sometimes collectively
				## relicensed when there is a new release (example: Samba 3.2 relicensed
				## to GPLv3+) so the version number can be very significant.
				## determinelicense should *always* imply determineversion
				if determineversion or determinelicense:
					c.execute("select distinct sha256, linenumber, language from extracted_file where programstring=?", (line,))
					versionsha256s = c.fetchall()

					pv = {}
					line_sha256_version = []
					for s in versionsha256s:
						if s[2] != language:
							continue
						if not sha256_versions.has_key(s[0]):
							c.execute("select distinct version, package, filename from processed_file where sha256=?", (s[0],))
							versions = c.fetchall()
							versions = filter(lambda x: x[1] == package, versions)
							sha256_versions[s[0]] = map(lambda x: (x[0], x[2]), versions)
							for v in versions:
								if not pv.has_key(v[0]):
									pv[v[0]] = 1
								line_sha256_version.append((s[0], v[0], s[1], v[2]))
						else:   
							for v in sha256_versions[s[0]]:
								if not pv.has_key(v[0]):
									pv[v[0]] = 1
								line_sha256_version.append((s[0], v[0], s[1], v[1]))
					for v in pv:
						if packageversions.has_key(package):
							if packageversions[package].has_key(v):
								packageversions[package][v] = packageversions[package][v] + 1
							else:
								packageversions[package][v] = 1
						else:   
							packageversions[package] = {}
							packageversions[package][v] = 1
					uniqueMatches[package] = uniqueMatches.get(package, []) + [(line, line_sha256_version)]
					if determinelicense:
						pv = []
						for s in versionsha256s:
							if not sha256_licenses.has_key(s):
								c.execute("select distinct license from licenses where sha256=?", (s[0],))
								licenses = c.fetchall()
								sha256_licenses[s] = map(lambda x: x[0], licenses)
								for v in licenses[0]:
									## Ninka was not able to determine a license, so
									## no need reporting it
									if v == 'NONE':
										continue
									pv.append(v)
						if packagelicenses.has_key(package):
							packagelicenses[package] = list(set(packagelicenses[package] + pv))
						else:
							packagelicenses[package] = list(set(pv))
				else:
					## store the uniqueMatches without any information about checksums
					uniqueMatches[package] = uniqueMatches.get(package, []) + [(line, )]
			else:
				nonUniqueMatchLines.append(line)
				## The string we found is not unique to a package, but is it 
				## unique to a filename?
				## This method does assume that files that are named the same
				## also contain the same or similar content.
				filenames = {}

				for packagename in pkgs:
					## packagename = (name of package, [list of filenames with 'line'])
					## we record in how many different packages we find the
					## same filename that contain line
					for fn in list(set(pkgs[packagename])):
						if not filenames.has_key(fn):
							filenames[fn] = {}
						filenames[fn][packagename] = 1
				## now we can determine the score for the string
				try:
					score = len(line) / pow(alpha, (len(filenames) - 1))
				except Exception, e:
					## pow(alpha, (len(filenames.keys()) - 1)) is overflowing here
					## so the score would be very close to 0. The largest value
					## we have is sys.maxint, so use that one. The score will be
					## small enough...
					score = len(line) / sys.maxint

				if score > 1.0e-20:
					for packagename in pkgs:
						if not nonUniqueMatches.has_key(packagename):
							nonUniqueMatches[packagename] = [line]
						else:
							nonUniqueMatches[packagename] = nonUniqueMatches[packagename] + [line]
				## After having computed a score we determine if the files
				## we have found the string in are all called the same.
				## filenames {name of file: { name of package: 1} }
				for fn in filenames:
					if len(filenames[fn].values()) == 1:
						## The filename fn containing the matched string can only
						## be found in one package.
						## For example: string 'foobar' is present in 'foo.c' in package 'foo'
						## and 'bar.c' in package 'bar', but not in 'foo.c' in package 'bar'
						## or 'bar.c' in foo (if any).
						fnkey = filenames[fn].keys()[0]
						nonUniqueScore[fnkey] = nonUniqueScore.get(fnkey,0) + score
					else:
						## There are multiple packages in which the same
						## filename contains this string, for example 'foo.c'
						## in packages 'foo' and 'bar. This is likely to be
						## internal cloning in the repo.  This string is
						## assigned to a single package in the loop below.
						## Some strings will not signficantly contribute to the score, so they
						## could be ignored and not added to the list.
						## For now we exclude them, but in the future we could include them for
						## completeness.
						#if score > 1.0e-200:
						if score > 1.0e-20:
							stringsLeft['%s\t%s' % (line, fn)] = {'string': line, 'score': score, 'filename': fn, 'pkgs' : filenames[fn].keys()}

			if newmatch:
				conn.commit()
			newmatch = False

	if lenlines != 0:
		pass
		#print >>sys.stderr, "matchedlines: %d for %s" % (matchedlines, path)
		#print >>sys.stderr, matchedlines/(lenlines * 1.0)

	del lines

	## If the string is not unique, we have to do a little bit more work to determine which
	## file is the most likely, so we also record the filename.
	##
	## 1. determine whether the string is unique to a package
	## 2. if not, determine which filenames the string is in
	## 3. for each filename, determine whether or not this file (containing the string)
	##    is unique to a package
	## 4. if not, try to determine the most likely package the string was found in

	## For each string that occurs in the same filename in multiple
	## packages (e.g., "debugXML.c", a cloned file of libxml2 in several
	## packages), assign it to one package.  We do this by picking the
	## package that would gain the highest score increment across all
	## strings that are left.  This is repeated until no strings are left.
	pkgsScorePerString = {}
	for stri in stringsLeft:
		pkgsSortedTmp = map(lambda x: {'package': x, 'uniquescore': uniqueScore.get(x, 0)}, stringsLeft[stri]['pkgs'])

		## get the unique score per package and sort in reverse order
		pkgsSorted = sorted(pkgsSortedTmp, key=lambda x: x['uniquescore'], reverse=True)
		## and get rid of the unique scores again. Now it's sorted.
		pkgsSorted = map(lambda x: x['package'], pkgsSorted)
		pkgs2 = []

		for pkgSort in pkgsSorted:
			if uniqueScore.get(pkgSort, 0) == uniqueScore.get(pkgsSorted[0], 0):
				pkgs2.append(pkgSort)
		pkgsScorePerString[stri] = pkgs2

	roundNr = 0
	strleft = len(stringsLeft)
	while strleft > 0:
		roundNr = roundNr + 1
		#print >>sys.stderr, "round %d: %d strings left" % (roundNr, strleft)
		gain = {}
		stringsPerPkg = {}
		## Determine to which packages the remaining strings belong.
		for stri in stringsLeft:
			for p2 in pkgsScorePerString[stri]:
				gain[p2] = gain.get(p2, 0) + stringsLeft[stri]['score']
				stringsPerPkg[p2] = stringsPerPkg.get(p2, []) + [stri]

		## gain_sorted contains the sort order, gain contains the actual data
		gain_sorted = sorted(gain, key = lambda x: gain.__getitem__(x), reverse=True)

		## so far we think that this value is the best, but that might
		## change

		best = gain_sorted[0]

		## if we have multiple packages that have a big enough gain, we
		## add them to 'close' and battle it out to see which package is
		## the most likely hit.
		close = filter(lambda x: gain[x] > (gain[best] * 0.9), gain_sorted)

       		## Let's hope "sort" terminates on a comparison function that
       		## may not actually be a proper ordering.	
		if len(close) > 1:
			# print >>sys.stderr, "  doing battle royale between [close]"
			## reverse sort close, then best = close_sorted[0][0]
			close_sorted = map(lambda x: (x, averageStringsPerPkgVersion(x, conn)), close)
			close_sorted = sorted(close_sorted, key = lambda x: x[1], reverse=True)
			best = close_sorted[0][0]
		best_score = 0
		## for each string in the package with the best gain we add the score
		## to the package and move on to the next package.
		for xy in stringsPerPkg[best]:
			best_score += 1

			x = stringsLeft[xy]
			if not allMatches.has_key(best):
				allMatches[best] = {}

			allMatches[best][x['string']] = allMatches[best].get(x['string'],0) + x['score']
			sameFileScore[best] = sameFileScore.get(best, 0) + x['score']
			#print >>sys.stderr, "GAIN", gain[best], best
			del stringsLeft[xy]
		nonUniqueAssignments[best] = best_score
		if gain[best] < gaincutoff:
			break
		strleft = len(stringsLeft)

	scores = {}
	for k in uniqueScore.keys() + sameFileScore.keys():
		scores[k] = uniqueScore.get(k, 0) + sameFileScore.get(k, 0) + nonUniqueScore.get(k,0)
	scores_sorted = sorted(scores, key = lambda x: scores.__getitem__(x), reverse=True)

	rank = 1
	reports = []
	if scores == {}:
		totalscore = 0.0
	else:
		totalscore = float(reduce(lambda x, y: x + y, scores.values()))
	for s in scores_sorted:
		try:
			percentage = (scores[s]/totalscore)*100.0
		except:
			percentage = 0.0
		reports.append((rank, s, uniqueMatches.get(s,[]), percentage, packageversions.get(s, {}), packagelicenses.get(s, [])))
		rank = rank+1
	'''
	for s in scores_sorted:
		if not nonUniqueMatches.has_key(s):
			continue
		correlation_sort = {}
		for r in nonUniqueMatches:
			if r == s:
				continue
			correlation = len(set(nonUniqueMatches[s]).intersection(nonUniqueMatches[r]))
			if correlation != 0:
				correlation_sort[r] = correlation
		corr_sorted = sorted(correlation_sort, key = lambda x: correlation_sort.__getitem__(x), reverse=True)
		for c in corr_sorted:
			print >>sys.stderr, s, c, correlation_sort[c]
	'''
	return {'matchedlines': matchedlines, 'extractedlines': lenlines, 'reports': reports, 'nonUniqueMatches': nonUniqueMatches, 'nonUniqueAssignments': nonUniqueAssignments}


def averageStringsPerPkgVersion(pkg, conn):
	## Cache the average number of strings per package in the DB.
	## Danger: this table should be invalidated whenever the
	## "extracted_file" and "processed_file" tables change!
	res = conn.execute("select avgstrings from avg.avgstringscache where package = ?", (pkg,)).fetchall()
	if len(res) == 0:
            	count = conn.execute("select count(*) * 1.0 / (select count(distinct version) from processed_file where package = ?) from (select distinct e.programstring, p.version from extracted_file e JOIN processed_file p on e.sha256 = p.sha256 WHERE package = ?)", (pkg,pkg)).fetchone()[0]
        	conn.execute("insert or ignore into avgstringscache(package, avgstrings) values (?, ?)", (pkg, count))
		conn.commit()
	else:
		count = res[0][0]
	return count


def xmlprettyprint(res, root, envvars=None):
	if res['matchedlines'] == 0:
		return None
	tmpnode = root.createElement('ranking')

	matchedlines = root.createElement('matchedlines')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = str(res['matchedlines'])
	matchedlines.appendChild(tmpnodetext)
	tmpnode.appendChild(matchedlines)

	extractedlines = root.createElement('extractedlines')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = str(res['extractedlines'])
	extractedlines.appendChild(tmpnodetext)
	tmpnode.appendChild(extractedlines)

	for k in res['reports']:
		(rank, name, uniqueMatches, percentage, packageversions, packagelicenses) = k

		## add package name
		packagenode = root.createElement('package')
		tmpnodetext = root.createElement('name')
		namenode = xml.dom.minidom.Text()
		namenode.data = name
		tmpnodetext.appendChild(namenode)
		packagenode.appendChild(tmpnodetext)

		## add unique matches, if any
		if len(uniqueMatches) > 0:
			uniquenode = root.createElement('uniquematches')
			for match in uniqueMatches:
				matchnode = root.createElement('unique')
				tmpnodetext = xml.dom.minidom.Text()
				## TODO: not every character is legal in XML,
				## so we actually need to have a translation step
				## here that rewrites illegal characters!
				tmpnodetext.data = match[0]
				matchnode.appendChild(tmpnodetext)
				uniquenode.appendChild(matchnode)
			countnode = root.createElement('uniquecount')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = str(len(uniqueMatches))
			countnode.appendChild(tmpnodetext)
			uniquenode.appendChild(countnode)
			packagenode.appendChild(uniquenode)

		## add rank
		ranknode = root.createElement('rank')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = str(rank)
		ranknode.appendChild(tmpnodetext)

		## add score percentage
		percentagenode = root.createElement('percentage')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = str(percentage)
		percentagenode.appendChild(tmpnodetext)

		## add versions
		if not packageversions == {}:
			sortedversions = sorted(packageversions, key=lambda x: packageversions.__getitem__(x), reverse=True)
			for v in sortedversions:
				versionsnode = root.createElement('version')
				versionnode = root.createElement('number')
				tmpnodetext = xml.dom.minidom.Text()
				tmpnodetext.data = str(v)
				versionnode.appendChild(tmpnodetext)

				countnode = root.createElement('count')
				tmpnodetext = xml.dom.minidom.Text()
				tmpnodetext.data = str(packageversions[v])
				countnode.appendChild(tmpnodetext)
				versionsnode.appendChild(versionnode)
				versionsnode.appendChild(countnode)
				packagenode.appendChild(versionsnode)

		## add licenses
		if not packagelicenses == []:
			licensesnode = root.createElement('licenses')
			for v in packagelicenses:
				licensenode = root.createElement('license')
				tmpnodetext = xml.dom.minidom.Text()
				tmpnodetext.data = str(v)
				licensenode.appendChild(tmpnodetext)
				licensesnode.appendChild(licensenode)
			packagenode.appendChild(licensesnode)

		## add everything to the root node
		packagenode.appendChild(ranknode)
		packagenode.appendChild(percentagenode)
		tmpnode.appendChild(packagenode)
	return tmpnode
