#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains the ranking algorithm as described in the paper
"Finding Software License Violations Through Binary Code Clone Detection"
by Armijn Hemel, Karl Trygve Kalleberg, Eelco Dolstra and Rob Vermaas, as
presented at the Mining Software Repositories 2011 conference.
'''

import string, re, os, os.path, magic, sys, tempfile
import sqlite3
import subprocess
import xml.dom.minidom

ms = magic.open(magic.MAGIC_NONE)
ms.load()

## extract the strings using 'strings' and only consider strings >= 5,
## although this should be configurable
## Then run it through extractGeneric, that queries the database and does
## funky statistcs as described in our paper.
## Original code (in Perl) was written by Eelco Dolstra.
## Reimplementation in Python done by Armijn Hemel.
def searchGeneric(path, blacklist=[], offsets={}):
	## Only consider strings that are len(stringcutoff) or larger
	stringcutoff = 5
	## we want to use extra information for a few file types
	## * ELF files
	## * bFLT files
	## * Java class files
	## * Dalvik VM files
	## * Windows executables and libraries
	## * Mono/.NET files
	## * Flash/ActionScript
	## Focus is first on ELF
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
		## if we just have a blob we will just consider it as 'C' for now
		## In the future we might want to consider everything.
		language='C'

	if blacklist == []:
		scanfile = path
	else:
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
		scanfile = tmpfile
        try:
		lines = []
		if language == 'C':
			## For ELF binaries we can concentrate on just a few sections of the
			## binary namely the .rodata and .data sections and the dynamic
			## symbols.
			## DO NOT USE: readelf -p sometimes transforms tabs to spaces, which
			## makes our algorithm fail.
			## We only consider full binaries, not binaries that have parts carved
			## out of them because of blacklists
        		#if "ELF" in mstype and blacklist == []:
        		if "DONTUSE" in mstype and blacklist == []:
				for i in [".rodata", ".data"]:
        				p = subprocess.Popen(['readelf', '-p', i, scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)

					## run strings to get rid of weird characters that we don't even want to scan
        				p2 = subprocess.Popen(['strings', '-n', str(stringcutoff)], stdin=p.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        				(stanout, stanerr) = p2.communicate()

        				st = stanout.split("\n")

        				for s in st[1:]:
						## readelf -p results are in a specific format
                				res = re.match("\s+\[\s*\w+\]\s\s(.*)", s)
                				if res == None:
							## the invocation of 'strings' on the output sometimes gives
							## lines that do not adher to this format, because 'strings' has
							## broken up a line in several lines
                        				printstring = s
                				else:
                        				printstring = res.groups()[0]
                				if len(printstring) >= stringcutoff:
                        				lines.append(printstring)

				## sometimes we can extract useful information from the dynamic symbols
			 	p = subprocess.Popen(['readelf', '--dyn-syms', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				st = stanout.split("\n")

				for s in st[3:]:
        				if len(s.split()) <= 7:
                				continue
        				printstring = s.split()[7]
					## remove references to functions in other libraries such as glibc
        				if '@' in printstring:
                				continue
        				if len(printstring) >= stringcutoff:
						lines.append(printstring)

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
						lines.append(l.split("=", 1)[1][1:-1])
			elif "Dalvik dex" in mstype and blacklist == []:
				## we should find a way to extract strings from Dalvik files
				## Using dedexer http://dedexer.sourceforge.net/ we can extract string constants from Dalvik files
				## java -jar ~/Downloads/ddx1.15.jar -d $tmpdir classes.dex
				## then process each file in $tmpdir and search file for lines containing "const-string"
				pass
		else:
			lines = []

		res = extractGeneric(lines, path, language)
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
                print >>sys.stderr, "string scan failed for:", path, e
		if blacklist != []:
			## cleanup the tempfile
			os.unlink(tmpfile[1])
                return  None

## Extract the strings
def extractGeneric(lines, path, language='C'):
	allStrings = {}                ## {string, {package, version}}
	lenStringsFound = 0
	uniqueMatches = {}
	allMatches = {}
	uniqueScore = {}
	nonUniqueScore = {}
	nrUniqueMatches = 0
	stringsLeft = {}
	sameFileScore = {}
	alpha = 5.0
	gaincutoff = 5

	## open the database containing all the strings that were extracted
	## from source code.
	#conn = sqlite3.connect(os.environ.get('BAT_SQLITE_DB', '/tmp/sqlite'))
	conn = sqlite3.connect(os.environ.get('BAT_SQLITE_DB', '/tmp/master'))
	c = conn.cursor()

	## create extra tables and attach them to the current database connection
	## These databases should be wiped and/or recreated when the database with
	## strings has been changed!!
	c.execute("attach '/tmp/avg' as avg")
	c.execute("create table if not exists avg.avgstringscache (package text, avgstrings real, primary key (package))")
	c.execute("attach '/tmp/stringscache' as stringscache")
	c.execute("create table if not exists stringscache.stringscache (programstring text, package text, version text, filename text)")
	c.execute("create index if not exists stringscache.programstring_index on stringscache(programstring, language)")
	conn.commit()

	## (package, version) => count
	packagelist = {}

	## sort the lines first, so we can easily skip duplicates
	lines.sort()

	lenlines = len(lines)

	print >>sys.stderr, "total extracted strings for %s: %d" %(path, lenlines)

	res = []
	matchedlines = 0
	oldline = None
	matched = False
	for line in lines:
		## speedup if the lines happen to be the same as the old one
		if line == oldline:
			if matched:
				matchedlines = matchedlines + 1
			continue
		matched = False
		oldline = line
		newmatch = False
		## skip empty lines
                if line == "": continue
		res = conn.execute('''select package, version, filename FROM stringscache.stringscache WHERE programstring=? AND language=?''', (line,language)).fetchall()
		if len(res) == 0:
			## do we actually have a result?
			checkres = conn.execute('''select sha256, language from extracted_file WHERE programstring=? LIMIT 1''', (line,)).fetchall()
			res = []
			if len(checkres) != 0:
				for (checksha, checklan) in checkres:
					if checklan != language:
						continue
					else:
						res = conn.execute('''select package, version, filename FROM processed_file p WHERE sha256=?''', (checksha,)).fetchall()
			newmatch = True

		if len(res) != 0:
			## Add the length of the string to lenStringsFound.
			## We're not really using it, except for reporting.
			lenStringsFound = lenStringsFound + len(line)
			matched = True

			#print >>sys.stderr, "\n%d matches found for <(|%s|)> in %s" % (len(res), line, path)

			## for statistics it's nice to see how many lines we matched
			matchedlines = matchedlines + 1
			packageres = {}
			allStrings[line] = []
			for result in res:
				(package, version, filename) = result
				## record per line all (package, version, filename) combinations
				## in which this string was found.
				allStrings[line].append({'package': package, 'version': version, 'filename': filename})
				#print >>sys.stderr, "%s\t%s\t%s" % (package, version, filename)
				if newmatch:
					c.execute('''insert into stringscache.stringscache values (?, ?, ?, ?)''', (line, package, version, filename))
					conn.commit()
			newmatch = False
		else:
			print >>sys.stderr, "no matches found for <(|%s|)> in %s" % (line, path)

	print >>sys.stderr, "matchedlines: %d for %s" % (matchedlines, path)
	print >>sys.stderr, matchedlines/(len(lines) * 1.0)

	del lines

	## For each string we determine in how many packages (without version) the string
	## is found.
	## If the string is only found in one package the string is unique to the package
	## and we record it as such and add its length to a score.
	##
	## If not, we have to do a little bit more work to determine which file is
	## the most likely, so we also record the filename.
	##
	## 1. determine whether the string is unique to a package
	## 2. if not, determine which filenames the string is in
	## 3. for each filename, determine whether or not this file (containing the string)
	##    is unique to a package
	## 4. if not, try to determine the most likely package the string was found in
	for i in allStrings.keys():
		pkgs = {}    ## {package name: [filenames without path]}
		for match in allStrings[i]:
			if not pkgs.has_key(match['package']):
				pkgs[match['package']] = [os.path.basename(match['filename'])]
			else:
				pkgs[match['package']].append(os.path.basename(match['filename']))
		if len(pkgs.values()) == 1:
			## the string is unique to this package and this package only
			uniqueScore[match['package']] = uniqueScore.get(match['package'], 0) + len(i)
			uniqueMatches[match['package']] = uniqueMatches.get(match['package'], []) + [i]

			if not allMatches.has_key(match['package']):
				allMatches[match['package']] = {}

			allMatches[match['package']][i] = allMatches[match['package']].get(i,0) + len(i)

			nrUniqueMatches = nrUniqueMatches + 1
		else:
			## The string we found is not unique to a package, but is it 
			## unique to a filename?
			## This method does assume that files that are named the same
			## also contain the same or similar content.
			filenames = {}

			for packagename in pkgs.items():
				## packagename = (name of package, [list of filenames with 'i'])
				## we record in how many different packages we find the
				## same filename that contain i
				## remove duplicates first
				for fn in list(set(packagename[1])):
					if not filenames.has_key(fn):
						filenames[fn] = {}
					filenames[fn][packagename[0]] = 1
			## now we can determine the score for the string
			try:
				score = len(i) / pow(alpha, (len(filenames.keys()) - 1))
			except Exception, e:
				## print >>sys.stderr, e
				## pow(alpha, (len(filenames.keys()) - 1)) is overflowing here
				## so the score would be very close to 0. The largest value
				## we have is sys.maxint, so use that one. The score will be
				## small enough...
				score = len(i) / sys.maxint

			## After having computed a score we determine if the files
			## we have found the string in are all called the same.
			## filenames {name of file: { name of package: 1} }
			for fn in filenames.keys():
				if len(filenames[fn].values()) == 1:
					## The filename fn containing the matched string can only
					## be found in one package.
					## For example: 'foo.c' in package 'foo'
					## or 'bar.c' in package 'bar'
					## The matched string is present in both 'foo.c' and 'bar.c'
					fnkey = filenames[fn].keys()[0]
					nonUniqueScore[fnkey] = nonUniqueScore.get(fnkey,0) + score
				else:
					## There are multiple packages in which the same
					## filename contains this string, for example 'foo.c'
					## in packages 'foo' and 'bar. This is likely to be
					## internal cloning in the repo.  This string is
					## assigned to a single package in the loop below.
					stringsLeft['%s\t%s' % (i, fn)] = {'string': i, 'score': score, 'filename': fn, 'pkgs' : filenames[fn].keys()}
		del allStrings[i]
	del filenames

	## For each string that occurs in the same filename in multiple
	## packages (e.g., "debugXML.c", a cloned file of libxml2 in several
	## packages), assign it to one package.  We do this by picking the
	## package that would gain the highest score increment across all
	## strings that are left.  This is repeated until no strings are left.
	roundNr = 0
	while len(stringsLeft.keys()) > 0:
		roundNr = roundNr + 1
		print >>sys.stderr, "round %d: %d strings left" % (roundNr, len(stringsLeft.keys()))
		gain = {}
		stringsPerPkg = {}
		for stri in stringsLeft.items():
			## when a string will not significantly contribute to the score we can just ignore
			## it and remove it from the list. This speeds up the algorithm A LOT.
			if stri[1]['score'] <= 1.0e-20:
				del stringsLeft[stri[0]]
				continue
			## get the unique score per package, temporarily record it and sort in reverse order
			pkgsSorted = map(lambda x: {'package': x, 'uniquescore': uniqueScore.get(x, 0)}, stri[1]['pkgs'])
			pkgsSorted = sorted(pkgsSorted, key=lambda x: x['uniquescore'], reverse=True)
			## and get rid of the unique scores again
			pkgsSorted = map(lambda x: x['package'], pkgsSorted)

			pkgs2 = []

			for pkgSort in pkgsSorted:
				if uniqueScore.get(pkgSort, 0) == uniqueScore.get(pkgsSorted[0], 0):
					pkgs2.append(pkgSort)
			for p2 in pkgs2:
				gain[p2] = gain.get(p2, 0) + stri[1]['score']
				stringsPerPkg[p2] = stri[0]
		## gain_sorted contains the sort order, gain contains the actual data
		gain_sorted = sorted(gain, key = lambda x: gain.__getitem__(x), reverse=True)

		## so far we think that this value is the best, but that might
		## change

		best = gain_sorted[0]

		close = []
		## if we have multiple packages that have a big enough gain, we
		## add them to 'close' and battle it out to see which package is
		## the most likely hit.
		for p3 in gain_sorted:
			if gain[p3] > gain[best] * 0.9:
				close.append(p3)

       		## Let's hope "sort" terminates on a comparison function that
       		## may not actually be a proper ordering.	
		if len(close) > 1:
			# print "  doing battle royale between [close]"
			## reverse sort close, then best = close[0]
			close_sorted = map(lambda x: (x, averageStringsPerPkgVersion(x, conn)), close)
			close_sorted = sorted(close_sorted, key = lambda x: x[1], reverse=True)
			close = map(lambda x: x[0], close_sorted)
			best = close[0]
		x = stringsLeft[stringsPerPkg[best]]
		if not allMatches.has_key(best):
			allMatches[best] = {}

		allMatches[best][x['string']] = allMatches[best].get(x['string'],0) + x['score']
		sameFileScore[best] = sameFileScore.get(best, 0) + x['score']
		del stringsLeft[stringsPerPkg[best]]
		print >>sys.stderr, "GAIN", gain[best], best, x
		if gain[best] < gaincutoff:
			break

	scores = {}
	for k in uniqueScore.keys() + sameFileScore.keys():
		scores[k] = uniqueScore.get(k, 0) + sameFileScore.get(k, 0) + nonUniqueScore.get(k,0)
	scores_sorted = sorted(scores, key = lambda x: scores.__getitem__(x), reverse=True)

	rank = 1
	reports = []
	totalscore = reduce(lambda x, y: x + y, scores.values())
	for s in scores_sorted:
		reports.append((rank, s, uniqueMatches.get(s,[]), (scores[s]/totalscore)*100.0))
		rank = rank+1
	return {'matchedlines': matchedlines, 'extractedlines': lenlines, 'reports': reports}


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


## TODO: implement pretty printing for the reports. The question is:
## when should we report and when not? There are various possibilities:
## * best x packages
## * packages that together have a percentage of total the score (say 98%)
## * everything
## Drawbacks are reporting too much or too little
def xmlprettyprint(res, root):
	tmpnode = root.createElement('ranking')

	matchedlines = root.createElement('matchedlines')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = res['matchedlines']
	matchedlines.appendChild(tmpnodetext)
	tmpnode.appendChild(matchedlines)

	extractedlines = root.createElement('extractedlines')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = res['extractedlines']
	extractedlines.appendChild(tmpnodetext)
	tmpnode.appendChild(extractedlines)

	for k in res['reports']:
		(rank, name, uniqueMatches, percentage) = k

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
				tmpnodetext.data = match
				matchnode.appendChild(tmpnodetext)
				uniquenode.appendChild(matchnode)
			countnode = root.createElement('uniquecount')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = len(uniqueMatches)
			countnode.appendChild(tmpnodetext)
			uniquenode.appendChild(countnode)
			packagenode.appendChild(uniquenode)

		## add rank
		ranknode = root.createElement('rank')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = rank
		ranknode.appendChild(tmpnodetext)

		## add score percentage
		percentagenode = root.createElement('percentage')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = percentage
		percentagenode.appendChild(tmpnodetext)

		packagenode.appendChild(ranknode)
		packagenode.appendChild(percentagenode)
		tmpnode.appendChild(packagenode)
	return tmpnode
