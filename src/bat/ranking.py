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

## extract the strings using 'strings' and only consider strings >= 5,
## although this should be configurable
## Then run it through extractGeneric, that queries the database and does
## funky statistcs as described in our paper.
## Original code (in Perl) was written by Eelco Dolstra.
## Reimplementation in Python done by Armijn Hemel.
def searchGeneric(path, blacklist=[]):
	if blacklist == []:
		scanfile = path
	else:
		## we have already scanned parts of the file
		## we need to carve the right parts from the file first
		datafile = open(path, 'rb')
		data = datafile.read()
		datafile.close()
		scanfile = path
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
        try:
		## extract all strings from the binary. Only look at strings
		## that are 5 characters or longer. This should be made
		## configurable although the gain will be relatively low by also
		## scanning shorter strings.
		p = subprocess.Popen(['strings', '-n', '5', scanfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			if blacklist != []:
				## cleanup the tempfile
				os.unlink(tmpfile[1])
			return
		lines = stanout.split("\n")
		if extractGeneric(lines, path) != -1:
			if blacklist != []:
				## cleanup the tempfile
				os.unlink(tmpfile[1])
			return True
		else:
			if blacklist != []:
				## cleanup the tempfile
				os.unlink(tmpfile[1])
			return None
        except Exception, e:
                print >>sys.stderr, "string scan failed for:", path, e
		if blacklist != []:
			## cleanup the tempfile
			os.unlink(tmpfile[1])
                return None

## Extract the strings
def extractGeneric(lines, path):
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

	## open the database containing all the strings that were extracted
	## from source code.
	#conn = sqlite3.connect(os.environ.get('BAT_SQLITE_DB', '/tmp/sqlite'))
	conn = sqlite3.connect(os.environ.get('BAT_SQLITE_DB', '/tmp/master'))
	c = conn.cursor()

	## create an extra table and attach it to the current database connection
	c.execute("attach '/tmp/avg' as avg")
	c.execute("create table if not exists avg.avgstringscache (package text, avgstrings real, primary key (package))")
	conn.commit()

	## (package, version) => count
	packagelist = {}

	## sort the lines first, so we can easily skip duplicates
	lines.sort()

	print >>sys.stderr, "total extracted strings for %s: %d" %(path, len(lines))

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
		## skip empty lines
                if line == "": continue
		res = conn.execute('''select p.package, p.version, p.filename FROM processed_file p JOIN extracted_file e on p.sha256 = e.sha256 WHERE programstring=?''', (line,)).fetchall()

		if len(res) != 0:
			## Add the length of the string to lenStringsFound.
			## We're not really using it, except for reporting.
			lenStringsFound = lenStringsFound + len(line)
			matched = True

			print >>sys.stderr, "\n%d matches found for <(|%s|)> in %s" % (len(res), line, path)

			## for statistics it's nice to see how many lines we matched
			matchedlines = matchedlines + 1
			packageres = {}
			allStrings[line] = []
			for result in res:
				(package, version, filename) = result
				## record per line all (package, version, filename) combinations
				## in which this string was found.
				allStrings[line].append({'package': package, 'version': version, 'filename': filename})
				print >>sys.stderr, "%s\t%s\t%s" % (package, version, filename)
		else:
			continue

	print >>sys.stderr, "matchedlines: %d for %s" % (matchedlines, path)
	print >>sys.stderr, matchedlines/(len(lines) * 1.0)

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

		## For each string that occurs in the same filename in multiple
		## packages (e.g., "debugXML.c", a cloned file of libxml2 in several
		## packages), assign it to one package.  We do this by picking the
		## package that would gain the highest score increment across all
		## strings that are left.  This is repeated until no strings are left.
		roundNr = 0
		while len(stringsLeft.keys()) > 0:
			roundNr = roundNr + 1
			#print >>sys.stderr, "round %d: %d strings left" % (roundNr, len(stringsLeft.keys()))
			gain = {}
			stringsPerPkg = {}
			for stri in stringsLeft.items():
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
			if gain[best] < 1:
				break

	scores = {}
	for k in uniqueScore.keys() + sameFileScore.keys():
		scores[k] = uniqueScore.get(k, 0) + sameFileScore.get(k, 0) + nonUniqueScore.get(k,0)
	scores_sorted = sorted(scores, key = lambda x: scores.__getitem__(x), reverse=True)

	#print "found %d strings, %d unique matches, %s bytes" % (len(allStrings.keys()), nrUniqueMatches, lenStringsFound)
	#print "the binary contains likely clones from the following packages:\n";
	rank = 1
	reports = {}
	for s in scores_sorted:
		print "rank %d: package %s - score %s" % (rank, s, scores[s]), uniqueScore.get(s,0), len(uniqueMatches.get(s, []))
		rank = rank+1


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
	pass
