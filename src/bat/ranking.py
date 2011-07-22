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

import string, re, os, os.path, magic, sys
import sqlite3
import subprocess

## extract the strings using 'strings' and only consider strings >= 5,
## although this should be configurable
## Then run it through extractGeneric, that queries the database and does
## funky statistcs as described in our paper.
## Original code (in Perl) was written by Eelco Dolstra.
## Reimplementation in Python done by Armijn Hemel.
def searchGeneric(path, blacklist=[]):
        try:
		p = subprocess.Popen(['strings', '-n', '5', path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return
                lines = stanout.split("\n")
                if extractGeneric(lines, path) != -1:
			return True
		else:
			return None
        except Exception, e:
                print >>sys.stderr, "string scan failed:", e;
                return None

## Extract the strings
def extractGeneric(lines, path):
	allStrings = {}
	lenStringsFound = 0
	uniqueMatches = {}
	allMatches = {}
	uniqueScore = {}
	nonUniqueScore = {}
	nrUniqueMatches = 0
	stringsLeft = {}
	alpha = 5.0

	conn = sqlite3.connect(os.environ.get('BAT_SQLITE_DB', '/tmp/sqlite'))
	c = conn.cursor()

	## create an extra table and attach it to the current database connection
	c.execute("attach '/tmp/avg' as avg")
	c.execute("create table if not exists avg.avgstringscache (package text, avgstrings real, primary key (package))")
	conn.commit()

	## (package, version) => count
	packagelist = {}

	## sort the lines first
	lines.sort()

	res = []
	print >>sys.stderr, "total extracted strings:", len(lines)
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
		scoreDocs = c.execute('''select p.package, p.version, p.filename FROM processed_file p JOIN extracted_file e on p.sha256 = e.sha256 WHERE programstring=?''', (line,))

		res = scoreDocs.fetchall()
		if len(res) != 0:
			## Add the length of the string to lenStringsFound
			lenStringsFound = lenStringsFound + len(line)
			matched = True
			print >>sys.stderr, "\n%d matches found for <(|%s|)> in %s" % (len(res), line, path)
			matchedlines = matchedlines + 1
			packageres = {}
			allStrings[line] = []
			for result in res:
				(package, version, filename) = result
				## record in which packages we have seen this string
				allStrings[line].append({'package': package, 'version': version, 'filename': filename})
				print >>sys.stderr, "%s\t%s\t%s" % (package, version, filename)
		else:
			#print >>sys.stderr, line
			continue

	print >>sys.stderr, "matchedlines:", matchedlines
	print >>sys.stderr, matchedlines/(len(lines) * 1.0)
	for i in allStrings.keys():
		pkgs = {}
		for match in allStrings[i]:
			if not pkgs.has_key(match['package']):
				pkgs[match['package']] = [os.path.basename(match['filename'])]
			else:
				pkgs[match['package']].append(os.path.basename(match['filename']))
		if len(pkgs.values()) == 1:
			## the string is unique to this package and this package only
			if not allMatches.has_key(match['package']):
				allMatches[match['package']] = {}
			if not allMatches[match['package']].has_key(i):
				allMatches[match['package']][i] = len(i)
			else:
				allMatches[match['package']][i] = allMatches[match['package']][i] + len(i)
			nrUniqueMatches = nrUniqueMatches + 1
		else:
			## The string we found is not unique to a package, but is the
			## filename we found also unique to a filename?
			## This method does assume that files that are named the same
			## also contain the same or similar content.
			filenames = {}
			for f in pkgs.items():
				## f = (name of package, [list of filenames with 'i'])
				## remove duplicates first
				for fn in list(set(f[1])):
					if not filenames.has_key(fn):
						filenames[fn] = {}
					filenames[fn][f[0]] = 1
			## now we can determine the score for the string
			score = len(i) / pow(alpha, (len(filenames.keys()) - 1))
			#print score, i, filenames.keys()
			for fn in filenames.keys():
				if len(filenames[fn].values()) == 1:
					fnkey = filenames[fn].keys()[0]
					if not nonUniqueScore.has_key(fnkey):
						nonUniqueScore[fnkey] = score
					else:
						nonUniqueScore[fnkey] = nonUniqueScore[fnkey] + score
				else:
					pass
					#print filenames[fn].keys()
					# There are multiple packages in which the same
					# filename contains this string, which is likely to be
					# internal cloning in the repo.  This string is
					# assigned to a single package in the loop below.
					stringsLeft['%s\t%s' % (i, fn)] = {'string': i, 'score': score, 'filename': fn}

		# For each string that occurs in the same filename in multiple
		# packages (e.g., "debugXML.c", a cloned file of libxml2 in several
		# packages), assign it to one package.  We do this by picking the
		# package that would gain the highest score increment across all
		# strings that are left.  This is repeated until no strings are left.
		sameFileScore = {}
		round = 0
		while len(stringsLeft.keys()) > 0:
			round = round + 1
			print "round %d: %d strings left" % (round, len(stringsLeft.keys()))
			gain = {}
			stringsPerPkgs = {}
			for stri in stringsLeft.items():
				print stri[0], stri[1]['string']
			sys.exit(0)
			pass

		print "nonUniqueScore for %s: " % i, nonUniqueScore
		print stringsLeft

def comparePkgs(a, b, cursor, conn):
	counta = averageStringsPerPkgVersion(a, cursor, conn)
	countb = averageStringsPerPkgVersion(b, cursor, conn)
	return cmp(counta, countb)

def averageStringsPerPkgVersion(pkg, cursor, conn):
	# Cache the average number of strings per package in the DB.
	# Danger: this table should be invalidated whenever the
	# "extracted_file" and "processed_file" tables change!
	res = conn.execute("select avgstrings from avg.avgstringscache where package = ?", (pkg,)).fetchall()
	if len(res) == 0:
		pass
		print "   looking up average nr of strings in %s" % (pkg,)

            	cursor.execute("select count(*) * 1.0 / (select count(distinct version) from processed_file where package = ?) from (select distinct e.programstring, p.version from extracted_file e JOIN processed_file p on e.sha256 = p.sha256 WHERE package = ?)", (pkg,pkg))
		count = cursor.fetchone()[0]
        	cursor.execute("insert or ignore into avgstringscache(package, avgstrings) values (?, ?)", (pkg, count))
		conn.commit()
	else:
		count = res[0]
	return count
