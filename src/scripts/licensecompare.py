#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2014 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script uses a very crude approach to compare license classifications made
with Ninka and FOSSology. It is meant to find where Ninka and FOSSology differ
and to improve both.
'''

import sys
import sqlite3
from optparse import OptionParser
from multiprocessing import Pool

## two hashes with results that are equivalent
ninka_to_fossology = { 'LesserGPLv2+': 'LGPL-2.0+'
                     , 'BSD3': 'BSD-3-Clause'
                     , 'boostV1Ref': 'BSL-1.0'
                     }

fossology_to_ninka = { 'No_license_found': 'NONE'
                     , 'GPL-1.0': 'GPLv1'
                     , 'GPL-1.0+': 'GPLv1+'
                     , 'GPL-2.0': 'GPLv2'
                     , 'GPL-2.0+': 'GPLv2+'
                     , 'GPL-3.0': 'GPLv3'
                     , 'GPL-3.0+': 'GPLv3+'
                     , 'LGPL-2.0': 'LibraryGPLv2'
                     , 'LGPL-2.0+': 'LibraryGPLv2+'
                     , 'LGPL-2.1': 'LesserGPLv2.1'
                     , 'LGPL-2.1+': 'LesserGPLv2.1+'
                     , 'LGPL-3.0': 'LesserGPLv3'
                     , 'LGPL-3.0+': 'LesserGPLv3+'
                     , 'Apache-1.0': 'Apachev1.0'
                     , 'Apache-1.1': 'Apachev1.1'
                     , 'Apache-2.0': 'Apachev2'
                     , 'BSL-1.0': 'boostV1'
                     , 'MPL-1.0': 'MPLv1_0'
                     , 'FTL': 'FreeType'
                     , 'PHP-3.01': 'phpLicV3.01'
                     , 'Postfix': 'Postfix'
                     , 'QPL-1.0': 'QTv1'
                     , 'MPL-1.1': 'MPLv1_1'
                     , 'Zend-2.0': 'zendv2'
                     , 'NPL-1.1': 'NPLv1_1'
                     , 'BSD-2-Clause': 'spdxBSD2'
                     , 'BSD-3-Clause': 'spdxBSD3'
                     , 'EPL-1.0': 'EPLv1'
                     , 'Artifex': 'artifex'
                     , 'CDDL': 'CDDLic'
                     , 'Public-domain': 'publicDomain'
                     , 'Public-domain-ref': 'publicDomain'
                     , 'IPL': 'IBMv1'
                     , 'Intel': 'IntelACPILic'
                     , 'MX4J-1.0': 'MX4JLicensev1'
                     , 'Beerware': 'BeerWareVer42'
                     , 'CPL-1.0': 'CPLv1'
                     , 'Sun': 'sunRPC'
                     , 'SunPro': 'SunSimpleLic'
                     , 'W3C-IP': 'W3CLic'
                     , 'Artistic-1.0': 'ArtisticLicensev1'
                     }

def lookup((db, sha)):
	conn = sqlite3.connect(db)
	cursor = conn.cursor()
	licenses = cursor.execute("select distinct license, scanner from licenses where sha256=?", sha).fetchall()
	cursor.close()
	conn.close()
	## 2 licenses were found, one from Ninka, one from FOSSology
	if len(licenses) == 2:
		if licenses[0][1] == 'ninka':
			if fossology_to_ninka.has_key(licenses[1][0]):
				if fossology_to_ninka[licenses[1][0]] == licenses[0][0]:
					status = 'agreed'
					licenses = []
				else:
					if ninka_to_fossology.has_key(licenses[0][0]):
						if ninka_to_fossology[licenses[0][0]] == licenses[1][0]:
							status = 'agreed'
							licenses = []
						else:
							status = "difference"
					else:
						status = "difference"
			else:
				status = "difference"
		elif licenses[1][1] == 'ninka':
			if fossology_to_ninka.has_key(licenses[0][0]):
				if fossology_to_ninka[licenses[0][0]] == licenses[1][0]:
					status = 'agreed'
					licenses = []
				else:
					if ninka_to_fossology.has_key(licenses[1][0]):
						if ninka_to_fossology[licenses[0][0]] == licenses[1][0]:
							status = 'agreed'
							licenses = []
						else:
							status = "difference"
					else:
						status = "difference"
			else:
				status = "difference"
	## more licenses were found. Ignore for now.
	else:
		status = 'unscanned'
		licenses = []
	return (status, sha[0], licenses)

def main(argv):
	parser = OptionParser()
	parser.add_option("-l", "--licensedb", action="store", dest="licenses", help="path to licensing database", metavar="FILE")
	parser.add_option("-d", "--database", action="store", dest="db", help="path to master database", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.licenses == None:
		parser.error("Need path to licensing database")
	try:
		conn = sqlite3.connect(options.licenses)
	except:
		print >>sys.stderr, "Can't open licensing database"
		sys.exit(1)
	if options.db == None:
		parser.error("Need path to master database")
	try:
		dbconn = sqlite3.connect(options.db)
	except:
		print >>sys.stderr, "Can't open master database"
		sys.exit(1)

	cursor = conn.cursor()

	notsame = []

	bla = cursor.execute("select distinct sha256 from licenses")
	sha256s = cursor.fetchmany(10000)

	unscannedcounter = 0
	agreedcounter = 0

	dbcursor = dbconn.cursor()

	## create a pool of workers since all this work can be done in parallel
	pool = Pool()

	## two dictionaries that list per license scanner per license
	## what the other license scanner thinks happens
	ninkas = {}
	fossologys = {}

	while sha256s != []:
		tmpsha256 = map(lambda x: (options.licenses, x), sha256s)
		results = pool.map(lookup, tmpsha256, 1)

		interesting = filter(lambda x: x[0] == 'difference', results)
		agreed = filter(lambda x: x[0] == 'agreed', results)
		agreedcounter += len(agreed)
		unscanned = filter(lambda x: x[0] == 'unscanned', results)
		unscannedcounter += len(unscanned)
		for i in interesting:
			interestingfile = dbconn.execute("select filename from processed_file where sha256=?", (i[1],)).fetchone()
			if interestingfile == None:
				## error in the database
				continue
			## checksum, result of Ninka and then result of FOSSology
			(sha256, licenses) = i[1:]
			print "%s -- %s -- %s -- %s" % (sha256, licenses[0][0], licenses[1][0], interestingfile[0])
			if ninkas.has_key(licenses[0][0]):
				if ninkas[licenses[0][0]].has_key(licenses[1][0]):
					ninkas[licenses[0][0]][licenses[1][0]] += 1
				else:
					ninkas[licenses[0][0]][licenses[1][0]] = 1
			else:
				ninkas[licenses[0][0]] = {}
				ninkas[licenses[0][0]][licenses[1][0]] = 1
			if fossologys.has_key(licenses[1][0]):
				if fossologys[licenses[1][0]].has_key(licenses[0][0]):
					fossologys[licenses[1][0]][licenses[0][0]] += 1
				else:
					fossologys[licenses[1][0]][licenses[0][0]] = 1
			else:
				fossologys[licenses[1][0]] = {}
				fossologys[licenses[1][0]][licenses[0][0]] = 1
		sha256s = cursor.fetchmany(10000)

	pool.close()
	dbcursor.close()
	dbconn.close()
	cursor.close()
	conn.close()
	print "unscanned:", unscannedcounter
	print "agreed:", agreedcounter

	print
	for n in ninkas:
		for f in ninkas[n]:
			print "NINKA", n, f, ninkas[n][f]
	print
	for n in fossologys:
		for f in fossologys[n]:
			print "FOSSOLOGY", n, f, fossologys[n][f]

if __name__ == "__main__":
	main(sys.argv)
