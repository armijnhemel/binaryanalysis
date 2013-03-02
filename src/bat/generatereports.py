#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This plugin is used to generate reports. It is run as an aggregate scan for
a reason: as it turns out many reports that are generated are identical:
matched strings are often the same since the same database is used.

Since generating reports can have quite a bit of overhead it makes sense
to first deduplicate and then generate reports.

The method works as follows:

1. All data from pickles that is needed to generate reports is extracted in
parallel.
2. The checksum of the pickle is computed and recorded. If there is a duplicate
the pickle is removed and it is recorded which file it originally belonged to.
3. Reports are (partially) generated in parallel for the remaining pickle files.
4. The reports are copied and renamed, or assembled from partial reports
'''

import os, os.path, sys, subprocess, copy, cPickle, tempfile, hashlib, shutil, multiprocessing, cgi, gzip

## compute a SHA256 hash. This is done in chunks to prevent a big file from
## being read in its entirety at once, slowing down a machine.
def gethash(path):
	scanfile = open(path, 'r')
	h = hashlib.new('sha256')
	scanfile.seek(0)
	hashdata = scanfile.read(10000000)
	while hashdata != '':
		h.update(hashdata)
		hashdata = scanfile.read(10000000)
	scanfile.close()
	return h.hexdigest()

#def generatehtmlsnippet((picklefile, pickledir, filehash, reportdir)):
	#pass

def extractpickles((filehash, pickledir, topleveldir)):
	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()
	## return type: (filehash, reportresults, unmatchedresult)
	reportresults = []

	## (picklehash, picklename)
	unmatchedresult = None
	if leafreports.has_key('ranking'):
		## the ranking result is (res, dynamicRes, variablepvs)
		(res, dynamicRes, variablepvs) = leafreports['ranking']

		if res['unmatched'] != []:
			unmatches = list(set(res['unmatched']))
			unmatches.sort()

			tmppickle = tempfile.mkstemp()

			cPickle.dump(unmatches, os.fdopen(tmppickle[0], 'w'))
			picklehash = gethash(tmppickle[1])
			unmatchedresult = (picklehash, tmppickle[1])

		if res['reports'] != []:
			for j in res['reports']:
				(rank, packagename, uniquematches, percentage, packageversions, licenses) = j
				tmppickle = tempfile.mkstemp()
				cPickle.dump((packagename, uniquematches), os.fdopen(tmppickle[0], 'w'))
				picklehash = gethash(tmppickle[1])
				reportresults.append((picklehash, tmppickle[1]))
				## TODO: find out what to do with rank and percentage

	return (filehash, reportresults, unmatchedresult)

def generateunmatched((picklefile, pickledir, filehash, reportdir)):

	unmatched_pickle = open(os.path.join(pickledir, picklefile), 'rb')
	unmatches = cPickle.load(unmatched_pickle)
        unmatched_pickle.close()

	unmatchedhtml = "<html><body><h1>Unmatched strings</h1><p><ul>"
	for i in unmatches:
		unmatchedhtml = unmatchedhtml + "%s<br>\n" % cgi.escape(i)
	unmatchedhtml = unmatchedhtml + "</body></html>"
	unmatchedhtmlfile = gzip.open("%s/%s-unmatched.html.gz" % (reportdir, filehash), 'wb')
	unmatchedhtmlfile.write(unmatchedhtml)
	unmatchedhtmlfile.close()
	os.unlink(os.path.join(pickledir, picklefile))

def generatereports(unpackreports, scantempdir, topleveldir, envvars=None):
	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	reportdir = scanenv.get('BAT_REPORTDIR', "%s/%s" % (topleveldir, "reports"))
	try:
		os.stat(reportdir)
	except:
		## BAT_IMAGEDIR does not exist
		try:
			os.makedirs(reportdir)
		except Exception, e:
			return

	pickledir = scanenv.get('BAT_PICKLEDIR', "%s/%s" % (topleveldir, "pickles"))
	try:
		os.stat(pickledir)
	except:
		## BAT_PICKLEDIR does not exist
		try:
			os.makedirs(pickledir)
		except Exception, e:
			return

	rankingfiles = []

	## filter out the files which don't have ranking results
	for i in unpackreports:
		if not unpackreports[i].has_key('sha256'):
			continue
		if not unpackreports[i].has_key('tags'):
			continue
		if not 'ranking' in unpackreports[i]['tags']:
			continue
		filehash = unpackreports[i]['sha256']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		rankingfiles.append(i)

	pickles = []
	processed = []
	unmatchedpicklespackages = []
	picklespackages = []
	picklehashes = {}
	pickletofile = {}
	unmatchedpickles = []
	reportpickles = []

	filehashes = list(set(map(lambda x: unpackreports[x]['sha256'], rankingfiles)))

	## extract pickles
	extracttasks = map(lambda x: (x, pickledir, topleveldir), filehashes)
	pool = multiprocessing.Pool()
	res = filter(lambda x: x != None, pool.map(extractpickles, extracttasks))
	pool.terminate()

	for r in res:
		(filehash, resultreports, unmatchedresult) = r
		if r == None:
			continue
		if unmatchedresult != None:
			(picklehash, tmppickle) = unmatchedresult
			if picklehash in unmatchedpickles:
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]
				unmatchedpicklespackages.append((picklehash, filehash))
				os.unlink(tmppickle)
			else:
				shutil.move(tmppickle, pickledir)
				unmatchedpickles.append(picklehash)
				unmatchedpicklespackages.append((picklehash, filehash))
				picklehashes[picklehash] = os.path.basename(tmppickle)
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]
		if resultreports != []:
			for report in resultreports:
				(picklehash, tmppickle) = report
				if picklehash in reportpickles:
					if pickletofile.has_key(picklehash):
						pickletofile[picklehash].append(filehash)
					else:
						pickletofile[picklehash] = [filehash]
					picklespackages.append((picklehash, filehash))
					os.unlink(tmppickle)
				else:
					shutil.move(tmppickle, pickledir)
					reportpickles.append(picklehash)
					picklespackages.append((picklehash, filehash))
					picklehashes[picklehash] = os.path.basename(tmppickle)
					if pickletofile.has_key(picklehash):
						pickletofile[picklehash].append(filehash)
					else:
						pickletofile[picklehash] = [filehash]

	pool = multiprocessing.Pool()

	## generate files for unmatched strings
	if unmatchedpickles != []:
		unmatchedtasks = list(set(map(lambda x: (picklehashes[x[0]], pickledir, x[0], reportdir), unmatchedpicklespackages)))
		results = pool.map(generateunmatched, unmatchedtasks, 1)
		for p in unmatchedpicklespackages:
			oldfilename = "%s-%s" % (p[0], "unmatched.html.gz")
			filename = "%s-%s" % (p[1], "unmatched.html.gz")
			if os.path.exists(os.path.join(reportdir, oldfilename)):
				shutil.copy(os.path.join(reportdir, oldfilename), os.path.join(reportdir, filename))
		for p in unmatchedpicklespackages:
			try:
				filename = "%s-%s" % (p[0], "unmatched.html.gz")
				os.unlink(os.path.join(reportdir, filename))
			except Exception, e:
				#print >>sys.stderr, "ERR", e
				pass
	pool.terminate()
