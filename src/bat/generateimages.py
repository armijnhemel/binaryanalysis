#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, tempfile, hashlib, shutil, multiprocessing

'''
This plugin is used to aggregate ranking results for Java JAR files.
The ranking scan only ranks individual class files, which often do not
contain enough information. By aggregating the results of these classes
it is possible to get a better view of what is inside a JAR.
'''

def generateversionchart((versionpickle, picklehash, package, versiontype, imagedir, pickledir)):
	p = subprocess.Popen(['bat-generate-version-chart.py', '-i', os.path.join(pickledir, versionpickle), '-o', '%s/%s-%s-%s.png' % (imagedir, picklehash, package, versiontype)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		print >>sys.stderr, stanerr
		os.unlink(os.path.join(pickledir, versionpickle))
		return None
	else:
		os.unlink(os.path.join(pickledir, versionpickle))
		return '%s-%s-%s.png' % (picklehash, package, versiontype)

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

def generateimages(unpackreports, scantempdir, topleveldir, envvars=None):
	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	imagedir = scanenv.get('BAT_IMAGEDIR', "%s/%s" % (topleveldir, "images"))
	try:
		os.stat(imagedir)
	except:
		## BAT_IMAGEDIR does not exist
		try:
			os.makedirs(imagedir)
		except Exception, e:
			return
	## TODO: remove hardcoded path
	pickledir = '/tmp/pickle'
	rankingfiles = []
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
	funcpicklespackages = []
	versionpicklespackages = []
	picklehashes = {}
	pickletofile = {}
	for r in rankingfiles:
		filehash = unpackreports[r]['sha256']
		if filehash in processed:
			continue
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		## generate piechart and version information
		if leafreports.has_key('ranking'):
			## the ranking result is (res, dynamicRes, variablepvs)
			(res, dynamicRes, variablepvs) = leafreports['ranking']
			if res == None and dynamicRes == {}:
				continue

			## generate version information for strings
			for j in res['reports']:
				if j[4] != {}:
					package = j[1]
					tmppickle = tempfile.mkstemp()
					pickledata = []
					vals = list(set(j[4].values()))
					vals.sort()
					for v in vals:
						j_sorted = filter(lambda x: x[1] == v, j[4].items())
						j_sorted.sort()
						for v2 in j_sorted:
							pickledata.append(v2)
					cPickle.dump(pickledata, os.fdopen(tmppickle[0], 'w'))
					picklehash = gethash(tmppickle[1])
					if picklehash in pickles:
						if pickletofile.has_key(picklehash):
							pickletofile[picklehash].append(filehash)
						else:
							pickletofile[picklehash] = [filehash]
						os.unlink(tmppickle[1])
					else:
						shutil.move(tmppickle[1], pickledir)
						pickles.append(picklehash)
						versionpicklespackages.append((picklehash, package))
						picklehashes[picklehash] = os.path.basename(tmppickle[1])
						if pickletofile.has_key(picklehash):
							pickletofile[picklehash].append(filehash)
						else:
							pickletofile[picklehash] = [filehash]

			## generate version information for functions
			if dynamicRes.has_key('packages'):
				for package in dynamicRes['packages']:
					print >>sys.stderr, "PACKAGE", package, filehash
					packagedata = copy.copy(dynamicRes['packages'][package])
					tmppickle = tempfile.mkstemp()
					pickledata = []
					p_sorted = sorted(packagedata, key=lambda x: x[1])
					vals = list(set(map(lambda x: x[1], p_sorted)))
					vals.sort()
					for v in vals:
						j_sorted = filter(lambda x: x[1] == v, p_sorted)
						j_sorted.sort()
						for v2 in j_sorted:
							pickledata.append(v2)
					cPickle.dump(pickledata, os.fdopen(tmppickle[0], 'w'))
					picklehash = gethash(tmppickle[1])
					if picklehash in pickles:
						if pickletofile.has_key(picklehash):
							pickletofile[picklehash].append(filehash)
						else:
							pickletofile[picklehash] = [filehash]
						os.unlink(tmppickle[1])
					else:
						shutil.move(tmppickle[1], pickledir)
						pickles.append(picklehash)
						funcpicklespackages.append((picklehash, package))
						picklehashes[picklehash] = os.path.basename(tmppickle[1])
						if pickletofile.has_key(picklehash):
							pickletofile[picklehash].append(filehash)
						else:
							pickletofile[picklehash] = [filehash]
			processed.append(filehash)

	pool = multiprocessing.Pool()
	generatetasks = map(lambda x: (picklehashes[x[0]],) + x + ("funcversion", imagedir, pickledir), funcpicklespackages) + map(lambda x: (picklehashes[x[0]],) + x + ("version", imagedir, pickledir), versionpicklespackages)
	results = pool.map(generateversionchart, generatetasks)
	pool.terminate()
	results = filter(lambda x: x != None, results)
	for r in results:
		(filehash, extension) = r.split('-', 1)
		for f in pickletofile[filehash]:
			shutil.copy(os.path.join(imagedir, r), os.path.join(imagedir, "%s-%s" % (f, extension)))
		os.unlink(os.path.join(imagedir, r))
