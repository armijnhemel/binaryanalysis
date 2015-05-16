#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This program prints out a possible partial configuration for all Linux kernel
images plus associated modules found in a scan done by BAT.
'''

import sys, os, os.path, cPickle, sqlite3, tempfile, tarfile, gzip, re, copy
from optparse import OptionParser

def main(argv):
	parser = OptionParser()
        parser.add_option("-a", "--archive", action="store", dest="archive", help="result archive of BAT scan", metavar="ARCHIVE")
        parser.add_option("-d", "--database", action="store", dest="database", help="database with kernel configurations", metavar="DATABASE")
	(options, args) = parser.parse_args()

	if options.archive == None:
		parser.error("result archive not found")

	if not os.path.exists(options.archive):
		print >>sys.stderr, "result archive not found"
		sys.exit(1)

	if options.database == None:
		parser.error("database not found")

	if not os.path.exists(options.database):
		print >>sys.stderr, "database not found"
		sys.exit(1)

	conn = sqlite3.connect(options.database)
	cursor = conn.cursor()
	## first unpack the tar archive into a temporary directory
	tmpdir = tempfile.mkdtemp()
	try:
		tar = tarfile.open(options.archive, 'r:gz')
		tar.extractall(tmpdir)
		tar.close()
	except Exception, e:
		pass

	picklefile = open(os.path.join(tmpdir, 'scandata.pickle'))
	unpackreports = cPickle.load(picklefile)
	picklefile.close()

	## loop through the reports, record modules and kernel
	kernelfiles = set()
	for u in unpackreports:
		if not unpackreports[u].has_key('tags'):
			continue
		if not 'linuxkernel' in unpackreports[u]['tags']:
			continue
		if not unpackreports[u].has_key('checksum'):
			continue
		if not os.path.exists(os.path.join(tmpdir, 'filereports', "%s-filereport.pickle.gz" % unpackreports[u]['checksum'])):
			continue
		kernelfiles.add(u)

	## store kernel versions per file, since there might be multiple copies
	kernelversions = {}
	for i in kernelfiles:
		sha256sum = unpackreports[i]['checksum']
		picklefile = gzip.open(os.path.join(tmpdir, 'filereports', "%s-filereport.pickle.gz" % sha256sum))
		leafreports = cPickle.load(picklefile)
		picklefile.close()
		if not leafreports.has_key('ranking'):
			continue
		if leafreports.has_key('kernelchecks'):
			if leafreports['kernelchecks'].has_key('version'):
				if kernelversions.has_key(leafreports['kernelchecks']['version']):
					kernelversions[leafreports['kernelchecks']['version']].append(sha256sum)
				else:
					kernelversions[leafreports['kernelchecks']['version']] = [sha256sum]
		if leafreports.has_key('kernelmoduleversion'):
			if kernelversions.has_key(leafreports['kernelmoduleversion']):
				kernelversions[leafreports['kernelmoduleversion']].append(sha256sum)
			else:
				kernelversions[leafreports['kernelmoduleversion']] = [sha256sum]

	## Kernel version might need some clean up first.
	## TODO: integrate in loop above
	for i in kernelversions.keys():
		res = re.match('(\d\.\d+[\.\d+]*)', i)
		newversion = res.groups()[0]
		if i == newversion:
			continue
		else:
			tmpversion = copy.deepcopy(kernelversions[i])
			kernelversions[newversion] = tmpversion
			del kernelversions[i]

	## suck in the results. TODO: integrate into loop(s) above
	for i in kernelversions:
		possiblekernelfiles = set()
		for k in set(kernelversions[i]):
			picklefile = gzip.open(os.path.join(tmpdir, 'filereports', "%s-filereport.pickle.gz" % k))
			leafreports = cPickle.load(picklefile)
			picklefile.close()
			(res, dynamicRes, variablepvs, language) = leafreports['ranking']
			## first process string matches
			if res != None:
				for j in res['reports']:
					(rank, packagename, uniquematches, uniquematcheslen, percentage, packageversions, licenses, copyrights) = j
					if len(uniquematches) == 0:
						continue
					if packagename != 'linux':
						continue
					for u in uniquematches:
						(line, results) = u
						for r in results:
							(checksum, linenumber, versres) = r
							for v in versres:
								(version, filename) = v
								if version == i:
									possiblekernelfiles.add(filename)
			## then process function names
			## TODO: needs support in ranking.py for kernel function names first

			## then process kernel variable names, if any
			if variablepvs['type'] == 'linuxkernel':
				if variablepvs['versionresults'] != {}:
					for p in variablepvs['versionresults']:
						if p != 'linux':
							continue
						for var in variablepvs['versionresults'][p]:
							(line, results) = var
							for r in results:
								(checksum, linenumber, versres) = r
								for v in versres:
									(version, filename) = v
									if version == i:
										possiblekernelfiles.add(filename)

		configs = []

		## split the paths since sometimes directories might also
		## be relevant
		tmpkernelfiles = set()
		for p in possiblekernelfiles:
			if p.startswith('linux-%s' % i):
				p = p.split('/', 1)[1]
			tmpkernelfiles.add(p)
			numberofsplits = p.count('/')
			for r in range(0,numberofsplits):
				p = os.path.dirname(p)
				tmpkernelfiles.add(p + "/")

		for p in tmpkernelfiles:
			cursor.execute("select configstring from kernel_configuration where filename=? and version=?", (p, i))
			configres = cursor.fetchall()
			if configres != []:
				configs += map(lambda x: x[0], configres)

		## TODO: add information derived from Kconfig files. Some configurations are added by
		## default, but there is no file that includes it, for example CONFIG_YENTA_RICOH in 3.10.9
		for c in set(configs):
			print c

	cursor.close()
	conn.close()

if __name__ == "__main__":
	main(sys.argv)
