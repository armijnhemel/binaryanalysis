#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle

'''
This program can be used to check whether the dependencies of a dynamically
linked executable or library can be satisfied at runtime given the libraries
in a scanned archive.

For this the correct dynamic libraries for an executable and for other libraries
need to be found. There might be more than one copy or version for a particular
library since there could for example be multiple file systems inside a firmware.
It is hard to find out what the actual state at runtime might possibly be because
it might be unknown how the dynamic linker is configured, or which file systems
are mounted where and when. Although in the vast majority of cases it is crystal
clear which libraries are used sometimes it can get tricky.

The following needs to be done:

* verify the architectures of the dependencies are compatible with the
executable or library.
* handle symlinks, since not the fully qualified file name might have been
used in the binary, but the name of a symlink was used.
* multiple copies of (possibly conflicting) libraries need to be dealt with
properly.

Something similar is done for remote and local variables.
'''

def findlibs(unpackreports, scantempdir, topleveldir, envvars=None):
	## store names of all ELF files present in scan archive
	elffiles = []

	## keep track of which libraries map to what.
	## For example, libm.so.0 could map to lib/libm.so.0 and lib2/libm.so.0
	## libraryname -> [list of libraries]
	squashedelffiles = {}

	## cache the names of local and remote functions and variables
	localfunctionnames = {}
	remotefunctionnames = {}
	localvariablenames = {}
	remotevariablenames = {}

	## a list of unresolvable files: they don't exist on the system
	unresolvable = []

	## store all symlinks in the scan archive, since they might point to libraries
	symlinks = {}
	for i in unpackreports:
		if not unpackreports[i].has_key('sha256'):
			continue
		filehash = unpackreports[i]['sha256']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			## possibly we're dealing with a symlink
			## OK, so this does not work with localized systems.
			## TODO: work around possible localization issues
			if 'symbolic link' in unpackreports[i]['magic']:
				target = unpackreports[i]['magic'].split('`')[-1][:-1]
				if symlinks.has_key(os.path.basename(i)):
					symlinks[os.path.basename(i)].append({'original': i, 'target': target})
				else:
					symlinks[os.path.basename(i)] = [{'original': i, 'target': target}]
			continue

		if not 'elf' in unpackreports[i]['tags']:
			continue

		if not squashedelffiles.has_key(os.path.basename(i)):
			squashedelffiles[os.path.basename(i)] = [i]
		else:
			squashedelffiles[os.path.basename(i)].append(i)
		elffiles.append(i)

	## map functions to libraries. For each function name a list of libraries
	## that define the function is kept.
	funcstolibs = {}

	## Map sonames to libraries For each soname a list of files that define the
	## soname is kept.
	sonames = {}

	## a list of variable names to ignore.
	varignores = ['__dl_ldso__']

	## Store all local and remote function names for each dynamic ELF executable
	## or library on the system.
	for i in elffiles:
		remotefuncs = []
		localfuncs = []
		remotevars = []
		localvars = []
		p = subprocess.Popen(['readelf', '-W', '--dyn-syms', os.path.join(scantempdir, i)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			continue
		for s in stanout.split("\n")[3:]:
			functionstrings = s.split()
			if len(functionstrings) <= 7:
				continue
			## only store functions and objects
			if functionstrings[3] != 'FUNC' and functionstrings[3] != 'IFUNC' and functionstrings[3] != 'OBJECT':
				continue
			## store local functions
			elif functionstrings[6] != 'UND':
				if functionstrings[3] == 'FUNC' or functionstrings[3] == 'IFUNC':
					funcname = functionstrings[7].split('@')[0]
					localfuncs.append(funcname)
					if funcstolibs.has_key(funcname):
						funcstolibs[funcname].append(i)
					else:
						funcstolibs[funcname] = [i]
				elif functionstrings[3] == 'OBJECT' and functionstrings[6] != 'ABS':
					if functionstrings[7].split('@')[0] not in varignores:
						localvars.append(functionstrings[7].split('@')[0])
				continue
			## See http://gcc.gnu.org/ml/gcc/2002-06/msg00112.html
			if functionstrings[7].split('@')[0] == '_Jv_RegisterClasses':
				continue
			## some things are annotated with '@' which could come in handy in the future
			if functionstrings[3] == 'FUNC' or functionstrings[3] == 'IFUNC':
				remotefuncs.append(functionstrings[7].split('@')[0])
			elif functionstrings[3] == 'OBJECT' and functionstrings[6] != 'ABS':
				if functionstrings[7].split('@')[0] not in varignores:
					remotevars.append(functionstrings[7].split('@')[0])

		localfunctionnames[i] = localfuncs
		remotefunctionnames[i] = remotefuncs
		localvariablenames[i] = localvars
		remotevariablenames[i] = remotevars

		p = subprocess.Popen(['readelf', '-d', "%s" % os.path.join(scantempdir, i)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return

		for line in stanout.split('\n'):
			if "Library soname:" in line:
				soname = line.split(': ')[1][1:-1]
				if sonames.has_key(soname):
					sonames[soname].append(i)
				else:
					sonames[soname] = [i]
				break


	## TODO: look if RPATH is used, since that will give use more information
	## by default

	## For each file keep a list of other files that use this file. This is mostly
	## for reporting.
	usedby = {}
	usedlibsperfile = {}
	unusedlibsperfile = {}

	notfoundfuncsperfile = {}
	notfoundvarssperfile = {}

	## Keep a list of files that are identical, for example copies of libraries
	dupes = {}
	for i in elffiles:
		## per ELF file keep lists of used libraries and possibly used libraries.
		## The later is kept if which libraries were used needs to be guessed.
		usedlibs = []
		possiblyused = []

		filehash = unpackreports[i]['sha256']

		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		## This makes no sense for for example statically linked libraries and the
		## pickle will have been read needlessly. TODO: only read files that are dynamically
		## linked.
		if leafreports.has_key('libs'):

			## keep copies of the original data
			remotefuncswc = copy.copy(remotefunctionnames[i])
			remotevarswc = copy.copy(remotevariablenames[i])

			## only process if there actually is anything to process
			if remotefunctionnames[i] != [] or remotevariablenames[i] != []:
				funcsfound = []
				varsfound = []
				for l in leafreports['libs']:

					## temporary storage to hold the names of the libraries
					## searched for. This list will be manipulated later on.
					filtersquash = []

					if not squashedelffiles.has_key(l):
						## No library (or libraries ) with the name that has been declared
						## in the ELF file can be found. It could be because the
						## declared name is actually a symbolic link that could, or could
						## not be present on the system.
						if not symlinks.has_key(l):
							## There are no symlinks that point to a library that's needed.
							## There could be various reasons for this, such as a missing
							## symlink that was not created during unpacking.
							if not sonames.has_key(l):
								unresolvable.append(l)
								continue
							else:
								if len(sonames[l]) == 1:
									possiblyused.append(sonames[l][0])
									filtersquash = filtersquash + squashedelffiles[os.path.basename(sonames[l][0])]
								else:
									## TODO: more libraries could possibly
									## fullfill the dependency.
									unresolvable.append(l)
									continue
						else:
							## there are one or possibly more symlinks that can fullfill
							## this requirement
							for sl in symlinks[l]:
								## absolute link, figure out how to deal with that
								if sl['target'].startswith('/'):
									pass
								else:
									target = os.path.normpath(os.path.join(os.path.dirname(sl['original']), sl['target']))
									## TODO: verify if any of the links are symlinks
									## themselves. Add a safety mechanism for cyclical
									## symlinks.
									if os.path.islink(target):
										pass
									## add all resolved symlinks to the list of
									## libraries to consider
									filtersquash.append(target)
					else:
						filtersquash = filter(lambda x: leafreports['architecture'] == leafreports['architecture'], squashedelffiles[l])
					## now walk through the possible files that can resolve this dependency.
					## First verify how many possible files are in 'filtersquash' have.
					## In the common case this will be just one and then everything is easy.
					## Since there might be multiple files that satisfy a dependency (because
					## they have the same name) a few verification steps have to be taken.
					## Quite often the copies will be the same as well, which is easy to check using:
					## * SHA256 checksums
					## * equivalent local and remote function names (and in the future localvars and remotevars)
					if len(filtersquash) > 1:
						if len(list(set(map(lambda x: unpackreports[x]['sha256'], filtersquash)))) == 1:
							filtersquash = [filtersquash[0]]
							## store duplicates for later reporting of alternatives
							dupes[filtersquash[0]] = filtersquash
						else:
							difference = False
							## compare the local and remote funcs and vars. If they
							## are equivalent they can be treated as if they were identical
							for f1 in filtersquash:
								if difference == True:
									break
								for f2 in filtersquash:
									if len(set(localfunctionnames[f1]).intersection(set(localfunctionnames[f2]))) == len(localfunctionnames[f1]):
										difference = True
										break
									if len(set(remotefunctionnames[f1]).intersection(set(remotefunctionnames[f2]))) != len(remotefunctionnames[f1]):
										difference = True
										break
							if not difference:
								dupes[filtersquash[0]] = filtersquash
					if len(filtersquash) == 1:
						if remotefuncswc != []:
							if localfunctionnames.has_key(filtersquash[0]):
								## easy case
								localfuncsfound = list(set(remotefuncswc).intersection(set(localfunctionnames[filtersquash[0]])))
								if localfuncsfound != []:
									if usedby.has_key(filtersquash[0]):
										usedby[filtersquash[0]].append(i)
									else:
										usedby[filtersquash[0]] = [i]
									usedlibs.append(l)
								funcsfound = funcsfound + localfuncsfound
								remotefuncswc = list(set(remotefuncswc).difference(set(funcsfound)))
						if remotevarswc != []:
							if localvariablenames.has_key(filtersquash[0]):
								localvarsfound = list(set(remotevarswc).intersection(set(localvariablenames[filtersquash[0]])))
								if localvarsfound != []:
									if usedby.has_key(filtersquash[0]):
										usedby[filtersquash[0]].append(i)
									else:
										usedby[filtersquash[0]] = [i]
									usedlibs.append(l)
								varsfound = varsfound + localvarsfound
								remotevarswc = list(set(remotevarswc).difference(set(varsfound)))
					else:
						## TODO
						pass
			if remotevarswc != []:
				notfoundvarssperfile[i] = remotevarswc
			if remotefuncswc != []:
				notfoundfuncsperfile[i] = remotefuncswc
				#print >>sys.stderr, "NOT FULLFILLED", i, remotefuncswc, remotevarswc
				possiblymissinglibs = list(set(leafreports['libs']).difference(set(usedlibs)))
				if possiblymissinglibs != []:
					pass
					#print >>sys.stderr, "POSSIBLY MISSING AND/OR UNUSED", possiblymissinglibs
				possiblesolutions = []
				for r in remotefuncswc:
					if funcstolibs.has_key(r):
						possiblesolutions = possiblesolutions + funcstolibs[r]
				if possiblesolutions != []:
					pass
					#print >>sys.stderr, "POSSIBLE LIBS TO SATISFY CONDITIONS", list(set(possiblesolutions))
				#print >>sys.stderr
			if list(set(leafreports['libs']).difference(set(usedlibs))) != [] and remotefuncswc == []:
				unusedlibs = list(set(leafreports['libs']).difference(set(usedlibs)))
				unusedlibs.sort()
				unusedlibsperfile[i] = unusedlibs
				#print >>sys.stderr, "UNUSED LIBS", i, list(set(leafreports[i]['libs']).difference(set(usedlibs)))
				#print >>sys.stderr
			if possiblyused != []:
				pass
				#print >>sys.stderr, "POSSIBLY USED", i, possiblyused
				#print >>sys.stderr
			if not usedlibsperfile.has_key(i):
				usedlibs = list(set(usedlibs))
				usedlibs.sort()
				usedlibsperfile[i] = usedlibs
	#print >>sys.stderr,"DUPES",  dupes

	## return a dictionary, with for each ELF file for which there are results
	## a separate dictionary with the results. These will be added to 'scans' in
	## leafreports by the top level script.
	aggregatereturn = {}
	for i in elffiles:
		writeback = False
		filehash = unpackreports[i]['sha256']

		if not aggregatereturn.has_key(i):
			aggregatereturn[i] = {}
		if usedby.has_key(i):
			aggregatereturn[i]['elfusedby'] = usedby[i]
			writeback = True
		if usedlibsperfile.has_key(i):
			aggregatereturn[i]['elfused'] = usedlibsperfile[i]
			writeback = True
		if unusedlibsperfile.has_key(i):
			aggregatereturn[i]['elfunused'] = unusedlibsperfile[i]
			writeback = True
		if notfoundfuncsperfile.has_key(i):
			aggregatereturn[i]['notfoundfuncs'] = notfoundfuncsperfile[i]
			writeback = True
		if notfoundvarssperfile.has_key(i):
			aggregatereturn[i]['notfoundvars'] = notfoundvarssperfile[i]
			writeback = True

		## only write the new leafreport if there actually is something to write back
		if writeback:
			leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
			leafreports = cPickle.load(leaf_file)
			leaf_file.close()

			for e in aggregatereturn[i]:
				if aggregatereturn[i].has_key(e):
					leafreports[e] = copy.deepcopy(aggregatereturn[i][e])

			leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
			leafreports = cPickle.dump(leafreports, leaf_file)
			leaf_file.close()

	return aggregatereturn
