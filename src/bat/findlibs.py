#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy

'''
This program can be used to check whether the dependencies of a dynamically
linked executable or library can be satisfied at runtime given the libraries
in a scanned archive.

For this we need to find the correct dynamic libraries for an executable and for
other libraries. There might be more than one copy or version for a particular
library since there could for example be multiple file systems inside a firmware
and we might not know how the dynamic linker is configured, or which file systems
are mounted where and when and get the right combination of libraries.

We need to do the following:

* verify the architectures of the dependencies are compatible with the
executable or library.
* handle symlinks, since not the fully qualified file name might have been
used in the binary, but the name of a symlink was used.
* multiple copies of (possibly conflicting) libraries need to be dealt with
properly.

We do something similar for remote and local variables.
'''

def findlibs(unpackreports, leafreports, scantempdir, envvars=None):
	elffiles = []
	squashedelffiles = {}
	localfunctionnames = {}
	remotefunctionnames = {}
	localvariablenames = {}
	remotevariablenames = {}
	unresolvable = []
	symlinks = {}
	for i in unpackreports:
		if not leafreports.has_key(i):
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
		if not 'elf' in leafreports[i]['tags']:
			continue
		if not squashedelffiles.has_key(os.path.basename(i)):
			squashedelffiles[os.path.basename(i)] = [i]
		else:
			squashedelffiles[os.path.basename(i)].append(i)
		elffiles.append(i)

	## first store all local and remote function names for each dynamic
	## ELF executable on the system.
	## Also store the soname of the library
	sonames = {}
	varignores = ['__dl_ldso__']
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
			## we only want functions and objects
			if functionstrings[3] != 'FUNC' and functionstrings[3] != 'IFUNC' and functionstrings[3] != 'OBJECT':
				continue
			## store local functions
			elif functionstrings[6] != 'UND':
				if functionstrings[3] == 'FUNC' or functionstrings[3] == 'IFUNC':
					localfuncs.append(functionstrings[7].split('@')[0])
				elif functionstrings[3] == 'OBJECT' and functionstrings[6] != 'ABS':
					if functionstrings[7].split('@')[0] not in varignores:
						localvars.append(functionstrings[7].split('@')[0])
				continue
			## See http://gcc.gnu.org/ml/gcc/2002-06/msg00112.html
			if functionstrings[7].split('@')[0] == '_Jv_RegisterClasses':
				continue
			## we can probably make use of the fact some are annotated with '@'
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
	usedby = {}
	dupes = {}
	for i in elffiles:
		usedlibs = []
		if leafreports[i].has_key('libs'):
			if remotefunctionnames[i] == [] and remotevariablenames[i] == []:
				if list(set(leafreports[i]['libs']).difference(set(usedlibs))) != []:
					print >>sys.stderr, "UNUSED LIBS", i, list(set(leafreports[i]['libs']).difference(set(usedlibs)))
				print >>sys.stderr
				continue
			## first create a copy of the names to resolve
			remotefuncswc = copy.copy(remotefunctionnames[i])
			remotevarswc = copy.copy(remotevariablenames[i])
			funcsfound = []
			varsfound = []
			for l in leafreports[i]['libs']:
				filtersquash = []
				if not squashedelffiles.has_key(l):
					## perhaps we have the so as a symlink, or a missing symlink
					if not symlinks.has_key(l):
						## we can't resolve the dependencies. There could be various
						## reasons for that, such as a missing symlink that was not
						## created during unpacking.
						if not sonames.has_key(l):
							unresolvable.append(l)
							continue
						else:
							## TODO: we have one or more libraries which could
							## possible fullfill the dependency.
							unresolvable.append(l)
							continue
					## we have one or possibly more symlinks that can fullfill
					## this requirement
					for sl in symlinks[l]:
						## absolute link, figure out how to deal with that
						if sl['target'].startswith('/'):
							pass
						else:
							filtersquash.append(os.path.normpath(os.path.join(os.path.dirname(sl['original']), sl['target'])))
				else:
					filtersquash = filter(lambda x: leafreports[x]['architecture'] == leafreports[i]['architecture'], squashedelffiles[l])
				## now walk through the possible files that can resolve
				## this dependency.
				## First we verify how many possible files we have. Since there might be
				## multiple files that satisfy a dependency (because they have the same name) we 
				## need to verify if the libraries are the same or not:
				## * checksums
				## * equivalent localfuncs and remote funcs (and in the future localvars and remotevars)
				if len(filtersquash) > 1:
					if len(list(set(map(lambda x: unpackreports[x]['sha256'], filtersquash)))) == 1:
						filtersquash = [filtersquash[0]]
						## store so we can report later
						dupes[filtersquash[0]] = filtersquash
					else:
						difference = False
						## now we compare the local and remote funcs and vars. If they
						## are equivalent we
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
						localvarsfound = list(set(remotevarswc).intersection(set(localvariablenames[filtersquash[0]])))
						if localvarsfound != []:
							if usedby.has_key(filtersquash[0]):
								usedby[filtersquash[0]].append(i)
							else:
								usedby[filtersquash[0]] = [i]
							usedlibs.append(l)
						varsfound = varsfound + localvarsfound
						remotevarswc = list(set(remotevarswc).difference(set(varsfound)))
						pass
				else:
					## TODO
					pass
			if remotefuncswc != []:
				print >>sys.stderr, "NOT FULLFILLED", i, remotefuncswc, remotevarswc
				possiblymissinglibs = list(set(leafreports[i]['libs']).difference(set(usedlibs)))
				if possiblymissinglibs != []:
					print >>sys.stderr, "POSSIBLY MISSING", possiblymissinglibs
				print >>sys.stderr
			if list(set(leafreports[i]['libs']).difference(set(usedlibs))) != [] and remotefuncswc == []:
				print >>sys.stderr, "UNUSED LIBS", i, list(set(leafreports[i]['libs']).difference(set(usedlibs)))
				print >>sys.stderr
	print >>sys.stderr,"DUPES",  dupes

	for u in usedby:
		print >>sys.stderr, "USED", u, usedby[u]
		print >>sys.stderr
