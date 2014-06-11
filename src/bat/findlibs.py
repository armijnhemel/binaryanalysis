#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, multiprocessing, pydot
import bat.interfaces

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

Then symbols need to be resolved in a few steps (both for functions and
variables):

1. for each undefined symbol in a file see if it is defined in one of the
declared dependencies as GLOBAL.
2. for each weak undefined symbol in a file see if it is defined in one of the
declared dependencies as GLOBAL.
3. for each undefined symbol in a file that has not been resolved yet see if it
is defined in one of the declared dependencies as WEAK.
4. for each defined weak symbol in a file see if one of the declared
dependencies defines the same symbols as GLOBAL.

This method does not always work. Some vendors run sstrip on the binaries.
Some versions of the sstrip tool are buggy and create files with a section
header that confuses standard readelf:

https://dev.openwrt.org/ticket/6847
https://bugs.busybox.net/show_bug.cgi?id=729
'''

def knownInterface(names, ptype):
	if ptype == 'functions':
		for i in names:
			if i not in bat.interfaces.allfunctions:
				return False
	elif ptype == 'variables':
		for i in names:
			if i not in bat.interfaces.allvars:
				return False
	return True

## generate PNG files and optionally SVG
def writeGraph((elfgraph, filehash, imagedir, generatesvg)):
	elfgraph_tmp = pydot.graph_from_dot_data(elfgraph)
	elfgraph_tmp.write_png(os.path.join(imagedir, '%s-graph.png' % filehash))
	if generatesvg:
		elfgraph_tmp.write_svg(os.path.join(imagedir, '%s-graph.svg' % filehash))

## extract variable names, function names and the soname from an ELF file
def extractfromelf((path, filename)):
	remotefuncs = set()
	localfuncs = set()
	remotevars = set()
	localvars = set()
	rpaths = set()
	weakremotevars = set()
	weakremotefuncs = set()
	weaklocalvars = set()
	weaklocalfuncs = set()
	sonames = set()
	elftype = ""

	p = subprocess.Popen(['readelf', '-W', '--dyn-syms', os.path.join(path, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return

	## a list of variable names to ignore.
	varignores = ['__dl_ldso__']

	stansplit = stanout.split("\n")
	for s in stansplit[3:]:
		functionstrings = s.split()
		if len(functionstrings) <= 7:
			continue
		## only store functions and objects
		if functionstrings[3] != 'FUNC' and functionstrings[3] != 'IFUNC' and functionstrings[3] != 'OBJECT':
			continue
		## store local functions and variables (normal and weak)
		elif functionstrings[6] != 'UND':
			if functionstrings[3] == 'FUNC' or functionstrings[3] == 'IFUNC':
				funcname = functionstrings[7].split('@')[0]
				if functionstrings[4] == 'WEAK':
					weaklocalfuncs.add(funcname)
				else:
					localfuncs.add(funcname)
			elif functionstrings[3] == 'OBJECT' and functionstrings[6] != 'ABS':
				varname = functionstrings[7].split('@')[0]
				if varname not in varignores:
					varname = functionstrings[7].split('@')[0]
					if functionstrings[4] == 'WEAK':
						weaklocalvars.add(varname)
					else:
						localvars.add(varname)
			continue
		## See http://gcc.gnu.org/ml/gcc/2002-06/msg00112.html
		if functionstrings[7].split('@')[0] == '_Jv_RegisterClasses':
			continue
		## some things are annotated with '@' which could come in handy in the future
		if functionstrings[3] == 'FUNC' or functionstrings[3] == 'IFUNC':
			funcname = functionstrings[7].split('@')[0]
			if functionstrings[4] == 'WEAK':
				weakremotefuncs.add(funcname)
			else:
				remotefuncs.add(funcname)
		elif functionstrings[3] == 'OBJECT' and functionstrings[6] != 'ABS':
			if functionstrings[7].split('@')[0] not in varignores:
				remotevars.add(functionstrings[7].split('@')[0])

	## extract dynamic section
	p = subprocess.Popen(['readelf', '-Wd', "%s" % os.path.join(path, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return

	## determine if a library might have a soname
	for line in stanout.split('\n'):
		if "(SONAME)" in line:
			soname_split = line.split(': ')
			if len(soname_split) < 2:
				continue
			soname = line.split(': ')[1][1:-1]
			sonames.add(soname)
		if "(RPATH)" in line:
			rpath_split = line.split('[')[1]
			rpaths = rpath_split[:-1].split(':')
	sonames = set(sonames)

	p = subprocess.Popen(['readelf', '-h', "%s" % os.path.join(path, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return
	for line in stanout.split('\n'):
		if "Type:" in line:
			if "DYN" in line:
				elftype = "lib"
			if "EXE" in line:
				elftype = "exe"
			if "REL" in line:
				elftype = "kernelmod"

	return (filename, list(localfuncs), list(remotefuncs), list(localvars), list(remotevars), list(weaklocalfuncs), list(weakremotefuncs), list(weaklocalvars), list(weakremotevars), sonames, elftype, rpaths)

def findlibs(unpackreports, scantempdir, topleveldir, processors, debug=False, envvars=None, unpacktempdir=None):
	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	if scanenv.has_key('overridedir'):
		try:
			del scanenv['BAT_IMAGEDIR']
		except: 
			pass

	imagedir = scanenv.get('BAT_IMAGEDIR', os.path.join(topleveldir, "images"))
	try:
		os.stat(imagedir)
	except:
		## BAT_IMAGEDIR does not exist
		try:
			os.makedirs(imagedir)
		except Exception, e:
			return

	generatesvg = False
	if scanenv.get('ELF_SVG', '0') == '1':
		generatesvg = True

	## store names of all ELF files present in scan archive
	elffiles = set()

	## keep track of which libraries map to what.
	## For example, libm.so.0 could map to lib/libm.so.0 and lib2/libm.so.0
	## libraryname -> [list of libraries]
	squashedelffiles = {}

	## cache the names of local and remote functions and variables, both normal and weak
	localfunctionnames = {}
	remotefunctionnames = {}
	localvariablenames = {}
	remotevariablenames = {}
	weaklocalfunctionnames = {}
	weakremotefunctionnames = {}
	weaklocalvariablenames = {}
	weakremotevariablenames = {}

	## a list of unresolvable files: they don't exist on the system
	unresolvable = []

	## store all symlinks in the scan archive, since they might point to libraries
	symlinks = {}
	for i in unpackreports:
		if not unpackreports[i].has_key('sha256'):
			## possibly there are symlinks
			## TODO: rewrite symlinks to absolute paths before storing
			if unpackreports[i].has_key('tags'):
				if 'symlink' in unpackreports[i]['tags']:
					target = unpackreports[i]['magic'].split('`')[-1][:-1]
					if symlinks.has_key(os.path.basename(i)):
						symlinks[os.path.basename(i)].append({'original': i, 'target': target})
					else:
						symlinks[os.path.basename(i)] = [{'original': i, 'target': target}]
			continue
		filehash = unpackreports[i]['sha256']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue

		if not 'elf' in unpackreports[i]['tags']:
			continue

		## This makes no sense for for example statically linked libraries and, Linux kernel
		## images and Linux kernel modules, so skip.
		if 'static' in unpackreports[i]['tags']:
			continue
		if 'linuxkernel' in unpackreports[i]['tags']:
			continue

		if not squashedelffiles.has_key(os.path.basename(i)):
			squashedelffiles[os.path.basename(i)] = [i]
		else:
			squashedelffiles[os.path.basename(i)].append(i)
		elffiles.add(i)

	## map functions to libraries. For each function name a list of libraries
	## that define the function is kept.
	funcstolibs = {}
	weakfuncstolibs = {}

	## Map sonames to libraries For each soname a list of files that define the
	## soname is kept.
	sonames = {}

	## a list of variable names to ignore.
	varignores = ['__dl_ldso__']

	## Store all local and remote function names for each dynamic ELF executable
	## or library on the system.

	pool = multiprocessing.Pool(processes=processors)
	elftasks = map(lambda x: (scantempdir, x), elffiles)
	elfres = pool.map(extractfromelf, elftasks)
	pool.terminate()

	elftypes = {}
	rpaths = {}

	for i in elfres:
		if i == None:
			continue
		(filename, localfuncs, remotefuncs, localvars, remotevars, weaklocalfuncs, weakremotefuncs, weaklocalvars, weakremotevars, elfsonames, elftype, elfrpaths) = i
		if elfrpaths != []:
			rpaths[filename] = elfrpaths
		for soname in elfsonames:
			if sonames.has_key(soname):
				sonames[soname].append(filename)
			else:
				sonames[soname] = [filename]
		for funcname in localfuncs:
			if funcstolibs.has_key(funcname):
				funcstolibs[funcname].append(filename)
			else:
				funcstolibs[funcname] = [filename]
		for funcname in weaklocalfuncs:
			if weakfuncstolibs.has_key(funcname):
				weakfuncstolibs[funcname].append(filename)
			else:
				weakfuncstolibs[funcname] = [filename]

		## store normal functions and variables ...
		localfunctionnames[filename] = localfuncs
		remotefunctionnames[filename] = remotefuncs
		localvariablenames[filename] = localvars
		remotevariablenames[filename] = remotevars

		## ... as well as the weak ones
		weaklocalfunctionnames[filename] = weaklocalfuncs
		weakremotefunctionnames[filename] = weakremotefuncs
		weaklocalvariablenames[filename] = weaklocalvars
		weakremotevariablenames[filename] = weakremotevars
		elftypes[filename] = elftype

	## For each file keep a list of other files that use this file. This is mostly
	## for reporting.
	usedby = {}
	usedlibsperfile = {}
	usedlibsandcountperfile = {}
	unusedlibsperfile = {}
	possiblyusedlibsperfile = {}
	plugins = {}

	notfoundfuncsperfile = {}
	notfoundvarssperfile = {}

	## Keep a list of files that are identical, for example copies of libraries
	dupes = {}

	## Is this correct???
	ignorefuncs = set(["__ashldi3", "__ashrdi3", "__cmpdi2", "__divdi3", "__fixdfdi", "__fixsfdi", "__fixunsdfdi", "__fixunssfdi", "__floatdidf", "__floatdisf", "__floatundidf", "__lshrdi3", "__moddi3", "__ucmpdi2", "__udivdi3", "__umoddi3", "main"])
	for i in elffiles:
		if elftypes[i] == 'kernelmod':
			continue
		## per ELF file keep lists of used libraries and possibly used libraries.
		## The later is searched if it needs to be guessed which libraries were used.
		usedlibs = []
		possiblyused = []
		plugsinto = []

		filehash = unpackreports[i]['sha256']

		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		if leafreports.has_key('libs'):
			if remotefunctionnames[i] == [] and remotevariablenames[i] == [] and weakremotefunctionnames == [] and weakremotevariablenames == []:
				## nothing to resolve, so continue
				continue
			## keep copies of the original data
			remotefuncswc = copy.copy(remotefunctionnames[i])
			remotevarswc = copy.copy(remotevariablenames[i])

			funcsfound = []
			varsfound = []
			filteredlibs = []

			## reverse mapping
			filteredlookup = {}
			for l in leafreports['libs']:

				## temporary storage to hold the names of the libraries
				## searched for. This list will be manipulated later on.
				filtersquash = []

				if not squashedelffiles.has_key(l):
					## No library (or libraries) with the name that has been declared
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
					## TODO: fix this. What was I thinking?
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
					if len(set(map(lambda x: unpackreports[x]['sha256'], filtersquash))) == 1:
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
							filtersquash = [filtersquash[0]]
				if len(filtersquash) == 1:
					filteredlibs += filtersquash
					if filteredlookup.has_key(filtersquash[0]):
						filteredlookup[filtersquash[0]].append(l)
					else:
						filteredlookup[filtersquash[0]] = [l]
					if remotefuncswc != []:
						if localfunctionnames.has_key(filtersquash[0]):
							## easy case
							localfuncsfound = list(set(remotefuncswc).intersection(set(localfunctionnames[filtersquash[0]])))
							if localfuncsfound != []:
								if usedby.has_key(filtersquash[0]):
									usedby[filtersquash[0]].append(i)
								else:
									usedby[filtersquash[0]] = [i]
								if knownInterface(localfuncsfound, 'functions'):
									usedlibs.append((l,len(localfuncsfound), True))
								else:
									usedlibs.append((l,len(localfuncsfound), False))
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
								if knownInterface(localvarsfound, 'variables'):
									usedlibs.append((l,len(localvarsfound), True))
								else:
									usedlibs.append((l,len(localvarsfound), False))
							varsfound = varsfound + localvarsfound
							remotevarswc = list(set(remotevarswc).difference(set(varsfound)))
				else:
					## TODO
					pass
			## normal resolving has finished, now resolve WEAK undefined symbols, first against
			## normal symbols ...
			weakremotefuncswc = copy.copy(weakremotefunctionnames[i])
			weakremotevarswc = copy.copy(weakremotevariablenames[i])
			for f in filteredlibs:
				if weakremotefuncswc != []:
					if localfunctionnames.has_key(f):
						## easy case
						localfuncsfound = list(set(weakremotefuncswc).intersection(set(localfunctionnames[f])))
						if localfuncsfound != []:
							if usedby.has_key(f):
								usedby[f].append(i)
							else:
								usedby[f] = [i]
							if len(filteredlookup[f]) == 1:
								if knownInterface(localfuncsfound, 'functions'):
									usedlibs.append((filteredlookup[f][0],len(localfuncsfound), True))
								else:
									usedlibs.append((filteredlookup[f][0],len(localfuncsfound), False))
							else:
								## this should never happen
								pass
							funcsfound = funcsfound + localfuncsfound
							weakremotefuncswc = list(set(weakremotefuncswc).difference(set(funcsfound)))
				if weakremotevarswc != []:
					if localvariablenames.has_key(f):
						localvarsfound = list(set(weakremotevarswc).intersection(set(localvariablenames[filtersquash[0]])))
						if localvarsfound != []:
							if usedby.has_key(f):
								usedby[f].append(i)
							else:
								usedby[f] = [i]
							if len(filteredlookup[f]) == 1:
								if knownInterface(localvarsfound, 'variables'):
									usedlibs.append((filteredlookup[f][0],len(localvarsfound), True))
								else:
									usedlibs.append((filteredlookup[f][0],len(localvarsfound), False))
							else:
								## this should never happen
								pass
							varsfound = varsfound + localvarsfound
							weakremotevarswc = list(set(weakremotevarswc).difference(set(varsfound)))

			## then resolve normal unresolved symbols against weak symbols
			for f in filteredlibs:
				if remotefuncswc != []:
					if weaklocalfunctionnames.has_key(f):
						## easy case
						localfuncsfound = list(set(remotefuncswc).intersection(set(weaklocalfunctionnames[f])))
						if localfuncsfound != []:
							if usedby.has_key(f):
								usedby[f].append(i)
							else:
								usedby[f] = [i]
							if len(filteredlookup[f]) == 1:
								if knownInterface(localfuncsfound, 'functions'):
									usedlibs.append((filteredlookup[f][0],len(localfuncsfound), True))
								else:
									usedlibs.append((filteredlookup[f][0],len(localfuncsfound), False))
							else:
								## this should never happen
								pass
							funcsfound = funcsfound + localfuncsfound
							remotefuncswc = list(set(remotefuncswc).difference(set(funcsfound)))
				if remotevarswc != []:
					if weaklocalvariablenames.has_key(f):
						localvarsfound = list(set(remotevarswc).intersection(set(weaklocalvariablenames[f])))
						if localvarsfound != []:
							if usedby.has_key(f):
								usedby[f].append(i)
							else:
								usedby[f] = [i]
							if len(filteredlookup[f]) == 1:
								if knownInterface(localvarsfound, 'variables'):
									usedlibs.append((filteredlookup[f][0],len(localvarsfound), True))
								else:
									usedlibs.append((filteredlookup[f][0],len(localvarsfound), False))
							else:
								## this should never happen
								pass
							varsfound = varsfound + localvarsfound
							remotevarswc = list(set(remotevarswc).difference(set(varsfound)))

			## finally check the weak local symbols and see if they have been defined somewhere
			## else as a global symbol. In that case the global symbol has preference.
			weaklocalfuncswc = copy.copy(weaklocalfunctionnames[i])
			weaklocalvarswc = copy.copy(weaklocalvariablenames[i])

			for f in filteredlibs:
				if weaklocalfuncswc != []:
					if localfunctionnames.has_key(f):
						localfuncsfound = list(set(weaklocalfuncswc).intersection(set(localfunctionnames[f])))
						if localfuncsfound != []:
							if usedby.has_key(f):
								usedby[f].append(i)
							else:
								usedby[f] = [i]
							if len(filteredlookup[f]) == 1:
								if knownInterface(localfuncsfound, 'functions'):
									usedlibs.append((filteredlookup[f][0],len(localfuncsfound), True))
								else:
									usedlibs.append((filteredlookup[f][0],len(localfuncsfound), False))
							else:
								## this should never happen
								pass
							funcsfound = funcsfound + localfuncsfound

							weaklocalfuncswc = list(set(weaklocalfuncswc).difference(set(funcsfound)))
				if weaklocalvarswc != []:
					if localvariablenames.has_key(f):
						localvarsfound = list(set(weaklocalvarswc).intersection(set(localvariablenames[f])))
						if localvarsfound != []:
							if usedby.has_key(f):
								usedby[f].append(i)
							else:
								usedby[f] = [i]
							if len(filteredlookup[f]) == 1:
								if knownInterface(localvarsfound, 'variables'):
									usedlibs.append((filteredlookup[f][0],len(localvarsfound), True))
								else:
									usedlibs.append((filteredlookup[f][0],len(localvarsfound), False))
							else:
								## this should never happen
								pass
							varsfound = varsfound + localvarsfound
							weaklocalvarswc = list(set(weaklocalvarswc).difference(set(varsfound)))
			if remotevarswc != []:
				## TODO: find possible solutions for unresolved vars
				notfoundvarssperfile[i] = remotevarswc

			if remotefuncswc != []:
				## The scan has ended, but there are still symbols left.
				notfoundfuncsperfile[i] = remotefuncswc
				unusedlibs = list(set(leafreports['libs']).difference(set(map(lambda x: x[0], usedlibs))))
				unusedlibs.sort()
				unusedlibsperfile[i] = unusedlibs

				possiblesolutions = []

				## try to find solutions for the currently unresolved symbols.
				## 1. check if one of the existing used libraries already defines it as
				##    a WEAK symbol. If so, continue.
				## 2. check other libraries. If there is a match, store it as a possible
				##    solution.
				##
				## This could possibly be incorrect if an existing used library defines
				## the symbol as WEAK, but another "hidden" dependency has it as GLOBAL.
				## First for remote functions...
				for r in remotefuncswc:
					if r in ignorefuncs:
						continue
					if weakfuncstolibs.has_key(r):
						existing = False
						for w in weakfuncstolibs[r]:
							## TODO: update count if match was found
							if w in filteredlibs:
								existing = True
								break
						if not existing:
							possiblesolutions = possiblesolutions + weakfuncstolibs[r]
							#print >>sys.stderr, "NOT FOUND WEAK", r, weakfuncstolibs[r], filteredlibs
					elif funcstolibs.has_key(r):
						if len(funcstolibs[r]) == 1:
							possiblesolutions = possiblesolutions + funcstolibs[r]
							continue
						else:
							found = False
							for l in funcstolibs[r]:
								if l in possiblesolutions:
									## prefer a dependency that is already used
									found = True
									break
							if not found:
								## there are a few scenarions:
								## 1. the file is a plugin that is loaded into executables
								##    at run time.
								## 2. false positives.
								if elftypes[i] == 'lib':
									if list(set(map(lambda x: elftypes[x], funcstolibs[r]))) == ['exe']:
										plugsinto += funcstolibs[r]
								## there are multiple files that can satisfy this dependency
								## 1. check if the files are identical (checksum)
								## 2. if identical, check for soname and choose the one
								## of which the name matches
								## 3. check if the files that implement the same thing are
								## libs or executables. Prefer libs.
								if len(set(map(lambda x: unpackreports[x]['sha256'], funcstolibs[r]))) == 1:
									for l in funcstolibs[r]:
										if sonames.has_key(os.path.basename(l)):
											found = True
											possiblesolutions.append(l)
											break
									if not found:
										pass
								else:
									pass
				## ... then for remote variables ...
				for r in remotevarswc:
					pass
				#print >>sys.stderr, "NOT FULLFILLED", i, remotefuncswc, remotevarswc, usedlibs
				if possiblesolutions != []:
					#print >>sys.stderr, "POSSIBLE LIBS TO SATISFY CONDITIONS", i, list(set(possiblesolutions))
					possiblyusedlibsperfile[i] = list(set(possiblesolutions))
			else:
				if set(leafreports['libs']).difference(set(map(lambda x: x[0], usedlibs))) != set():
					unusedlibs = list(set(leafreports['libs']).difference(set(map(lambda x: x[0], usedlibs))))
					unusedlibs.sort()
					unusedlibsperfile[i] = unusedlibs
					#print >>sys.stderr, "UNUSED LIBS", i, list(set(leafreports[i]['libs']).difference(set(usedlibs)))
					#print >>sys.stderr
			if possiblyused != []:
				pass
				#print >>sys.stderr, "POSSIBLY USED", i, possiblyused
				#print >>sys.stderr
		usedlibs_tmp = {}
		for l in usedlibs:
			if usedlibs_tmp.has_key(l[0]):
				inposix = usedlibs_tmp[l[0]][1] and l[2]
				usedlibs_tmp[l[0]] = (usedlibs_tmp[l[0]][0] + l[1], inposix)
			else:
				usedlibs_tmp[l[0]] = (l[1], l[2])
		if not usedlibsperfile.has_key(i):
			usedlibsp = list(set(map(lambda x: x[0], usedlibs)))
			usedlibsp.sort()
			usedlibsperfile[i] = usedlibsp
		if not usedlibsandcountperfile.has_key(i):
			usedlibsandcountperfile[i] = map(lambda x: (x[0],) + x[1], usedlibs_tmp.items())
		if plugsinto != []:
			pcount = {}
			for p in plugsinto:
				if pcount.has_key(p):
					pcount[p] += 1
				else:
					pcount[p] = 1
			plugins[i] = pcount

	## return a dictionary, with for each ELF file for which there are results
	## a separate dictionary with the results. These will be added to 'scans' in
	## leafreports by the top level script.
	aggregatereturn = {}
	for i in elffiles:
		if elftypes[i] == 'kernelmod':
			continue
		writeback = False
		filehash = unpackreports[i]['sha256']

		if not aggregatereturn.has_key(i):
			aggregatereturn[i] = {}
		if usedby.has_key(i):
			aggregatereturn[i]['elfusedby'] = list(set(usedby[i]))
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
		if possiblyusedlibsperfile.has_key(i):
			aggregatereturn[i]['elfpossiblyused'] = possiblyusedlibsperfile[i]
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


	squashedgraph = {}
	for i in elffiles:
		if elftypes[i] == 'kernelmod':
			continue
		libdeps = usedlibsandcountperfile[i]
		if not squashedgraph.has_key(i):
			squashedgraph[i] = []
		for d in libdeps:
			if not squashedelffiles.has_key(d[0]):
				if sonames.has_key(d[0]):
					if len(sonames[d[0]]) != 1:
						continue
					else:
						squashedgraph[i].append((sonames[d[0]][0], d[1], d[2]))
				else:
					continue
			else:
				if len(squashedelffiles[d[0]]) != 1:
					pass
				else:
					squashedgraph[i].append((squashedelffiles[d[0]][0], d[1], d[2]))

	## TODO: make more parallel
	elfgraphs = set()
	for i in elffiles:
		if elftypes[i] == 'kernelmod':
			continue
		if not squashedgraph.has_key(i):
			continue
		filehash = unpackreports[i]['sha256']
		ppname = os.path.join(unpackreports[i]['path'], unpackreports[i]['name'])
		seen = set()
		elfgraph = pydot.Dot(graph_type='digraph')
		rootnode = pydot.Node(ppname)
		elfgraph.add_node(rootnode)

		## processnodes is a tuple with 4 values:
		## (parent node, node text, count, nodetype)
		## 1. parent node: pointer to the parent node in the graph
		## 2. node text: text displayed in the node
		## 3. count: amount of links
		## 4. nodetype
		## Five types: normal knowninterface unused undeclared plugin
		## 1. used: the dependency is a normal dependency
		## 2. knowninterface: all used symbols are in a known standard
		## 3. unused: the dependency is not used
		## 4. undeclared: the dependency is used but undeclared
		## 5. plugin: the dependency is used as a plugin
		processnodes = set(map(lambda x: (rootnode,) + x + (True, True), squashedgraph[i]))
		newprocessNodes = set()
		for pr in processnodes:
			if pr[3] == True:
				newprocessNodes.add(pr[0:3] + ("knowninterface",))
			else:
				newprocessNodes.add(pr[0:3] + ("used",))
		processnodes = newprocessNodes
		if unusedlibsperfile.has_key(i):
			for j in unusedlibsperfile[i]:
				if not squashedelffiles.has_key(j):
					continue
				if len(squashedelffiles[j]) != 1:
					continue
				processnodes.add((rootnode, squashedelffiles[j][0], 0, "unused"))
				seen.add((i,j))
		if possiblyusedlibsperfile.has_key(i):
			for j in possiblyusedlibsperfile[i]:
				processnodes.add((rootnode, j, 0, "undeclared"))
				seen.add((i,j))
		seen.update(map(lambda x: (i, x[0]), squashedgraph[i]))

		while True:
			newprocessnodes = set()
			for j in processnodes:
				(parentnode, nodetext, count, nodetype) = j
				ppname = os.path.join(unpackreports[nodetext]['path'], unpackreports[nodetext]['name'])
				tmpnode = pydot.Node(ppname)
				elfgraph.add_node(tmpnode)
				if nodetype == "unused":
					## declared but unused dependencies are represented by dashed blue lines
					elfgraph.add_edge(pydot.Edge(parentnode, tmpnode, style='dashed', color='blue'))
				elif nodetype == "undeclared":
					## undeclared but used dependencies get a red solid line
					elfgraph.add_edge(pydot.Edge(parentnode, tmpnode, color='red'))
				elif nodetype == "knowninterface":
					elfgraph.add_edge(pydot.Edge(parentnode, tmpnode, style='dotted', label="%d" % count, labeldistance=1.5, labelfontsize=20.0))
				elif nodetype == "used":
					elfgraph.add_edge(pydot.Edge(parentnode, tmpnode, label="%d" % count, labeldistance=1.5, labelfontsize=20.0))

				if squashedgraph.has_key(nodetext):
					for n in squashedgraph[nodetext]:
						if not (nodetext, n[0]) in seen:
							if n[-1] == True:
								newprocessnodes.add((tmpnode,) +  n[0:-1] + ("knowninterface",))
							else:
								newprocessnodes.add((tmpnode,) +  n[0:-1] + ("used",))
							seen.add((nodetext, n[0]))
				if possiblyusedlibsperfile.has_key(nodetext):
					for u in possiblyusedlibsperfile[nodetext]:
						if not (nodetext, u) in seen:
							newprocessnodes.add((tmpnode, u, 0, "undeclared"))
							seen.add((nodetext, u))
				if unusedlibsperfile.has_key(nodetext):
					for u in unusedlibsperfile[nodetext]:
						if not (nodetext, u) in seen:
							if not squashedelffiles.has_key(u):
								continue
							if len(squashedelffiles[u]) != 1:
								continue
							newprocessnodes.add((tmpnode, squashedelffiles[u][0], 0, "unused"))
							seen.add((nodetext, u))
			processnodes = newprocessnodes
			if processnodes == set():
				break

		elfgraph_data = elfgraph.to_string()
		elfgraphs.add((elfgraph_data, filehash, imagedir, generatesvg))

	pool = multiprocessing.Pool(processes=processors)
	elfres = pool.map(writeGraph, elfgraphs,1)
	pool.terminate()
