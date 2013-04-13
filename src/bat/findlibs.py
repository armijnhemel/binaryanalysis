#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, multiprocessing, pydot

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

## extract variable names, function names and the soname from an ELF file
def extractfromelf((path, filename)):
	remotefuncs = []
	localfuncs = []
	remotevars = []
	localvars = []
	weakvars = []
	weakfuncs = []
	sonames = []
	elftype = ""

	p = subprocess.Popen(['readelf', '-W', '--dyn-syms', os.path.join(path, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return

	## a list of variable names to ignore.
	varignores = ['__dl_ldso__']

	for s in stanout.split("\n")[3:]:
		functionstrings = s.split()
		if len(functionstrings) <= 7:
			continue
		## only store functions and objects
		if functionstrings[3] != 'FUNC' and functionstrings[3] != 'IFUNC' and functionstrings[3] != 'OBJECT':
			continue
		## store local functions and variables
		## TODO: store WEAK symbols separately
		elif functionstrings[6] != 'UND':
			if functionstrings[3] == 'FUNC' or functionstrings[3] == 'IFUNC':
				funcname = functionstrings[7].split('@')[0]
				localfuncs.append(funcname)
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

	p = subprocess.Popen(['readelf', '-d', "%s" % os.path.join(path, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return

	## determine if a library might have a soname
	for line in stanout.split('\n'):
		if "(SONAME)" in line:
			soname = line.split(': ')[1][1:-1]
			sonames.append(soname)
	sonames = list(set(sonames))

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

	return (filename, localfuncs, remotefuncs, localvars, remotevars, sonames, elftype)

def findlibs(unpackreports, scantempdir, topleveldir, envvars=None):
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

		## This makes no sense for for example statically linked libraries and the
		## pickle will have been read needlessly.
		if 'static' in unpackreports[i]['tags']:
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

	pool = multiprocessing.Pool()
	elftasks = map(lambda x: (scantempdir, x), elffiles)
	elfres = pool.map(extractfromelf, elftasks)
	pool.terminate()

	elftypes = {}

	for i in elfres:
		(filename, localfuncs, remotefuncs, localvars, remotevars, elfsonames, elftype) = i
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

		localfunctionnames[filename] = localfuncs
		remotefunctionnames[filename] = remotefuncs
		localvariablenames[filename] = localvars
		remotevariablenames[filename] = remotevars
		elftypes[filename] = elftype

	## TODO: look if RPATH is used, since that will give use more information
	## by default

	## For each file keep a list of other files that use this file. This is mostly
	## for reporting.
	usedby = {}
	usedlibsperfile = {}
	unusedlibsperfile = {}
	possiblyusedlibsperfile = {}

	notfoundfuncsperfile = {}
	notfoundvarssperfile = {}

	## Keep a list of files that are identical, for example copies of libraries
	dupes = {}
	for i in elffiles:
		## per ELF file keep lists of used libraries and possibly used libraries.
		## The later is searched if it needs to be guessed which libraries were used.
		usedlibs = []
		possiblyused = []

		filehash = unpackreports[i]['sha256']

		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

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
				## The scan has ended, but there are still symbols left.
				notfoundfuncsperfile[i] = remotefuncswc
				#print >>sys.stderr, "NOT FULLFILLED", i, remotefuncswc, remotevarswc
				unusedlibs = list(set(leafreports['libs']).difference(set(usedlibs)))
				unusedlibs.sort()
				unusedlibsperfile[i] = unusedlibs

				possiblesolutions = []
				for r in remotefuncswc:
					if funcstolibs.has_key(r):
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
								## there are multiple files that can satisfy this dependency
								## 1. check if the files are identical (checksum)
								## 2. if identical, check for soname and choose the one
								## of which the name matches
								## 3. check if the files that implement the same thing are
								## libs or executables. Prefer libs.
								if len(list(set(map(lambda x: unpackreports[x]['sha256'], funcstolibs[r])))) == 1:
									for l in funcstolibs[r]:
										if sonames.has_key(os.path.basename(l)):
											found = True
											possiblesolutions.append(l)
											break
									if not found:
										pass
								else:
									pass
				if possiblesolutions != []:
					#print >>sys.stderr, "POSSIBLE LIBS TO SATISFY CONDITIONS", i, list(set(possiblesolutions))
					possiblyusedlibsperfile[i] = list(set(possiblesolutions))
			else:
				if list(set(leafreports['libs']).difference(set(usedlibs))) != []:
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
		libdeps = usedlibsperfile[i]
		if libdeps == []:
			continue
		if not squashedgraph.has_key(i):
			squashedgraph[i] = []
		for d in libdeps:
			if not squashedelffiles.has_key(d):
				if sonames.has_key(d):
					if len(sonames[d]) != 1:
						continue
					else:
						squashedgraph[i].append(sonames[d][0])
				else:
					continue
			else:
				if len(squashedelffiles[d]) != 1:
					pass
				else:
					squashedgraph[i].append(squashedelffiles[d][0])

	## TODO: make parallel
	for i in elffiles:
		if not squashedgraph.has_key(i):
			continue
		if squashedgraph[i] == []:
			continue
		else:
			filehash = unpackreports[i]['sha256']
			ppname = os.path.join(unpackreports[i]['path'], unpackreports[i]['name'])
			seen = []
			elfgraph = pydot.Dot(graph_type='digraph')
			rootnode = pydot.Node(ppname)
			elfgraph.add_node(rootnode)
			processnodes = map(lambda x: (rootnode, x, True, True), squashedgraph[i])
			if unusedlibsperfile.has_key(i):
				for j in unusedlibsperfile[i]:
					if not squashedelffiles.has_key(j):
						continue
					if len(squashedelffiles[j]) != 1:
						continue
					processnodes.append((rootnode, squashedelffiles[j][0], False, False))
			if possiblyusedlibsperfile.has_key(i):
				for j in possiblyusedlibsperfile[i]:
					processnodes.append((rootnode, j, True, False))
					seen.append((i,j))
			seen = seen + map(lambda x: (i, x), squashedgraph[i])

			while True:
				newprocessnodes = []
				for j in processnodes:
					(parentnode, nodetext, used, declared) = j
					ppname = os.path.join(unpackreports[nodetext]['path'], unpackreports[nodetext]['name'])
					tmpnode = pydot.Node(ppname)
					elfgraph.add_node(tmpnode)
					if not used:
						elfgraph.add_edge(pydot.Edge(parentnode, tmpnode, style='dashed', color='blue'))
					else:
						if not declared:
							elfgraph.add_edge(pydot.Edge(parentnode, tmpnode, color='red'))
						else:
							elfgraph.add_edge(pydot.Edge(parentnode, tmpnode))

					if squashedgraph.has_key(nodetext):
						for n in squashedgraph[nodetext]:
							if not (nodetext, n) in seen:
								newprocessnodes.append((tmpnode, n, True, True))
								seen.append((nodetext, n))
					if possiblyusedlibsperfile.has_key(nodetext):
						for u in possiblyusedlibsperfile[nodetext]:
							if not (nodetext, u) in seen:
								newprocessnodes.append((tmpnode, u, True, False))
								seen.append((nodetext, u))
					if unusedlibsperfile.has_key(nodetext):
						for u in unusedlibsperfile[nodetext]:
							if not (nodetext, u) in seen:
								if not squashedelffiles.has_key(u):
									continue
								if len(squashedelffiles[u]) != 1:
									continue
								newprocessnodes.append((tmpnode, squashedelffiles[u][0], False, False))
								seen.append((nodetext, u))
				processnodes = newprocessnodes
				if processnodes == []:
					break

			elfgraph.write_png(os.path.join(imagedir, '%s-graph.png' % filehash))
