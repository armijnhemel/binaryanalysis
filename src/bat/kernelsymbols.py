#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, multiprocessing
import pydot, collections, csv, tempfile, shutil
import bat.batdb

'''
This plugin for the Binary Analysis Tool can be used to check how the symbols
needed by kernel modules are used as well as detect various "smells".

* undeclared dependencies: a module requires another module but doesn't declare
it in the "depends" field in the module
* non-GPL licensed modules that use symbols from another module while the other
module only makes these modules available using EXPORT_SYMBOL_GPL()
* symbols that are not found in any versions found in the BAT database, so it is
unclear what their symbol type is

The method works as follows. First information is extracted from the kernel
files, or retrieved from already available information:

* kernel symbols defined in and exported by the module or Linux kernel image
* symbols that are needed by a module (modules only)
* declared dependencies (modules only)
* version number

The result is a dependency graph for each module that requires any symbols from
any other kernel file.

This method depends on bat/kernelanalysis.py to tag modules and extract Linux
kernel versions and bat/identifier.py to extract Linux kernel symbols from the
main Linux kernel image.

It uses the BAT database to look for the type of the kernel symbol.

WARNING: 2.4 and earlier kernel modules are not supported!
'''

## write the data to a separate CSV file that can be loaded into a spreadsheet
## like LibreOffice Calc or Excel
## Per line of the CSV file the following information is kept:
## * full path of the kernel module (as determined by BAT)
## * name of the kernel module
## * symbol name
## * type (EXPORT_SYMBOL, EXPORT_SYMBOL_GPL, unknown, unresolved)
## * full path of the dependency providing the symbol (either kernel module or main kernel)
## * name of the dependency providing the symbol (either kernel module or main kernel)
## * kernel version name
## TODO: do something with "unresolved symbols"
def writeCSV(csvpath, useddependenciesperfilename, useddependenciessymbolsperfilename, nametofilehash, filehashtodeclaredlicenses, filehashtokernelsymbols, filehashtoversions, symboltotype, unresolvedsymbols):
	## process each of the kernel modules that have dependencies
	csvfile = open(csvpath, 'wb')
	batcsv = csv.writer(csvfile, dialect='excel')
	batcsv.writerow(["Full path of caller", "Name of caller", "Caller version", "Symbol name", "Symbol type", "Full path of callee", "Name of callee", "Callee version"])
	for i in useddependenciessymbolsperfilename:
		filehash = nametofilehash[i]
		modulename = os.path.basename(i)
		filehashtodeclaredlicenses[filehash]
		version = filehashtoversions[filehash]
		## process each of the found dependencies. Create a line in the CSV file for every symbol
		## in the dependency
		for dependency in useddependenciessymbolsperfilename[i]:
			dependencyversion = filehashtoversions[nametofilehash[dependency]]
			for symbol in useddependenciessymbolsperfilename[i][dependency]:
				## the symbol type for this symbol, possibly rewrite it for display reasons
				symboltype = symboltotype[dependencyversion][symbol]
				if symboltype == 'kernelsymbol':
					symboltype = 'EXPORT_SYMBOL'
				elif symboltype == 'gplkernelsymbol':
					symboltype = 'EXPORT_SYMBOL_GPL'
				batcsv.writerow([i, modulename, version, symbol, symboltype, dependency, os.path.basename(dependency), dependencyversion])
		pass
	csvfile.close()

## write the graph to a PNG image and optionally SVG if defined in the
## BAT configuration file
def writeGraph((symbolgraph, filehash, counter, imagedir, generatesvg)):
	symbolgraph_tmp = pydot.graph_from_dot_data(symbolgraph)
	symbolgraph_tmp.write_png(os.path.join(imagedir, '%s-%d-kernel-symbol-graph.png' % (filehash, counter)))
	if generatesvg:
		symbolgraph_tmp.write_svg(os.path.join(imagedir, '%s-%d-kernel-symbol-graph.svg' % (filehash, counter)))

## extract, lookup and bundle information for kernel files
## * version
## * kernel symbols (both locally defined and needed from remote)
## * dependencies
def extractfromkernelfile((filehash, filename, topleveldir, scantempdir)):
 	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()
	if leafreports.has_key('identifier'):
		if leafreports['identifier'].has_key('kernelsymbols'):
			kernelsymbols = leafreports['identifier']['kernelsymbols']
		else:
			kernelsymbols = set()
	else:
		kernelsymbols = set()

	if leafreports.has_key('kernelmodulelicense'):
		declaredlicenses = leafreports['kernelmodulelicense']
	else:
		declaredlicenses = set()

	version = None
	remotesymbols = set()
	dependencies = set()
	module = False

	if not "elf" in leafreports['tags']:
		## this is a Linux kernel image, not a module. It does not define any remote symbols
		version = leafreports['kernelchecks']['version']
		declaredlicenses.add('GPL')
		return (filehash, version, remotesymbols, dependencies, declaredlicenses, kernelsymbols, module)
	else:
		if leafreports.has_key('kernelchecks'):
			## this is a Linux kernel image, not a module. It does not define any remote symbols
			version = leafreports['kernelchecks']['version']
			return (filehash, version, remotesymbols, dependencies, declaredlicenses, kernelsymbols, module)
		else:
			## module, so continue
			version = leafreports['kernelmoduleversion']
			module = True

	## for modules read the symbol table and extract the right symbols
	p = subprocess.Popen(['readelf', '-W', '--syms', os.path.join(scantempdir, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return

	stansplit = stanout.split("\n")
	for s in stansplit[3:]:
		functionstrings = s.split()
		if len(functionstrings) <= 7:
			continue
		## not interested in anything but undefined kernel symbols
		if functionstrings[6] == 'UND':
			if functionstrings[4] != 'GLOBAL':
				continue
			funcname = functionstrings[7]
			remotesymbols.add(funcname)

	## now extract the defined dependencies using modinfo
	if 'misnamedkernelmodule' in leafreports['tags']:
		tmpfile = tempfile.mkstemp(suffix='.ko')
		os.fdopen(tmpfile[0]).close()
		shutil.copy(os.path.join(scantempdir, filename), tmpfile[1])
		p = subprocess.Popen(['/sbin/modinfo', "-F", "depends", tmpfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		os.unlink(tmpfile[1])
		if p.returncode != 0:
			return
	else:
		p = subprocess.Popen(['/sbin/modinfo', "-F", "depends", os.path.join(scantempdir, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return

	## dependencies are separated by ','
	if stanout.strip() != '':
		depsplits = stanout.strip().split(',')
		for i in depsplits:
			dependencies.add(i)

	return (filehash, version, remotesymbols, dependencies, declaredlicenses, kernelsymbols, module)

## the main method called by BAT
def findsymbols(unpackreports, scantempdir, topleveldir, processors, scanenv={}, scandebug=False, unpacktempdir=None):
	(envresult, newenv) = kernelsymbolssetup(scanenv, scandebug)

	if not envresult:
		return None

	## if KERNELSYMBOL_SVG is set in the configuration then the graph will
	## also be generated in SVG format by writeGraph()
	generatesvg = False
	if scanenv.get("KERNELSYMBOL_SVG", 0) == '1':
		generatesvg = True
	if scanenv.get("KERNELSYMBOL_CSV", 0) == '1':
		generatecsv = True
	else:
		generatecsv = False

	## if KERNELSYMBOL_DEPENDENCIES is set in the configuration then the graph
	## will display information about dependencies as declared in the module
	## or lack thereof.
	displaydependencies = False
	if scanenv.get("KERNELSYMBOL_DEPENDENCIES", 0) == '1':
		displaydependencies = True


	if scanenv.has_key('overridedir'):
		try:
			del scanenv['BAT_IMAGEDIR']
		except: 
			pass

	imagedir = scanenv.get('BAT_IMAGEDIR', os.path.join(topleveldir, "images"))
	reportdir = scanenv.get('BAT_REPORTDIR', os.path.join(topleveldir, "reports"))
	try:
		os.stat(imagedir)
	except:
		## BAT_IMAGEDIR does not exist
		try:
			os.makedirs(imagedir)
		except Exception, e:
			return

	try:
		os.stat(reportdir)
	except:
		## BAT_REPORTDIR does not exist
		try:
			os.makedirs(reportdir)
		except Exception, e:
			return

	batdb = bat.batdb.BatDb(scanenv['DBBACKEND'])

	## Is the master database defined?
	if not scanenv.has_key('BAT_DB'):
		return

	masterdb = scanenv.get('BAT_DB')

	## open database connection to the master database
	masterconn = batdb.getConnection(masterdb,scanenv)
	mastercursor = masterconn.cursor()

	## store names of all files containing Linux kernel images or modules
	symbolfiles = set()

	## store a mapping for filehashes to names and vice versa
	filehashtoname = {}
	nametofilehash = {}

	## walk all unpackreports and keep track of which are Linux kernel images or modules
	for i in unpackreports:
		if not unpackreports[i].has_key('sha256'):
			continue
		filehash = unpackreports[i]['sha256']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		if not 'linuxkernel' in unpackreports[i]['tags']:
			continue
		symbolfiles.add((filehash, i))
		if filehashtoname.has_key(filehash):
			filehashtoname[filehash].append(i)
		else:
			filehashtoname[filehash] = [i]
		nametofilehash[i] = filehash

	## now check each file in symbolfiles and return:
	## 1. version
	## 2. symbols that are defined and symbols that are needed (empty for main Linux kernel)
	## 3. defined dependencies
	pool = multiprocessing.Pool(processes=processors)
	symboltasks = map(lambda x: x + (topleveldir, scantempdir), symbolfiles)
	symbolres = pool.map(extractfromkernelfile, symboltasks)

	## check if there actually are modules. If not, there is nothing to do
	if filter(lambda x: x[-1] == True, symbolres) == []:
		pool.terminate()
		## close the database cursor and connection
		mastercursor.close()
		masterconn.close()
		return

	filehashtoremotesymbols = {}
	filehashtokernelsymbols = {}

	## keep per version per symbol which filehashes define that
	## symbol. A symbol could be defined by more than one module.
	kernelsymboltofilehash = {}

	## store which dependencies were defined for each filehash, if any
	filehashtodependencies = {}

	## store which versions each filehash has
	filehashtoversions = {}

	filehashtodeclaredlicenses = {}

	filehashtomodules = set()
	nametomodules = set()

	## store which type each symbol has in a dictionary:
	## * gplkernel (EXPORT_SYMBOL_GPL)
	## * kernel (EXPORT_SYMBOL)
	## * undecided (either EXPORT_SYMBOL or EXPORT_SYMBOL_GPL)
	## * unknown (symbol not found in the database for this version)
	## This can change per version
	symboltotype = {}

	symbolquery = batdb.getQuery('select * from extracted_name where name=%s')
	versionquery = batdb.getQuery('select package,version from processed_file where checksum=%s')

	for i in symbolres:
		(filehash, version, remotesymbols, dependencies, declaredlicenses, kernelsymbols, module) = i
		if filehashtoversions.has_key(filehash):
			continue
		if module:
			filehashtomodules.add(filehash)
			for n in filehashtoname[filehash]:
				nametomodules.add(n)
		filehashtoversions[filehash] = version
		filehashtodeclaredlicenses[filehash] = declaredlicenses
		filehashtokernelsymbols[filehash] = kernelsymbols
		if not kernelsymboltofilehash.has_key(version):
			kernelsymboltofilehash[version] = {}
		for k in kernelsymbols:
			if kernelsymboltofilehash[version].has_key(k):
				kernelsymboltofilehash[version][k].append(filehash)
			else:
				kernelsymboltofilehash[version][k] = [filehash]
		for d in dependencies:
			if filehashtodependencies.has_key(filehash):
				filehashtodependencies[filehash].append(d)
			else:
				filehashtodependencies[filehash] = [d]
		if len(remotesymbols) != 0:
			filehashtoremotesymbols[filehash] = remotesymbols

		## now determine the types of each symbol, per found version
		if not symboltotype.has_key(version):
			symboltotype[version] = {}
		scansymbols = set()
		scansymbols.update(kernelsymbols)
		scansymbols.update(remotesymbols)
		for k in scansymbols:
			if symboltotype[version].has_key(k):
				continue
			mastercursor.execute(symbolquery, (k,))
			symres = mastercursor.fetchall()
			symres = filter(lambda x: x[2] == 'kernelsymbol' or x[2] == 'gplkernelsymbol', symres)
			symlen = len(set(map(lambda x: x[2], symres)))
			if symlen == 0:
				## unknown symbol. Perhaps an out of tree module, or a kernel version
				## that is not in the database.
				symboltotype[version][k] = 'unknown'
				continue
			if symlen == 1:
				## just one type found in the database, so report
				## TODO: perhaps it makes sense to do an extra version check here?
				if symres[0][2] == 'kernelsymbol':
					symboltotype[version][k] = 'kernelsymbol'
				elif symres[0][2] == 'gplkernelsymbol':
					symboltotype[version][k] = 'gplkernelsymbol'
				continue
			## the symbol can be found as both 'kernelsymbol' and 'gplkernelsymbol'
			## in the database so try to narrow results down.
			linuxsymres = set()
			## find the entries that are closest to the kernel version extracted from the binary
			symboltypefinal = None
			for sy in symres:
				(syfilehash, symbolname, symboltype, language, linenumber) = sy
				mastercursor.execute(versionquery, (syfilehash,))
				packageres = mastercursor.fetchall()
				for p in packageres:
					if p[0] != 'linux':
						continue
					## first try to see if any of the kernel versions matched in the database
					## is the same as the one extracted from the binary
					if p[1] == version:
						## direct match
						symboltypefinal = symboltype
						break
					else:
						## if the version cannot be found in the database it might have a
						## EXTRAVERSION set in the Linux kernel Makefile
						if '-' in version:
							## modify the version and rerun the check
							newversion = version.split('-', 1)[0]
							if p[1] == newversion:
								symboltypefinal = symboltype
								break
			if symboltypefinal == None:
				## the package the symbol can be found in is not a Linux kernel, but likely
				## an out of tree module
				symboltotype[version][k] = 'undecided'
			else:
				symboltotype[version][k] = symboltypefinal

	## close the database cursor and connection
	mastercursor.close()
	masterconn.close()

	useddependenciessymbolsperfilename = {}

	## store dependency information per file name
	useddependenciesperfilename = {}

	usedby = {}

	## store which filehashes are equivalent symbolwise
	## This functionality is currently not used.
	equivalents = {}

	for version in kernelsymboltofilehash:
		for s in kernelsymboltofilehash[version]:
			kernsymlen = len(set(kernelsymboltofilehash[version][s]))
			if kernsymlen > 1:
				for f in range(0, kernsymlen):
					filehash1 = kernelsymboltofilehash[version][s][f]
					for g in range(1, kernsymlen):
						filehash2 = kernelsymboltofilehash[version][s][g]
						if filehash1 == filehash2:
							continue
						if equivalents.has_key(filehash1):
							if filehash2 in equivalents[filehash1]:
								continue
						if equivalents.has_key(filehash2):
							if filehash1 in equivalents[filehash2]:
								continue
						if set(filehashtokernelsymbols[filehash1]) == set(filehashtokernelsymbols[filehash2]):
							if equivalents.has_key(filehash1):
								equivalents[filehash1].append(filehash2)
							else:
								equivalents[filehash1] = [filehash2]
						else:
							## modules/images define the same symbol and have the
							## same kernel version. TODO: decide how to deal with this
							## and how to report.
							pass

	## store per filehash which symbols cannot be resolved
	unresolvedsymbols = {}

	## process each of the filehashes that have undefined symbols
	for filehash in filehashtoremotesymbols:
		version = filehashtoversions[filehash]
		if not kernelsymboltofilehash.has_key(version):
			## standalone symbol, or version checks are disabled in the kernel
			## TODO: find out how to deal with this
			continue

		## store all the dependencies per file name. This has to be done by file name so
		## the graphs can be generated with the correct labels (example: there are multiple
		## copies of a file system with kernel and modules in a firmware image).
		for i in filehashtoname[filehash]:
			useddependenciesperfilename[i] = set()
			useddependenciessymbolsperfilename[i] = {}

		for r in filehashtoremotesymbols[filehash]:
			if not kernelsymboltofilehash[version].has_key(r):
				## unresolved symbol. This is bad bad bad.
				if unresolvedsymbols.has_key(filehash):
					unresolvedsymbols[filehash].add(r)
				else:
					unresolvedsymbols[filehash] = set([r])
				continue
			## if there is only one dependency that has this symbol it is easy
			if len(set(kernelsymboltofilehash[version][r])) == 1:
				dep = kernelsymboltofilehash[version][r][0]
				for i in filehashtoname[filehash]:
					maxlen = 0
					winner = None
					for n in filehashtoname[dep]:
						commonlen = len(os.path.commonprefix([n, i]))
						if commonlen > maxlen:
							maxlen = commonlen
							winner = n
					if winner != None:
						useddependenciesperfilename[i].add(winner)
						if useddependenciessymbolsperfilename[i].has_key(winner):
							useddependenciessymbolsperfilename[i][winner].add(r)
						else:
							useddependenciessymbolsperfilename[i][winner] = set([r])
			## There could be more than one file fullfilling this dependency. A common example
			## is that there are two Linux kernel images, for example a rescue image.
			else:
				## easy case: the filehash only maps to one file, so choose the dependency with
				## the biggest shared path of the file name. It's a bit hackish, but hey, it seems
				## to work well.
				if len(filehashtoname[filehash]) == 1:
					maxlen = 0
					winner = None
					possibledeps = map(lambda x: filehashtoname[x], kernelsymboltofilehash[version][r])
					for d in possibledeps:
						for dep in d:
							commonlen = len(os.path.commonprefix([dep, filehashtoname[filehash][0]]))
							if commonlen > maxlen:
								maxlen = commonlen
								winner = dep
					## if there is a winner then record it as the dependency
					if winner != None:
						dep = nametofilehash[winner]
						for i in filehashtoname[filehash]:
							useddependenciesperfilename[i].add(winner)
							if useddependenciessymbolsperfilename[i].has_key(winner):
								useddependenciessymbolsperfilename[i][winner].add(r)
							else:
								useddependenciessymbolsperfilename[i][winner] = set([r])
				## harder case: there are two or more files with the same hash and there are two
				## or more files with a *different* hash that fullfill the dependency
				else:
					possibledeps = map(lambda x: filehashtoname[x], kernelsymboltofilehash[version][r])
					for i in filehashtoname[filehash]:
						maxlen = 0
						winner = None
						for d in possibledeps:
							for dep in d:
								commonlen = len(os.path.commonprefix([dep, i]))
								if commonlen > maxlen:
									maxlen = commonlen
									winner = dep
						if winner != None:
							dep = nametofilehash[winner]
							useddependenciesperfilename[i].add(winner)
							if useddependenciessymbolsperfilename[i].has_key(winner):
								useddependenciessymbolsperfilename[i][winner].add(r)
							else:
								useddependenciessymbolsperfilename[i][winner] = set([r])
	## Write a CSV file with results
	if generatecsv:
		csvpath = os.path.join(reportdir, 'kernelsymbols.csv')
		writeCSV(csvpath, useddependenciesperfilename, useddependenciessymbolsperfilename, nametofilehash, filehashtodeclaredlicenses, filehashtokernelsymbols, filehashtoversions, symboltotype, unresolvedsymbols)

	## store the graphs
	symbolgraphs = set()

	## store how often each file hash is processed. There could be multiple graphs per file hash.
	## The difference would be the label. Example: a firmware that contains multiple (near) identical
	## file systems or collections of Linux kernel and modules under different paths.
	uniqueversions = collections.Counter()

	## for each of the files loop through the recorded dependencies, find
	## out the type of the symbols (predetermined) and create
	## nodes and edges with the following information:
	## * amount of kernelsymbols
	## * amount of gplkernelsymbols
	## * amount of kernelsymbols where the status is undecided
	## * amount of unknown symbols
	for filename in useddependenciesperfilename:
		symbolgraph = pydot.Dot(graph_type='digraph')

		i = nametofilehash[filename]
		uniqueversions.update([i])
		counter = uniqueversions[i]

		## first create the root node
		version = filehashtoversions[i]
		declaredlicenses = filehashtodeclaredlicenses.get(i, None)

		gplkernelsymbols = set()
		for s in filehashtokernelsymbols[i]:
			if symboltotype[version][s] == 'gplkernelsymbol':
				gplkernelsymbols.add(s)

		## assume modules are not GPL licensed by default
		gpllicense = False

		if declaredlicenses != None:
			if declaredlicenses != set():
				nodename = "%s\n%s" % (filename, reduce(lambda x, y: x + "," + y, declaredlicenses))
				for l in declaredlicenses:
					if 'GPL' in l:
						gpllicense = True
						break
			else:
				nodename = filename
		else:
			nodename = filename
		## if the module is not GPL licensed, but has GPL kernel symbols colour the node red
		if len(gplkernelsymbols) != 0:
			if not gpllicense:
				rootnode = pydot.Node(nodename, color='red')
			else:
				rootnode = pydot.Node(nodename)
		else:
			rootnode = pydot.Node(nodename)
		symbolgraph.add_node(rootnode)

		## keep track of which edges have already been processed
		seen = set()

		processnodes = set(map(lambda x: (filename, rootnode, gpllicense, filehash, x), useddependenciesperfilename[filename]))
		while True:
			newprocessnodes = set()
			for k in processnodes:
				(parent, parentnode, parentgpllicense, parenthash, dependencyname) = k
				if (parent,dependencyname) in seen:
					continue
				dependency = nametofilehash[dependencyname]

				## by default set the label to dependencyname
				nodename = dependencyname

				## assume modules are not GPL licensed
				gpllicense = False

				declaredlicenses = filehashtodeclaredlicenses.get(dependency, None)
				if declaredlicenses != None:
					if declaredlicenses != set():
						nodename = "%s\n%s" % (dependencyname, reduce(lambda x, y: x + "," + y, declaredlicenses))
					for l in declaredlicenses:
						if 'GPL' in l:
							gpllicense = True
							break
				tmpnode = pydot.Node(nodename)
				symbolgraph.add_node(tmpnode)

				unknownsymbols = set()
				gplkernelsymbols = set()
				kernelsymbols = set()
				undecidedsymbols = set()
				if useddependenciesperfilename.has_key(dependencyname):
					## make 'dependency' the new parent and add to the list of nodes to be processed
					newprocessnodes.update(set(map(lambda x: (dependencyname, tmpnode, gpllicense, dependency, x), useddependenciesperfilename[dependencyname])))
			
				for s in useddependenciessymbolsperfilename[parent][dependencyname]:
					if symboltotype[version][s] == 'unknown':
						unknownsymbols.add(s)
					elif symboltotype[version][s] == 'kernelsymbol':
						kernelsymbols.add(s)
					elif symboltotype[version][s] == 'gplkernelsymbol':
						gplkernelsymbols.add(s)
					elif symboltotype[version][s] == 'undecided':
						undecidedsymbols.add(s)

				## create the edges based on what symbols were found and which type the symbols have
				if len(unknownsymbols) != 0:
					symbolgraph.add_edge(pydot.Edge(parentnode, tmpnode, label="%d" % len(unknownsymbols), style='solid', color='blue', tooltip=reduce(lambda x, y: x + " " + y, unknownsymbols)))
				if len(kernelsymbols) != 0:
					symbolgraph.add_edge(pydot.Edge(parentnode, tmpnode, label="%d" % len(kernelsymbols), style='solid', color='black', tooltip=reduce(lambda x, y: x + " " + y, kernelsymbols)))
				if len(undecidedsymbols) != 0:
					symbolgraph.add_edge(pydot.Edge(parentnode, tmpnode, label="%d" % len(undecidedsymbols), style='dashed', color='red', tooltip=reduce(lambda x, y: x + " " + y, undecidedsymbols)))
				if len(gplkernelsymbols) != 0:
					symbolgraph.add_edge(pydot.Edge(parentnode, tmpnode, label="%d" % len(gplkernelsymbols), style='solid', color='red', tooltip=reduce(lambda x, y: x + " " + y, gplkernelsymbols)))
					## if there is an incompatibility between GPL symbols and the license
					## of the parent node then colour both the parent node and the dependency
					## red.
					if not parentgpllicense:
						parentnode.set_color('red')
						tmpnode.set_color('red')

				## See if the dependency was explicitely declared in the binary module
				## Dependencies can only be declared for other modules.
				if dependencyname in nametomodules and displaydependencies:
					cleaned_dependency_name = os.path.basename(dependencyname).rsplit('.', 1)[0]
					declared_dependencies = filehashtodependencies.get(parenthash, [])
					if cleaned_dependency_name in declared_dependencies:
						symbolgraph.add_edge(pydot.Edge(parentnode, tmpnode, style='dotted', color='black'))
					else:
						symbolgraph.add_edge(pydot.Edge(parentnode, tmpnode, style='dotted', color='red'))
				seen.add((parent,dependencyname))
			processnodes = newprocessnodes
			if processnodes == set():
				break
		symbolgraph_data = symbolgraph.to_string()
		symbolgraphs.add((symbolgraph_data, i, counter, imagedir, generatesvg))

	## write the graphs in parallel in PNG and, optionally, SVG formats
	pool.map(writeGraph, symbolgraphs, 1)
	pool.terminate()

def kernelsymbolssetup(scanenv, debug=False):
	if not 'DBBACKEND' in scanenv:
		return (False, None)
	if scanenv['DBBACKEND'] == 'sqlite3':
		return kernelsymbolssetup_sqlite3(scanenv, debug)
	if scanenv['DBBACKEND'] == 'postgresql':
		return kernelsymbolssetup_postgresql(scanenv, debug)
	return (False, None)

def kernelsymbolssetup_postgresql(scanenv, debug=False):
	newenv = copy.deepcopy(scanenv)
	batdb = bat.batdb.BatDb('postgresql')
	conn = batdb.getConnection(None,scanenv)
	if conn == None:
		return (False, None)
	conn.close()
	return (True, newenv)

def kernelsymbolssetup_sqlite3(scanenv, debug=False):
	newenv = copy.deepcopy(scanenv)

	## Is the master database defined?
	if not scanenv.has_key('BAT_DB'):
		return (False, None)

	masterdb = scanenv.get('BAT_DB')

	## Does the master database exist?
	if not os.path.exists(masterdb):
		return (False, None)

	## TODO: many more checks
	return (True, newenv)
