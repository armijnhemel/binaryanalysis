#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. Its purpose is to determine the
package a file belongs to based on the name of a package. This information is
mined from distributions like Fedora and Debian.
'''

import os, os.path, sqlite3, sys, subprocess, copy, Queue, cPickle
import bat.batdb
import multiprocessing
from multiprocessing import Process, Lock
from multiprocessing.sharedctypes import Value, Array

def grabpackage(scanqueue, reportqueue, cursor, query):
	## select the packages that are available. It would be better to also have the directory
	## name available, so we should get rid of 'path' and use something else that is better
	## suited
	while True:
		filename = scanqueue.get(timeout=2592000)
		cursor.execute(query, (os.path.basename(filename),))
		res = cursor.fetchall()
		if res != []:
			returnres = []
			## TODO: filter results, only return files that are not in tons of packages
			for r in res:
				(package, packageversion, distribution, distroversion) = r
				distrores = {}
				distrores['package'] = package
				distrores['packageversion'] = packageversion
				distrores['distribution'] = distribution
				distrores['distributionversion'] = distroversion
				returnres.append(distrores)
			reportqueue.put({filename: returnres})
		scanqueue.task_done()

def filename2package(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):
	(envresult, newenv) = file2packagesetup(scanenv, scandebug)
	if not envresult:
		return None

	if not scanenv.has_key('BAT_PACKAGE_DB'):
		return

	## open the database containing the mapping of filenames to package
	batdb = bat.batdb.BatDb(scanenv['DBBACKEND'])

	processtasks = []
	for i in unpackreports:
		if not 'checksum' in unpackreports[i]:
			continue
		processtasks.append(i)

	if processors == None:
		processamount = 1
	else:
		processamount = processors
	## create a queue for tasks, with a few threads reading from the queue
	## and looking up results and putting them in a result queue
	query = batdb.getQuery("select distinct package, packageversion, source, distroversion from file where filename = %s")
	scanmanager = multiprocessing.Manager()
	scanqueue = multiprocessing.JoinableQueue(maxsize=0)
	reportqueue = scanmanager.Queue(maxsize=0)
	processpool = []
        batcons = []
        batcursors = []

        map(lambda x: scanqueue.put(x), processtasks)
        minprocessamount = min(len(processtasks), processamount)
	res = []

	for i in range(0,minprocessamount):
		conn = batdb.getConnection(scanenv['BAT_PACKAGE_DB'],scanenv)
		c = conn.cursor()
		batcursors.append(c)
		batcons.append(conn)
		p = multiprocessing.Process(target=grabpackage, args=(scanqueue,reportqueue,batcursors[i],query))
		processpool.append(p)
		p.start()

	scanqueue.join()

	while True:
		try:
			val = reportqueue.get_nowait()
			res.append(val)
			reportqueue.task_done()
		except Queue.Empty, e:
			## Queue is empty
			break
			reportqueue.join()

	for p in processpool:
		p.terminate()

	for c in batcons:
		c.close()

	for r in res:
		filename = r.keys()[0]
		filehash = unpackreports[filename]['checksum']

                ## read pickle file
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		## write pickle file
		leafreports['file2package'] = r[filename]
		leafreports['tags'].append('file2package')
		unpackreports[filename]['tags'].append('file2package')
		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'wb')
		cPickle.dump(leafreports, leaf_file)
		leaf_file.close()

	returnres = res

def file2packagesetup(scanenv, debug=False):
	if not 'DBBACKEND' in scanenv:
		return (False, None)
	if scanenv['DBBACKEND'] == 'sqlite3':
		return file2packagesetup_sqlite3(scanenv, debug)
	if scanenv['DBBACKEND'] == 'postgresql':
		return file2packagesetup_postgresql(scanenv, debug)
	return (False, None)

def file2packagesetup_postgresql(scanenv, debug=False):
	newenv = copy.deepcopy(scanenv)
	batdb = bat.batdb.BatDb('postgresql')
	conn = batdb.getConnection(None,scanenv)
	if conn == None:
		return (False, None)
	conn.close()
	return (True, scanenv)

## checks specific for sqlite3 databases
def file2packagesetup_sqlite3(scanenv, debug=False):
	newenv = copy.deepcopy(scanenv)

	## Is the package database defined?
	if not scanenv.has_key('BAT_PACKAGE_DB'):
		return (False, None)

	packagedb = scanenv.get('BAT_PACKAGE_DB')

	## Does the package database exist?
	if not os.path.exists(packagedb):
		return (False, None)

	## Does the package database have the right table?
	conn = sqlite3.connect(packagedb)
	c = conn.cursor()
	res = c.execute("select * from sqlite_master where type='table' and name='file'").fetchall()
	c.close()
	conn.close()
	if res == []:
		return (False, None)

	## TODO: more sanity checks
	return (True, newenv)
