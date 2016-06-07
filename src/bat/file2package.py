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

def filename2package(unpackreports, scantempdir, topleveldir, processors, scanenv, batcursors, batcons, scandebug=False, unpacktempdir=None):
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
	query = "select distinct package, packageversion, source, distroversion from file where filename = %s"
	scanmanager = multiprocessing.Manager()
	scanqueue = multiprocessing.JoinableQueue(maxsize=0)
	reportqueue = scanmanager.Queue(maxsize=0)
	processpool = []

	map(lambda x: scanqueue.put(x), processtasks)
	minprocessamount = min(len(processtasks), processamount)
	res = []

	for i in range(0,minprocessamount):
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

def file2packagesetup(scanenv, cursor, conn, debug=False):
	if cursor == None:
		return (False, {})
	cursor.execute("select table_name from information_schema.tables where table_type='BASE TABLE' and table_schema='public'")
	tablenames = map(lambda x: x[0], cursor.fetchall())
	conn.commit()
	if not 'file' in tablenames:
		return (False, {})
	return (True, scanenv)
