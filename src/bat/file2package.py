#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. Its purpose is to determine the
package a file belongs to based on the name of a package. This information is
mined from distributions like Fedora and Debian.

This scan should be run as a leaf scan.
'''

import os, os.path, sqlite3, sys, subprocess, copy
import xml.dom.minidom
import bat.batdb

def filename2package(path, tags, blacklist=[], scanenv={}, scandebug=False, unpacktempdir=None):
	if not scanenv.has_key('BAT_PACKAGE_DB'):
		return
	## open the database containing the mapping of filenames to package
	batdb = bat.batdb.BatDb(scanenv['DBBACKEND'])
	conn = batdb.getConnection(scanenv['BAT_PACKAGE_DB'])
	c = conn.cursor()
	## select the packages that are available. It would be better to also have the directory
	## name available, so we should get rid of 'path' and use something else that is better
	## suited
	c.execute("select distinct package, packageversion, source, distroversion from file where filename = '%s'" % (os.path.basename(path),))
	res = c.fetchall()
	## TODO: filter results, only return files that are not in tons of packages
	if res != []:
		returnres = []
		for r in res:
			(package, packageversion, distribution, distroversion) = r
			distrores = {}
			distrores['package'] = package
			distrores['packageversion'] = packageversion
			distrores['distribution'] = distribution
			distrores['distributionversion'] = distroversion
			returnres.append(distrores)
		c.close()
		conn.close()
		return (['file2package'], returnres)
	c.close()
	conn.close()
	return None

def xmlprettyprint(res, root, scanenv={}):
	topnode = root.createElement("filelist")
	#tags = ['packagename', 'version', 'distribution']
	tags = ['packagename', 'distribution']
	for i in res:
		tmpnode = root.createElement('packageguess')
		for j in range(0,len(tags)):
			tagnode = root.createElement(tags[j])
			tagnodetext = xml.dom.minidom.Text()
			tagnodetext.data = i[j]
			tagnode.appendChild(tagnodetext)
			tmpnode.appendChild(tagnode)
		topnode.appendChild(tmpnode)
	return topnode

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
	conn = batdb.getConnection(None)
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
	if res == []:
		c.close()
		conn.close()
		return (False, None)

	## TODO: more sanity checks
	return (True, newenv)
