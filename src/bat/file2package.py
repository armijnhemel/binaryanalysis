#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. Its purpose is to determine the
package a file belongs to based on the name of a package. This information is
mined from distributions like Fedora and Debian.

This scan should be run as a leaf scan.
'''

import os, os.path, sqlite3, sys, subprocess
import xml.dom.minidom

def filename2package(path, blacklist=[], envvars=None):
	scanenv = os.environ.copy()
	## open the database containing the mapping of filenames to package
	conn = sqlite3.connect(scanenv.get('BAT_PACKAGE_DB', '/tmp/filepackages'))
	c = conn.cursor()
	## select the packages that are available. It would be better to also have the directory
	## name available, so we should get rid of 'path' and use something else that is better
	## suited
	c.execute("select distinct package, packageversion, source from file where filename = '%s'" % (os.path.basename(path),))
	res = c.fetchall()
	## TODO: filter results, only return files that are not in tons of packages
	if res != []:
		return (['file2package'], res)
	return None

def xmlprettyprint(res, root, envvars=None):
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
