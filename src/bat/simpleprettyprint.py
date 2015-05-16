#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Simple pretty printer for results of BAT. This one is defined as the default. If you want to change it provide
a method that has the same parameters as prettyprintresxml
* unpackreports: result set of the scan
* scandate
* scans: full configuration of scans that were run
* toplevelfile: name of top level file so the root can be determined easily
* topleveldir: name of the directory where results are stored so pickles with results can be found
* scanenv: environment, possibly empty

Ideally the XML snippets would be generated in parallel. Unfortunately it seems that the
way that the XML is generated does not work nicely with multiprocessing which passes parameters
as pickles and recursion depth is quickly reached, especially with ranking.

Making a deepcopy() and returning that fixes it, but unfortunately there is this bug:

http://bugs.python.org/issue10131

Using cloneNode() does not work properly because of the way that the root document element
is passed: its type is <'instance'> but it needs to be xml.dom.minidom.Element. The __class__
variable is set to this value, but that does not help.
'''

import xml.dom.minidom
import sys, cPickle, os, os.path

## generic method for pretty printing of an element
## Parameters:
## * root - top level root element of the DOM, needed to create XML nodes
## * nodename - name the new element should get
## * nodedata - content of the element
def generateNode(root, nodename, nodedata):
	tmpnode = root.createElement(nodename)
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = str(nodedata)
	tmpnode.appendChild(tmpnodetext)
	return tmpnode

## generic method for pretty printing of an element
## Parameters:
## * root - top level root element of the DOM, needed to create XML nodes
## * leafreports
## * scanconfigs - list with configurations (dictionaries)
def prettyprintxmlsnippet(root, leafreports, scanconfigs):
	topnodes = []
	for i in leafreports.keys():
		## unfortunately we can't use a lambda expression here,
		## because then the exec statement will barf.
		#configs = filter(lambda x: x['name'] == i, scanconfigs)
		config = None
		for c in scanconfigs:
			if c['name'] == i:
				config = c
				break
		## no config found, so probably 'tags'
		if config == None:
			continue

		if config.has_key('ppoutput'):
			try:
				if config.has_key('ppmodule'):
					module = config['ppmodule']
				else:
					module = config['module']
				method = config['ppoutput']
				exec "from %s import %s as bat_%s" % (module, method, method)
				xmlres = eval("bat_%s(leafreports[i], root, config['environment'])" % (method))
				if xmlres != None:
					tmpnode = xmlres
					topnodes.append(tmpnode)
			except Exception, e:
				tmpnode = generateNode(root, i, leafreports[i])
				topnodes.append(tmpnode)
		else:
			tmpnode = generateNode(root, i, leafreports[i])
			topnodes.append(tmpnode)
	return topnodes

## top level XML pretty printing, view results with xml_pp or Firefox
def prettyprintresxml(unpackreports, scandate, scans, toplevelfile, topleveldir, scanenv={}):
	root = xml.dom.minidom.Document()
	topnode = root.createElement("report")
	tmpnode = root.createElement('scandate')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = scandate.isoformat()
	tmpnode.appendChild(tmpnodetext)
	topnode.appendChild(tmpnode)
	root.appendChild(topnode)

	## something is horribly wrong and this should never happen.
	if not unpackreports.has_key(toplevelfile):
		return root.toxml()

	## first add a few things for the top level node
	for i in ["name", "path", "realpath", "magic", "checksum", "size"]:
		if unpackreports[toplevelfile].has_key(i):
			tmpnode = generateNode(root, i, unpackreports[toplevelfile][i])
                	topnode.appendChild(tmpnode)

	if unpackreports[toplevelfile].has_key('scans'):
		scansnode = prettyprintscan(unpackreports, root, toplevelfile, scans, topleveldir)
		if scansnode != None:
			topnode.appendChild(scansnode)

	return root.toxml()

def prettyprintscan(unpackreports, root, scannode, scans, topleveldir):
	scansnode = None
	## pretty print the individual results for the top level file.
	if unpackreports[scannode].has_key('checksum'):
		filehash = unpackreports[scannode]['checksum']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			return scansnode

		leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()
		ppnodes = prettyprintxmlsnippet(root, leafreports, scans['leafscans'])
		for p in ppnodes:
			if scansnode == None:
				scansnode = root.createElement("scans")
			scansnode.appendChild(p)
	## recurse into the unpacked files
	if unpackreports[scannode]['scans'] != []:
		for s in unpackreports[scannode]['scans']:
			## sanity checks
			if not s.has_key('offset'):
				continue
			if not s.has_key('scanreports'):
				continue
			if not s.has_key('scanname'):
				continue
			## add unpack node
			unpacknode = root.createElement("unpack")

			## first the type
			typenode = root.createElement("type")
			typenodetext = xml.dom.minidom.Text()
			typenodetext.data = str(s['scanname'])
			typenode.appendChild(typenodetext)
			unpacknode.appendChild(typenode)

			## then the offset
			offsetnode = root.createElement("offset")
			offsetnodetext = xml.dom.minidom.Text()
			offsetnodetext.data = str(s['offset'])
			offsetnode.appendChild(offsetnodetext)
			unpacknode.appendChild(offsetnode)

			## then recurse for every file that was found
			for r in s['scanreports']:
				if not unpackreports.has_key(r):
					continue
				filenode = root.createElement("file")
				for i in ["name", "path", "realpath", "magic", "checksum", "size"]:
					if unpackreports[r].has_key(i):
						tmpnode = generateNode(root, i, unpackreports[r][i])
                				filenode.appendChild(tmpnode)
				if unpackreports[r].has_key('scans'):
					ss = prettyprintscan(unpackreports, root, r, scans, topleveldir)
					if ss != None:
						filenode.appendChild(ss)
				unpacknode.appendChild(filenode)

			## then add everything to the top level node
			if scansnode == None:
				scansnode = root.createElement("scans")
			scansnode.appendChild(unpacknode)
	return scansnode
