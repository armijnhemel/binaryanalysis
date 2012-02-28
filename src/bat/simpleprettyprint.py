#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Simple pretty printer for results of BAT
'''

import xml.dom.minidom

## pretty printing for various elements
def generateNodes(elem, root, confs):
	nodes = []
	for conf in confs:
		if conf in elem:
			tmpnode = root.createElement(conf)
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = str(elem[conf])
			tmpnode.appendChild(tmpnodetext)
			nodes.append(tmpnode)
	return nodes

## This method recursively generates XML snippets. If a method for a 'program'
## has a pretty printing method defined, it will be used instead of the generic
## one.
def prettyprintresxmlsnippet(res, root, unpackscans, programscans):
	## this should always be len == 1, have more checks
	for i in res:
		for confs in programscans:
			if i == confs['name']:
				try:
					module = confs['module']
					method = confs['xmloutput']
					if confs.has_key('envvars'):
						envvars = confs['envvars']
					else:
						envvars = None
					exec "from %s import %s as bat_%s" % (module, method, method)
					xmlres = eval("bat_%s(res[i], root, envvars)" % (method))
					if xmlres != None:
                				topnode = xmlres
					else:
						topnode = None
				except Exception, e:
                			topnode = root.createElement(i)
                			tmpnodetext = xml.dom.minidom.Text()
                			tmpnodetext.data = str(res[i])
                			topnode.appendChild(tmpnodetext)
		for confs in unpackscans:
			if i == confs['name']:
                		topnode = root.createElement('unpack')
                		typenode = root.createElement('type')
                		tmpnodetext = xml.dom.minidom.Text()
                		tmpnodetext.data = str(i)
                		typenode.appendChild(tmpnodetext)
                		topnode.appendChild(typenode)
				scanelems = res[i]
				scanelems.sort()
				for elem in scanelems:
					if 'offset' in elem:
                				tmpnode = root.createElement("offset")
                				tmpnodetext = xml.dom.minidom.Text()
                				tmpnodetext.data = str(elem['offset'])
                				tmpnode.appendChild(tmpnodetext)
                				topnode.appendChild(tmpnode)
					else:
                				tmpnode = root.createElement("file")
						tmpnodes = generateNodes(elem, root, ["name", "path", "realpath", "magic", "sha256", "size"])
						for tmpnode2 in tmpnodes:
                					tmpnode.appendChild(tmpnode2)

						if 'scans' in elem:
							childscannodes = []
							for scan in elem['scans']:
								childscannode = prettyprintresxmlsnippet(scan, root, unpackscans, programscans)
								if childscannode != None:
									childscannodes.append(childscannode)
							if childscannodes != []:
								tmpnode2 = root.createElement('scans')
								for childscannode in childscannodes:
									tmpnode2.appendChild(childscannode)
								tmpnode.appendChild(tmpnode2)
                			topnode.appendChild(tmpnode)
	return topnode

## top level XML pretty printing, view results with xml_pp or Firefox
def prettyprintresxml(res, scandate, scans, envvars=None):
	root = xml.dom.minidom.Document()
	topnode = root.createElement("report")
	tmpnode = root.createElement('scandate')
	tmpnodetext = xml.dom.minidom.Text()
	tmpnodetext.data = scandate.isoformat()
	tmpnode.appendChild(tmpnodetext)
	topnode.appendChild(tmpnode)

	## there are a few things we always want to know about the top level node
	tmpnodes = generateNodes(res, root, ["name", "path", "realpath", "magic", "sha256", "size"])
	for tmpnode in tmpnodes:
                topnode.appendChild(tmpnode)

	## then we recurse into the results from the individual scans
	if 'scans' in res:
		childscannodes = []
		for scan in res['scans']:
			childscannode = prettyprintresxmlsnippet(scan, root, scans['unpackscans'], scans['programscans'])
			if childscannode != None:
				childscannodes.append(childscannode)
		if childscannodes != []:
			tmpnode = root.createElement('scans')
			for childscannode in childscannodes:
				tmpnode.appendChild(childscannode)
			topnode.appendChild(tmpnode)
	root.appendChild(topnode)
	return root
