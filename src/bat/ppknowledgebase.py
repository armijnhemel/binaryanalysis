#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Pretty printer for results of BAT, that uses a database with previous results. It is almost identical to the simple pretty printer, except it uses a knowledgebase to get extra info
'''

import xml.dom.minidom
import os, sys, sqlite3

def getVendorInfo(sha256, cursor, root):
	cursor.execute("select d.vendor, d.name, d.version, d.chipset, d.upstream from device d JOIN binary b on d.id = b.deviceid where b.sha256=?", (sha256,))
	sha256s = cursor.fetchall()
	if sha256s == None:
		return
	else:
		topnode = root.createElement('knowledgebasematches')
		for s in sha256s:
			tmpnode = root.createElement('knowledgebasematch')
			(vendor, devicename, version, chipset, upstream) = s

			vnode = root.createElement('vendor')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = str(vendor)
			vnode.appendChild(tmpnodetext)

			dnode = root.createElement('devicename')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = str(devicename)
			dnode.appendChild(tmpnodetext)

			vsnode = root.createElement('version')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = str(version)
			vsnode.appendChild(tmpnodetext)

			cnode = root.createElement('chipset')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = str(chipset)
			cnode.appendChild(tmpnodetext)

			unode = root.createElement('upstream')
			tmpnodetext = xml.dom.minidom.Text()
			tmpnodetext.data = str(upstream)
			unode.appendChild(tmpnodetext)

			tmpnode.appendChild(vnode)
			tmpnode.appendChild(dnode)
			tmpnode.appendChild(vsnode)
			tmpnode.appendChild(cnode)
			tmpnode.appendChild(unode)
			topnode.appendChild(tmpnode)
	return topnode

## generic method for pretty printing of an elements
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
## All interesting data can be found in the 'res' parameter
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

						vendornode = getVendorInfo(res['sha256'], c, root)
						if vendornode != None:
							tmpnode.appendChild(vendornode)

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

	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	## open the database containing all the strings that were extracted
	## from source code.
	conn = sqlite3.connect(scanenv.get('BAT_KNOWLEDGEBASE', '/tmp/knowledgebase'))
	## we have byte strings in our database, not utf-8 characters...I hope
	conn.text_factory = str
	c = conn.cursor()

	## there are a few things we always want to know about the top level node
	tmpnodes = generateNodes(res, root, ["name", "path", "realpath", "magic", "sha256", "size"])
	for tmpnode in tmpnodes:
                topnode.appendChild(tmpnode)
	vendornode = getVendorInfo(res['sha256'], c, root)
	if vendornode != None:
		topnode.appendChild(vendornode)

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
	return root.toxml()
