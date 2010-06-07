#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script takes the XML output of the brute force script and adds it to the knowledgebase.
This program needs PyXML installed to be able to do XPath expressions.
'''

import sys, os
from optparse import OptionParser
import ConfigParser
import datetime
import sqlite3
import xml.dom.minidom
from xml.dom.ext.reader import PyExpat
from xml.xpath import Evaluate


## unpack the data and push them into the knowledgebase. This uses the configuration file to find the interesting file system sections
## This requires that the script generating the XML file uses the same configuration file as this file for consistency
def process(xmldata, config, options):
	## first put information regarding the device itself in the knowledgebase
	t = (options.vendor, options.name, options.hwversion, options.chipset, options.upstream)
	c.execute('''insert into device(vendor, name, version, chipset, upstream) values (?, ?, ?, ?, ?)''', t)
	conn.commit()

	## Insert the information about the firmware in the knowledgebase.
	## The deviceid we use later on is the autoincremented id for the
	## row we just inserted for the device.
	deviceid = c.lastrowid
	sha256 = Evaluate('file/sha256', j)[0].childNodes[0].data
	t = (sha256, "", deviceid)
	c.execute('''insert into firmware(sha256, version, deviceid) values (?, ?, ?)''', t)
	conn.commit()
	fwid = c.lastrowid

	## first put information regarding the top level firmware in the knowledgebase
	xmldoc = reader = PyExpat.Reader()
	dom = reader.fromStream(xmldata)
	elems = Evaluate('/report/sha256', dom)
	sha256 = elems[0].childNodes[0].data
	elems = Evaluate('/report/scans', dom)
	for i in elems:
		processScan(i, config, options, 0, fwid)



## search for all file systems, extract sha256, type, offset in the parent and put that in the knowledgebase
def processScan(elem, config, options, parentid, firmwareid):
	for j in elem.childNodes:
		if config.has_option(j.tagName, 'type'):
			if config.get(j.tagName, 'type') == 'unpack':
				mag = config.get(j.tagName, 'magic')
				offset = Evaluate('offset', j)[0].childNodes[0].data
				sha256 = Evaluate('file/sha256', j)[0].childNodes[0].data
				t = (sha256, "", mag, offset, parentid, firmwareid)
				c.execute('''insert into filesystem(sha256, type, compression, offset, parentid, firmware) values (?, ?, ?, ?, ?, ?)''', t)
				conn.commit()
				fsid = c.lastrowid
				# now recurse into the files in a file system
				newelems = Evaluate('file/scans', j)
				for el in newelems:
					processScan(el, config, options, fsid, firmwareid)

def main(argv):
        parser = OptionParser()
        parser.add_option("-c", "--config", action="store", dest="cfg", help="path to config file", metavar="FILE")
        parser.add_option("-d", "--database", action="store", dest="db", help="path to sqlite database", metavar="FILE")
        parser.add_option("-n", "--name", action="store", dest="name", help="device name")
        parser.add_option("-p", "--chipset", action="store", dest="chipset", help="chipset (optional)")
        parser.add_option("-r", "--hwversion", action="store", dest="hwversion", help="device version/revision")
        parser.add_option("-s", "--vendor", action="store", dest="vendor", help="device vendor")
        parser.add_option("-u", "--upstream", action="store", dest="upstream", help="upstream vendor (optional)")
        parser.add_option("-x", "--xml", action="store", dest="xmlfile", help="path to XML file", metavar="FILE")
        (options, args) = parser.parse_args()

        if options.xmlfile == None:
                parser.error("Path to XML file needed")
        try:
		## quick sanity check to see if we have valid XML
        	xmldom = xml.dom.minidom.parse(options.xmlfile)
        	xmldata = open(options.xmlfile)
        except:
                print "No valid XML file"
                sys.exit(1)

        global conn
        conn = None

        if options.db == None:
                parser.error("Path to database needed")
	else:
                try:
                        conn = sqlite3.connect(options.db)
                except:
                        print >>sys.stderr, "Can't open database file"
                        sys.exit(1)

        if options.cfg == None:
                parser.error("Path to configuration file needed")
	else:
                try:
                        configfile = open(options.cfg, 'r')
                except:
                        print >>sys.stderr, "Can't open configuration file"
                        sys.exit(1)

        if configfile != None:
                config = ConfigParser.ConfigParser()
                config.readfp(configfile)
        ## use default system wide config
        else:
                pass

	## these entries are needed to be able to make a correct entry into the knowledgebase
        if options.name == None:
                parser.error("Device name needed")
        if options.vendor == None:
                parser.error("Vendor name needed")
        if options.hwversion == None:
                parser.error("Hardware version/revision needed")

	global c
	c = conn.cursor()

	process(xmldata, config, options)



if __name__ == "__main__":
        main(sys.argv)
