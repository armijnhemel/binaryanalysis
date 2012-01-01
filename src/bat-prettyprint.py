#!/usr/bin/python

##
## Binary Analysis Tool
## Copyright 2011-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details
##

'''
Ultrasimple pretty printer for a few basic things
'''

import sys, re
import ConfigParser
import string
import xml.dom
from xml.dom import minidom

from xml.dom.ext.reader import PyExpat
from string import Template
from datetime import date

from optparse import OptionParser

def prettyprint(domroot):
	reports = domroot.getElementsByTagName('report')
	if len(reports) != 1:
		return ""
	resultdoc = '''<html>
<body>
'''
	if len(domroot.getElementsByTagName('busybox-version')) != 0:
		#print domroot.getElementsByTagName('busybox-version')
		pass
	resultdoc += "</body>\n</html>"
	return resultdoc
	

def main(argv):
	parser = OptionParser()
	parser.add_option("-r", "--report", action="store", dest="report", help="path to BAT report", metavar="FILE")
        (options, args) = parser.parse_args()
	if options.report == None:
		parser.error("Path to BAT report needed")
	dom = minidom.parse(options.report)
	doc = prettyprint(dom)
	print doc

if __name__ == "__main__":
	main(sys.argv)
