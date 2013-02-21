#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script can be used to add chipset data to an existing knowledgebase
'''

import os, sys, sqlite3
from optparse import OptionParser

def main(argv):
        parser = OptionParser()
	parser.add_option("-d", "--database", dest="db", help="path to database", metavar="FILE")
	parser.add_option("-c", "--chipset", dest="chipset", help="name of chipset", metavar="CHIPSET")
	parser.add_option("-a", "--architecture", dest="architecture", help="chipset architecture (MIPS, ARM, etc.)", metavar="ARCHITECTURE")
	parser.add_option("-m", "--manufacturer", dest="manufacturer", help="chipset manufacturer", metavar="MANUFACTURER")
	(options, args) = parser.parse_args()

	if options.db == None:
                parser.error("Path to database file needed")
        try:
                conn = sqlite3.connect(options.db)
        except:
                print "Can't open database file"
                sys.exit(1)

	if options.chipset == None:
                parser.error("Need name of chipset")
	if options.manufacturer == None:
                parser.error("Need name of manufacturer")
	if options.architecture == None:
                parser.error("Need name of architecture")

	c = conn.cursor()

	## insert some test data
	## chipset information from http://wiki.openwrt.org/toh/start
	c.execute('''insert into chipset values (?, ?, ?)''', (options.chipset, options.manufacturer, options.architecture))
	#c.execute('''insert into chipset values ('AR7', 'Texas Instruments', 'MIPS')''')
	#c.execute('''insert into chipset values ('BCM6851', 'Broadcom', 'MIPS')''')
	#c.execute('''insert into chipset values ('BCM4712', 'Broadcom', 'MIPS')''')
	conn.commit()
	c.close()

if __name__ == "__main__":
        main(sys.argv)
