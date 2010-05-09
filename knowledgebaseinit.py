#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script can be used to initialize an empty knowledgebase and create all tables.
'''

import os, sys, sqlite3
from optparse import OptionParser

def main(argv):
        parser = OptionParser()
	parser.add_option("-d", "--database", dest="db", help="path to database", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.db == None:
                parser.error("Path to database file needed")
        try:
                conn = sqlite3.connect(options.db)
        except:
                print "Can't open database file"
                sys.exit(1)

	c = conn.cursor()

	## create some tables
	c.execute('''create table chipset (name text, vendor text, family text)''')
	c.execute('''create table filesystem (id integer, sha256 text, type text, compression text, offset integer, parentid integer, firmware integer)''')
	c.execute('''create table device (id integer, vendor text, name text, version text, chipset text, upstream text)''')
	c.execute('''create table firmware (id integer, sha256 text, version text, deviceid integer)''')

	## insert some test data
	c.execute('''insert into chipset values ('AR7', 'Texas Instruments', 'MIPS')''')
	c.execute('''insert into chipset values ('BCM6851', 'Broadcom', 'MIPS')''')
	c.execute('''insert into chipset values ('BCM4712', 'Broadcom', 'MIPS')''')
	c.execute('''insert into device values (1, 'Linksys', 'WRT54G', '2.0', 'BCM4712', '')''')
	c.execute('''insert into firmware values (1, 'fa3e0f350293ff0a3e92ff6a702167bf798919236111e263fcc7f2f8539780dd', '4.21.1', 1)''')
	conn.commit()
	c.close()

if __name__ == "__main__":
        main(sys.argv)
