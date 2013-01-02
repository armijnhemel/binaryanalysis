#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script can be used to initialize the clone database.
'''

import os, sys, sqlite3
from optparse import OptionParser

def main(argv):
        parser = OptionParser()
	parser.add_option("-d", "--database", dest="db", help="path to clone database", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.db == None:
                parser.error("Path to clone database file needed")
        try:
                conn = sqlite3.connect(options.db)
        except:
                print "Can't open clone database file"
                sys.exit(1)

	c = conn.cursor()

	## create clone tables
	c.execute('''create table if not exists renames (originalname text, newname text)''')
	c.execute('''create index if not exists renames_index on renames (originalname)''')
	c.execute('''create index if not exists renames_index on renames (newname)''')

	conn.commit()
	c.close()

if __name__ == "__main__":
        main(sys.argv)
