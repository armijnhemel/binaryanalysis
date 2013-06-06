#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script can be used to initialize the clone database. The clone database is
used to record information about which packages should be treated as the same
package, or under which alternative names it is known, and so on.

Cloning of packages happens frequently:

* renaming: packages are renamed for some reason, like politics
* bundling: one package is copied entirely into another package, for example
  as "third party software"
* partial copying: parts of a package have been copied into another package.
  Examples are glue code for some Python packages, where a large amount of
  packages share just one file

Apart from verbatim cloning there is also cloning that happens in a more subtle
way. For example, code was copied, then slightly adapted. It might not be the
same when looking at SHA256 checksums of the files, but it might still look
the same when looking at strings or function names.
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

	## create table for renamed packages
	c.execute('''create table if not exists renames (originalname text, newname text)''')
	c.execute('''create index if not exists renames_index on renames (originalname)''')
	c.execute('''create index if not exists renames_index on renames (newname)''')

	## insert some values as examples
	c.execute('''insert into renames values ('ethereal', 'wireshark')''')
	c.execute('''insert into renames values ('koffice', 'calligra')''')
	c.execute('''insert into renames values ('ucd-snmp', 'net-snmp')''')
	c.execute('''insert into renames values ('iproute', 'iproute2')''')
	c.execute('''insert into renames values ('gaim', 'pidgin')''')
	c.execute('''insert into renames values ('kdebase-runtime', 'kde-runtime')''')
	c.execute('''insert into renames values ('kdebase-workspace', 'kde-workspace')''')
	c.execute('''insert into renames values ('eglibc', 'glibc')''')
	c.execute('''insert into renames values ('org.apache.servicemix.bundles.ant', 'apache-ant')''')
	
	conn.commit()
	c.close()
	conn.close()

if __name__ == "__main__":
        main(sys.argv)
