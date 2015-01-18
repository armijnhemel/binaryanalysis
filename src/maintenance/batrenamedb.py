#!/usr/bin/python
# -*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Script to rename certain tables in the BAT database to make sure old databases
work with BAT 20. If you have an old database you will need to run this script
before using BAT 20.

Because all data is copied and 'vacuum' is run you will need 3 times as much
diskspace as the original database.
'''

import sys, os
from optparse import OptionParser
import sqlite3

def main(argv):
	parser = OptionParser()
	parser.add_option("-l", "--licensedb", action="store", dest="licensedb", help="path to licenses database file", metavar="FILE")
	parser.add_option("-m", "--masterdb", action="store", dest="masterdb", help="path to master database file", metavar="FILE")

	(options, args) = parser.parse_args()

	if options.licensedb == None:
		parser.exit("licenses database not supplied, exiting")
	if options.masterdb == None:
		parser.exit("master database not supplied, exiting")

	if not os.path.exists(options.licensedb):
		parser.exit("licenses database does not exist, exiting")
	if not os.path.exists(options.masterdb):
		parser.exit("master database does not exist, exiting")

	licenseconn = sqlite3.connect(options.licensedb)
	licensecursor = licenseconn.cursor()
	try:
		licensecursor.execute("select * from sqlite_master")
	except:
		print >>sys.stderr, "license db is not a valid database file, exiting"
		licensecursor.close()
		licenseconn.close()
		sys.exit(1)

	## first create a new table
	print "creating new licenses table"
	licensecursor.execute("create table licenses_new (checksum text, license text, scanner text, version text)")
	print "copying all licensing data"
	licensecursor.execute("insert into licenses_new select sha256, license, scanner, version from licenses")
	print "dropping old licensing table"
	licensecursor.execute("drop table licenses")
	print "renaming licensing table"
	licensecursor.execute("alter table licenses_new rename to licenses")
	print "recreating index"
	licensecursor.execute("create index license_index on licenses(checksum)")

	print "creating new copyright table"
	licensecursor.execute("create table extracted_copyright_new (checksum text, copyright text, type text, offset int)")
	print "copying all copyright data"
	licensecursor.execute("insert into extracted_copyright_new select sha256, copyright, type, offset from extracted_copyright")
	print "dropping old copyright table"
	licensecursor.execute("drop table extracted_copyright")
	print "renaming copyright table"
	licensecursor.execute("alter table extracted_copyright_new rename to extracted_copyright")
	print "recreating indexes"
	licensecursor.execute("create index copyright_index on extracted_copyright(checksum)")
	licensecursor.execute("create index copyright_type_index on extracted_copyright(copyright, type)")
	print "vacuuming"
	licensecursor.execute("vacuum")

	licensecursor.close()
	licenseconn.close()
	sys.exit(0)

	masterconn = sqlite3.connect(options.masterdb)
	mastercursor = masterconn.cursor()
	try:
		mastercursor.execute("select * from sqlite_master")
	except:
		print >>sys.stderr, "master db is not a valid database file, exiting"
		mastercursor.close()
		masterconn.close()
		sys.exit(1)

	print "creating new processed table"
	mastercursor.execute('''create table processed_new (package text, version text, filename text, origin text, checksum text)''')
	print "copying all processed data"
	mastercursor.execute("insert into processed_new select package, version, filename, origin, sha256 from processed")
	print "dropping old processed table"
	mastercursor.execute("drop table processed")
	print "renaming processed table"
	mastercursor.execute("alter table processed_new rename to processed")
	print "recreating indexes"
	mastercursor.execute('''create index if not exists processed_index on processed(package, version)''')
	mastercursor.execute('''create index if not exists processed_checksum on processed(checksum)''')
	mastercursor.execute('''create index if not exists processed_origin on processed(origin)''')

	print "creating new processed_file table"
	mastercursor.execute('''create table processed_file_new (package text, version text, filename text, checksum text)''')
	print "copying all processed_file data"
	mastercursor.execute("insert into processed_file_new select package, version, filename, sha256 from processed_file")
	print "dropping old processed_file table"
	mastercursor.execute("drop table processed_file")
	print "renaming processed_file table"
	mastercursor.execute("alter table processed_file_new rename to processed_file")
	print "recreating indexes"
	mastercursor.execute('''create index if not exists processedfile_package_sha256_index on processed_file(checksum, package)''')
	mastercursor.execute('''create index if not exists processedfile_package_version_index on processed_file(package, version)''')

	print "creating new extracted_file table"
	mastercursor.execute('''create table if not exists extracted_file_new (stringidentifier text, checksum text, language text, linenumber int)''')  
	print "copying all extracted_file data"
	mastercursor.execute("insert into extracted_file_new select stringidentifier, sha256, language, linenumber from extracted_file")
	print "dropping old extracted_file table"
	mastercursor.execute("drop table extracted_file")
	print "renaming extracted_file table"
	mastercursor.execute("alter table extracted_file_new rename to extracted_file")
	print "recreating indexes"
	mastercursor.execute('''create index if not exists stringidentifier_index on extracted_file(stringidentifier)''')
	mastercursor.execute('''create index if not exists extracted_hash on extracted_file(checksum)''')
	mastercursor.execute('''create index if not exists extracted_language on extracted_file(language);''')

	mastercursor.close()
	masterconn.close()

if __name__ == "__main__":
	main(sys.argv)
