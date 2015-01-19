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

In some cases it might be easier to regenerate a new database.
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

	print "creating new extracted_string table"
	mastercursor.execute('''create table if not exists extracted_string(stringidentifier text, checksum text, language text, linenumber int)''')  
	print "copying all extracted_file data"
	mastercursor.execute("insert into extracted_string select stringidentifier, sha256, language, linenumber from extracted_file")
	print "dropping old extracted_file table"
	mastercursor.execute("drop table extracted_file")
	print "recreating indexes"
	mastercursor.execute('''create index if not exists stringidentifier_index on extracted_string(stringidentifier)''')
	mastercursor.execute('''create index if not exists extracted_hash on extracted_string(checksum)''')
	mastercursor.execute('''create index if not exists extracted_language on extracted_string(language);''')

	print "creating new extracted_function table"
	mastercursor.execute('''create table if not exists extracted_function_new (checksum text, functionname text, language text, linenumber int)''')
	print "copying all extracted_function data"
	mastercursor.execute("insert into extracted_function_new select sha256, functionname, language, linenumber from extracted_file")
	print "dropping old extracted_function table"
	mastercursor.execute("drop table extracted_function")
	print "renaming extracted_function table"
	mastercursor.execute("alter table extracted_function_new rename to extracted_function")
	print "recreating indexes"
	mastercursor.execute('''create index if not exists function_checksum_index on extracted_function(checksum);''')
	mastercursor.execute('''create index if not exists function_name_index on extracted_function(functionname)''')
	mastercursor.execute('''create index if not exists function_name_language on extracted_function(language);''')

	print "creating new extracted_name table"
	mastercursor.execute('''create table if not exists extracted_name_new (checksum text, name text, type text, language text, linenumber int)''')
	print "copying all extracted_name data"
	mastercursor.execute("insert into extracted_name_new select sha256, name, language, type, linenumber from extracted_file")
	print "dropping old extracted_name table"
	mastercursor.execute("drop table extracted_name")
	print "renaming extracted_name table"
	mastercursor.execute("alter table extracted_name_new rename to extracted_name")
	print "recreating indexes"
	mastercursor.execute('''create index if not exists name_checksum_index on extracted_name(checksum);''')
	mastercursor.execute('''create index if not exists name_name_index on extracted_name(name)''')
	mastercursor.execute('''create index if not exists name_type_index on extracted_name(type)''')
	mastercursor.execute('''create index if not exists name_language_index on extracted_name(language);''')

	print "creating new kernelmodule_alias"
	mastercursor.execute("create table kernelmodule_alias_new(checksum text, modulename text, alias text)")
	print "copying all kernelmodule_alias data"
	mastercursor.execute("insert into kernelmodule_alias_new select sha256, modulename, alias from kernelmodule_alias")
	print "dropping old kernelmodule_alias table"
	mastercursor.execute("drop table kernelmodule_alias")
	print "renaming kernelmodule_alias table"
	mastercursor.execute("alter table kernelmodule_alias_new rename to kernelmodule_alias")
	print "recreating indexes"
	mastercursor.execute("create index kernelmodule_alias_index on kernelmodule_alias(alias)")
	mastercursor.execute("create index kernelmodule_alias_checksum_index on kernelmodule_alias(checksum)")

	print "creating new kernelmodule_author table"
	mastercursor.execute("create table kernelmodule_author_new(checksum text, modulename text, author text)")
	print "copying all kernelmodule_author data"
	mastercursor.execute("insert into kernelmodule_author_new select sha256, modulename, author from kernelmodule_author")
	print "dropping old kernelmodule_author table"
	mastercursor.execute("drop table kernelmodule_author")
	print "renaming kernelmodule_author table"
	mastercursor.execute("alter table kernelmodule_author_new rename to kernelmodule_author")
	print "recreating indexes"
	mastercursor.execute("create index kernelmodule_author_index on kernelmodule_author(author)")
	mastercursor.execute("create index kernelmodule_author_checksum_index on kernelmodule_author(checksum)")

	print "creating new kernelmodule_description table"
	mastercursor.execute("create table kernelmodule_description_new(checksum text, modulename text, description text)")
	print "copying all kernelmodule_description data"
	mastercursor.execute("insert into kernelmodule_description_new select sha256, modulename, author from kernelmodule_description")
	print "dropping old kernelmodule_description table"
	mastercursor.execute("drop table kernelmodule_description")
	print "renaming kernelmodule_description table"
	mastercursor.execute("alter table kernelmodule_description_new rename to kernelmodule_description")
	print "recreating indexes"
	mastercursor.execute("create index kernelmodule_description_index on kernelmodule_description(description)")
	mastercursor.execute("create index kernelmodule_description_checksum_index on kernelmodule_description(checksum)")

	print "creating new kernelmodule_firmware table"
	mastercursor.execute("create table kernelmodule_firmware_new(checksum text, modulename text, firmware text)")
	print "copying all kernelmodule_firmware data"
	mastercursor.execute("insert into kernelmodule_firmware_new select sha256, modulename, firmware from kernelmodule_firmware")
	print "dropping old kernelmodule_firmware table"
	mastercursor.execute("drop table kernelmodule_firmware")
	print "renaming kernelmodule_firmware table"
	mastercursor.execute("alter table kernelmodule_firmware_new rename to kernelmodule_firmware")
	print "recreating indexes"
	mastercursor.execute("create index kernelmodule_firmware_index on kernelmodule_firmware(firmware)")
	mastercursor.execute("create index kernelmodule_firmware_checksum_index on kernelmodule_firmware(checksum)")

	print "creating new kernelmodule_license table"
	mastercursor.execute("create table kernelmodule_license_new(checksum text, modulename text, license text)")
	print "copying all kernelmodule_license data"
	mastercursor.execute("insert into kernelmodule_license_new select sha256, modulename, license from kernelmodule_license")
	print "dropping old kernelmodule_license table"
	mastercursor.execute("drop table kernelmodule_license")
	print "renaming kernelmodule_license table"
	mastercursor.execute("alter table kernelmodule_license_new rename to kernelmodule_license")
	print "recreating indexes"
	mastercursor.execute("create index kernelmodule_license_index on kernelmodule_license(license)")
	mastercursor.execute("create index kernelmodule_license_checksum_index on kernelmodule_license(checksum)")

	print "creating new kernelmodule_parameter"
	mastercursor.execute("create table kernelmodule_parameter_new(checksum text, modulename text, paramname text, paramtype text)")
	print "copying all kernelmodule_parameter data"
	mastercursor.execute("insert into kernelmodule_parameter_new select sha256, modulename, paramname, paramtype from kernelmodule_parameter")
	print "dropping old kernelmodule_parameter table"
	mastercursor.execute("drop table kernelmodule_parameter")
	print "renaming kernelmodule_parameter table"
	mastercursor.execute("alter table kernelmodule_parameter_new rename to kernelmodule_parameter")
	print "recreating indexes"
	mastercursor.execute("create index kernelmodule_parameter_index on kernelmodule_parameter(paramname)")
	mastercursor.execute("create index kernelmodule_parameter_checksum_index on kernelmodule_parameter(checksum)")

	print "creating new kernelmodule_parameter_description"
	mastercursor.execute("create table kernelmodule_parameter_description_new(checksum text, modulename text, paramname text, description text)")
	print "copying all kernelmodule_parameter_description data"
	mastercursor.execute("insert into kernelmodule_parameter_description_new select sha256, modulename, paramname, description from kernelmodule_parameter_description")
	print "dropping old kernelmodule_parameter_description table"
	mastercursor.execute("drop table kernelmodule_parameter_description")
	print "renaming kernelmodule_parameter_description table"
	mastercursor.execute("alter table kernelmodule_parameter_description_new rename to kernelmodule_parameter_description")
	print "recreating indexes"
	mastercursor.execute("create index kernelmodule_parameter_description_index on kernelmodule_parameter_description(description)")
	mastercursor.execute("create index kernelmodule_parameter_description_checksum_index on kernelmodule_parameter_description(checksum)")

	print "creating new kernelmodule_version table"
	mastercursor.execute("create table kernelmodule_version_new(checksum text, modulename text, version text)")
	print "copying all kernelmodule_version data"
	mastercursor.execute("insert into kernelmodule_version_new select sha256, modulename, version from kernelmodule_version")
	print "dropping old kernelmodule_version table"
	mastercursor.execute("drop table kernelmodule_version")
	print "renaming kernelmodule_version table"
	mastercursor.execute("alter table kernelmodule_version_new rename to kernelmodule_version")
	print "recreating indexes"
	mastercursor.execute("create index if not exists kernelmodule_version_index on kernelmodule_version(version)")
	mastercursor.execute("create index if not exists kernelmodule_version_checksum_index on kernelmodule_version(checksum)")

	print "creating new misc table"
	mastercursor.execute("create table if not exists misc_new(checksum text, name text)")
	print "copying all misc data"
	mastercursor.execute("insert into misc_new select sha256, name from misc")
	print "droppping old misc table"
	mastercursor.execute("drop table misc")
	print "renaming misc table"
	mastercursor.execute("alter table misc_new rename to misc")
	print "recreating indexes"
	mastercursor.execute("create index if not exists misc_checksum_index on misc(checksum)")
	mastercursor.execute("create index if not exists misc_name_index on misc(name)")
	mastercursor.execute("vacuum")

	mastercursor.close()
	masterconn.close()

if __name__ == "__main__":
	main(sys.argv)
