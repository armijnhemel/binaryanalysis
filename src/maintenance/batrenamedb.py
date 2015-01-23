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
	parser.add_option("-n", "--newmasterdb", action="store", dest="newmasterdb", help="path to newmaster database file", metavar="FILE")

	(options, args) = parser.parse_args()

	if options.licensedb == None:
		parser.exit("licenses database not supplied, exiting")
	if options.masterdb == None:
		parser.exit("master database not supplied, exiting")
	if options.newmasterdb == None:
		parser.exit("new master database not supplied, exiting")

	if not os.path.exists(options.licensedb):
		parser.exit("licenses database does not exist, exiting")
	if not os.path.exists(options.masterdb):
		parser.exit("master database does not exist, exiting")
	if os.path.exists(options.newmasterdb):
		parser.exit("new master database already exists, exiting")

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

	## then move on to the master database
	## first create the new tables
	## then vacuum
	## then recreate indexes
	masterconn = sqlite3.connect(options.masterdb)
	mastercursor = masterconn.cursor()

	try:
		mastercursor.execute("select * from sqlite_master")
	except:
		print >>sys.stderr, "master db is not a valid database file, exiting"
		mastercursor.close()
		masterconn.close()
		sys.exit(1)

	mastercursor.execute("attach '%s' as slave" % options.newmasterdb)
	print "creating new processed table"
	mastercursor.execute("create table slave.processed (package text, version text, filename text, origin text, checksum text, downloadurl text)")
	print "copying all processed data"
	mastercursor.execute("insert into slave.processed select package, version, filename, origin, sha256 from processed")

	print "creating new processed_file table"
	mastercursor.execute("create table slave.processed_file (package text, version text, filename text, checksum text)")
	print "copying all processed_file data"
	mastercursor.execute("insert into slave.processed_file select package, version, filename, sha256 from processed_file")
	print "creating new extracted_string table"
	mastercursor.execute("create table if not exists slave.extracted_string(stringidentifier text, checksum text, language text, linenumber int)")  
	print "copying all extracted_file data"
	mastercursor.execute("insert into slave.extracted_string select programstring, sha256, language, linenumber from extracted_file")

	print "creating new extracted_function table"
	mastercursor.execute("create table if not exists slave.extracted_function (checksum text, functionname text, language text, linenumber int)")
	print "copying all extracted_function data"
	mastercursor.execute("insert into slave.extracted_function select sha256, functionname, language, linenumber from extracted_function")

	print "creating new extracted_name table"
	mastercursor.execute("create table if not exists slave.extracted_name (checksum text, name text, type text, language text, linenumber int)")
	print "copying all extracted_name data"
	mastercursor.execute("insert into slave.extracted_name select sha256, name, type, language, linenumber from extracted_name")

	print "creating new kernelmodule_alias"
	mastercursor.execute("create table slave.kernelmodule_alias(checksum text, modulename text, alias text)")
	print "copying all kernelmodule_alias data"
	mastercursor.execute("insert into slave.kernelmodule_alias select sha256, modulename, alias from kernelmodule_alias")

	print "creating new kernelmodule_author table"
	mastercursor.execute("create table slave.kernelmodule_author(checksum text, modulename text, author text)")
	print "copying all kernelmodule_author data"
	mastercursor.execute("insert into slave.kernelmodule_author select sha256, modulename, author from kernelmodule_author")

	print "creating new kernelmodule_description table"
	mastercursor.execute("create table slave.kernelmodule_description(checksum text, modulename text, description text)")
	print "copying all kernelmodule_description data"
	mastercursor.execute("insert into slave.kernelmodule_description select sha256, modulename, description from kernelmodule_description")

	print "creating new kernelmodule_firmware table"
	mastercursor.execute("create table slave.kernelmodule_firmware(checksum text, modulename text, firmware text)")
	print "copying all kernelmodule_firmware data"
	mastercursor.execute("insert into slave.kernelmodule_firmware select sha256, modulename, firmware from kernelmodule_firmware")

	print "creating new kernelmodule_license table"
	mastercursor.execute("create table slave.kernelmodule_license(checksum text, modulename text, license text)")
	print "copying all kernelmodule_license data"
	mastercursor.execute("insert into slave.kernelmodule_license select sha256, modulename, license from kernelmodule_license")

	print "creating new kernelmodule_parameter"
	mastercursor.execute("create table slave.kernelmodule_parameter(checksum text, modulename text, paramname text, paramtype text)")
	print "copying all kernelmodule_parameter data"
	mastercursor.execute("insert into slave.kernelmodule_parameter select sha256, modulename, paramname, paramtype from kernelmodule_parameter")

	print "creating new kernelmodule_parameter_description"
	mastercursor.execute("create table slave.kernelmodule_parameter_description(checksum text, modulename text, paramname text, description text)")
	print "copying all kernelmodule_parameter_description data"
	mastercursor.execute("insert into slave.kernelmodule_parameter_description select sha256, modulename, paramname, description from kernelmodule_parameter_description")

	print "creating new kernelmodule_version table"
	mastercursor.execute("create table slave.kernelmodule_version(checksum text, modulename text, version text)")
	print "copying all kernelmodule_version data"
	mastercursor.execute("insert into slave.kernelmodule_version select sha256, modulename, version from kernelmodule_version")

	print "creating new kernel_configuration table"
	mastercursor.execute("create table if not exists slave.kernel_configuration(configstring text, filename text, version text)")

	mastercursor.execute("insert into slave.kernel_configuration select configstring, filename, version from kernel_configuration")
	print "creating new misc table"
	mastercursor.execute("create table if not exists slave.misc(checksum text, name text)")
	print "copying all misc data"
	mastercursor.execute("insert into slave.misc select sha256, name from misc")

	print "creating new hashconversion table"
	mastercursor.execute("create table slave.hashconversion (sha256 text, md5 text, sha1 text, crc32 text)")
	print "copying all hashconversion data"
	mastercursor.execute("insert into slave.hashconversion select sha256, md5, sha1, crc32 from hashconversion")

	#print "vacuuming"
	#mastercursor.execute("vacuum")

	print "recreating indexes processed"
	mastercursor.execute("create index if not exists slave.processed_index on processed(package, version)"
	mastercursor.execute("create index if not exists slave.processed_checksum on processed(checksum)"
	mastercursor.execute("create index if not exists slave.processed_origin on processed(origin)"

	print "recreating indexes processed_file"
	mastercursor.execute("create index if not exists slave.processedfile_package_checksum_index on processed_file(checksum, package)"
	mastercursor.execute("create index if not exists slave.processedfile_package_version_index on processed_file(package, version)"

	print "recreating indexes extracted_string"
	mastercursor.execute("create index if not exists slave.stringidentifier_index on extracted_string(stringidentifier)"
	mastercursor.execute("create index if not exists slave.extracted_hash on extracted_string(checksum)"
	mastercursor.execute("create index if not exists slave.extracted_language on extracted_string(language);"

	print "recreating indexes extracted_function"
	mastercursor.execute("create index if not exists slave.function_checksum_index on extracted_function(checksum);"
	mastercursor.execute("create index if not exists slave.function_name_index on extracted_function(functionname)"
	mastercursor.execute("create index if not exists slave.function_name_language on extracted_function(language);"

	print "recreating indexes extracted_name"
	mastercursor.execute("create index if not exists slave.name_checksum_index on extracted_name(checksum)")
	mastercursor.execute("create index if not exists slave.name_name_index on extracted_name(name)")
	mastercursor.execute("create index if not exists slave.name_type_index on extracted_name(type)")
	mastercursor.execute("create index if not exists slave.name_language_index on extracted_name(language)")

	print "recreating indexes kernelmodule_alias"
	mastercursor.execute("create index slave.kernelmodule_alias_index on kernelmodule_alias(alias)")
	mastercursor.execute("create index slave.kernelmodule_alias_checksum_index on kernelmodule_alias(checksum)")

	print "recreating indexes kernelmodule_author"
	mastercursor.execute("create index slave.kernelmodule_author_index on kernelmodule_author(author)")
	mastercursor.execute("create index slave.kernelmodule_author_checksum_index on kernelmodule_author(checksum)")

	print "recreating indexes kernelmodule_description"
	mastercursor.execute("create index slave.kernelmodule_description_index on kernelmodule_description(description)")
	mastercursor.execute("create index slave.kernelmodule_description_checksum_index on kernelmodule_description(checksum)")

	print "recreating indexes kernelmodule_firmware"
	mastercursor.execute("create index slave.kernelmodule_firmware_index on kernelmodule_firmware(firmware)")
	mastercursor.execute("create index slave.kernelmodule_firmware_checksum_index on kernelmodule_firmware(checksum)")

	print "recreating indexes kernelmodule_license"
	mastercursor.execute("create index slave.kernelmodule_license_index on kernelmodule_license(license)")
	mastercursor.execute("create index slave.kernelmodule_license_checksum_index on kernelmodule_license(checksum)")

	print "recreating indexes kernelmodule_parameter"
	mastercursor.execute("create index slave.kernelmodule_parameter_index on kernelmodule_parameter(paramname)")
	mastercursor.execute("create index slave.kernelmodule_parameter_checksum_index on kernelmodule_parameter(checksum)")

	print "recreating indexes kernel_parameter_description"
	mastercursor.execute("create index slave.kernelmodule_parameter_description_index on kernelmodule_parameter_description(description)")
	mastercursor.execute("create index slave.kernelmodule_parameter_description_checksum_index on kernelmodule_parameter_description(checksum)")

	print "recreating indexes kernelmodule_version"
	mastercursor.execute("create index slave.kernelmodule_version_index on kernelmodule_version(version)")
	mastercursor.execute("create index slave.kernelmodule_version_checksum_index on kernelmodule_version(checksum)")

	print "recreating indexes kernel_configuration"
	mastercursor.execute("create index slave.kernel_configuration_filename on kernel_configuration(filename)")

	print "recreating indexes misc"
	mastercursor.execute("create index if not exists slave.misc_checksum_index on misc(checksum)")
	mastercursor.execute("create index if not exists slave.misc_name_index on misc(name)")

	print "recreating indexes hashconversion"
	mastercursor.execute("create index slave.hashconversion_sha256_index on hashconversion(sha256)")
	mastercursor.execute("create index slave.hashconversion_md5_index on hashconversion(md5)")
	mastercursor.execute("create index slave.hashconversion_sha1_index on hashconversion(sha1)")
	mastercursor.execute("create index slave.hashconversion_crc32_index on hashconversion(crc32)")

	mastercursor.close()
	masterconn.close()

if __name__ == "__main__":
	main(sys.argv)
