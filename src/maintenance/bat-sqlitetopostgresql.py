#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Copyright 2015 Black Duck Software, Inc. All Rights Reserved.
## Licensed under Apache 2.0, see LICENSE file for details

'''
Convert BAT databases from SQLite to PostgreSQL
'''

import os, sys, sqlite3, datetime
import psycopg2
from optparse import OptionParser

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="sqlitedb", help="path to SQLite database file", metavar="FILE")
	parser.add_option("-l", "--licensedatabase", action="store", dest="licensesqlitedb", help="path to SQLite license database file", metavar="FILE")
	parser.add_option("-f", "--filedatabase", action="store", dest="filesqlitedb", help="path to SQLite license database file", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.sqlitedb == None:
		parser.error("Specify SQLite database file")

	if not os.path.exists(options.sqlitedb):
		print >>sys.stderr, "SQLite database file does not exist, exiting"
		sys.exit(1)

	if options.filesqlitedb != None:
		if not os.path.exists(options.filesqlitedb):
			print >>sys.stderr, "SQLite file database file specified, but does not exist, exiting"
			sys.exit(1)
	## first set up sqlite cursor
	sqliteconn = sqlite3.connect(options.sqlitedb)
	sqlitecursor = sqliteconn.cursor()

	## the set up PostgreSQL cursor
	## TODO: make configurable
	postgresqlconn = psycopg2.connect("dbname=bat user=bat password=bat")
	postgresqlcursor = postgresqlconn.cursor()

	indexes = ["processed_index",
                   "processed_checksum",
                   "processed_origin",
                   "processedfile_package_checksum_index",
                   "processedfile_package_version_index",
                   "processedfile_filename_index",
                   "stringidentifier_index",
                   "extracted_hash_index",
                   "extracted_language_index",
                   "function_index",
                   "functionname_index",
                   "functionname_language",
                   "name_checksum_index",
                   "name_name_index",
                   "name_type_index",
                   "name_language_index",
                   "kernel_configuration_filename",
                   "kernelmodule_alias_index",
                   "kernelmodule_author_index",
                   "kernelmodule_description_index",
                   "kernelmodule_firmware_index",
                   "kernelmodule_license_index",
                   "kernelmodule_parameter_index",
                   "kernelmodule_parameter_description_index",
                   "kernelmodule_version_index",
                   "kernelmodule_alias_checksum_index",
                   "kernelmodule_author_checksum_index",
                   "kernelmodule_description_checksum_index",
                   "kernelmodule_firmware_checksum_index",
                   "kernelmodule_license_checksum_index",
                   "kernelmodule_parameter_checksum_index",
                   "kernelmodule_parameter_description_checksum_index",
                   "kernelmodule_version_checksum_index",
                   "rpm_checksum_index",
                   "rpm_rpmname_index",
                   "archivealias_checksum_index",
                   "misc_checksum_index",
                   "misc_name_index",
                   "hashconversion_sha256_index",
                   "renames_index_originalname",
                   "renames_index_newname",]

	## TODO: make configurable
	cleandb = True
	if cleandb:
		print "cleaning old tables", datetime.datetime.utcnow().isoformat()
		postgresqlcursor.execute("truncate processed")
		postgresqlcursor.execute("truncate processed_file")
		postgresqlcursor.execute("truncate extracted_string")
		postgresqlcursor.execute("truncate extracted_function")
		postgresqlcursor.execute("truncate extracted_name")
		postgresqlconn.commit()
		for i in indexes:
			query = "drop index %s" % i
			try:
				postgresqlcursor.execute(query)
			except Exception, e:
				## something went wrong, so finish the transaction
				postgresqlconn.commit()
		postgresqlconn.commit()

	## then import all the data
	## first processed
	print "importing processed", datetime.datetime.utcnow().isoformat()

	sqlitecursor.execute("select distinct * from processed")
	data = sqlitecursor.fetchall()
	postgresqlcursor.execute("prepare batprocessed as insert into processed (package, version, filename, origin, checksum, downloadurl) values ($1, $2, $3, $4, $5, $6)")
	postgresqlcursor.executemany("execute batprocessed(%s,%s,%s,%s,%s,%s)", data)

	## then processed_file
	print "importing processed_file", datetime.datetime.utcnow().isoformat()

	sqlitecursor.execute("select distinct * from processed_file")
	data = sqlitecursor.fetchmany(10000)
	postgresqlcursor.execute("prepare batprocessed_file as insert into processed_file (package, version, pathname, checksum, filename, thirdparty) values ($1, $2, $3, $4, $5, $6)")
	while data != []:
		postgresqlcursor.executemany("execute batprocessed_file(%s,%s,%s,%s,%s,%s)", data)
		data = sqlitecursor.fetchmany(10000)

	## then extracted_string
	print "importing extracted_string", datetime.datetime.utcnow().isoformat()

	sqlitecursor.execute("select distinct * from extracted_string")
	data = sqlitecursor.fetchmany(10000)
	postgresqlcursor.execute("prepare batextracted_string as insert into extracted_string (stringidentifier, checksum, language, linenumber) values ($1, $2, $3, $4)")
	while data != []:
		postgresqlcursor.executemany("execute batextracted_string(%s, %s, %s, %s)", data)
		data = sqlitecursor.fetchmany(10000)

	print "importing extracted_function", datetime.datetime.utcnow().isoformat()
	## then extracted_function
	sqlitecursor.execute("select distinct * from extracted_function")
	data = sqlitecursor.fetchmany(10000)
	postgresqlcursor.execute("prepare batextracted_function as insert into extracted_function (checksum, functionname, language, linenumber) values ($1, $2, $3, $4)")
	while data != []:
		for d in data:
			#checksum, functionname, language, linenumber
			postgresqlcursor.execute("execute batextracted_function(%s, %s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	print "importing extracted_name", datetime.datetime.utcnow().isoformat()
	## then extracted_name
	sqlitecursor.execute("select distinct * from extracted_name")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# checksum, name, type, language, linenumber
			postgresqlcursor.execute("insert into extracted_name (checksum, name, type, language, linenumber) values (%s, %s, %s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	## then other stuff

	## then all the kernel specific data
	print "importing Linux kernel information", datetime.datetime.utcnow().isoformat()
	sqlitecursor.execute("select distinct * from kernel_configuration")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernel_configuration(configstring text, filename text, version text)
			postgresqlcursor.execute("insert into kernel_configuration (configstring, filename, version) values (%s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	sqlitecursor.execute("select distinct * from kernelmodule_alias")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_alias(checksum text, modulename text, alias text)
			postgresqlcursor.execute("insert into kernelmodule_alias (checksum, modulename, alias) values (%s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	sqlitecursor.execute("select distinct * from kernelmodule_author")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_alias(checksum text, modulename text, author text)
			postgresqlcursor.execute("insert into kernelmodule_author (checksum, modulename, author) values (%s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	sqlitecursor.execute("select distinct * from kernelmodule_description")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_description(checksum text, modulename text, description text)
			postgresqlcursor.execute("insert into kernelmodule_description (checksum, modulename, description) values (%s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	sqlitecursor.execute("select distinct * from kernelmodule_firmware")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_firmware(checksum text, modulename text, firmware text)
			postgresqlcursor.execute("insert into kernelmodule_firmware (checksum, modulename, firmware) values (%s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	sqlitecursor.execute("select distinct * from kernelmodule_license")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_license(checksum text, modulename text, license text)
			postgresqlcursor.execute("insert into kernelmodule_license (checksum, modulename, license) values (%s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	sqlitecursor.execute("select distinct * from kernelmodule_parameter")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_parameter(checksum text, modulename text, paramname text, paramtype text)
			postgresqlcursor.execute("insert into kernelmodule_parameter(checksum, modulename, paramname, paramtype) values (%s, %s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	sqlitecursor.execute("select distinct * from kernelmodule_parameter_description")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_parameter_description(checksum text, modulename text, paramname text, description text)
			postgresqlcursor.execute("insert into kernelmodule_parameter_description(checksum, modulename, paramname, description) values (%s, %s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	sqlitecursor.execute("select distinct * from kernelmodule_version")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_version(checksum text, modulename text, version text)
			postgresqlcursor.execute("insert into kernelmodule_version(checksum, modulename, version) values (%s, %s, %s)", d)
		data = sqlitecursor.fetchmany(10000)

	## then all hashes -- hardcoded SHA256, SHA1, MD5, CRC32

	sqlitecursor.close()
	sqliteconn.close()

	postgresqlconn.commit()
	## then copy all the caches
	## then any other database that might be kicking around
	## first file lists
	if options.filesqlitedb != None:
		## first set up sqlite cursor
		sqliteconn = sqlite3.connect(options.filesqlitedb)
		sqlitecursor = sqliteconn.cursor()
		if cleandb:
			postgresqlcursor.execute("truncate file")
			try:
				postgresqlcursor.execute("drop index file_index")
			except:
				postgresqlconn.commit()
			postgresqlconn.commit()
		print "importing Linux distribution information", datetime.datetime.utcnow().isoformat()
		sqlitecursor.execute("select distinct * from file")
		data = sqlitecursor.fetchmany(10000)
		postgresqlcursor.execute("prepare batfile as insert into file (filename, directory, package, packageversion, source, distroversion) values ($1, $2, $3, $4, $5, $6)")
		counter = len(data)
		while data != []:
			postgresqlcursor.executemany("execute batfile(%s, %s, %s, %s, %s, %s)", data)
			data = sqlitecursor.fetchmany(10000)
			counter += len(data)
		postgresqlconn.commit()
		sqlitecursor.close()
		sqliteconn.close()

	## then licenses and copyright
	## then security

	## finally clean up
	postgresqlconn.commit()
	postgresqlcursor.close()
	postgresqlconn.close()

	print "Finished! Don't forget to recreate indexes!"

if __name__ == "__main__":
	main(sys.argv)
