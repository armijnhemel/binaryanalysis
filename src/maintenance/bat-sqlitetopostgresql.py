#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Copyright 2015 Black Duck Software, Inc. All Rights Reserved.
## Licensed under Apache 2.0, see LICENSE file for details

'''
Convert BAT databases from SQLite to PostgreSQL
'''

import os, sys, sqlite3
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

	## first set up sqlite cursor
	sqliteconn = sqlite3.connect(options.sqlitedb)
	sqlitecursor = sqliteconn.cursor()

	## the set up PostgreSQL cursor
	## TODO: make configurable
	postgresqlconn = psycopg2.connect("dbname=bat user=bat password=bat")
	postgresqlcursor = postgresqlconn.cursor()

	## TODO: make configurable
	cleandb = True
	if cleandb:
		postgresqlcursor.execute("delete from processed")
		postgresqlcursor.execute("delete from processed_file")
		postgresqlcursor.execute("delete from extracted_string")
		postgresqlcursor.execute("delete from extracted_function")
		postgresqlcursor.execute("delete from extracted_name")
		postgresqlconn.commit()

	## then import all the data
	## first processed
	sqlitecursor.execute("select distinct * from processed")
	data = sqlitecursor.fetchall()
	for d in data:
		#package, version, filename, origin, checksum, downloadurl	
		postgresqlcursor.execute("insert into processed (package, version, filename, origin, checksum, downloadurl) values (%s, %s, %s, %s, %s, %s)", d)
	postgresqlconn.commit()

	## then processed_file
	sqlitecursor.execute("select distinct * from processed_file")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			#package, version, pathname, checksum, filename
			postgresqlcursor.execute("insert into processed_file (package, version, pathname, checksum, filename) values (%s, %s, %s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	## then extracted_string
	sqlitecursor.execute("select distinct * from extracted_string")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			#stringidentifier, checksum, language, linenumber
			postgresqlcursor.execute("insert into extracted_string (stringidentifier, checksum, language, linenumber) values (%s, %s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	## then extracted_function
	sqlitecursor.execute("select distinct * from extracted_function")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			#checksum, functionname, language, linenumber
			postgresqlcursor.execute("insert into extracted_function (checksum, functionname, language, linenumber) values (%s, %s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	## then extracted_name
	sqlitecursor.execute("select distinct * from extracted_name")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# checksum, name, type, language, linenumber
			postgresqlcursor.execute("insert into extracted_name (checksum, name, type, language, linenumber) values (%s, %s, %s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	## then other stuff

	## then all the kernel specific data
	sqlitecursor.execute("select distinct * from kernel_configuration")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernel_configuration(configstring text, filename text, version text)
			postgresqlcursor.execute("insert into kernel_configuration (configstring, filename, version) values (%s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	sqlitecursor.execute("select distinct * from kernelmodule_alias")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_alias(checksum text, modulename text, alias text)
			postgresqlcursor.execute("insert into kernelmodule_alias (checksum, modulename, alias) values (%s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	sqlitecursor.execute("select distinct * from kernelmodule_author")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_alias(checksum text, modulename text, author text)
			postgresqlcursor.execute("insert into kernelmodule_author (checksum, modulename, author) values (%s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	sqlitecursor.execute("select distinct * from kernelmodule_description")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_description(checksum text, modulename text, description text)
			postgresqlcursor.execute("insert into kernelmodule_description (checksum, modulename, description) values (%s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	sqlitecursor.execute("select distinct * from kernelmodule_firmware")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_firmware(checksum text, modulename text, firmware text)
			postgresqlcursor.execute("insert into kernelmodule_firmware (checksum, modulename, firmware) values (%s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	sqlitecursor.execute("select distinct * from kernelmodule_license")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_license(checksum text, modulename text, license text)
			postgresqlcursor.execute("insert into kernelmodule_license (checksum, modulename, license) values (%s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	sqlitecursor.execute("select distinct * from kernelmodule_parameter")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_parameter(checksum text, modulename text, paramname text, paramtype text)
			postgresqlcursor.execute("insert into kernelmodule_parameter(checksum, modulename, paramname, paramtype) values (%s, %s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	sqlitecursor.execute("select distinct * from kernelmodule_parameter_description")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_parameter_description(checksum text, modulename text, paramname text, description text)
			postgresqlcursor.execute("insert into kernelmodule_parameter_description(checksum, modulename, paramname, description) values (%s, %s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	sqlitecursor.execute("select distinct * from kernelmodule_version")
	data = sqlitecursor.fetchmany(10000)
	while data != []:
		for d in data:
			# kernelmodule_version(checksum text, modulename text, version text)
			postgresqlcursor.execute("insert into kernelmodule_version(checksum, modulename, version) values (%s, %s, %s)", d)
		postgresqlconn.commit()
		data = sqlitecursor.fetchmany(10000)
	postgresqlconn.commit()

	## then all hashes -- hardcoded SHA256, SHA1, MD5, CRC32

	sqlitecursor.close()
	sqliteconn.close()

	## then copy all the caches
	## then any other database that might be kicking around
	## first file lists
	if options.filesqlitedb != None:
		if not os.path.exists(options.filesqlitedb):
			print >>sys.stderr, "SQLite file database file specified, but does not exist, exiting"
			sys.exit(1)

		## first set up sqlite cursor
		sqliteconn = sqlite3.connect(options.filesqlitedb)
		sqlitecursor = sqliteconn.cursor()
		if cleandb:
			postgresqlcursor.execute("delete from file")
		sqlitecursor.execute("select distinct * from file")
		data = sqlitecursor.fetchmany(10000)
		while data != []:
			for d in data:
				# filename, directory, package, packageversion, source, distroversion
				postgresqlcursor.execute("insert into file (filename, directory, package, packageversion, source, distroversion) values (%s, %s, %s, %s, %s, %s)", d)
			postgresqlconn.commit()
			data = sqlitecursor.fetchmany(10000)
		postgresqlconn.commit()
		sqlitecursor.close()
		sqliteconn.close()

	## then licenses and copyright
	## then security

	## finally clean up
	postgresqlcursor.close()
	postgresqlconn.close()

if __name__ == "__main__":
	main(sys.argv)
