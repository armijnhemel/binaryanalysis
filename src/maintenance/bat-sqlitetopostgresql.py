#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Copyright 2015 Black Duck Software, Inc. All Rights Reserved.
## Licensed under Apache 2.0, see LICENSE file for details

'''
Convert BAT databases from SQLite to PostgreSQL
'''

import os, sys, sqlite3, datetime, multiprocessing
import psycopg2
from optparse import OptionParser

def insertintopostgresql((sqlitedatabase, tablename, preparedstatement, execquery)):
	print "importing %s" % tablename, datetime.datetime.utcnow().isoformat()
	sqliteconn = sqlite3.connect(sqlitedatabase)
	sqlitecursor = sqliteconn.cursor()
	sqlitecursor.execute("PRAGMA synchronous=off")
	postgresqlconn = psycopg2.connect("dbname=bat user=bat password=bat")
	postgresqlcursor = postgresqlconn.cursor()
	postgresqlcursor.execute('set synchronous_commit=off')

	selectquery = "select distinct * from %s" % tablename
	sqlitecursor.execute(selectquery)
	data = sqlitecursor.fetchmany(10000)
	postgresqlcursor.execute(preparedstatement)
	while data != []:
		postgresqlcursor.executemany(execquery, data)
		data = sqlitecursor.fetchmany(10000)

	postgresqlconn.commit()
	postgresqlcursor.close()
	postgresqlconn.close()
	sqlitecursor.close()
	sqliteconn.close()
	print "importing %s finished" % tablename, datetime.datetime.utcnow().isoformat()

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="sqlitedb", help="path to SQLite database file", metavar="FILE")
	parser.add_option("-l", "--licensedatabase", action="store", dest="licensesqlitedb", help="path to SQLite license database file", metavar="FILE")
	parser.add_option("-f", "--filedatabase", action="store", dest="filesqlitedb", help="path to SQLite license database file", metavar="FILE")
	parser.add_option("-k", "--kernelcache", action="store", dest="kernelcachedb", help="path to SQLite kernel cache database file", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.sqlitedb == None:
		parser.error("Specify SQLite database file")

	if options.kernelcachedb == None:
		parser.error("Specify SQLite kernelcache database file")

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
                   "renames_index_originalname",
                   "renames_index_newname",
                   "linuxkernelfunctionname_index",
                   "linuxkernelnamecache_index",]

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
				postgresqlconn.commit()
			except Exception, e:
				## something went wrong, so finish the transaction
				postgresqlconn.commit()
		postgresqlconn.commit()
		if options.filesqlitedb != None:
			postgresqlcursor.execute("truncate file")
			postgresqlconn.commit()
			try:
				postgresqlcursor.execute("drop index file_index")
			except:
				postgresqlconn.commit()
	postgresqlconn.commit()
	postgresqlcursor.close()

	## prepared statements that will later be compiled
	preparedstatements = {}
	preparedstatements['processed'] = "prepare batprocessed as insert into processed (package, version, filename, origin, checksum, downloadurl) values ($1, $2, $3, $4, $5, $6)"
	preparedstatements['processed_file'] = "prepare batprocessed_file as insert into processed_file (package, version, pathname, checksum, filename, thirdparty) values ($1, $2, $3, $4, $5, $6)"
	preparedstatements['extracted_string'] = "prepare batextracted_string as insert into extracted_string (stringidentifier, checksum, language, linenumber) values ($1, $2, $3, $4)"
	preparedstatements['extracted_function'] = "prepare batextracted_function as insert into extracted_function (checksum, functionname, language, linenumber) values ($1, $2, $3, $4)"
	preparedstatements['extracted_name'] = "prepare batextracted_name as insert into extracted_name (checksum, name, type, language, linenumber) values ($1, $2, $3, $4, $5)"
	preparedstatements['kernel_configuration'] = "prepare batkernel_configuration as insert into kernel_configuration (configstring, filename, version) values ($1, $2, $3)"
	preparedstatements['kernelmodule_alias'] = "prepare batkernelmodule_alias as insert into kernelmodule_alias(checksum, modulename, alias) values ($1, $2, $3)"
	preparedstatements['kernelmodule_author'] = "prepare batkernelmodule_author as insert into kernelmodule_author(checksum, modulename, author) values ($1, $2, $3)"
	preparedstatements['kernelmodule_description'] = "prepare batkernelmodule_description as insert into kernelmodule_description(checksum, modulename, description) values ($1, $2, $3)"
	preparedstatements['kernelmodule_firmware'] = "prepare batkernelmodule_firmware as insert into kernelmodule_firmware(checksum, modulename, firmware) values ($1, $2, $3)"
	preparedstatements['kernelmodule_license'] = "prepare batkernelmodule_license as insert into kernelmodule_license(checksum, modulename, license) values ($1, $2, $3)"
	preparedstatements['kernelmodule_parameter'] = "prepare batkernelmodule_parameter as insert into kernelmodule_parameter(checksum, modulename, paramname, paramtype) values ($1, $2, $3, $4)"
	preparedstatements['kernelmodule_parameter_description'] = "prepare batkernelmodule_parameter_description as insert into kernelmodule_parameter_description(checksum, modulename, paramname, description) values ($1, $2, $3, $4)"
	preparedstatements['kernelmodule_version'] = "prepare batkernelmodule_version as insert into kernelmodule_version(checksum, modulename, version) values ($1, $2, $3)"

	## queries that will be launched
	execqueries = {}
	execqueries['processed'] = "execute batprocessed(%s,%s,%s,%s,%s,%s)"
	execqueries['processed_file'] = "execute batprocessed_file(%s,%s,%s,%s,%s,%s)"
	execqueries['extracted_string'] = "execute batextracted_string(%s, %s, %s, %s)"
	execqueries['extracted_function'] = "execute batextracted_function(%s, %s, %s, %s)"
	execqueries['extracted_name'] = "execute batextracted_name(%s, %s, %s, %s, %s)"
	execqueries['kernel_configuration'] = "execute batkernel_configuration(%s, %s, %s)"
	execqueries['kernelmodule_alias'] = "execute batkernelmodule_alias(%s, %s, %s)"
	execqueries['kernelmodule_author'] = "execute batkernelmodule_author(%s, %s, %s)"
	execqueries['kernelmodule_description'] = "execute batkernelmodule_description(%s, %s, %s)"
	execqueries['kernelmodule_firmware'] = "execute batkernelmodule_firmware(%s, %s, %s)"
	execqueries['kernelmodule_license'] = "execute batkernelmodule_license(%s, %s, %s)"
	execqueries['kernelmodule_parameter'] = "execute batkernelmodule_parameter(%s, %s, %s, %s)"
	execqueries['kernelmodule_parameter_description'] = "execute batkernelmodule_parameter_description(%s, %s, %s, %s)"
	execqueries['kernelmodule_version'] = "execute batkernelmodule_version(%s, %s, %s)"

	tables = ['processed', 'processed_file', 'extracted_string', 'extracted_function',
                  'extracted_name', 'kernel_configuration','kernelmodule_alias',
                  'kernelmodule_author','kernelmodule_description','kernelmodule_firmware',
                  'kernelmodule_license','kernelmodule_parameter', 'kernelmodule_parameter_description',
                  'kernelmodule_version']

	tabletasks = map(lambda x: (options.sqlitedb, x, preparedstatements[x], execqueries[x]), tables)

	if options.kernelcachedb != None:
		## TODO: use new name
		tables.append('kernelfunctionnamecache')
		#tables.append('linuxkernelfunctionnamecache')
		## (functionname text, package text)
		preparedstatement = "prepare batlinuxkernelfunctionnamecache as insert into linuxkernelfunctionnamecache (functionname, package) values ($1, $2)"
		execquery = "execute batlinuxkernelfunctionnamecache(%s, %s)"
		#tabletasks.append((options.kernelcachedb,'linuxkernelfunctionnamecache',preparedstatement, execquery))
		tabletasks.append((options.kernelcachedb,'kernelfunctionnamecache',preparedstatement, execquery))

	if options.filesqlitedb != None:
		tables.append('file')
		preparedstatement = "prepare batfile as insert into file (filename, directory, package, packageversion, source, distroversion) values ($1, $2, $3, $4, $5, $6)"
		execquery = "execute batfile(%s, %s, %s, %s, %s, %s)"
		tabletasks.append((options.filesqlitedb,'file',preparedstatement, execquery))

	## create a pool of workers
	workers = min(len(tabletasks), multiprocessing.cpu_count)
	pool = multiprocessing.Pool(workers)

	pool.map(insertintopostgresql, tabletasks, 1)
	pool.terminate()

	'''
	## then other stuff

	## then all hashes -- hardcoded SHA256, SHA1, MD5, CRC32

	'''

	## then licenses and copyright
	## then security

	print "Finished! Don't forget to recreate indexes!"

if __name__ == "__main__":
	main(sys.argv)
