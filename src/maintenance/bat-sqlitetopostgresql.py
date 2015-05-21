#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Copyright 2015 Black Duck Software, Inc. All Rights Reserved.
## Licensed under Lesser General Public License 3 or later since it uses psycopg2 specific extensions

'''
Convert BAT databases from SQLite to PostgreSQL

don't forget to set SQLITE_TMPDIR
'''

import os, sys, sqlite3, datetime, multiprocessing, codecs, types
import psycopg2
from optparse import OptionParser

stringscachesperlanguage = { 'C':                'stringscache_c'
                           , 'C#':               'stringscache_csharp'
                           , 'Java':             'stringscache_java'
                           , 'JavaScript':       'stringscache_javascript'
                           , 'PHP':              'stringscache_php'
                           , 'Python':           'stringscache_python'
                           , 'Ruby':             'stringscache_ruby'
                           , 'ActionScript':     'stringscache_actionscript'
                           }

## tables per language
stringcachetablesperlanguage = { 'C': ['stringscache_c', 'scores_c', 'avgstringscache_c']
                               , 'C#': ['stringscache_csharp', 'scores_csharp', 'avgstringscache_csharp']
                               , 'Java': ['stringscache_java', 'scores_java', 'avgstringscache_java']
                               , 'JavaScript': ['stringscache_javascript', 'scores_javascript', 'avgstringscache_javascript']
                               , 'PHP': ['stringscache_php', 'scores_php', 'avgstringscache_php']
                               , 'Python': ['stringscache_python', 'scores_python', 'avgstringscache_python']
                               , 'Ruby': ['stringscache_ruby', 'scores_ruby', 'avgstringscache_ruby']
                               , 'ActionScript': ['stringscache_actionscript', 'scores_actionscript', 'avgstringscache_actionscript']
                               }

funccaches = {'C': ['functioncache_c'], 'Java': ['functioncache_java']}
funccachestablesperlanguage = {'C': ['functionnamecache_c', 'linuxkernelfunctionnamecache', 'linuxkernelnamecache', 'varnamecache_c'],
                              'Java': ['functionnamecache_java', 'classcache_java', 'fieldcache_java']}

cachesdir = '/gpl/master2'
#cachesdir = '/gpl/tmp'

def createindexes((execquery,)):
	postgresqlconn = psycopg2.connect("dbname=bat user=bat password=bat")
	postgresqlcursor = postgresqlconn.cursor()
	try:
		postgresqlcursor.execute(execquery)
	except Exception, e:
		print "error", e
	postgresqlconn.commit()
	postgresqlcursor.close()
	postgresqlconn.close()
	print "done", execquery

def insertintopostgresql((sqlitedatabase, tablename, chunks, preparedstatement, execquery, needsdecode)):
	## argh! codecs!
	#supportedcodecs = ['utf-8','ascii','latin-1','euc_jp', 'euc_jis_2004', 'jisx0213', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr','shift_jis','shift_jis_2004','shift_jisx0213']
	supportedcodecs = ['utf-8','ascii','latin-1']

	print "importing %s" % tablename, datetime.datetime.utcnow().isoformat()
	sqliteconn = sqlite3.connect(sqlitedatabase)
	sqliteconn.text_factory = str
	sqlitecursor = sqliteconn.cursor()
	sqlitecursor.execute("PRAGMA synchronous=off")
	postgresqlconn = psycopg2.connect("dbname=bat user=bat password=bat")
	postgresqlcursor = postgresqlconn.cursor()
	postgresqlcursor.execute('set synchronous_commit=off')

	## TODO: make sure that the data is actually deduplicated
	selectquery = "select * from %s" % tablename
	sqlitecursor.execute(selectquery)
	data = sqlitecursor.fetchmany(10000)
	postgresqlcursor.execute(preparedstatement)
	offset = 0
	paramstring = "(" + ("%s," * execquery['param'])[:-1] + ")"
	total = 0
	while data != []:
		offset = 0
		print tablename, total
		sys.stdout.flush()
		while True:
			querydata = []
			if (len(data) - offset)%chunks == 0 and len(data) > offset:
				researchdata = data[offset:offset+chunks]
			else:
				researchdata = data[offset:]

			if needsdecode:
				for d in researchdata:
					dtup = ()
					for dc in d:
						if type(dc) == types.StringType:
							decoded = False
							lastcodec = None
							for c in supportedcodecs:
								lastcodec = c
								try:
									dc = dc.decode(c)
									decoded = True
									dtup = dtup + (dc,)
									break
								except Exception, e:
									#print e, d
									pass
							if not decoded:
								print "NOT DECODED", d
								sys.stdout.flush()
						else:
							dtup = dtup + (dc,)
					querydata.append(dtup)
			else:
				querydata = researchdata

			if (len(data) - offset)%chunks == 0 and len(data) > offset:
				argstring = ",".join(postgresqlcursor.mogrify(paramstring,x) for x in querydata)
				query = execquery['chunked'] + argstring
				sys.stdout.flush()
				postgresqlcursor.execute(query)
				sys.stdout.flush()
			else:
				if len(querydata) != 0:
					print 'executing many', total, len(data), len(querydata)
					postgresqlcursor.executemany(execquery['base'], querydata)
				break
			offset += chunks
			total += chunks
		data = sqlitecursor.fetchmany(10000)

	postgresqlconn.commit()
	postgresqlcursor.close()
	postgresqlconn.close()
	sqlitecursor.close()
	sqliteconn.close()
	print "importing %s finished" % tablename, datetime.datetime.utcnow().isoformat()

def main(argv):
	parser = OptionParser()
	parser.add_option("-c", "--cachesdirectory", action="store", dest="cachesdirectory", help="path to caches directory", metavar="DIR")
	parser.add_option("-d", "--database", action="store", dest="sqlitedb", help="path to SQLite database file", metavar="FILE")
	parser.add_option("-l", "--licensedatabase", action="store", dest="licensesqlitedb", help="path to SQLite license database file", metavar="FILE")
	parser.add_option("-f", "--filedatabase", action="store", dest="filesqlitedb", help="path to SQLite license database file", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.sqlitedb == None:
		parser.error("Specify SQLite database file")

	if options.cachesdirectory == None:
		parser.error("Specify SQLite caches directory")

	if options.licensesqlitedb == None:
		parser.error("Specify SQLite licenses database file")

	if not os.path.exists(options.sqlitedb):
		print >>sys.stderr, "SQLite database file does not exist, exiting"
		sys.exit(1)

	if options.filesqlitedb != None:
		if not os.path.exists(options.filesqlitedb):
			print >>sys.stderr, "SQLite file database file specified, but does not exist, exiting"
			sys.exit(1)

	## set up PostgreSQL cursor
	## TODO: make configurable
	postgresqlconn = psycopg2.connect("dbname=bat user=bat password=bat")
	postgresqlcursor = postgresqlconn.cursor()

	indexes = {"processed": ["processed_index", "processed_checksum", "processed_origin"],
                   "processed_file": ["processedfile_package_checksum_index", "processedfile_package_version_index", "processedfile_filename_index"],
                   "extracted_string": ["stringidentifier_index", "extracted_hash_index", "extracted_language_index"],
                   "extracted_function": ["function_index", "functionname_index", "functionname_language"],
                   "extracted_name": ["name_checksum_index", "name_name_index", "name_type_index", "name_language_index"],
                   "kernel_configuration": ["kernel_configuration_filename"],
                   "kernelmodule_alias": ["kernelmodule_alias_index", "kernelmodule_alias_checksum_index"],
                   "kernelmodule_author": ["kernelmodule_author_index", "kernelmodule_author_checksum_index"],
                   "kernelmodule_description": ["kernelmodule_description_index", "kernelmodule_description_checksum_index"],
                   "kernelmodule_firmware": ["kernelmodule_firmware_index", "kernelmodule_firmware_checksum_index"],
                   "kernelmodule_license": ["kernelmodule_license_index", "kernelmodule_license_checksum_index"],
                   "kernelmodule_parameter": ["kernelmodule_parameter_index", "kernelmodule_parameter_checksum_index"],
                   "kernelmodule_parameter_description": ["kernelmodule_parameter_description_index", "kernelmodule_parameter_description_checksum_index"],
                   "kernelmodule_version": ["kernelmodule_version_index", "kernelmodule_version_checksum_index"],
                   "rpm": ["rpm_checksum_index", "rpm_rpmname_index"],
                   "archivealias": ["archivealias_checksum_index"],
                   "misc": ["misc_checksum_index", "misc_name_index"],

                   "hashconversion": ["hashconversion_sha256_index", "hashconversion_md5_index", "hashconversion_sha1_index", "hashconversion_crc32_index"],
                   "renames": ["renames_index_originalname", "renames_index_originalname", "renames_index_newname"],
                   "licenses": ["license_index"],
                   "extracted_copyright": ["copyright_index", "copyright_type_index"],
                   "stringscache_actionscript": ["stringidentifier_actionscript_index"],
                   "scores_actionscript": ["scores_actionscript_index"],
                   "avgstringscache_actionscript": ["avgpackage_actionscript_index"],

                   "stringscache_c": ["stringidentifier_c_index"],
                   "scores_c": ["scores_c_index"],
                   "avgstringscache_c": ["avgpackage_c_index"],

                   "stringscache_csharp": ["stringidentifier_csharp_index"],
                   "scores_csharp": ["scores_csharp_index"],
                   "avgstringscache_csharp": ["avgpackage_csharp_index"],

                   "stringscache_java": ["stringidentifier_java_index"],
                   "scores_java": ["scores_java_index"],
                   "avgstringscache_java": ["avgpackage_java_index"],

                   "stringscache_javascript": ["stringidentifier_javascript_index"],
                   "scores_javascript": ["scores_javascript_index"],
                   "avgstringscache_javascript": ["avgpackage_javascript_index"],

                   "stringscache_php": ["stringidentifier_php_index"],
                   "scores_php": ["scores_php_index"],
                   "avgstringscache_php": ["avgpackage_php_index"],

                   "stringscache_python": ["stringidentifier_python_index"],
                   "scores_python": ["scores_python_index"],
                   "avgstringscache_python": ["avgpackage_python_index"],

                   "stringscache_ruby": ["stringidentifier_ruby_index"],
                   "scores_ruby": ["scores_ruby_index"],
                   "avgstringscache_ruby": ["avgpackage_ruby_index"],

                   "linuxkernelfunctionnamecache": ["linuxkernelfunctionname_index"],
                   "linuxkernelnamecache": ["linuxkernelnamecache_index"],}

	## prepared statements that will later be compiled
	chunks = 1000

	preparedstatements = {}

	preparedstatements['processed'] = "prepare batprocessed_base as insert into processed (package, version, filename, origin, checksum, downloadurl) values ($1, $2, $3, $4, $5, $6)"

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
	preparedstatements['hashconversion'] = "prepare bathashconversion as insert into hashconversion(sha256, md5, sha1, crc32) values ($1, $2, $3, $4)"

	## queries that will be launched
	execqueries = {}

	execqueries['processed'] = {}
	execqueries['processed']['base'] = "execute batprocessed_base(%s,%s,%s,%s,%s,%s)"
	execqueries['processed']['chunked'] = "insert into processed (package, version, filename, origin, checksum, downloadurl) values"
	execqueries['processed']['param'] = 6

	execqueries['processed_file'] = {}
	execqueries['processed_file']['base'] = "execute batprocessed_file(%s,%s,%s,%s,%s,%s)"
	execqueries['processed_file']['chunked'] = "insert into processed_file (package, version, pathname, checksum, filename, thirdparty) values"
	execqueries['processed_file']['param'] = 6

	execqueries['extracted_string'] = {}
	execqueries['extracted_string']['base'] = "execute batextracted_string(%s, %s, %s, %s)"
	execqueries['extracted_string']['chunked'] = "insert into extracted_string (stringidentifier, checksum, language, linenumber) values"
	execqueries['extracted_string']['param'] = 4

	execqueries['extracted_function'] = {}
	execqueries['extracted_function']['base'] = "execute batextracted_function(%s, %s, %s, %s)"
	execqueries['extracted_function']['chunked'] = "insert into extracted_function (checksum, functionname, language, linenumber) values"
	execqueries['extracted_function']['param'] = 4

	execqueries['extracted_name'] = {}
	execqueries['extracted_name']['base'] = "execute batextracted_name(%s, %s, %s, %s, %s)"
	execqueries['extracted_name']['chunked'] = "insert into extracted_name (checksum, name, type, language, linenumber) values"
	execqueries['extracted_name']['param'] = 5

	execqueries['kernel_configuration'] = {}
	execqueries['kernel_configuration']['base'] = "execute batkernel_configuration(%s, %s, %s)"
	execqueries['kernel_configuration']['chunked'] = "insert into kernel_configuration (configstring, filename, version) values"
	execqueries['kernel_configuration']['param'] = 3

	execqueries['kernelmodule_alias'] = {}
	execqueries['kernelmodule_alias']['base'] = "execute batkernelmodule_alias(%s, %s, %s)"
	execqueries['kernelmodule_alias']['chunked'] = "insert into kernelmodule_alias(checksum, modulename, alias) values"
	execqueries['kernelmodule_alias']['param'] = 3

	execqueries['kernelmodule_author'] = {}
	execqueries['kernelmodule_author']['base'] = "execute batkernelmodule_author(%s, %s, %s)"
	execqueries['kernelmodule_author']['chunked'] = "insert into kernelmodule_author(checksum, modulename, author) values"
	execqueries['kernelmodule_author']['param'] = 3

	execqueries['kernelmodule_description'] = {}
	execqueries['kernelmodule_description']['base'] = "execute batkernelmodule_description(%s, %s, %s)"
	execqueries['kernelmodule_description']['chunked'] = "insert into kernelmodule_description(checksum, modulename, description) values"
	execqueries['kernelmodule_description']['param'] = 3

	execqueries['kernelmodule_firmware'] = {}
	execqueries['kernelmodule_firmware']['base'] = "execute batkernelmodule_firmware(%s, %s, %s)"
	execqueries['kernelmodule_firmware']['chunked'] = "insert into kernelmodule_firmware(checksum, modulename, firmware) values"
	execqueries['kernelmodule_firmware']['param'] = 3

	execqueries['kernelmodule_license'] = {}
	execqueries['kernelmodule_license']['base'] = "execute batkernelmodule_license(%s, %s, %s)"
	execqueries['kernelmodule_license']['chunked'] = "insert into kernelmodule_license(checksum, modulename, license) values"
	execqueries['kernelmodule_license']['param'] = 3

	execqueries['kernelmodule_parameter'] = {}
	execqueries['kernelmodule_parameter']['base'] = "execute batkernelmodule_parameter(%s, %s, %s, %s)"
	execqueries['kernelmodule_parameter']['chunked'] = "insert into kernelmodule_parameter(checksum, modulename, paramname, paramtype) values"
	execqueries['kernelmodule_parameter']['param'] = 4

	execqueries['kernelmodule_parameter_description'] = {}
	execqueries['kernelmodule_parameter_description']['base'] = "execute batkernelmodule_parameter_description(%s, %s, %s, %s)"
	execqueries['kernelmodule_parameter_description']['chunked'] = "insert into kernelmodule_parameter_description(checksum, modulename, paramname, description) values"
	execqueries['kernelmodule_parameter_description']['param'] = 4

	execqueries['kernelmodule_version'] = {}
	execqueries['kernelmodule_version']['base'] = "execute batkernelmodule_version(%s, %s, %s)"
	execqueries['kernelmodule_version']['chunked'] = "insert into kernelmodule_version(checksum, modulename, version) values"
	execqueries['kernelmodule_version']['param'] = 3

	execqueries['hashconversion'] = {}
	execqueries['hashconversion']['base'] = "execute bathashconversion(%s, %s, %s, %s)"
	execqueries['hashconversion']['chunked'] = "insert into hashconversion(sha256, md5, sha1, crc32) values"
	execqueries['hashconversion']['param'] = 4

	tables = ['processed', 'processed_file', 'extracted_string', 'extracted_function',
                  'extracted_name', 'kernel_configuration','kernelmodule_alias',
                  'kernelmodule_author','kernelmodule_description','kernelmodule_firmware',
                  'kernelmodule_license','kernelmodule_parameter', 'kernelmodule_parameter_description',
                  'kernelmodule_version','hashconversion']

	#tables = ['processed']
	tables = ['hashconversion']

	needsdecode = False

	tabletasks = map(lambda x: (options.sqlitedb, x, chunks, preparedstatements[x], execqueries[x], needsdecode), tables)

	if options.filesqlitedb != None:
		tablename = 'file'
		tables.append(tablename)
		preparedstatement = "prepare batfile as insert into file (filename, directory, package, packageversion, source, distroversion) values ($1, $2, $3, $4, $5, $6)"
		execqueries[tablename] = {}
		execqueries[tablename]['base'] = "execute batfile(%s, %s, %s, %s, %s, %s)"
		execqueries[tablename]['chunked'] = "insert into file (filename, directory, package, packageversion, source, distroversion) values"
		execqueries[tablename]['param'] = 6
		needsdecode = False
		#tabletasks.append((options.filesqlitedb,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))

	if options.licensesqlitedb != None:
		tablename = 'licenses'
		tables.append(tablename)
		preparedstatement = "prepare bat_licenses as insert into licenses (checksum, license, scanner, version) values ($1, $2, $3, $4)"
		execqueries[tablename] = {}
		execqueries[tablename]['base'] = "execute bat_licenses(%s, %s, %s, %s)"
		execqueries[tablename]['chunked'] = "insert into licenses (checksum, license, scanner, version) values"
		execqueries[tablename]['param'] = 4
		needsdecode = False
		#tabletasks.append((options.licensesqlitedb,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))
		tablename = 'extracted_copyright'
		tables.append(tablename)
		preparedstatement = "prepare bat_extracted_copyright as insert into extracted_copyright (checksum, copyright, type, byteoffset) values ($1, $2, $3, $4)"
		execqueries[tablename] = {}
		execqueries[tablename]['base'] = "execute bat_extracted_copyright(%s, %s, %s, %s)"
		execqueries[tablename]['chunked'] = "insert into extracted_copyright (checksum, copyright, type, byteoffset) values"
		execqueries[tablename]['param'] = 4
		needsdecode = True
		#tabletasks.append((options.licensesqlitedb,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))

	## TODO: make configurable
	cleandb = True
	if cleandb:
		print "cleaning old tables", datetime.datetime.utcnow().isoformat()
		for table in tables:
			tablequery = "truncate %s" % table
			try:
				postgresqlcursor.execute(tablequery)
				postgresqlconn.commit()
			except Exception, e:
				## something went wrong, so finish the transaction
				postgresqlconn.commit()
			if table not in indexes:
				continue
			for i in indexes[table]:
				print "dropping", i
				sys.stdout.flush()
				query = "drop index %s" % i
				try:
					postgresqlcursor.execute(query)
					postgresqlconn.commit()
				except Exception, e:
					## something went wrong, so finish the transaction
					postgresqlconn.commit()
		postgresqlconn.commit()
		options.kernelcachedb = None
		if options.kernelcachedb != None:
			postgresqlcursor.execute("truncate linuxkernelfunctionnamecache")
			postgresqlconn.commit()
			try:
				postgresqlcursor.execute("drop index linuxkernelfunctionname_index")
			except:
				postgresqlconn.commit()
		if options.filesqlitedb != None:
			postgresqlcursor.execute("truncate file")
			postgresqlconn.commit()
			try:
				postgresqlcursor.execute("drop index file_index")
			except:
				postgresqlconn.commit()

	for i in funccaches:
		for j in funccaches[i]:
			dbfile = os.path.join(cachesdir, j)
			if os.path.exists(dbfile):
				for t in funccachestablesperlanguage[i]:
					print 'table', t
					tablename = t
					tables.append(tablename)
					execqueries[tablename] = {}
					needsdecode = False

					## generic
					if t.startswith('functionnamecache'):
						execqueries[tablename]['param'] = 2
						preparedstatement = "prepare bat_%s as insert into %s (functionname, package) values ($1, $2)" % (t,t)
						execqueries[tablename]['base'] = "execute bat_%s" % t + "(%s, %s)"
						execqueries[tablename]['chunked'] = "insert into %s(functionname, package) values" % t
						#tabletasks.append((dbfile,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))
					## language specific
					if i == 'C':
						execqueries[tablename]['param'] = 2
						if t.startswith('linuxkernelfunctionnamecache'):
							preparedstatement = "prepare bat_%s as insert into %s (functionname, package) values ($1, $2)" % (t,t)
							execqueries[tablename]['base'] = "execute bat_%s" % t + "(%s, %s)"
							execqueries[tablename]['chunked'] = "insert into %s(functionname, package) values" % t
							#tabletasks.append((dbfile,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))
						elif t.startswith('linuxkernelnamecache'):
							preparedstatement = "prepare bat_%s as insert into %s (varname, package) values ($1, $2)" % (t,t)
							execqueries[tablename]['base'] = "execute bat_%s" % t + "(%s, %s)"
							execqueries[tablename]['chunked'] = "insert into %s(varname, package) values" % t
							#tabletasks.append((dbfile,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))
						elif t.startswith('varnamecache_c'):
							preparedstatement = "prepare bat_%s as insert into %s (varname, package) values ($1, $2)" % (t,t)
							execqueries[tablename]['base'] = "execute bat_%s" % t + "(%s, %s)"
							execqueries[tablename]['chunked'] = "insert into %s(varname, package) values" % t
							#tabletasks.append((dbfile,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))
					if i == 'Java':
						execqueries[tablename]['param'] = 2
						if t.startswith('fieldcache_java'):
							preparedstatement = "prepare bat_%s as insert into %s (fieldname, package) values ($1, $2)" % (t,t)
							execqueries[tablename]['base'] = "execute bat_%s" % t + "(%s, %s)"
							execqueries[tablename]['chunked'] = "insert into %s(fieldname, package) values" % t
							#tabletasks.append((dbfile,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))
						elif t.startswith('classcache_java'):
							preparedstatement = "prepare bat_%s as insert into %s (classname, package) values ($1, $2)" % (t,t)
							execqueries[tablename]['base'] = "execute bat_%s" % t + "(%s, %s)"
							execqueries[tablename]['chunked'] = "insert into %s(classname, package) values" % t
							#tabletasks.append((dbfile,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))

	for i in stringscachesperlanguage:
		dbfile = os.path.join(cachesdir, stringscachesperlanguage[i])
		if os.path.exists(dbfile):
			for j in stringcachetablesperlanguage[i]:

				tablename = j
				tables.append(tablename)
				execqueries[tablename] = {}
				execqueries[tablename]['param'] = 3
				needsdecode = True

				if j.startswith('stringscache'):
					preparedstatement = "prepare bat_%s as insert into %s (stringidentifier, package, filename) values ($1, $2, $3)" % (j,j)
					execqueries[tablename]['base'] = "execute bat_%s" % j + "(%s, %s, %s)"
					execqueries[tablename]['chunked'] = "insert into %s(stringidentifier, package, filename) values" % j
					#tabletasks.append((dbfile,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))
				elif j.startswith('scores'):
					preparedstatement = "prepare bat_%s as insert into %s (stringidentifier, packages, score) values ($1, $2, $3)" % (j,j)
					execqueries[tablename]['base'] = "execute bat_%s" % j + "(%s, %s, %s)"
					execqueries[tablename]['chunked'] = "insert into %s(stringidentifier, packages, score) values" % j
					#tabletasks.append((dbfile,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))
				elif j.startswith('avgstringscache'):
					preparedstatement = "prepare bat_%s as insert into %s (package, avgstrings) values ($1, $2)" % (j,j)
					execqueries[tablename]['base'] = "execute bat_%s" % j + "(%s, %s)"
					execqueries[tablename]['chunked'] = "insert into %s(package, avgstrings) values" % j
					execqueries[tablename]['param'] = 2
					#tabletasks.append((dbfile,tablename,chunks,preparedstatement, execqueries[tablename],needsdecode))

	postgresqlconn.commit()
	postgresqlcursor.close()

	## create a pool of workers
	workers = max(1, min(len(tabletasks), multiprocessing.cpu_count()))
	pool = multiprocessing.Pool(workers)

	pool.map(insertintopostgresql, tabletasks, 1)

	print "creating indexes"
	sys.stdout.flush()
	indextasks = map(lambda x: (x.strip(),), open('postgresql-index.sql').readlines())
	pool.terminate()

	pool = multiprocessing.Pool(processes=2)
	pool.map(createindexes, indextasks, 1)
	pool.terminate()

	'''
	## then other stuff

	## then all hashes -- hardcoded SHA256, SHA1, MD5, CRC32

	'''

	## then licenses and copyright
	## then security

if __name__ == "__main__":
	main(sys.argv)
