#!/usr/bin/python

import os, sys, sqlite3
import psycopg2
from optparse import OptionParser

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="sqlitedb", help="path to SQLite database file", metavar="FILE")
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

	postgresqlcursor.close()
	postgresqlconn.close()

	sqlitecursor.close()
	sqliteconn.close()

if __name__ == "__main__":
	main(sys.argv)
