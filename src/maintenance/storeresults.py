#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Script to upload BAT results into the BAT database. Works on a directory with scan results.
'''

import sys, os, os.path, json, gzip, cPickle
from optparse import OptionParser
import ConfigParser

## import the PostgreSQL connection module
import psycopg2

def main(argv):
	config = ConfigParser.ConfigParser()

	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-r", "--resultdirectory", action="store", dest="resultdirectory", help="path to result directory", metavar="DIR")

	(options, args) = parser.parse_args()

	## first check the configuration to see if the database information is there

	if options.cfg == None:
		parser.error("Specify configuration file")

	if not os.path.exists(options.cfg):
		parser.error("Configuration file does not exist")
	try:
		configfile = open(options.cfg, 'r')
	except:
		parser.error("Configuration file not readable")
	config.readfp(configfile)
	configfile.close()

	batconf = {}

	## the configuration file is actually the same as the configuration for BAT scanning
	for section in config.sections():
		if section != "batconfig":
			continue
		try:
			postgresql_user = config.get(section, 'postgresql_user')
			postgresql_password = config.get(section, 'postgresql_password')
			postgresql_db = config.get(section, 'postgresql_db')

			## check to see if a host (IP-address) was supplied either
			## as host or hostaddr. hostaddr is not supported on older
			## versions of psycopg2, for example CentOS 6.6, so it is not
			## used at the moment.
			try:
				postgresql_host = config.get(section, 'postgresql_host')
			except:
				postgresql_host = None
			try:
				postgresql_hostaddr = config.get(section, 'postgresql_hostaddr')
			except:
				postgresql_hostaddr = None

			## check to see if a port was specified. If not, default to 'None'
			try:
				postgresql_port = config.get(section, 'postgresql_port')
			except Exception, e:
				postgresql_port = None

		except Exception, e:
			print >>sys.stderr, "PostgreSQL information incomplete, exiting"
			sys.stderr.flush()
			sys.exit(1)

	if options.resultdirectory == None:
		parser.error("Specify result directory")

	if not os.path.exists(options.resultdirectory):
		parser.error("result directory does not exist")

	if not os.path.exists(os.path.join(options.resultdirectory, "scandata.json")):
		parser.error("directory is not a valid BAT result directory")

	if not os.path.exists(os.path.join(options.resultdirectory, "filereports")):
		parser.error("directory is not a valid BAT result directory")

	## check if the database connection works
	try:
		conn = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password, host=postgresql_host, port=postgresql_port)
		cursor = conn.cursor()
	except Exception, e:
		print >>sys.stderr, "could not connect to database "
		sys.stderr.flush()
		sys.exit(1)

	## first parse the JSON file with the results
	jsonfile = open(os.path.join(options.resultdirectory, "scandata.json"), 'r')
	scandata = jsonfile.read()
	jsonfile.close()
	try:
		jsondata = json.loads(scandata)
	except Exception, e:
		print >>sys.stderr, "top level JSON file could not be loaded"
		sys.stderr.flush()
		sys.exit(1)

	## find the top level element
	toplevelelem = None
	toplevelchecksum = None
	for i in jsondata:
		if not 'checksum' in i:
			continue
		if 'toplevel' in i['tags']:
			toplevelelem = i
			toplevelchecksum = i['sha256']
			lentopleveldir = len(i['realpath'])
			break

	## then record some data for each (real) file in the report
	for i in jsondata:
		if not 'checksum' in i:
			continue
		storepath = os.path.join(i['realpath'][lentopleveldir:], i['name'])
		if storepath.startswith('/'):
			storepath = storepath[1:]
		tlshchecksum = None
		if 'tlsh' in i:
			tlshchecksum = i['tlsh']
		cursor.execute("insert into batresult (checksum, filename, tlsh, pathname, parentname, parentchecksum) values (%s, %s, %s, %s, %s, %s)", (i['sha256'], i['name'], tlshchecksum, storepath, toplevelelem['name'], toplevelchecksum))

	## commit all the pending data
	conn.commit()

	## now check to see if any interesting security information like passwords were found
	if 'passwords' in toplevelelem['tags']:
		## first check if there is a pickle for the top level file,
		## either gzip compressed or regular
		if os.path.exists(os.path.join(options.resultdirectory, 'filereports', '%s-filereport.pickle') % toplevelchecksum):
			leaf_file = open(os.path.join(options.resultdirectory, 'filereports', '%s-filereport.pickle') % toplevelchecksum)
		elif os.path.exists(os.path.join(options.resultdirectory, 'filereports', '%s-filereport.pickle.gz') % toplevelchecksum):
			leaf_file = gzip.open(os.path.join(options.resultdirectory, 'filereports', '%s-filereport.pickle.gz') % toplevelchecksum)
		else:
			## close the database connections
			cursor.close()
			conn.close()
			sys.exit(0)
		leafreports = cPickle.load(leaf_file)
		leaf_file.close()

		for i in set(map(lambda x: (x[1], x[2]), leafreports['passwords'])):
			(password, orighash) = i
			# security_password(hash text, password text);
			cursor.execute("insert into security_password (hash, password, origin) values (%s, %s, %s)", (orighash, password, "file://%s" % toplevelelem['name']))
		conn.commit()

	## close the database connections
	cursor.close()
	conn.close()

if __name__ == "__main__":
	main(sys.argv)
