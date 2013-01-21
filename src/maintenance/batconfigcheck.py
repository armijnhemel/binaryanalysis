#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script can be used to check the validity of the BAT configuration file. It
specifically is used to check the validity of databases for the ranking scan.
'''

import os, sys, sqlite3
from optparse import OptionParser
import ConfigParser
import bat.bruteforcescan

## Check if this has been defined for file2package
## * BAT_PACKAGE

## Check if any of these have been defined for ranking and check database
## schemas, whether it has the correct format, etc.
## * BAT_AVG_C
## * BAT_AVG_JAVA
## * BAT_AVG_C#
## * BAT_AVG_ACTIONSCRIPT
## * BAT_CLONE_DB
## * BAT_DB
## * BAT_FUNCTIONNAMECACHE_C
## * BAT_FUNCTIONNAMECACHE_JAVA
## * BAT_LICENSE_DB
## * BAT_STRINGSCACHE_C
## * BAT_STRINGSCACHE_JAVA
## * BAT_STRINGSCACHE_C#
## * BAT_STRINGSCACHE_ACTIONSCRIPT

## Check if any of these have been defined in any of the postrunscans
## * BAT_REPORTDIR
## * storedir

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")

	(options, args) = parser.parse_args()
	if options.cfg != None:
		try:
			configfile = open(options.cfg, 'r')
		except:
			parser.error("Need configuration file")
	else:
		parser.error("Need configuration file")

	try:
		config.readfp(configfile)
	except:
		print >>sys.stderr, "Error: Invalid config: %s" % options.cfg
		sys.exit(1)
	scans = bat.bruteforcescan.readconfig(config)

	ranking_old = ["BAT_SQLITE_AVG_C", "BAT_SQLITE_AVG_JAVA", "BAT_SQLITE_AVG_C#", "BAT_SQLITE_AVG_ACTIONSCRIPT", "BAT_SQLITE_DB", "BAT_SQLITE_FUNCTIONNAME_CACHE", "BAT_SQLITE_STRINGSCACHE_C", "BAT_SQLITE_STRINGSCACHE_C#", "BAT_SQLITE_STRINGSCACHE_ACTIONSCRIPT", "BAT_SQLITE_STRINGSCACHE_JAVA"]

	ranking_valid = ["BAT_AVG_C", "BAT_STRINGSCACHE_C", "BAT_AVG_JAVA", "BAT_STRINGSCACHE_JAVA", "BAT_AVG_C#", "BAT_STRINGSCACHE_C#", "BAT_AVG_ACTIONSCRIPT", "BAT_STRINGSCACHE_ACTIONSCRIPT", "BAT_DB", "BAT_FUNCTIONNAMECACHE_C", "BAT_FUNCTIONNAMECACHE_JAVA", "BAT_RANKING_FULLCACHE", "BAT_RANKING_LICENSE", "BAT_RANKING_VERSION", "BAT_CLONE_DB", "BAT_LICENSE_DB"]
	if scans.has_key('programscans'):
		for s in scans['programscans']:
			if s['name'] == 'ranking':
				if not s.has_key('envvars'):
					print "Error: ranking has no environment for databases defined"
					continue
				else:
					rankingfull = False
					licenses = False
					masterdb = None
					envvars = s['envvars']
					for en in envvars.split(':'):
						envsplits = en.split('=')
						if envsplits[0] in ranking_old:
							print "Error: old configuration parameter found: %s" % envsplits[0]
						if envsplits[0] not in ranking_valid:
							print "Error: unknown configuration parameter found: %s" % envsplits[0]
						if len(envsplits) == 1:
							print "Error: %s has no value defined" % envsplits[0]
							continue
						if len(envsplits) > 2:
							print "Error: %s has too many values defined" % envsplits[0]
							continue
						if len(envsplits) == 1 and envsplits[1] == '':
							print "Error: %s has no value defined" % envsplits[0]
							continue
						if envsplits[0] == 'BAT_RANKING_LICENSE':
							if envsplits[1] != '0' and envsplits[1] != '1':
								print "Error: incorrect value for %s" % envsplits[0]
								continue
							if envsplits[1] == '1':
								licenses = True
						if envsplits[0] == 'BAT_RANKING_FULLCACHE':
							if envsplits[1] != '0' and envsplits[1] != '1':
								print "Error: incorrect value for %s" % envsplits[0]
								continue
							if envsplits[1] == '1':
								rankingfull = True
						if envsplits[0] in ["BAT_CLONE_DB", "BAT_LICENSE_DB"]:
							if not os.path.exists(envsplits[1]):
								print "Error: database for %s does not exist" % envsplits[0]
								continue
						if envsplits[0] == "BAT_DB":
							if not os.path.exists(envsplits[1]):
								print "Error: database for %s does not exist" % envsplits[0]
								continue
							masterdb = envsplits[1]
							## now do some database checks
							db_correct = True
							conn = sqlite3.connect(masterdb)
							c = conn.cursor()
							res = c.execute("select * from sqlite_master where type='table' and name = 'processed'").fetchall()
							if res == []:
								db_correct = False
							res = c.execute("select * from sqlite_master where type='table' and name = 'processed_file'").fetchall()
							if res == []:
								db_correct = False
							res = c.execute("select * from sqlite_master where type='table' and name = 'extracted_file'").fetchall()
							if res == []:
								db_correct = False
							c.close()
							conn.close()
							if not db_correct:
								print "Error: database %s does not have correct format" % envsplits[0]
								continue
					## BAT_DB always has to be defined
					if masterdb == None:
						print "Error: BAT_DB not defined"
					if licenses:
						if not "BAT_LICENSE_DB" in envvars:
							print "Error: database for license does not exist, but license scanning defined"
					## the following databases can be generated on the fly but if rankingfull
					## is set they should be treated as "fixed" databases
					for en in envvars.split(':'):
						envsplits = en.split('=')
						if envsplits[0] in ["BAT_AVG_C", "BAT_STRINGSCACHE_C", "BAT_AVG_JAVA", "BAT_STRINGSCACHE_JAVA", "BAT_FUNCTIONNAMECACHE_C", "BAT_FUNCTIONNAMECACHE_JAVA"]:
							if rankingfull:
								if not os.path.exists(envsplits[1]):
									print "Error: database for %s does not exist, but rankingfull defined" % envsplits[0]
							

	## for each postrunscan check:
	## * BAT_REPORTDIR
	## * storedir
	if scans.has_key('postrunscans'):
		pass

if __name__ == "__main__":
	main(sys.argv)
