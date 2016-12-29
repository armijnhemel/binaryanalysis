#! /usr/bin/python

## Binary Analysis Tool
## Copyright 2014-2016 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a barebones script to print information about cloning inside
the BAT database. Two types of clones are stored:

* identical clones: all files of the package are the same. This could be
because the packages are identical, or because the number of files that BAT
would process is actually really really small. This happens for example with
wrappers around libraries to provide language bindings

* embedding: a package is completely copied into another package.

Results are printed on stdout. The database is not automatically adapted.
'''

import sys, os, psycopg2, multiprocessing, ConfigParser, Queue
from optparse import OptionParser

def counthashes(conn, cursor, scanqueue, reportqueue, packageclones, ignorepackages, timeout, debug):
	while True:
		(package, version) = scanqueue.get(timeout=timeout)
		if package in ignorepackages:
			scanqueue.task_done()
			continue
		cursor.execute("select distinct checksum from processed_file where package=%s and version=%s", (package, version))
		sha256 = cursor.fetchall()
		conn.commit()
		if debug:
			print >>sys.stderr, "hashing %s, %s" % (package, version), len(sha256)
			sys.stderr.flush()
		reportqueue.put(((package, version), len(sha256)))
		scanqueue.task_done()

## process packages by querying the database.
## This method takes three parameters:
## * db -- location of the database
## * packageversion -- tuple (packagename, version)
## * packageclones -- boolean to indicate whether or not clones
## between different versions of the same package should also be
## considered.
## * ignorepackages -- list of packages that should be ignored
def clonedetect(conn, cursor, scanqueue, reportqueue, packageclones, ignorepackages, timeout, debug):
	while True:
		(package, version) = scanqueue.get(timeout=timeout)
		possibleclones = {}
		if package in ignorepackages:
			reportqueue.put(((package, version), possibleclones))
			scanqueue.task_done()
			continue
		if debug:
			print >>sys.stderr, "processing %s, %s" % (package, version)
			sys.stderr.flush()
		cursor.execute("select distinct checksum from processed_file where package=%s and version=%s", (package, version))
		sha256 = cursor.fetchall()
		conn.commit()
		if len(sha256) != 0:
			clonep = {}
			for s in sha256:
				cursor.execute('select distinct package, version from processed_file where checksum=%s', s)
				clonesha256 = cursor.fetchall()
				conn.commit()
				## one file is unique to this package, so there are no complete clones
				if len(clonesha256) == 1:
					clonep = {}
					break
				if not packageclones:
					if len(set(map(lambda x: x[0], clonesha256))) == 1:
						continue
				for p in clonesha256:
					if not packageclones:
						if p[0] == package:
							continue
					else:
						if p[1] == version:
							continue
					if clonep.has_key(p):
						clonep[p] += 1
					else:
						clonep[p] = 1

		clonep_final = {}
		for p in clonep:
			## only consider results that contain the package completely
			if clonep[p] >= len(sha256):
				clonep_final[p] = clonep[p]
	
		reportqueue.put(((package, version), clonep_final))
		scanqueue.task_done()

def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	(options, args) = parser.parse_args()

	if options.cfg == None:
		parser.error("Need path to configuration file")

	try:
		configfile = open(options.cfg, 'r')
	except:
		parser.error("Configuration file not readable")
	config.readfp(configfile)
	configfile.close()

        section = 'extractconfig'

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
	except:
		print >>sys.stderr, "Database connection not defined in configuration file. Exiting..."
		sys.stderr.flush()
		sys.exit(1)

	try:
		conn = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password, host=postgresql_host, port=postgresql_port)

		cursor = conn.cursor()
	except:
		print >>sys.stderr, "Can't open database"
		sys.exit(1)

	## first grab all the package/version combinations from the database
	cursor.execute("select package, version from processed")
	packages = cursor.fetchall()
	conn.commit()
	cursor.close()
	conn.close()

	ignorepackages = ['linux']
	#ignorepackages = []

	## create a set of processes that grabs all the data
	## from the database

        processors = multiprocessing.cpu_count()

	scanmanager = multiprocessing.Manager()
	scanqueue = multiprocessing.JoinableQueue(maxsize=0)
	reportqueue = scanmanager.Queue(maxsize=0)

	map(lambda x: scanqueue.put(x), packages)

	batcons = []
	batcursors = []

	for i in range(0,processors):
		try:
			c = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password, host=postgresql_host, port=postgresql_port)
			cursor = c.cursor()
			batcons.append(c)
			batcursors.append(cursor)
		except Exception, e:
			usedatabase = False
			break

	processpool = []
	## TODO: make configurable
	timeout = 2592000

	packageclones = False
	debug = False

	for i in range(0,processors):
		cursor = batcursors[i]
		conn = batcons[i]
		p = multiprocessing.Process(target=counthashes, args=(conn, cursor, scanqueue, reportqueue, packageclones, ignorepackages, timeout, debug))
		processpool.append(p)
		p.start()

	scanqueue.join()

	sha256perpackage = {}
	while True:
		try:
			val = reportqueue.get_nowait()
			if val != None:
				(package, lensha256) = val
				sha256perpackage[package] = lensha256
			reportqueue.task_done()
		except Queue.Empty, e:
			## Queue is empty
			break

	## block here until the reportqueue is empty
	reportqueue.join()

	for p in processpool:
		p.terminate()

	## make new queues
	scanqueue = multiprocessing.JoinableQueue(maxsize=0)
	reportqueue = scanmanager.Queue(maxsize=0)
	map(lambda x: scanqueue.put(x), packages)

	for i in range(0,processors):
		cursor = batcursors[i]
		conn = batcons[i]
		p = multiprocessing.Process(target=clonedetect, args=(conn, cursor, scanqueue, reportqueue, packageclones, ignorepackages, timeout, debug))
		processpool.append(p)
		p.start()

	scanqueue.join()

	clonedb = {}
	while True:
		try:
			val = reportqueue.get_nowait()
			if val != None:
				(package, clones) = val
				clonedb[package] = clones
			reportqueue.task_done()
		except Queue.Empty, e:
			## Queue is empty
			break

	## block here until the reportqueue is empty
	reportqueue.join()

	for p in processpool:
		p.terminate()

	scanmanager.shutdown()

	for i in clonedb:
		for j in clonedb[i]:
			if j in sha256perpackage:
				if sha256perpackage[i] == sha256perpackage[j]:
					args = i + j + (sha256perpackage[i],)
					print "identical:\t%s, %s == %s, %s -- %d" % args
					sys.stdout.flush()
				else:
					args = i + j + (sha256perpackage[i], sha256perpackage[j])
					print "partial:\t%s, %s << %s, %s -- %d %d" % args
					sys.stdout.flush()

if __name__ == "__main__":
	main(sys.argv)
