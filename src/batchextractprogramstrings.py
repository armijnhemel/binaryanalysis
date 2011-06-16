#!/usr/bin/python
# -*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
Program to process a whole directory full of compressed source code archives
to create a knowledgebase. Needs a file LIST in the directory it is passed as
a parameter.

package version filename

seperated by whitespace.

Compression is determined using magic
'''

import sys, os, magic, string, re, subprocess, shutil
import tempfile, bz2, tarfile, gzip
from optparse import OptionParser
from multiprocessing import Pool
import sqlite3, hashlib

tarmagic = ['POSIX tar archive (GNU)'
           , 'tar archive'
           ]

ms = magic.open(magic.MAGIC_NONE)
ms.load()

def unpack(directory, filename):
        filemagic = ms.file(os.path.realpath("%s/%s" % (directory, filename)))

        ## just assume if it is bz2 or gzip that we are looking at tar files with compression

        if 'bzip2 compressed data' in filemagic:
       		tmpdir = tempfile.mkdtemp()
		## for some reason sometimes the tar.bz2 unpacking from python doesn't work, like aeneas-1.0.tar.bz2 from GNU, so resort to calling a subprocess
 		p = subprocess.Popen(['tar', 'jxf', "%s/%s" % (directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
	        #tar = tarfile.open("%s/%s" % (dir, filename), 'r:bz2')
		#print tar.list()
       		#tar.extractall(path=tmpdir)
        	#tar.close()
		return tmpdir
        elif 'gzip compressed data' in filemagic:
	        tar = tarfile.open("%s/%s" % (directory, filename), 'r:gz')
       		tmpdir = tempfile.mkdtemp()
       		tar.extractall(path=tmpdir)
        	tar.close()
		return tmpdir

def unpack_verify(filedir, filename):
	try:
		os.stat("%s/%s" % (filedir, filename))
	except:
		print >>sys.stderr, "Can't find %s" % filename

def unpack_getstrings((filedir, package, version, filename, dbpath, cleanup)):
	print filename
	scanfile = open("%s/%s" % (filedir, filename), 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	filehash = h.hexdigest()

	## Check if we've already processed this file, if so, we can easily skip it.
        conn = sqlite3.connect(dbpath, check_same_thread = False)
	c = conn.cursor()
	c.execute('''select * from processed where package=? and version=?''', (package, version,))
	if len(c.fetchall()) != 0:
		c.close()
		conn.close()
		return
	## TODO: here we should check on program + version
	temporarydir = unpack(filedir, filename)
	if temporarydir == None:
		c.close()
		conn.close()
		if cleanup:
			shutil.rmtree(temporarydir)
		return None
	## check if we have any strings from program + version. If so,
	## first remove them before we add them to avoid duplication
	c.execute('''select * from extracted where package=? and version=?''', (package, version))
	if len(c.fetchall()) != 0:
		c.execute('''delete from extracted where package=? and version=?''', (package, version))
		conn.commit()
	sqlres = extractstrings(temporarydir, conn, package, version)
	for res in sqlres:
		c.execute('''insert into extracted (programstring, package, version, filename) values (?,?,?,?)''', res)
	conn.commit()
	## add the file to the database: name of archive, sha256sum, packagename, version
	## This is to be able to just update the database instead of recreating it.
	c.execute('''insert into processed (package, version, filename, sha256) values (?,?,?,?)''', (package, version, filename, filehash))
	conn.commit()
	c.close()
	conn.close()
	if cleanup:
		shutil.rmtree(temporarydir)
	return

def extractstrings(srcdir, conn, package, version):
	srcdirlen = len(srcdir)+1
	osgen = os.walk(srcdir)
	sqlres = []

	try:
		while True:
			i = osgen.next()
			for p in i[2]:
				sqlres = sqlres + extractsourcestrings(p, i[0], package, version, srcdirlen)
	except Exception, e:
		print >>sys.stderr, e
		pass
	return sqlres

def extractsourcestrings(filename, filedir, package, version, srcdirlen):
	sqlres = []
	## we're only interested in a few files right now, will add more in the future
	## some filenames might have uppercase extensions, so lowercase them first
	p_nocase = filename.lower()
	if (p_nocase.endswith('.c') or p_nocase.endswith('.h') or p_nocase.endswith('.cpp') or p_nocase.endswith('.cc') or p_nocase.endswith('.hh') or p_nocase.endswith('.cxx') or p_nocase.endswith('.c++') or p_nocase.endswith('.hpp') or p_nocase.endswith('.hxx')):
		## Remove all C and C++ style comments. If a file is in iso-8859-1
		## instead of ASCII or UTF-8 we need to do some extra work by
		## converting it first using iconv.
		## This is not failsafe, because magic gets it wrong sometimes, so we
		## need some way to kill the subprocess if it is running too long.
		datatype = ms.file("%s/%s" % (filedir, filename))
		if "AppleDouble" in datatype:
			return sqlres
		if "ISO-8859" in datatype:
			src = open("%s/%s" % (filedir, filename)).read()
			p1 = subprocess.Popen(["iconv", "-f", "latin1", "-t", "utf-8"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
			cleanedup_src = p1.communicate(src)[0]
			p2 = subprocess.Popen(['./remccoms3.sed'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,close_fds=True)
			(stanout, stanerr) = p2.communicate(cleanedup_src)
			source = stanout
			## we don't know what this is, assuming it's latin1, but we could be wrong
		elif "data" in datatype or "ASCII" in datatype:
			src = open("%s/%s" % (filedir, filename)).read()
			p1 = subprocess.Popen(["iconv", "-f", "latin1", "-t", "utf-8"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
			cleanedup_src = p1.communicate(src)[0]
			p2 = subprocess.Popen(['./remccoms3.sed'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,close_fds=True)
			(stanout, stanerr) = p2.communicate(cleanedup_src)
			source = stanout
		else:
			p1 = subprocess.Popen(['./remccoms3.sed', "%s/%s" % (filedir, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
                       	(stanout, stanerr) = p1.communicate()
                       	if p1.returncode != 0:
				return sqlres
			else:
				source = stanout
		## if " is directly preceded by an uneven amount of \ it should not be used
		## TODO: fix for uneveness
		## Not matched: " directly preceded by '
		## double quotes that are escaped using \
		###### results = re.findall("(?<!')\"(.*?)(?<!\\\)\"", source, re.MULTILINE|re.DOTALL)
		#results = re.findall("\"(.*?)(?<!\\\)\"", source, re.MULTILINE|re.DOTALL)
		## http://stackoverflow.com/questions/5150398/using-python-to-split-a-string-with-delimiter-while-ignoring-the-delimiter-and-e
		#results = re.findall(r'"[^"\\]*(?:\\.[^"\\]*)*"', source, re.MULTILINE|re.DOTALL)
		## and prepend with "don't match a single quote first", which seems to do the trick.
		results = re.findall(r'(?<!\')"[^"\\]*(?:\\.[^"\\]*)*"', source, re.MULTILINE|re.DOTALL)
		for res in results:
                	storestring = res[1:-1] # strip double quotes around the string
			# Handle \" and \t.
			# Handle \n.  The "strings" tool treats multi-line strings as separate 
			# strings, so we also store them in the database as separate strings.
			# Ideally, we would patch "strings" to return multi-line strings.
			for line in storestring.split("\\n"):
				if line is '': continue
				line = line.replace("\\\n", "")
				line = line.replace("\\\"", "\"")
				line = line.replace("\\t", "\t")
				line = line.replace("\\\\", "\\")
				#if "\n" in line:
				#        print >>sys.stderr, "skipping multiline string in file %s" % (p,), storestring
                                #print >>sys.stderr, "storing", line
				#sqlres.append((unicode(storestring), package, version, u"%s/%s" % (i[0][srcdirlen:], p)))
				sqlres.append((unicode(line), package, version, u"%s/%s" % (filedir[srcdirlen:], filename)))
	#print "package", package, len(sqlres)
	return sqlres

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="db", help="path to database", metavar="DIR")
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-v", "--verify", action="store_true", dest="verify", help="verify files, don't process (default: false)")
	parser.add_option("-z", "--cleanup", action="store_true", dest="cleanup", help="cleanup after unpacking? (default: false)")
	parser.add_option("-w", "--wipe", action="store_true", dest="wipe", help="wipe database instead of update (default: false)")
	(options, args) = parser.parse_args()
	if options.filedir == None:
		print >>sys.stderr, "Specify dir with files"
		sys.exit(1)

	if options.db == None:
		print >>sys.stderr, "Specify path to database"
		sys.exit(1)

	if options.cleanup != None:
		cleanup = True
	else:
		cleanup = False

	if options.wipe != None:
		wipe = True
	else:
		wipe = False

	#conn = sqlite3.connect(options.id)
	#conn = sqlite3.connect("/tmp/sqlite", check_same_thread = False)
	conn = sqlite3.connect(options.db, check_same_thread = False)
	c = conn.cursor()

	if wipe:
		try:
			c.execute('''drop table extracted''')
			c.execute('''drop table processed''')
			c.execute('''drop table processed_file''')
			c.execute('''drop table extracted_file''')
			conn.commit()
		except:
			pass
        try:
		c.execute('''create table extracted (programstring text, package text, version text, filename text)''')
		## create an index to speed up searches
		c.execute('''create index programstring_index on extracted(programstring)''')
		c.execute('''create table processed (package text, version text, filename text, sha256 text)''')
		## create an index to speed up searches
		c.execute('''create index processed_index on processed(package, version)''')
		c.execute('''create table processed_file (package text, version text, filename text, sha256 text)''')
		## create an index to speed up searches
		c.execute('''create index processed_index on processed_file(sha256)''')
		## since there is a lot of duplication inside source packages we store strings per checksum
		## which we later link with files
		c.execute('''create table extracted_file (programstring text, sha256 text)''')
		## create an index to speed up searches
		c.execute('''create index programstring_index on extracted_file(programstring)''')
		conn.commit()
	except:
		pass
	c.close()
	conn.close()
	#print pkgmeta

	#pool = Pool(processes=2)
	pool = Pool(processes=1)

	pkgmeta = []
	## TODO: do all kinds of checks here
	filelist = open(options.filedir + "/LIST").readlines()
	for unpackfile in filelist:
		(package, version, filename) = unpackfile.strip().split()
		pkgmeta.append((options.filedir, package, version, filename, options.db, cleanup))
		#print >>sys.stderr, filename
		if options.verify:
			unpack_verify(options.filedir, filename)

	result = pool.map(unpack_getstrings, pkgmeta)


if __name__ == "__main__":
    main(sys.argv)
