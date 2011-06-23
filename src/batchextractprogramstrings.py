#!/usr/bin/python
# -*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Program to process a whole directory full of compressed source code archives
to create a knowledgebase. Needs a file LIST in the directory it is passed as
a parameter, which has the following format:

package version filename

seperated by whitespace

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

        ## Just assume if it is bz2 or gzip that we are looking at tar files with compression
        if 'bzip2 compressed data' in filemagic:
       		tmpdir = tempfile.mkdtemp()
		## for some reason sometimes the tar.bz2 unpacking from python doesn't always work,
		## like aeneas-1.0.tar.bz2 from GNU, so resort to calling a subprocess instead of using
		## the Python tar functionality.
 		p = subprocess.Popen(['tar', 'jxf', "%s/%s" % (directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
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

def unpack_getstrings((filedir, package, version, filename, dbpath, cleanup, license)):
	print filename
	scanfile = open("%s/%s" % (filedir, filename), 'r')
	h = hashlib.new('sha256')
	h.update(scanfile.read())
	scanfile.close()
	filehash = h.hexdigest()

	## Check if we've already processed this file. If so, we can easily skip it and return.
        conn = sqlite3.connect(dbpath, check_same_thread = False)
	c = conn.cursor()
	#c.execute('PRAGMA journal_mode=off')
	c.execute('''select * from processed where package=? and version=?''', (package, version,))
	if len(c.fetchall()) != 0:
		c.close()
		conn.close()
		return
	## unpack the archive. If we fail, cleanup and return.
	temporarydir = unpack(filedir, filename)
	if temporarydir == None:
		c.close()
		conn.close()
		if cleanup:
			shutil.rmtree(temporarydir)
		return None
	## Check if we already have any strings from program + version. If so,
	## first remove them before we add them to avoid unnecessary duplication.
	c.execute('''select * from processed_file where package=? and version=?''', (package, version))
	if len(c.fetchall()) != 0:
		c.execute('''delete from processed_file where package=? and version=?''', (package, version))
		conn.commit()
	sqlres = extractstrings(temporarydir, conn, c, package, version, license)
	## Add the file to the database: name of archive, sha256, packagename and version
	## This is to be able to just update the database instead of recreating it.
	c.execute('''insert into processed (package, version, filename, sha256) values (?,?,?,?)''', (package, version, filename, filehash))
	conn.commit()
	c.close()
	conn.close()
	if cleanup:
		shutil.rmtree(temporarydir)
	return

def extractstrings(srcdir, conn, cursor, package, version, license):
	srcdirlen = len(srcdir)+1
	osgen = os.walk(srcdir)

	if license:
		ninkaenv = os.environ
		ninkaenv['PATH'] = ninkaenv['PATH'] + ":/tmp/dmgerman-ninka-7a9a5c4/comments/comments"
	try:
		while True:
			i = osgen.next()
			for p in i[2]:
			## we can't determine anything about an empty file
				if os.stat("%s/%s" % (i[0], p)).st_size == 0:
					continue
				## we're only interested in a few files right now, will add more in the future
				## some filenames might have uppercase extensions, so lowercase them first
				p_nocase = p.lower()
				if (p_nocase.endswith('.c') or p_nocase.endswith('.h') or p_nocase.endswith('.cpp') or p_nocase.endswith('.cc') or p_nocase.endswith('.hh') or p_nocase.endswith('.cxx') or p_nocase.endswith('.c++') or p_nocase.endswith('.hpp') or p_nocase.endswith('.hxx')):
					scanfile = open("%s/%s" % (i[0], p), 'r')
					h = hashlib.new('sha256')
					h.update(scanfile.read())
					scanfile.close()
					filehash = h.hexdigest()
					cursor.execute('''insert into processed_file (package, version, filename, sha256) values (?,?,?,?)''', (package, version, "%s/%s" % (i[0],p), filehash))
					cursor.execute('''select * from extracted_file where sha256=?''', (filehash,))
					if len(cursor.fetchall()) != 0:
						print >>sys.stderr, "duplicate %s %s: %s/%s" % (package, version, i[0], p)
						continue
					## if we want to scan for licenses, run Ninka and (future work) FOSSology
					if license:
						p1 = subprocess.Popen(["/tmp/dmgerman-ninka-7a9a5c4/ninka.pl", "-d", "%s/%s" % (i[0], p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=ninkaenv)
                                		(stanout, stanerr) = p1.communicate()
						ninkasplit = stanout.strip().split(';')[1:]
						## filter out the licenses we can't determine. We actually should run these through FOSSology to try and obtain a match.
						if ninkasplit[0].startswith("UNMATCHED"):
							pass
						elif ninkasplit[0].startswith("UNKNOWN"):
							pass
						else:
							licenses = ninkasplit[0].split(',')
							for license in licenses:
								print >>sys.stderr, "%s/%s" % (i[0],p), license
								cursor.execute('''insert into licenses (sha256, license, scanner) values (?,?,?)''', (filehash, license, "ninka"))
					## TODO: remove ninka temporary files (.sentences, .license)
					sqlres = extractsourcestrings(p, i[0], package, version, srcdirlen)
					for res in sqlres:
						cursor.execute('''insert into extracted_file (programstring, sha256) values (?,?)''', (res, filehash))
						pass
	except Exception, e:
		print >>sys.stderr, e
		pass
	conn.commit()
	return

def extractsourcestrings(filename, filedir, package, version, srcdirlen):
	sqlres = []
	## Remove all C and C++ style comments first using the C preprocessor
	p1 = subprocess.Popen(['cpp', '-dD', '-fpreprocessed', "%s/%s" % (filedir, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
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
	try:
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
				sqlres.append(unicode(line))
	except Exception, e:
		## if we can't process the error due to codec errors perhaps we should first use iconv and try again
		'''
		src = open("%s/%s" % (filedir, filename)).read()
		p1 = subprocess.Popen(["iconv", "-f", "latin1", "-t", "utf-8"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
		cleanedup_src = p1.communicate(src)[0]
		p2 = subprocess.Popen(['./remccoms3.sed'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,close_fds=True)
		(stanout, stanerr) = p2.communicate(cleanedup_src)
		source = stanout
		'''
		print >>sys.stderr, e
	return sqlres

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", dest="db", help="path to database", metavar="DIR")
	parser.add_option("-f", "--filedir", action="store", dest="filedir", help="path to directory containing files to unpack", metavar="DIR")
	parser.add_option("-v", "--verify", action="store_true", dest="verify", help="verify files, don't process (default: false)")
	parser.add_option("-z", "--cleanup", action="store_true", dest="cleanup", help="cleanup after unpacking? (default: false)")
	parser.add_option("-w", "--wipe", action="store_true", dest="wipe", help="wipe database instead of update (default: false)")
	parser.add_option("-l", "--licenses", action="store_true", dest="licenses", help="extract licenses (default: false)")
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

	if options.licenses != None:
		license = True
	else:
		license = False

	conn = sqlite3.connect(options.db, check_same_thread = False)
	c = conn.cursor()
	#c.execute('PRAGMA journal_mode=off')

	if wipe:
		try:
			c.execute('''drop table extracted''')
		except:
			pass
		try:
			c.execute('''drop table processed''')
		except:
			pass
		try:
			c.execute('''drop table processed_file''')
		except:
			pass
		try:
			c.execute('''drop table extracted_file''')
		except:
			pass
		try:
			c.execute('''drop table licenses''')
		except:
			pass
		conn.commit()
        try:
		## Keep an archive of which packages and archive files (tar.gz, tar.bz2, etc.) we've already
		## processed, so we don't repeat work.
		c.execute('''create table processed (package text, version text, filename text, sha256 text)''')
		c.execute('''create index processed_index on processed(package, version)''')

		## Since there is a lot of duplication inside source packages we store strings per checksum
		## which we can later link with files
		c.execute('''create table processed_file (package text, version text, filename text, sha256 text)''')
		c.execute('''create index processedfile_index on processed_file(sha256)''')

		## Store the extracted strings per checksum, not per (package, version, filename).
		## This saves a lot of space in the database
		c.execute('''create table extracted_file (programstring text, sha256 text)''')
		c.execute('''create index programstring_index on extracted_file(programstring)''')
		c.execute('''create index extracted_hash on extracted_file(sha256)''')

		## Store the extracted licenses per checksum.
		c.execute('''create table licenses (sha256 text, license text, scanner)''')
                c.execute('''create index license_index on licenses(sha256);''')

		conn.commit()
	except Exception, e:
		print >>sys.stderr, e
	c.close()
	conn.close()
	#print pkgmeta

	## TODO: make this a configuration parameter
	#pool = Pool(processes=2)
	#pool = Pool(processes=1)

	pkgmeta = []
	## TODO: do all kinds of checks here
	filelist = open(options.filedir + "/LIST").readlines()
	for unpackfile in filelist:
		(package, version, filename) = unpackfile.strip().split()
		pkgmeta.append((options.filedir, package, version, filename, options.db, cleanup, license))
		if options.verify:
			unpack_verify(options.filedir, filename)
		res = unpack_getstrings((options.filedir, package, version, filename, options.db, cleanup, license))
	#result = pool.map(unpack_getstrings, pkgmeta)

if __name__ == "__main__":
    main(sys.argv)
