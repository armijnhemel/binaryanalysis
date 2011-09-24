#!/usr/bin/python
# -*- coding: utf-8 -*-

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Program to process a whole directory full of compressed source code archives
to create a knowledgebase. Needs a file LIST in the directory it is passed as
a parameter, which has the following format:

package version filename origin

separated by whitespace

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

## list of extensions, plus what language they should be mapped to
## This is not necessarily correct, but right now it is the best we have.
extensions = {'.c'     : 'C',
              '.h'     : 'C',
              '.cc'    : 'C',
              '.hh'    : 'C',
              '.c++'   : 'C',
              '.cpp'   : 'C',
              '.hpp'   : 'C',
              '.cxx'   : 'C',
              '.hxx'   : 'C',
              '.S'     : 'C',
              '.java'  : 'Java',
              '.scala' : 'Java',
              '.as'    : 'ActionScript',
             }

## unpack the directories to be scanned. For speed improvements it might be
## wise to use a ramdisk or tmpfs for this, although the program does not
## seem to be I/O bound...
def unpack(directory, filename):
	try:
		os.stat("%s/%s" % (directory, filename))
	except:
		print >>sys.stderr, "Can't find %s" % filename
		return None

        filemagic = ms.file(os.path.realpath("%s/%s" % (directory, filename)))

        ## Assume if we have bz2 or gzip compressed file we are dealing with compressed tar files
        if 'bzip2 compressed data' in filemagic:
       		tmpdir = tempfile.mkdtemp()
		## for some reason the tar.bz2 unpacking from python doesn't always work, like
		## aeneas-1.0.tar.bz2 from GNU, so use a subprocess instead of using the
		## Python tar functionality.
 		p = subprocess.Popen(['tar', 'jxf', "%s/%s" % (directory, filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=tmpdir)
		(stanout, stanerr) = p.communicate()
		return tmpdir
        elif 'gzip compressed data' in filemagic:
		try:
	        	tar = tarfile.open("%s/%s" % (directory, filename), 'r:gz')
       			tmpdir = tempfile.mkdtemp()
       			tar.extractall(path=tmpdir)
        		tar.close()
			return tmpdir
		except Exception, e:
			print e
	elif 'Zip archive data' in filemagic:
		try:
       			tmpdir = tempfile.mkdtemp()
			p = subprocess.Popen(['unzip', "%s/%s" % (directory, filename), '-d', tmpdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0:
				## TODO: cleanup
				pass
			else:
				return tmpdir
		except Exception, e:
			print e

def unpack_verify(filedir, filename):
	try:
		os.stat("%s/%s" % (filedir, filename))
	except:
		print >>sys.stderr, "Can't find %s" % filename

## get strings plus the license. This method should be renamed to better
## reflect its true functionality...
def unpack_getstrings((filedir, package, version, filename, origin, dbpath, cleanup, license)):
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
	c.execute('''select * from processed where package=? and version=?''', (package, version))
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
			try:
				shutil.rmtree(temporarydir)
			except: pass
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
	c.execute('''insert into processed (package, version, filename, origin, sha256) values (?,?,?,?,?)''', (package, version, filename, origin, filehash))
	conn.commit()
	c.close()
	conn.close()
	if cleanup:
		try:
			shutil.rmtree(temporarydir)
		except:
			## probably a permission problem, like no access to a directory. Meh.
			pass
	return

def extractstrings(srcdir, conn, cursor, package, version, license):
	srcdirlen = len(srcdir)+1
	osgen = os.walk(srcdir)

	if license:
		ninkaenv = os.environ
		ninkaenv['PATH'] = ninkaenv['PATH'] + ":/tmp/dmgerman-ninka-594d5e4/comments/comments"
	try:
		while True:
			i = osgen.next()
			for p in i[2]:
			## we can't determine anything about an empty file, so skip
				if os.stat("%s/%s" % (i[0], p)).st_size == 0:
					continue
				## some filenames might have uppercase extensions, so lowercase them first
				p_nocase = p.lower()
				for extension in extensions.keys():
					if (p_nocase.endswith(extension)):
						scanfile = open("%s/%s" % (i[0], p), 'r')
						h = hashlib.new('sha256')
						h.update(scanfile.read())
						scanfile.close()
						filehash = h.hexdigest()
						cursor.execute('''insert into processed_file (package, version, filename, sha256) values (?,?,?,?)''', (package, version, "%s/%s" % (i[0][srcdirlen:],p), filehash))
						cursor.execute('''select * from extracted_file where sha256=?''', (filehash,))
						if len(cursor.fetchall()) != 0:
							#print >>sys.stderr, "duplicate %s %s: %s/%s" % (package, version, i[0], p)
							continue
						## if we want to scan for licenses, run Ninka and (future work) FOSSology
						if license:
							## first we generate just a .comments file and see if we've already seen it
							## before. This is because often license headers are very similar, so we
							## don't need to rescan everything.
							## For gtk+ 2.20.1 scanning time dropped with about 25%.
							p1 = subprocess.Popen(["/tmp/dmgerman-ninka-594d5e4/ninka.pl", "-c", "%s/%s" % (i[0], p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=ninkaenv)
                                			(stanout, stanerr) = p1.communicate()
							scanfile = open("%s/%s.comments" % (i[0], p), 'r')
							ch = hashlib.new('sha256')
							ch.update(scanfile.read())
							scanfile.close()
							commentshash = ch.hexdigest()
							cursor.execute('''select license, version from ninkacomments where sha256=?''', (commentshash,))
							res = cursor.fetchall()
							if len(res) > 0:
								#print >>sys.stderr, "duplicate comment %s %s: %s/%s" % (package, version, i[0], p)
								## store all the licenses we already know for this file
								for r in res:
									(filelicense, scannerversion) = r
									## hardcode the scanner to 'ninka'. This could/should change in the future.
									cursor.execute('''insert into licenses (sha256, license, scanner, version) values (?,?,?,?)''', (filehash, filelicense, "ninka", scannerversion))
							else:
								## we don't have any information about this .comments file yet, so
								## restart Ninka for a full scan.
								p2 = subprocess.Popen(["/tmp/dmgerman-ninka-594d5e4/ninka.pl", "%s/%s" % (i[0], p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=ninkaenv)
                                				(stanout, stanerr) = p2.communicate()
								ninkasplit = stanout.strip().split(';')[1:]
								## filter out the licenses we can't determine.
								## We actually should run these through FOSSology to try and obtain a match.
								if ninkasplit[0] == '':
									print >>sys.stderr, "NINKA     %s/%s" % (i[0],p), "UNKNOWN"
									cursor.execute('''insert into licenses (sha256, license, scanner, version) values (?,?,?,?)''', (filehash, license, "ninka", "594d5e4"))
									cursor.execute('''insert into ninkacomments (sha256, license, scanner, version) values (?,?,?,?)''', (commentshash, license, "ninka", "594d5e4"))
								else:
									licenses = ninkasplit[0].split(',')
									for license in licenses:
										print >>sys.stderr, "NINKA     %s/%s" % (i[0],p), license
										cursor.execute('''insert into licenses (sha256, license, scanner, version) values (?,?,?,?)''', (filehash, license, "ninka", "594d5e4"))
										cursor.execute('''insert into ninkacomments (sha256, license, scanner, version) values (?,?,?,?)''', (commentshash, license, "ninka", "594d5e4"))
								## Also run FOSSology
								## this requires that the user has enough privileges to actually connect to the FOSSology database!
								p2 = subprocess.Popen(["/usr/lib/fossology/agents/nomos", "%s/%s" % (i[0], p)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                                				(stanout, stanerr) = p2.communicate()
								if "FATAL" in stanout:
									pass
								else:
									fossysplit = stanout.strip().rsplit(" ", 1)
									licenses = fossysplit[-1].split(',')
									for license in licenses:
										print >>sys.stderr, "FOSSOLOGY %s/%s" % (i[0],p), license
										cursor.execute('''insert into licenses (sha256, license, scanner, version) values (?,?,?,?)''', (filehash, license, "nomos", "1.4.0"))
								print >> sys.stderr
						sqlres = extractsourcestrings(p, i[0], package, version, srcdirlen)
						for res in sqlres:
							(pstring, linenumber) = res
							cursor.execute('''insert into extracted_file (programstring, sha256, language, linenumber) values (?,?,?,?)''', (pstring, filehash, extensions[extension], linenumber))
							pass
	except Exception, e:
		print >>sys.stderr, e
		pass
	conn.commit()
	return

##
## Extract strings using xgettext. Apparently this does not always work correctly. For example for busybox 1.6.1:
## $ xgettext -a -o - fdisk.c
##  xgettext: Non-ASCII string at fdisk.c:203.
##  Please specify the source encoding through --from-code.
## We fix this by rerunning xgettext with --from-code=utf-8
## The results might not be perfect, but they are acceptable.
## TODO: use version from bat/extractor.py
def extractsourcestrings(filename, filedir, package, version, srcdirlen):
	sqlres = []
	p1 = subprocess.Popen(['xgettext', '-a', "--omit-header", "--no-wrap", "%s/%s" % (filedir, filename), '-o', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p1.communicate()
	if p1.returncode != 0:
		## analyze stderr first
		if "Non-ASCII" in stanerr:
			## rerun xgettext with a different encoding
			p2 = subprocess.Popen(['xgettext', '-a', "--omit-header", "--no-wrap", "--from-code=utf-8", "%s/%s" % (filedir, filename), '-o', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			## overwrite stanout
			(stanout, pstanerr) = p2.communicate()
			if p2.returncode != 0:
				return sqlres
	source = stanout 
	lines = []
	linenumbers = []

	## escape just once to speed up extraction of filenumbers
	filename_escape = re.escape(filename)

	for l in stanout.split("\n"):
		## skip comments and hints
		if l.startswith("#, "):
			continue
		if l.startswith("#: "):
			## there can actually be more than one entry on a single line
			res = re.findall("%s:(\d+)" % (filename_escape,), l[3:])
			if res != None:
				linenumbers = linenumbers + map(lambda x: int(x), res)
			else:
				linenumbers.append(0)

		if l.startswith("msgid "):
			lines = []
			lines.append(l[7:-1])
		## when we see msgstr "" we have reached the end of a block and we can start
		## processing
		elif l.startswith("msgstr \"\""):
			count = len(linenumbers)
			for xline in lines:
				## split at \r
				## TODO: handle \0 (although xgettext will not scan any further when encountering a \0 in a string)
				for line in xline.split("\\r\\n"):
					for sline in line.split("\\n"):
						## do we really need this?
						sline = sline.replace("\\\n", "")

						## unescape a few values
						sline = sline.replace("\\\"", "\"")
						sline = sline.replace("\\t", "\t")
						sline = sline.replace("\\\\", "\\")
	
						## we don't want to store empty strings, they won't show up in binaries
						## but they do make the database a lot larger
						if sline == '':
							continue
						for i in range(0, len(linenumbers)):
							sqlres.append((sline, linenumbers[i]))
			linenumbers = []
		## the other strings are added to the list of strings we need to process
		else:
			lines.append(l[1:-1])
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
		try:
			c.execute('''drop table ninkacomments''')
		except:
			pass
		conn.commit()
        try:
		## Keep an archive of which packages and archive files (tar.gz, tar.bz2, etc.) we've already
		## processed, so we don't repeat work.
		c.execute('''create table processed (package text, version text, filename text, origin text, sha256 text)''')
		c.execute('''create index processed_index on processed(package, version)''')

		## Since there is a lot of duplication inside source packages we store strings per checksum
		## which we can later link with files
		c.execute('''create table processed_file (package text, version text, filename text, sha256 text)''')
		c.execute('''create index processedfile_index on processed_file(sha256)''')
		c.execute('''create index processedfile__package_index on processed_file(package)''')
		c.execute('''create unique index processedfile_package_index_unique on processed_file(package, version, filename, sha256)''')

		## Store the extracted strings per checksum, not per (package, version, filename).
		## This saves a lot of space in the database
		## The field 'language' denotes what 'language' (family) the file the string is extracted from
		## is in. Current values: 'C' (C and C++) and Java
		c.execute('''create table extracted_file (programstring text, sha256 text, language text, linenumber int)''')
		c.execute('''create index programstring_index on extracted_file(programstring)''')
		c.execute('''create index extracted_hash on extracted_file(sha256)''')

		## Store the extracted licenses per checksum.
		c.execute('''create table licenses (sha256 text, license text, scanner, version)''')
                c.execute('''create index license_index on licenses(sha256);''')

		## Store the comments extracted by Ninka per checksum.
		c.execute('''create table ninkacomments (sha256 text, license text, scanner, version)''')
                c.execute('''create index comments_index on licenses(sha256);''')
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
		try:
			unpacks = unpackfile.strip().split()
			if len(unpacks) == 3:
				origin = "unknown"
				(package, version, filename) = unpacks
			else:
				(package, version, filename, origin) = unpacks
			#pkgmeta.append((options.filedir, package, version, filename, origin, options.db, cleanup, license))
			if options.verify:
				unpack_verify(options.filedir, filename)
			res = unpack_getstrings((options.filedir, package, version, filename, origin, options.db, cleanup, license))
		except Exception, e:
			# oops, something went wrong
			print >>sys.stderr, e
	#result = pool.map(unpack_getstrings, pkgmeta)

if __name__ == "__main__":
    main(sys.argv)
