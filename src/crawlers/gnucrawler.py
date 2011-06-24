#!/usr/bin/python

import sys, os, os.path, re
import ftplib, fnmatch
import ConfigParser
from optparse import OptionParser

## Binary Analysis Tool
## Copyright 2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script crawls a mirror of the GNU FTP site, so it can be used to download
the latest GNU packages to build/update a database.
'''

def setup(storedir):
	try:
		os.makedirs("%s" % (storedir,))
	except:
		pass

## get a blacklist of extensions or patterns we're not interested in
extensions = ['.sig', '.patch.bz2', '.patch.gz', '.diff', 'diff.gz',
		'.diff.lzma', 'diff.bz2', 'diffs.gz', '.txt', '.text',
		'.tex', '.md5', 'md5sum', 'sha1', '.exe', '.i386.rpm',
		'.x86_64.rpm', '.i586.rpm', '.noarch.rpm', '.deb',
		'.asc', '.gpg', '.pkg.gz', '.spec', '.xdelta', '.xdp.gz',
		'.pdf', '.ps', '.png', '.jpg', '.info', '.dsc', '.changes', '.xpi',
		'.dmg', '.egg', '.description', '.html', '.html.gz', '.html.bz2',
		'.html.tar.bz2', '.html.tar.gz', '.ttf.gz', 'doc.tar.gz',
		'doc-html.tar.gz', 'doc-html.zip', 'doc-info.tar.gz', 'doc-info.zip',
		'doc-pdf.tar.gz', 'doc-pdf.zip', 'doc-ps.tar.gz', 'doc-ps.zip',
		'.doc', '.directive', '.gem', '.dvi', '.dvi.gz', 'texi.gz',
		'.pdf.gz', '.ps.gz', '.pgn.gz', 'pics.tar.gz', 'manual.tar.gz',
		'.info.gz', '.txt.gz', '.text.gz', 'pkg.tar.gz', '686.tar.xz',
		'686.tar.bz2', '386.tar.bz2', '386.tar.xz', 'patch.gz', 'patch.bz2',
		'.debian.tar.gz'
		]
blacklistfile = ['README', 'readme', 'NEWS', 'SUMMARY', 'LICENSE', 'CHANGES',
		'COPYING', 'ChangeLog', 'INDEX', 'RELEASE', 'ANNOUNCE',
		'i386', 'i586', 'i686', 'x86-64', 'ix86','x86', 'x64', 'sparc',
		'powerpc', 'openbsd', 'freebsd', 'netbsd', 'cygwin', 'win32',
		'mingw32', 'w32', 'woe32', 'win64', 'darwin', 'solaris', 'linux386',
		'mac-universal', 'md5.sum', 'gr-howto', 'mit-scheme-doc', 'ghostscript-fonts',
		'gnu-gs-fonts', 'glibc-2.0.1.bin', 'readline-doc', 'ps.tar.gz', 'aspell-lang'
		]

## prune dirs we're not interested in (audio, video)
blacklistdirs = ['GNUsBulletins', 'GNUinfo', 'MicrosPorts', 'Licenses',
		'non-gnu/cvs/binary', 'gtypist/w32_binaries', 'gnu-crypto/binaries',
		'mc/binaries', 'sather/Doc', 'aspell/dict', 'clisp/mailing-list',
		'intlfonts', 'parted/static', 'gnu-c-manual', 'bayonne/voices', 'freefont'
		]


def processline(line):
	if line.startswith('l'):
		return
	if line.startswith('d'):
		ftpdirname = line.split()[8]
		for i in blacklistdirs:
			if "%s/%s" % (prefix,ftpdirname) == "%s/%s" % (hostprefix, i):
				return
		dirlist.append("%s/%s" % (prefix, ftpdirname))
	else:
		ftpfilename = line.split()[8]
		for i in blacklistfile:
			if i in ftpfilename:
				return
		for i in extensions:
			if ftpfilename.endswith(i):
				return
		filelist.append("%s/%s" % (prefix, ftpfilename))

## get rid of all duplicates, also make sure we don't get all the gcc subpackages
## prefer bz2 files, then gz, then xz, then lzma
## TODO Also first check (for now just the storedir, later perhaps query a database)
## to see if we already have downloaded this version of the package.
def prune(storedir):
	grablist = []
	oslist = os.listdir(storedir)
	for i in filelist:
		try:
			(base, extension) = i.rsplit(".", 1)
		except:
			#print >>sys.stderr, "CAN'T UNPACK:", i
			continue
		if re.search('gcc-[a-z]+', i) != None:
			continue
		## see if we can match the filename, without the extension, if
		## so we don't download the file.
		matches = fnmatch.filter(oslist, "%s.*" % base.rsplit('/', 1)[-1])
		if len(matches) != 0:
			continue
		## we don't have the file yet, so put it in the grablist
		if extension == "bz2":
			grablist.append(i)
			for ext in ['gz', 'xz', 'lzma']:
				try:
					grablist.remove("%s.%s" % (base, ext))
				except Exception, e:
					pass
			continue
		if extension == "gz":
			if "%s.%s" % (base, "bz2") in grablist:
				continue
			if "%s.%s" % (base, "bz2") in filelist:
				continue
			grablist.append(i)
			for ext in ['xz', 'lzma']:
				try:
					grablist.remove("%s.%s" % (base, ext))
				except Exception, e:
					pass
					#print >>sys.stderr, e, i
			continue
		if extension == "xz":
			for ext in ['lzma']:
				try:
					grablist.remove("%s.%s" % (base, ext))
				except Exception, e:
					pass
					#print >>sys.stderr, e, i
			grablist.append(i)
			for ext in ['bz2', 'gz']:
				if "%s.%s" % (base, ext) in grablist:
					try:
						grablist.remove(i)
					except Exception, e:
						pass
						#print >>sys.stderr, e, i
				elif "%s.%s" % (base, ext) in filelist:
					try:
						grablist.remove(i)
					except Exception, e:
						pass
						#print >>sys.stderr, e, i
			continue
		if extension == "lzma":
			grablist.append(i)
			for ext in ['bz2', 'gz', 'xz']:
				if "%s.%s" % (base, ext) in grablist:
					try:
						grablist.remove(i)
					except Exception, e:
						pass
						#print >>sys.stderr, e, i
				elif "%s.%s" % (base, ext) in filelist:
					try:
						grablist.remove(i)
					except Exception, e:
						pass
						#print >>sys.stderr, e, i
	return grablist

def grab(filename, ftp, storedir):
	ftp.retrbinary('RETR %s' % (filename,), open("%s/%s" % (storedir, os.path.basename(filename)), 'wb').write)
	
def main(argv):
	config = ConfigParser.ConfigParser()
	parser = OptionParser()
	parser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
	parser.add_option("-d", "--directory", action="store", dest="directory", help="path to directory to store files", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.cfg != None:
		try:
			configfile = open(options.cfg, 'r')
		except:
			print "Need configuration file"
			sys.exit(1)
	else:
		print "Need configuration file"
		sys.exit(1)

	config.readfp(configfile)
	if not config.has_section("hostconfig"):
		print >>sys.stderr, "Configuration file malformed"
		sys.exit(1)
	if not config.has_option("hostconfig", "url"):
		print >>sys.stderr, "Configuration file malformed"
		sys.exit(1)
	if not config.has_option("hostconfig", "storedir"):
		print >>sys.stderr, "Configuration file malformed"
		sys.exit(1)
	## grab the URL from the configuration file
	hosturl = config.get("hostconfig", "url")
	storedir = config.get("hostconfig", "storedir")
	setup(storedir)
	## for some reason we ran into http://mail.python.org/pipermail/python-bugs-list/2005-January/027257.html
	## so: first create a list of URLs we want to grab, then grab them.
	global dirlist
	global filelist
	global prefix
	global hostprefix
	(hostname,prefix) = hosturl.split('/', 1)
	hostprefix = hosturl.split('/', 1)[1]
	ftp = ftplib.FTP(hostname)
	ftp.login()
	ftp.set_pasv(True)
	filelist = []
	dirlist = [prefix]
	while dirlist != []:
		prefix = dirlist.pop()
		bla = ftp.retrlines('LIST %s' % prefix, processline)
	grablist = prune(storedir)
	for i in grablist:
		print "GRABBING:", i
		grab(i, ftp, storedir)

if __name__ == "__main__":
	main(sys.argv)
