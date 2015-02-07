#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This program helps extract copyright statements from source code files.
Ninka and FOSSology are used to extract copyrights, and results are cross
checked. Using information from the build tree (object files, possibly
Makefiles in the future) the set of possible files that copyrights should
be extracted from is reduced.
'''

import os, os.path, sys, hashlib, subprocess, stat, multiprocessing, magic, re
from optparse import OptionParser

ms = magic.open(magic.MAGIC_NONE)
ms.load()

includeregex = re.compile("#\s*include\s+\"([\w\.]+)\"")

## some more precompiled regex for the FOSSology results
recopyright = re.compile('^\s*\[(\d+):\d+:(\w+)] \'(.*)\'$')
recopyright2 = re.compile('^\s*\[(\d+):\d+:(\w+)] \'(.*)')

def extractCopyrights((filedir, filename)):
	## first generate a .comments file with Ninka
	ninkaenv = os.environ.copy()
	ninkaversion = "1.1"
	ninkabasepath = '/gpl/ninka/ninka-%s' % ninkaversion
	ninkaenv['PATH'] = ninkaenv['PATH'] + ":%s/comments" % ninkabasepath

	p1 = subprocess.Popen(["%s/ninka.pl" % ninkabasepath, "-c", os.path.join(filedir, filename)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ninkaenv)
	(ninkastanout, ninkastanerr) = p1.communicate()
	## TODO: check return codes etc.

	## Then run FOSSology's copyright scanner
	p2 = subprocess.Popen(["/usr/share/fossology/copyright/agent/copyright", "-C", os.path.join(filedir, filename)], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
	(fossstanout, fossstanerr) = p2.communicate()
	if "FATAL" in fossstanout or "FATAL" in fossstanerr:
		## TODO: better error handling
		return None
	else:
		clines = fossstanout.split("\n")
		continuation = True
		bufstr = ""
		buftype = ""
		offset = 0
		copyrightsres = []
		if len(clines[-1]) == 0:
			clines = clines[:-1]
		for c in clines[1:]:
			## FOSSology extracts copyright information, like URLs, e-mail
			## addresses and copyright statements.
			## The only interesting things for this use case are the
			## copyright statements.
			if '[' in c and ']' in c:
				res = recopyright.match(c)
				if res != None:
					if continuation:
						if bufstr != "" and buftype != "":
							if bufstr.endswith("'"):
								bufstr = bufstr[:-1]
							copyrightsres.append((buftype, bufstr, offset))
					continuation = False
					bufstr = ""
					buftype = ""
					offset = res.groups()[0]
					## e-mail addresses are never on multiple lines
					if res.groups()[1] == 'email':
						continue
					## urls should are never on multiple lines
					elif res.groups()[1] == 'url':
						continue
					## copyright statements can be on multiple lines, but this is
					## the start of a new statement
					elif res.groups()[1] == 'statement':
						continuation = True
						buftype = "statement"
						bufstr = res.groups()[2]
				else:   
					res = recopyright2.match(c)
					if res != None:
						if res.groups()[1] == 'statement':
							continuation = True
							buftype = "statement"
							bufstr = res.groups()[2]
							offset = res.groups()[0]
					else:   
						bufstr = bufstr + "\n" + c
						continuation = True
			else:   
				bufstr = bufstr + "\n" + c
				continuation = True
		## perhaps some lingering data
		if continuation:
			if bufstr != "" and buftype != "":
				if bufstr.endswith("'"):
					bufstr = bufstr[:-1]
				copyrightsres.append((buftype, bufstr, offset))

	if len(copyrightsres) != 0:
		match = True
		unmatchedcopyrightsres = []
		## first check if the .comments file is not identical to the entire file
		commentsfile = os.path.join(filedir, "%s.comments" % filename
		if not os.path.exists(commentsfile):
			if '$' in commentsfile:
				commentsfile = commentsfile.replace('$', '\$')
		if os.stat(commentsfile).st_size == os.stat("%s/%s" % (filedir, filename)).st_size:
			match = False
		if match:
        		ninkacommentsfile = open(commentsfile, 'r')
			ninkadata = ninkacommentsfile.read()
			ninkacommentsfile.close()
			ninkadata = ninkadata.lower()
			for c in copyrightsres:
				(copyrighttype, copyrightstatement, offset) = c
				if copyrighttype != 'statement':
					continue
				if not match:
					unmatchedcopyrightsres.append(copyrightstatement)
				## first replace 'funny' characters because FOSSology cannot handle them
				## http://www.fossology.org/issues/7665
				if '\xc2\xa9' in ninkadata:
					ninkadata = ninkadata.replace('\xc2\xa9', '  ')
				if not copyrightstatement in ninkadata:
					## first check whether or not the last part of
					## the copyright statement is perhaps a C style include.
					## http://www.fossology.org/issues/7659
					## If so, first remove it, then redo the scan.
					if "include" in copyrightstatement:
						laststatement = copyrightstatement.rsplit('\n', 1)[-1]
						if re.match("#\s*include\s+<[\w/\.]+>$", laststatement) != None:
							copyrightstatement = copyrightstatement[0]
							if not copyrightstatement in ninkadata:
								match = False
								unmatchedcopyrightsres.append(copyrightstatement)
					else:
						match = False
						unmatchedcopyrightsres.append(copyrightstatement)
		if match:
			return (filedir, filename, True, [])
		else:
			return (filedir, filename, False, unmatchedcopyrightsres)
	else:
		return (filedir, filename, False, [])

def processDir(topleveldir):
	osgen = os.walk(topleveldir)
	scantasks = []
	skipfiles = ['Makefile', 'Makefile.am', 'Makefile.in', 'README', 'COPYING', 'INSTALL', 'Kbuild']
	localscanfiles = set()
	localheaderfiles = {}
	headerextensions = ['h', 'hxx', 'hpp']
	try:
		while True:
			i = osgen.next()
			## make sure all directories can be accessed
			for d in i[1]:
				if not os.path.islink("%s/%s" % (i[0], d)):
					os.chmod("%s/%s" % (i[0], d), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
			for p in i[2]:
				try:
					if p in skipfiles:
						continue
					if p in localscanfiles:
						continue
					## make sure all files can be accessed as well. Skip links.
					## check to see whether or not a file is an ELF relocatable. If so,
					## search for a matching C file. Open the C file to check for any
					## include statements
					if not os.path.islink("%s/%s" % (i[0], p)):
						os.chmod("%s/%s" % (i[0], p), stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
						msmagic = ms.file(os.path.join(i[0], p))
						if "ELF" in msmagic:
							if "relocatable" in msmagic:
								filebase = os.path.join(i[0], p[:-2])
								## try to find a .c file
								if os.path.exists(os.path.join(i[0], "%s.c" % p[:-2])):
									scantasks.append((i[0], "%s.c" % p[:-2]))
									localscanfiles.add((i[0], "%s.c" % p[:-2]))
								## try to find an assembler file
								elif os.path.exists(os.path.join(i[0], "%s.S" % p[:-2])):
									scantasks.append((i[0], "%s.S" % p[:-2]))
									localscanfiles.add((i[0], "%s.S" % p[:-2]))
								else:
									print "NO C FILE", os.path.join(i[0], p)
						extension = p.rsplit('.', 1)[-1]
						if extension.lower() in headerextensions:
							if localheaderfiles.has_key(p):
								localheaderfiles[p].append((i[0], p))
							else:
								localheaderfiles[p] = [(i[0], p)]
				except Exception, e:
					print e
					pass
	except StopIteration:
		pass

	seen = []
	while True:
		try:
			(filedir, filename) = localscanfiles.pop()
			if (filedir, filename) in seen:
				continue
			sourcefile = open(os.path.join(filedir, filename), 'r')
			sourcelines = sourcefile.readlines()
			sourcefile.close()
			for i in sourcelines:
				if not 'include' in i.strip():
					continue
				else:
					regexres = includeregex.match(i.strip())
					if regexres != None:
						header = regexres.groups()[0]
						if os.path.exists(os.path.join(filedir, header)):
							scantasks.append((filedir, header))
							localscanfiles.add((filedir, header))
						else:
							if localheaderfiles.has_key(header):
								scantasks += localheaderfiles[header]
								localscanfiles.update(localheaderfiles[header])
			seen.append((filedir, filename))
		except Exception, e:
			#print e
			break

	pool = multiprocessing.Pool()
	res = pool.map(extractCopyrights, set(scantasks))
	pool.close()
	matches = filter(lambda x: x[2] == True, res)
	nonmatches = filter(lambda x: x[2] == False, res)

	for m in matches:
		(filedir, filename, status, fossology) = m
		print "match: %s" % os.path.join(filedir, filename)
	print
	for m in nonmatches:
		(filedir, filename, status, fossology) = m
		if fossology == []:
			print "no match, no FOSSology results: %s\n" % os.path.join(filedir, filename)
			continue
		print "no match: %s\n" % os.path.join(filedir, filename)
		for c in fossology:
			print c
		print

def main(argv):
	parser = OptionParser()
	parser.add_option("-d", "--directory", action="store", dest="topleveldir", help="path to directory to be scanned", metavar="DIR")
	(options, args) = parser.parse_args()
	if options.topleveldir == None:
		parser.error("Path to directory to be scanned needed")

	p2 = subprocess.Popen(["/usr/share/fossology/copyright/agent/copyright", "-h"], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
	(stanout, stanerr) = p2.communicate()
	if "FATAL" in stanout or "FATAL" in stanerr:
		print >>sys.stderr, "ERROR: copyright extraction enabled, but FOSSology not running"
		sys.exit(1)
	processDir(options.topleveldir)

if __name__ == "__main__":
	main(sys.argv)
