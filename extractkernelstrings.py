#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, string, re
from optparse import OptionParser
import sqlite3
from bat import extractor

## some strings we are interested in can't be extracted using xgettext.
## We use a few regular expressions for them to extract them. Since there
## macros being introduced (and removed) from the kernel sources regularly
## we should try and keep this list up to date.
exprs = []
exprs.append(re.compile("WIRELESS_SHOW\s*\((\w+),", re.MULTILINE))
exprs.append(re.compile("NETSTAT_ENTRY\s*\((\w+)", re.MULTILINE))
## lots of things with _ATTR, like DEVICE_ATTR and SYSDEV_ATTR)
exprs.append(re.compile("\w+_ATTR\w*\s*\((\w+)", re.MULTILINE))

## TODO: check if these can be replaced by a call to xgettext
exprs.append(re.compile("devfs_remove\s*\(\"([\w\s\-=/%]+)\"", re.MULTILINE))
exprs.append(re.compile("\.comm\s*=\s*\"([\w\-=]*)\"", re.MULTILINE))
# unsure)
#searchresults = searchresults + re.findall("\.comment\s*=\s*\"([\w\-=]*)\"", source, re.MULTILINE))
exprs.append(re.compile("\w*name\s*[:=]\s*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("E\((?:\w+,\s*)\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("add_hotplug_env_var\((?:[\w&]+,\s*){6}\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))

bugtrapexpr = re.compile("BUG_TRAP\s*\(([\w\s\.:<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\);", re.MULTILINE)

funexprs = []
funexprs.append(re.compile("(?:static|extern) (?:\w+\s)+(?:\*\s)*(\w+)\(", re.MULTILINE))

symbolexprs = []
symbolexprs.append(re.compile("EXPORT_SYMBOL\s*\(([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\\\]+)", re.MULTILINE))
symbolexprs.append(re.compile("EXPORT_SYMBOL_GPL\s*\(([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\\\]+)", re.MULTILINE))

staticexprs = []
staticexprs.append(re.compile("static\s+(?:\w+s+)?struct\s+(?:[\w*\[\]{};\s]+)\s*=\s*\{(.*)\};", re.MULTILINE|re.DOTALL))
staticexprs.append(re.compile("static\s+(?:\w+\s+)?char\s+\s*\*\s*\w+\[\w*\]\s*=\s*\{(.*)\};", re.MULTILINE|re.DOTALL))

def extractkernelstrings(kerneldir, sqldb):
	kerneldirlen = len(kerneldir)+1
	osgen = os.walk(kerneldir)

	try:
		while True:
                	i = osgen.next()
			## everything inside the Documentation directory can be skipped for now
			if "/Documentation" in i[0]:
				continue
                	for p in i[2]:
				p_nocase = p.lower()
				## some files are not interesting at all
				if p == '.gitignore':
					continue
				if p == 'MAINTAINERS':
					continue
				if p == 'Makefile':
					continue
				if p == 'ChangeLog':
					continue
				elif p == 'TODO':
					continue
				elif p.endswith('defconfig'):
					continue
				elif 'README' in p:
					continue
				elif 'Kconfig' in p:
					continue
				elif 'Kbuild' in p:
					continue
				elif 'COPYING' in p:
					continue
				## right now we are just interested in C/C++/assembler files
                                if (p_nocase.endswith('.c') or p_nocase.endswith('.h') or p_nocase.endswith('.cpp') or p_nocase.endswith('.cc') or p_nocase.endswith('.hh') or p_nocase.endswith('.cxx') or p_nocase.endswith('.c++') or p_nocase.endswith('.hpp') or p_nocase.endswith('.hxx') or p_nocase.endswith('.S')):
					source = open("%s/%s" % (i[0], p)).read()
					searchresults = []

					searchresults = searchresults + extractor.extractStrings(p, i[0])
					#print searchresults

					## values that we can't extract using xgettext are extracted using regular
					## expressions. We set the line number for the result to 0, since
					## we don't know it (TODO)
					for ex in exprs:
						searchresults = searchresults + map(lambda x: (x,0), ex.findall(source))
	
					bugtraps = bugtrapexpr.findall(source)
					for bugtrap in bugtraps:
						if "#define" in bugtrap:
							continue
						searchresults.append((re.sub("\n\s*", " ", bugtrap),0))
					'''
					debugs = re.findall("DBG\s*\([\w\s]*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", source, re.MULTILINE)
					for debug in debugs:
						if "#define" in debug:
							continue
                                		searchresults.append(debug)
					debugs = re.findall("DPRINTK\s*\([\w\s]*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", source, re.MULTILINE)
					for debug in debugs:
						if "#define" in debug:
							continue
                                		searchresults.append((debug, 0))
					'''
	
					## extract the module parameters and append it to the name of the file
					## without the extension. Separate with a dot.
					paramstrings = re.findall("module_param\(([\w\d]+)", source, re.MULTILINE)
					for paramstring in paramstrings:
						## we skip the lines that start with #define, since they are
						## no parameter names
						if "#define" in paramstring:
							continue
                                		searchresults.append(("%s.%s" % (p.split(".")[0], paramstring), 0))
	
					chars = re.findall("static\s+char\s+\*\s*\w+\[\w*\]\s*=\s*\{([\w+\",\s]*)};", source, re.MULTILINE)
					chars = chars + re.findall("static\s+const char\s+\s*\w+\[\w*\]\[\w*\]\s*=\s*\{([\w+%\",\s]*)};", source, re.MULTILINE)
					if chars != []:
						for c in chars:
							## TODO: add line number
							searchresults = searchresults + map(lambda x: (x,0), re.split(",\s*", c.strip().replace("\"", "")))
	
					for staticexpr in staticexprs:
						results = staticexpr.findall(source)
        					for res in results:
							## TODO: add line number
							searchresults = searchresults + map(lambda x: (x,0), re.findall("\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", res, re.MULTILINE))
	
					for result in searchresults:
						(res, lineno) = result
						## some strings are simply not interesting
						if res.strip() == "\\n":
							continue
						if res.strip() == "\\n\\n":
							continue
						elif res.strip() == "\\t":
							continue
						elif res.strip() == "%s%s":
							continue
						elif res.strip() == "%s:":
							continue
						elif res.strip() == "%s":
							continue
						elif res.strip() == "%d":
							continue
						elif res.strip() == ":":
							continue
						elif res.strip() == "":
							continue
						if res.strip().endswith("\\n"):
							storestring = res.strip()[:-2]
						else:
							storestring = res.strip()
						if storestring.startswith("\\n"):
							storestring = storestring[2:].strip()
						# replace tabs
						storestring = storestring.replace("\\t", "\t").strip()
						#storestring = storestring.replace("\\n", "\n")
						sqldb.execute('''insert into extracted (printstring, filename, linenumber) values (?, ?, ?)''', (storestring, u"%s/%s" % (i[0][kerneldirlen:], p), lineno))
	
					## store the names of the symbols separately. Should we actually do this?
					results = []
					for symex in symbolexprs:
						results = results + symex.findall(source)
	
					for res in results:
						storestring = res.strip()
						sqldb.execute('''insert into symbol (symbolstring, filename) values (?, ?)''', (storestring, u"%s/%s" % (i[0][kerneldirlen:], p)))
	
					results = []
					for funex in funexprs:
						results = results + funex.findall(source)
	
					for res in results:
						if "#define" in res:
							continue
						storestring = res.strip()
						sqldb.execute('''insert into function (functionstring, filename) values (?, ?)''', (storestring, u"%s/%s" % (i[0][kerneldirlen:], p)))

	except StopIteration:
		pass

def main(argv):
        parser = OptionParser()
        parser.add_option("-k", "--kernel", dest="kd", help="path to Linux kernel directory", metavar="DIR")
        parser.add_option("-d", "--database", dest="db", help="path to SQLite database", metavar="FILE")
        (options, args) = parser.parse_args()
        if options.kd == None:
                parser.error("Path to Linux kernel directory needed")
        if options.db == None:
                parser.error("Path to SQLite database needed")
        #try:
        	## open the Linux kernel directory and do some sanity checks
                #kernel_path = open(options.kd, 'rb')
        #except:
                #print "No valid Linux kernel directory"
                #sys.exit(1)
	# strip trailing slash, will not work this way if there are tons of slashes
	if options.kd.endswith('/'):
		kerneldir = options.kd[:-1]
	else:
		kerneldir = options.kd

        conn = sqlite3.connect(options.db)
        c = conn.cursor()

        try:
		c.execute('''create table extracted (printstring text, filename text, linenumber int)''')
		c.execute('''create index printstring_index on extracted(printstring)''')
		c.execute('''create table symbol (symbolstring text, filename text)''')
		c.execute('''create index symbolstring_index on symbol(symbolstring)''')
		c.execute('''create table function (functionstring text, filename text)''')
		c.execute('''create index functionstring_index on function(functionstring)''')
        except:
                pass

	extractkernelstrings(kerneldir, c)
        conn.commit()
        c.close()


if __name__ == "__main__":
        main(sys.argv)
