#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, string, re
from optparse import OptionParser
import lucene

exprs = []
exprs.append(re.compile("sprintf\s*\((?:[\w\s+<>\-\[\]]*),\s*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("printf\s*\((?:[\w\s]*)\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("dev_warn\s*\((?:[\w\s&->\(\)]*),\s*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("panic\s*\(\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("die_if_kernel\s*\(\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("error\s*\(\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("slab_error\s*\((?:\w+,\s)\"([\w\-',\s=]*)\"", re.MULTILINE))
exprs.append(re.compile("PANIC_PIC\s*\(\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("SNMP_MIB_ITEM\s*\(\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("LIMIT_NETDEBUG\s*\([\w\s]*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("SOCK_DEBUG\s*\([\w]+,\s*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("IPW_DEBUG_HC\s*\(\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("WIRELESS_SHOW\s*\((\w+),", re.MULTILINE))
exprs.append(re.compile("NETSTAT_ENTRY\s*\((\w+)", re.MULTILINE))
## lots of things with _ATTR, like DEVICE_ATTR and SYSDEV_ATTR)
exprs.append(re.compile("\w+_ATTR\w*\s*\((\w+)", re.MULTILINE))
exprs.append(re.compile("INPUT_ADD_HOTPLUG_(?:\w+)VAR\s*\(\"([\w\s\.:\-=/%]+)\"", re.MULTILINE))
exprs.append(re.compile("sock_warn_obsolete_bsdism\(\"(\w+)\"", re.MULTILINE))
exprs.append(re.compile("pr_debug\s*\([\w\s]*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("moan_device\s*\(\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("dbg\s*\(\"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("__setup\s*\(\"([\w\-=]*)\"", re.MULTILINE))
exprs.append(re.compile("err\w{2} = \"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("kmem_cache_create\s*\(\"([\w\-=]*)\"", re.MULTILINE))
exprs.append(re.compile("parse_args\s*\(\"([\w\s\-=]*)\"", re.MULTILINE))
exprs.append(re.compile("proc_net_\w+\s*\(\s*\"([\w\s\-=/]*)\"", re.MULTILINE))
exprs.append(re.compile("sys_mkdir\s*\(\s*\"([\w\s\-=/]+)\"", re.MULTILINE))
exprs.append(re.compile("ipc_init_proc_interface\s*\(\s*\"([\w\s\-=/]*)\"", re.MULTILINE))
exprs.append(re.compile("create_proc_(?:\w+_)?entry\s*\(\s*\"([\w\s\-=/]*)\"", re.MULTILINE))
exprs.append(re.compile("CREATE_READ_PROC\s*\(\s*\"([\w\s\-=/]*)\"", re.MULTILINE))
exprs.append(re.compile("proc_mkdir(?:_mode)?\s*\(\s*\"([\w\s\-=/]*)\"", re.MULTILINE))
exprs.append(re.compile("strstr\s*\((?:\w+,\s)\"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("\w+_dbg\s*\((?:[\w\.&\->]+,\s)\"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("sysfs_\w+link\s*\((?:[\w\.&\->]+,\s)\"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("str\w*cmp\s*\((?:\w+,\s*)?\"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("sscanf\s*\((?:[\w\[\]\s\->&+]+,\s)\"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("memc\w{2}\s*\((?:[\w\[\]\s\->&+]+,\s)?\"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("strl?cpy\s*\((?:[\w\[\]\s\.\(\)\->&+]+,\s*)\"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("strlen\s*\(\"([\w\s\.:<>\-+=~`!@#$^%&*\[\]{}+?|/,'\(\)\\\]*)\"", re.MULTILINE))
exprs.append(re.compile("alloc_large_system_hash\s*\(\"([\w\s\-=]*)\"", re.MULTILINE))
exprs.append(re.compile("devfs_remove\s*\(\"([\w\s\-=/%]+)\"", re.MULTILINE))
exprs.append(re.compile("shmem_file_setup\s*\(\"([\w\s\-=/%]+)\"", re.MULTILINE))
exprs.append(re.compile("daemonize\s*\(\"([\w\s\.\-=/%]+)\"", re.MULTILINE))
exprs.append(re.compile("render_sigset_t\s*\(\"([\w\s\.:\-=/%]+)\"", re.MULTILINE))
exprs.append(re.compile("create_seq_entry\s*\(\"([\w\s\.\-=/%]+)\"", re.MULTILINE))
exprs.append(re.compile("create_\w*workqueue\s*\(\"([\w\s\-=/%]+)\"", re.MULTILINE))
exprs.append(re.compile("OHCI_DMA_\w+\(\"([\w\s\-=/%,\[\]]+)\"", re.MULTILINE))
exprs.append(re.compile("run_init_process\(\"([\w/]+)\"", re.MULTILINE))
exprs.append(re.compile("NEIGH_PRINTK1\(\"([\w\s:=%]+)", re.MULTILINE))
exprs.append(re.compile("seq_puts\s*\([\w]+,\s*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("\.description\s*=\s*\"([\w\s\.\-/=]+)\"", re.MULTILINE))
exprs.append(re.compile("\.id\w*\s*=\s*\"([\w\s\.',&\-/=]+)\"", re.MULTILINE))
exprs.append(re.compile("\.comm\s*=\s*\"([\w\-=]*)\"", re.MULTILINE))
# unsure)
#searchresults = searchresults + re.findall("\.comment\s*=\s*\"([\w\-=]*)\"", source, re.MULTILINE))
exprs.append(re.compile("set_kset_name\s*\(\"([\w\s\.\-=/%]+)\"", re.MULTILINE))
exprs.append(re.compile("\w*name\s*[:=]\s*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("panic_later\s*=\s*\"([\w\s\-`~!@#$%^&*\(\)=']*)\"", re.MULTILINE))
exprs.append(re.compile("msg\s*=[\w\(\)\s*]*\"([\w\s\-`~!@#$%^&*\(\)/=']*)\"", re.MULTILINE))
exprs.append(re.compile("find_sec\((?:\w+,\s){3}\"([\w\.]+)\"", re.MULTILINE))
exprs.append(re.compile("static(?:[\w\s]+)char(?:[\s\w\[\]*]*) = \"([\w\.\s<>@%\-+\\/\[\]\(\),]+)\";", re.MULTILINE))
exprs.append(re.compile("class_device_create\((?:[\w\s+&*\.\-<>\(\)]+,\s+){5,6}\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("sc?nprintf\((?:[\w\s+\.\-<>\(\)]+,\s+){2}\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("get_modinfo\((?:[\w\s+\.\-<>\(\)]+,\s){2}\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("[SD]PNORMRET[12]\((?:[\w\s+\.?\-<>\(\)]+,\s){3}\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("print_insn\s*\((?:[\w\s+*\.\-<>\(\)]+,\s){2}\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("blk_dump_rq_flags\((?:[\w\s+\.\-<>\(\)]+),\s*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("tty_paranoia_check\((?:[\w\s+\.\-<>\(\)]+,\s*){2}\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("ADDBUF\((?:[\w]+,\s*)\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("request_\w*region\((?:[\w]+,\s*)+\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("quirk_io_region\((?:[\w\(\)+\s]+,\s*)*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("piix4_\w+_quirk\((?:\w+,\s)\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("E\((?:\w+,\s*)\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("get_sb_pseudo\((?:\w+,\s)\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("ieee754\w+xcpt\((?:[\w\(\)]+,\s)\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("kthread_create\((?:[\w&]+,\s){2}\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("add_hotplug_env_var\((?:[\w&]+,\s*){6}\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("return \"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))
exprs.append(re.compile("\#define\s*\w+\s*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,\\'\(\)]+)\"", re.MULTILINE))
exprs.append(re.compile("seq_printf\s*\((?:[\w\s,]+),\s*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", re.MULTILINE))

bugtrapexpr = re.compile("BUG_TRAP\s*\(([\w\s\.:<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\);", re.MULTILINE)

funexprs = []
funexprs.append(re.compile("(?:static|extern) (?:\w+\s)+(?:\*\s)*(\w+)\(", re.MULTILINE))

symbolexprs = []
symbolexprs.append(re.compile("EXPORT_SYMBOL\s*\(([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\\\]+)", re.MULTILINE))
symbolexprs.append(re.compile("EXPORT_SYMBOL_GPL\s*\(([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\\\]+)", re.MULTILINE))

staticexprs = []
staticexprs.append(re.compile("static\s+(?:\w+s+)?struct\s+(?:[\w*\[\]{};\s]+)\s*=\s*\{(.*)\};", re.MULTILINE|re.DOTALL))
staticexprs.append(re.compile("static\s+(?:\w+\s+)?char\s+\s*\*\s*\w+\[\w*\]\s*=\s*\{(.*)\};", re.MULTILINE|re.DOTALL))

def extractkernelstrings(kerneldir, lucenewriter):
	kerneldirlen = len(kerneldir)+1
	osgen = os.walk(kerneldir)

	try:
		while True:
                	i = osgen.next()
			if "/Documentation" in i[0]:
				continue
                	for p in i[2]:
				## some files are not interesting at all
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
				source = open("%s/%s" % (i[0], p)).read()
				searchresults = []
				for ex in exprs:
					searchresults = searchresults + ex.findall(source)
				## printk
				results = re.findall("printk\s*\((?:[\w\s])*\"([\w\s\.:;<>\-+=`~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"\s*(\"[\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+\")*", source, re.MULTILINE)
                                for res in results:
                                        if res[1] != "":
						if res[0].strip().endswith("\\n"):
							tmpstr = res[0][:-3] + "\n"
                                                	searchresults.append(tmpstr + res[1][1:-1])
						else:
                                                	searchresults.append(res[0] + res[1][1:-1])
					else:
                                                searchresults.append(res[0])
				## catch various flavours of printf

				results = re.findall("printf\s*\((.*)\);", source, re.MULTILINE|re.DOTALL)
				results = results + re.findall("pr_info\s*\((.*)\);", source, re.MULTILINE|re.DOTALL)
				for res in results:
        				searchresults = searchresults + re.findall("\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", res, re.MULTILINE)

				bugtraps = bugtrapexpr.findall(source)
				for bugtrap in bugtraps:
					if "#define" in bugtrap:
						continue
					searchresults.append(re.sub("\n\s*", " ", bugtrap))
				debugs = re.findall("DBG\s*\([\w\s]*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", source, re.MULTILINE)
				for debug in debugs:
					if "#define" in debug:
						continue
                                	searchresults.append(debug)
				debugs = re.findall("DPRINTK\s*\([\w\s]*\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", source, re.MULTILINE)
				for debug in debugs:
					if "#define" in debug:
						continue
                                	searchresults.append(debug)

				## extract the module parameters and prepend the name of the file, with a dot.
				paramstrings = re.findall("module_param\(([\w\d]+)", source, re.MULTILINE)
				for paramstring in paramstrings:
					if "#define" in paramstring:
						continue
                                	searchresults.append("%s.%s" % (p.split(".")[0], paramstring))

				chars = re.findall("static\s+char\s+\*\s*\w+\[\w*\]\s*=\s*\{([\w+\",\s]*)};", source, re.MULTILINE)
				chars = chars + re.findall("static\s+const char\s+\s*\w+\[\w*\]\[\w*\]\s*=\s*\{([\w+%\",\s]*)};", source, re.MULTILINE)
				if chars != []:
					for c in chars:
						searchresults = searchresults + re.split(",\s*", c.strip().replace("\"", ""))

				for staticexpr in staticexprs:
					results = staticexpr.findall(source)
        				for res in results:
						searchresults = searchresults + re.findall("\"([\w\s\.:;<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\"", res, re.MULTILINE)

				for res in searchresults:
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
					doc = lucene.Document()
					doc.add(lucene.Field("name", "%s/%s" % (i[0][kerneldirlen:], p),
						lucene.Field.Store.YES,
						lucene.Field.Index.NOT_ANALYZED))
					lucenewriter.addDocument(doc)
					doc.add(lucene.Field("printstring", storestring,
						lucene.Field.Store.YES,
						lucene.Field.Index.NOT_ANALYZED))
					lucenewriter.addDocument(doc)

				results = []
				for symex in symbolexprs:
					results = results + symex.findall(source)

				for res in results:
					storestring = res.strip()
					doc = lucene.Document()
					doc.add(lucene.Field("name", "%s/%s" % (i[0][kerneldirlen:], p),
						lucene.Field.Store.YES,
						lucene.Field.Index.NOT_ANALYZED))
					lucenewriter.addDocument(doc)
					doc.add(lucene.Field("symbolstring", storestring,
						lucene.Field.Store.YES,
						lucene.Field.Index.NOT_ANALYZED))
					lucenewriter.addDocument(doc)

				results = []
				for funex in funexprs:
					results = results + funex.findall(source)

				for res in results:
					if "#define" in res:
						continue
					storestring = res.strip()
					doc = lucene.Document()
					doc.add(lucene.Field("name", "%s/%s" % (i[0][kerneldirlen:], p),
						lucene.Field.Store.YES,
						lucene.Field.Index.NOT_ANALYZED))
					lucenewriter.addDocument(doc)
					doc.add(lucene.Field("functionname", storestring,
						lucene.Field.Store.YES,
						lucene.Field.Index.NOT_ANALYZED))
					lucenewriter.addDocument(doc)
	except StopIteration:
		pass

def main(argv):
        parser = OptionParser()
        parser.add_option("-d", "--directory", dest="kd", help="path to Linux kernel directory", metavar="DIR")
        parser.add_option("-i", "--index", dest="id", help="path to Lucene index directory", metavar="DIR")
        (options, args) = parser.parse_args()
        if options.kd == None:
                parser.error("Path to Linux kernel directory needed")
        if options.id == None:
                parser.error("Path to Lucene index directory needed")
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
	lucene.initVM()

	storeDir = options.id
        store = lucene.SimpleFSDirectory(lucene.File(storeDir))
	analyzer = lucene.StandardAnalyzer(lucene.Version.LUCENE_CURRENT)
        writer = lucene.IndexWriter(store, analyzer, True,
                                    lucene.IndexWriter.MaxFieldLength.LIMITED)
        writer.setMaxFieldLength(1048576)

	extractkernelstrings(kerneldir, writer)

        writer.optimize()
        writer.close()


if __name__ == "__main__":
        main(sys.argv)
