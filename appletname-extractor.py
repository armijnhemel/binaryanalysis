#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

##
## Helper script to extract configurations from busybox source code.
## Results are dumped as a pickle file, which can later be used by the
## BusyBox processing scripts to map applet names back to configuration
## directives. This is useful when comparing with a supplied configuration
## file to see if these match.
##

import sys, os, re, pickle
from optparse import OptionParser

def extract_major_version(version):
        return version.rsplit('.', version.count('.')-1)[0]

## configs format:
## {symbolic link name: (appletname, config option)}
## Example:
## {'sha1sum': ('md5_sha1_sum', 'SHA1SUM')}
##
def extract_configuration(lines, version):
	configs = {}
	if version >= "1.1.1":
		if extract_major_version(version) >= "1.15":
			prefix = "IF_"
		else:
			prefix = "USE_"
		for line in lines:
			configname = re.match("%s([\w_]*)\(APPLET_\w+\(([\w\.\-_\[]+),\s*([\w\.\-_]*)" % (prefix,), line.strip())
			if configname != None:
				configs[configname.groups()[1]] = (configname.groups()[2], configname.groups()[0])
			else:
				configname = re.match("%s([\w_]*)\(APPLET\(([\w\.\-_\[]+)" % (prefix,), line.strip())
				if configname != None:
					configs[configname.groups()[1]] = (configname.groups()[1], configname.groups()[0])
	else:
		if version < "1.00":
			prefix = "BB"
		else:
			prefix = "CONFIG"
		for line in range(0,len(lines) -1):
			config = re.match("#ifdef %s\_([\_\w]+)" % (prefix,), lines[line].strip())
			if config == None:
				config = re.match("#if ENABLE\_([\_\w]+)", lines[line].strip())
				if config == None:
					config = re.match("#if BB\_APPLET\_([\_\w]+)", lines[line].strip())
					if config == None:
						config = re.match("#if defined\(%s\_(FEATURE\_[\_\w]+)\)" % (prefix,), lines[line].strip())
						if config == None:
							continue
			configname = re.match("APPLET\(([\w\.\-\_\[]+), ([\w\_]+),", lines[line+1].strip())
			if configname == None:
				configname = re.match("APPLET_(?:NOUSAGE|ODDNAME)\(\"([\w\.\-\_\[]+)\", ([\w\_]+),", lines[line+1].strip())
				if configname != None:
					## remove _main from the name of the applet, assuming it is
					## the same as the name of the applet
					configs[configname.groups()[0]] = (configname.groups()[1][:-5], config.groups()[0])
			else:
				## remove _main from the name of the applet, assuming it is
				## the same as the name of the applet
				configs[configname.groups()[0]] = (configname.groups()[1][:-5], config.groups()[0])
	return configs

def main(argv):
	parser = OptionParser()
        parser.add_option("-a", "--applets", action="store", dest="applets", help="path to applets.h or applets.src.h", metavar="FILE")
        parser.add_option("-n", "--busyboxversion", action="store", dest="busyboxversion", help="BusyBox version", metavar="VERSION")
        (options, args) = parser.parse_args()
        if options.applets == None:
                parser.error("Path to applets.h in BusyBox directory needed")
        if options.busyboxversion == None:
                parser.error("BusyBox version needed")

        busybox_applets = open(options.applets, 'rb')
        busybox_lines = busybox_applets.readlines()
	version = options.busyboxversion
        bb_configuration = extract_configuration(busybox_lines, version)
	if bb_configuration != []:
		output = open('%s-config' % (version, ), 'w')
		pickle.dump(bb_configuration, output)
		output.close()

if __name__ == "__main__":
        main(sys.argv)
