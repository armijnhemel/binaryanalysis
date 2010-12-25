#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This tool tries to determine if a vendor configuration likely matches with
what was extracted from a binary.
This tool will not produce a 100% match, since there are some things we don't scan
correctly, like the shell that is used, or several features and in some cases some
applets.

Right now this is proof of concept code which will for the most part be merged into
busybox.py in the near future.
'''

import sys, os, string, re
from optparse import OptionParser
import bat.busybox as busybox
import pickle
import xml.dom.minidom

'''
This method compares two lists of configurations, optionally with a database
of known configs from the official BusyBox sources if the version number is
known, to weed out configuration directives that do not map to actual applets.

This method returns a tuple with two lists:
* a list of applets defined in the binary, but not in the original config
* a list of applets defined in the original config, but not in the binary
'''
def compare_configs(extracted, original, configs=None):
	defined_in_extracted = []
	defined_in_original = []
	extracted.sort()
	original.sort()
	if configs != None:
		confvalues = map(lambda x: x[1], configs.values())
	else:
		confvalues = []
	for conf in extracted:
		if conf not in original:
			if "FEATURE" in conf:
				continue
			defined_in_extracted.append(conf)
	for conf in original:
		if conf not in extracted:
			## since it is (right now) hard to recognize all features ignore these
			if "FEATURE" in conf:
				continue
			## since it is (right now) hard to recognize all features ignore these
			if "CONFIG_ASH_" in conf:
				continue
			## run some extra checks if we know the version number
			if configs != None:
				if conf[7:] not in confvalues:
					continue
				else:
					defined_in_original.append(conf)
			else:
				defined_in_original.append(conf)
	return (defined_in_extracted, defined_in_original)

'''
To easily compare the configurations it is desirable to weed out several things:
* ignore whitespace
* ignore everything that has not explicitely been set to =y
* ignore everything in the config before the line # Applets

The latter is not necessary for the configurations we extract from a BusyBox binary
'''
def filterconfig(lines, generated=False):
	configs = []
	if generated:
		seenApplets = True
	else:
		seenApplets = False
	for line in lines:
		if "Applets" in line.strip():
			seenApplets = True
			continue
		if line.startswith("#"):
			continue
		if line.strip() == "":
			continue
		if "\"" in line.strip():
			continue
		if not seenApplets:
			continue
		(config, option) = line.strip().split('=')
		if option != 'y':
			continue
		configs.append(config)
	return configs

# pretty print in XML so other scripts can easily handle it
def prettyprintconfigxml(configs):
	xmlconfig = xml.dom.minidom.Document()
	topnode = xmlconfig.createElement("configurations")
	binarynode = xmlconfig.createElement("binary")
	for conf in configs[0]:
		tmpnode = xmlconfig.createElement("config")
		tmpnodetext = xml.dom.minidom.Text()
               	tmpnodetext.data = conf
               	tmpnode.appendChild(tmpnodetext)
		binarynode.appendChild(tmpnode)
	confignode = xmlconfig.createElement("configurationfile")
	for conf in configs[1]:
		tmpnode = xmlconfig.createElement("config")
		tmpnodetext = xml.dom.minidom.Text()
               	tmpnodetext.data = conf
               	tmpnode.appendChild(tmpnodetext)
		confignode.appendChild(tmpnode)
	topnode.appendChild(binarynode)
	topnode.appendChild(confignode)
	xmlconfig.appendChild(topnode)
	print xmlconfig.toxml()

def prettyprintconfig(configs):
	if configs[0] == []:
		pass
	else:
		print "Configuration for applets present in the binary, but not configured:\n"
		for conf in configs[0]:
			print "*", conf
	if configs[0] != [] and configs[1] != []:
		print
	if configs[1] == []:
		pass
	else:
		print "Configuration for applets defined in the config, but missing in the binary:\n"
		for conf in configs[1]:
			print "*", conf

def main(argv):
        parser = OptionParser()
        parser.add_option("-e", "--extracted", dest="ec", help="configuration extracted from BusyBox", metavar="FILE")
        parser.add_option("-f", "--configuration", dest="oc", help="original configuration supplied by vendor", metavar="FILE")
	parser.add_option("-n", "--busyboxversion", action="store", dest="busyboxversion", help="path to configuration file", metavar="VERSION")
	parser.add_option("-x", "--xml", action="store_true", dest="xmloutput", help="output XML (default false)", metavar="VERSION")
        (options, args) = parser.parse_args()
        if options.ec == None:
                parser.error("Path to extracted configuration needed")
        if options.oc == None:
                parser.error("Path to original configuration needed")
        try:
                extracted_config = open(options.ec, 'r').readlines()
        except:
                print "No valid configuration file"
                sys.exit(1)
        try:
                original_config = open(options.oc, 'r').readlines()
        except:
                print "No valid configuration file"
                sys.exit(1)
	if options.busyboxversion != None:
		try:
			bbconfig = pickle.load(open('configs/%s-config' % (options.busyboxversion,)))
		except:
                	print "No valid stored configurations file"
                	sys.exit(1)
		res = compare_configs(filterconfig(extracted_config, generated=True), filterconfig(original_config), bbconfig)
	else:
		res = compare_configs(filterconfig(extracted_config, generated=True), filterconfig(original_config))
	if options.xmloutput != None:
		prettyprintconfigxml(res)
	else:
		prettyprintconfig(res)

if __name__ == "__main__":
        main(sys.argv)
