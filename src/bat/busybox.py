#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, string, re
import pickle
from optparse import OptionParser
import extractor

## Some versions of busybox use different configuration directives
## We need to translate them from the name we got to the name that is actually
## used by BusyBox.
translation_table_1_15 = { 'dhcprelay': 'APP_DHCPRELAY'
                         , 'dumpleases': 'APP_DUMPLEASES'
                         , 'udhcpc': 'APP_UDHCPC'
                         , 'udhcpd': 'APP_UDHCPD'
                         }

translation_table = {'1.2': translation_table_1_15}
translation_table = {'1.3': translation_table_1_15}
translation_table = {'1.4': translation_table_1_15}
translation_table = {'1.5': translation_table_1_15}
translation_table = {'1.6': translation_table_1_15}
translation_table = {'1.7': translation_table_1_15}
translation_table = {'1.8': translation_table_1_15}
translation_table = {'1.9': translation_table_1_15}
translation_table = {'1.10': translation_table_1_15}
translation_table = {'1.11': translation_table_1_15}
translation_table = {'1.12': translation_table_1_15}
translation_table = {'1.13': translation_table_1_15}
translation_table = {'1.14': translation_table_1_15}
translation_table = {'1.15': translation_table_1_15}
translation_table = {'1.16': translation_table_1_15}

## helper method to extract the major version of a BusyBox program:
## 1.15.2 becomes 1.15
def extract_major_version(version):
	return version.rsplit('.', version.count('.')-1)[0]

## This method takes a configuration and a version and pretty prints
## it accordingly.
def prettyprint_configuration(configuration, version):
	if version <= "0.61":
		for config in configuration:
			print "#define BB_%s" % config.upper()
	else:
		pp_config = []
		for config in configuration:
			try:
				newconfig = translation_table[extract_major_version(version)][config]
				print "CONFIG_%s=y" % newconfig.upper()
			except:
				print "CONFIG_%s=y" % config.upper()

## Extracting configuration needs a two way pass.
## The first pass tries to extract configuration the easy way.
## If it succeeds the second pass will pretty print the configuration.
## If it fails the configuration has to be found the hard way.
def extract_configuration(lines, busybox, bbconfig):
	printables = extractor.extract_printables(lines)
	tmpconfig = extract_configuration_pass1(lines, busybox, printables)

	if tmpconfig != []:
		## This needs to be reworked to be more reliable, as in the other case
		## Lots of refactoring coming up, yay!
		## The configuration we have is not empty, so we're lucky.
		## Search through lines, using the configuration we got earlier
		## and try to extract the appletnames. This is not fool proof.

		## first make sure that everything we have is in alphabetical order
		tmpconfig.sort()

		## offset for first appletname we have found earlier, surrounded by spaces
		## this needs to be reworked to avoid false positives
		offset = printables.find(" " + tmpconfig[0] + " ")

		## offset for first occurance of last appletname, following first appletname, surrounded by spaces
		## this needs to be reworked to avoid false positives
		offset2 = printables.find(" " + tmpconfig[-1] + " ", offset)

		## split everything, we should have a reasonable config
		tmp2config = printables[offset+1:offset2 + 1 + len(tmpconfig[-1])].split()
		return tmp2config
	else:
		## we don't have a configuration, so we will just have to guess by inspecting the binary
		results = []
		results2 = []

		## use the configuration for this version of BusyBox as a starting point
		keys = bbconfig.keys()
		keys.sort()

		## first two items in the busybox config are [ and [[, ignore them
		pos = 2

		## search through the original binary, not the one with all spaces
		## to reduce the amount of false positives
		offset = lines.find(keys[pos])
		while pos < len(keys)-1:
			if offset == -1:
				## nothing found, continue searching for the next applet in the list
				pass
			else:
				## search through the original binary until we have an exact match
				## that is surrounded by non-printable characters, which is
				## exactly how the applet list in BusyBox works (currently)
				res = extractor.check_nonprintable(lines, offset, keys[pos])
				while res == False:
					offset = lines.find(keys[pos], offset+1)
					if offset == -1:
						break
					else:
						res = extractor.check_nonprintable(lines, offset, keys[pos])
				if offset != -1:
					results2.append((keys[pos], offset))
			pos = pos+1
			offset = lines.find(keys[pos])

		## Find the applets which are reasonably grouped together.
		## Take the one with the lowest offset and the highest one and
		## split just as in the other case, to also catch unknown applets.
		low = 0
		high = len(results2) - 1

		## calculate a reasonable maximum length that low and high will be apart
		## motivation: each applet in the list is separated by a few characters
		## we just take 8 to err on the safe side.
		maxlen = reduce(lambda x,y: x + len(y[0]), results2, 0) + len(results2) * 8

		# use the distances map to find closely group together programs
		distances = map(lambda x,y: y[1] - x[1], results2[:-1], results2[1:])

		## loop through the elements and see if we see closely grouped elements
		discounter = 0
		while discounter < len(distances):
			if distances[discounter] < maxlen and distances[discounter] > 0:
				## we have found two things which are closely together
				## check if it is also close to high
				res = results2[high][1] - results2[discounter][1]
				if res < maxlen and res > 0:
					# we have our offset, set low to it, and break out of the loop
					low = discounter
					break
				else:
					# it is more likely that high needs to be lowered
					lowered = False
					for i in range(high, discounter, -1):
						res = results2[i][1] - results2[discounter][1]
						if res < maxlen and res > 0:
							high = high - 1
							lowered = True
							break
					# we have not lowered high, so we'll raise low and try again
					if not lowered:
						discounter = discounter + 1
			else:
				discounter = discounter + 1

		## assuming we have a good value for low and high we can just
		## use the offsets in the original file to search for stuff
		## and split accordingly
		tmp2config = printables[results2[low][1]:results2[high][1] + len(results2[high][0])].split()
		return tmp2config

## If we can get the configuration in this pass, we can be really accurate.
def extract_configuration_pass1(lines, busybox, printables):
	config = []
	offset = printables.find("_main")
	if offset != -1:
		offset2 = printables.rfind(" ", 0, offset)
		if printables[offset2+1:offset] == "__uClibc":
			# uClibc
			offset = printables.find("_main", offset+1)
			while offset != -1:
				offset2 = printables.rfind(" ", 0, offset)
				config.append(printables[offset2+1:offset])
				offset = printables.find("_main", offset+1)
		elif printables[offset2+1:offset] == '__libc_start':
			# glibc, rewrite this to use the subprocess module
			res = os.popen("readelf -s %s" % (busybox,))
			lines = res.readlines()
			for line in lines:
				if not "_main" in line:
					continue
				elif "UND" in line:
					continue
				elif not "FUNC" in line:
					continue
				else:
					config.append(line.strip().split()[-1][0:-5])
	return config

## default pretty printer for undefined applets
def prettyprint_undefined_apps(undefined_apps):
	try:
		undefined_apps.remove('busybox')
	except:
		pass
	if undefined_apps == []:
		pass
	else:
		print "Undefined applications:\n"
		for undef_app in undefined_apps:
			print "* ", undef_app

## Helper method that extracts the BusyBox version using a regular
## expression. It needs printable characters for this.
## If it can't be found, it will return 'None' instead.
def extract_version(lines):
	## quick check to see if this is BusyBox. If not, we can return immediately
	offset = lines.find("BusyBox v")
	if offset == -1:
		return
	## BusyBox version numbers should fit in 40 characters
	printables = extractor.extract_printables(lines[offset:offset + 40])
	res = re.search("BusyBox v([\d\.\d\w-]+) \(", printables)
	if res != None:
		return res.groups(0)[0]
	else:
		return

def main(argv):
	parser = OptionParser()
	parser.add_option("-b", "--binary", dest="bb", help="path to BusyBox binary", metavar="FILE")
	parser.add_option("-c", "--config", dest="bbconfigs", help="path to extracted BusyBox configs", metavar="FILE")
	parser.add_option("-f", "--found", dest="found", action="store_true", help="print applets that can be found (default)")
	parser.add_option("-m", "--missing", dest="missing", action="store_true", help="print applets that can't be found", metavar=None)
	parser.add_option("-x", "--xml", dest="xmloutput", action="store_true", help="output in XML (default false)", metavar=None)
	(options, args) = parser.parse_args()
	if options.missing == None and options.found == None:
		options.found = True
	## suck in the BusyBox binary
	if options.bb == None:
		parser.error("Path to BusyBox binary needed")
	try:
		busybox_binary = open(options.bb, 'rb')
	except:
		print "No valid BusyBox file"
		sys.exit(1)
	busybox_lines = busybox_binary.read()

	## determine the BusyBox binary
	version = extract_version(busybox_lines)

	## ... and read in names from all applets we have extracted from the BusyBox source
	if version == None:
		print "File does not appear to contain BusyBox"
		sys.exit(1)

	## read the location of the BAT configuration, default to /etc/bat
	if options.bbconfigs != None:
		## TODO: verify the location actually exists
		bbconfigs = options.bbconfigs
	else:
		bbconfigs = "/etc/bat"

	bbconfig = pickle.load(open('%s/configs/%s-config' % (bbconfigs, version)))

	## determine the configuration (can be empty)
	bb_configuration = extract_configuration(busybox_lines, options.bb, bbconfig)

	## weed out the unknown applets and store them separately
	ppconfig = []
	undefined_apps = []
	for config in bb_configuration:
		try:
			ppconfig.append(bbconfig[config][1])
		except KeyError:
			undefined_apps.append(config)
	ppconfig = list(set(ppconfig))
	ppconfig.sort()

	## pretty print the configuration and the unknown applets
	if options.found:
		prettyprint_configuration(ppconfig, version)
	## pretty print some newlines
	if options.found and options.missing:
		print "\n"
	if options.missing:
		prettyprint_undefined_apps(undefined_apps)

if __name__ == "__main__":
	main(sys.argv)
