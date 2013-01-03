#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, string, re, subprocess
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
translation_table = {'1.17': translation_table_1_15}
translation_table = {'1.18': translation_table_1_15}
translation_table = {'1.19': translation_table_1_15}
translation_table = {'1.20': translation_table_1_15}

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
## If it succeeds the configuration can be pretty printed.
## If it fails the configuration has to be found the hard way.
def extract_configuration(lines, busybox, bbconfig):
	tmpconfig = extract_configuration_pass1(lines, busybox)

	if tmpconfig != []:
		## The configuration we have is not empty, so we're lucky.
		## Search through lines, using the configuration we got earlier
		## and try to extract the appletnames. This is not fool proof, but
		## should be good enough.

		## first make sure that everything we have is in alphabetical order
		tmpconfig.sort()

		## offset for first appletname we have found earlier, surrounded by NULL characters
		offset = lines.find("\x00" + tmpconfig[0] + "\x00")

		## offset for first occurance of last appletname after offset of first appletname
		## surrounded  by NULL characters
		offset2 = lines.find("\x00" + tmpconfig[-1] + "\x00", offset)

		## split everything, we should have a reasonable config
		tmp2config = lines[offset+1:offset2 + 1 + len(tmpconfig[-1])].split('\x00')
		tmp2config = filter(lambda x: x != '', tmp2config)
		## TODO: sanity check
		for i in tmpconfig:
			if i == 'busybox':
				continue
			if i == 'ftpgetput':
				continue
			if i == 'swap_on_off':
				continue
			if not i in tmp2config:
				## something went wrong, possibly offset that was wrong.
				pass
		return tmp2config
	else:
		## we don't have a configuration, so we will just have to guess one by inspecting the binary
		results = []
		results2 = []

		## use the configuration for this version of BusyBox as a starting point
		keys = bbconfig.keys()

		## the list of applets in BusyBox is sorted alphabetically
		keys.sort()
		for i in keys:
			if i == '[' or i == '[[':
				continue
			offset = lines.find(i)
			if offset == -1:
				## nothing found, continue searching for the next applet in the list
				continue
			else:
				## search through the original binary until we have an exact match
				## that is surrounded by NULL characters, which is how the applet
				## list in BusyBox works.
				## The risk is that the first hit we find is not in that list, but
				## is somewhere else in the binary.
				res = extractor.check_null(lines, offset, i)
				while res == False:
					offset = lines.find(i, offset+1)
					if offset == -1:
						break
					else:
						res = extractor.check_null(lines, offset, i)
				if offset != -1:
					results2.append((i, offset))

		## We have a list of applets, plus their offsets. It is expected that
		## for all applets we found that the offsets we found is in ascending
		## order. Of course, there might be unknown applets that have been
		## added in between the names that we do know, or the offsets that we
		## found were actually wrong.
		low = 0
		high = len(results2) - 1

		## calculate a reasonable maximum length that low and high will be apart
		## motivation: each applet in the list is separated by a few characters
		## we just take 8 to err on the safe side.
		maxlen = reduce(lambda x,y: x + len(y[0]), results2, 0) + len(results2) * 8

		# use the distances map to find closely group together programs
		distances = map(lambda x,y: y[1] - x[1], results2[:-1], results2[1:])

		## loop through the elements and see if we see closely grouped elements
		offsetcounter = 0
		while offsetcounter < len(distances):
			if distances[offsetcounter] < maxlen and distances[offsetcounter] > 0:
				## we have found two things which are closely together
				## check if it is also close to high
				res = results2[high][1] - results2[offsetcounter][1]
				if res < maxlen and res > 0:
					# we have our offset, set low to it, and break out of the loop
					low = offsetcounter
					break
				else:
					# it is more likely that high needs to be lowered
					lowered = False
					for i in range(high, offsetcounter, -1):
						res = results2[i][1] - results2[offsetcounter][1]
						if res < maxlen and res > 0:
							high = high - 1
							lowered = True
							break
					# we have not lowered high, so we'll raise low and try again
					if not lowered:
						offsetcounter = offsetcounter + 1
			else:
				offsetcounter = offsetcounter + 1

		## assuming we have a good value for low and high we can extract the appletnames
		tmp2config = lines[results2[low][1]:results2[high][1] + len(results2[high][0])].split('\x00')
		return tmp2config

## If we can get the configuration in this pass, we can be really accurate.
def extract_configuration_pass1(lines, busybox):
	config = []
	offset = lines.find("_main")
	if offset != -1:
		offset2 = lines.rfind("\x00", 0, offset)
		if lines[offset2+1:offset] == "__uClibc":
			# uClibc
			offset = lines.find("_main", offset+1)
			while offset != -1:
				offset2 = lines.rfind("\x00", 0, offset)
				config.append(lines[offset2+1:offset])
				offset = lines.find("_main", offset+1)
		elif lines[offset2+1:offset] == '__libc_start':
			# glibc
			p = subprocess.Popen(['readelf', '-sW', busybox], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			(stanout, stanerr) = p.communicate()
			if p.returncode != 0:
				return []
			lines = stanout.split('\n')
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
## expression. If it can't be found, it will return 'None' instead.
## This won't always work: if just one applet is compiled in it is
## likely that the "BusyBox v" string is not even included at all, which
## also means we can't extract a version number from it.
def extract_version(filename):
	offset = 0
	bboffset = 0

	## we use a buffer here to read data, because files we are scanning
	## might be incredibly big and we don't want to hog memory
	databuffer = []
	datafile = open(filename)
	datafile.seek(offset)
	databuffer = datafile.read(100000)
	while databuffer != '':
		## quick check to see if this is BusyBox. If not, we can return immediately
		markeroffset = databuffer.find("BusyBox v")
		if markeroffset != -1:
			bboffset = offset + markeroffset
			break
		## move the offset 99950, allowing some overlap
		datafile.seek(offset + 99950)
		databuffer = datafile.read(100000)
		if len(databuffer) >= 50:
			offset = offset + 99950
		else:
			offset = offset + len(databuffer)
	datafile.close()
	busybox = open(filename, 'rb')
	lines = busybox.read()
	busybox.close()

	bracket_offset = lines.find("(", bboffset)
	res = re.search("BusyBox v([\d\.\d\w-]+) \(", lines[bboffset:bracket_offset+1])
	if res != None:
		return res.groups(0)[0]
	else:
		return

def main(argv):
	parser = OptionParser()
	parser.add_option("-b", "--binary", dest="bb", help="path to BusyBox binary", metavar="FILE")
	parser.add_option("-c", "--config", dest="bbconfigs", help="path to extracted BusyBox configs", metavar="DIR")
	parser.add_option("-f", "--found", dest="found", action="store_true", help="print applets that can be found (default)")
	parser.add_option("-m", "--missing", dest="missing", action="store_true", help="print applets that can't be found", metavar=None)
	(options, args) = parser.parse_args()
	if options.missing == None and options.found == None:
		options.found = True
	## suck in the BusyBox binary
	if options.bb == None:
		parser.error("Path to BusyBox binary needed")
	try:
		busybox_binary = open(options.bb, 'rb')
	except:
		print >>sys.stderr, "No valid BusyBox file"
		sys.exit(1)

	## determine the BusyBox binary
	version = extract_version(options.bb)

	## ... and read in names from all applets we have extracted from the BusyBox source
	if version == None:
		print >>sys.stderr, "File does not appear to contain BusyBox"
		sys.exit(1)

	## read the location of the BAT configuration, default to /etc/bat
	if options.bbconfigs != None:
		try:
			os.stat(options.bbconfigs)
			bbconfigs = options.bbconfigs
		except:
			bbconfigs = "/etc/bat"
	else:
		bbconfigs = "/etc/bat"

	try:
		bbconfig = pickle.load(open('%s/configs/%s-config' % (bbconfigs, version)))
	except:
		print >>sys.stderr, "No configuration for %s found. Exiting." % version
		sys.exit(1)

	busybox_lines = busybox_binary.read()
	busybox_binary.close()
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
