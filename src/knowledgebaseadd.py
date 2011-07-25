#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This script can be used to add firmware data to an existing knowledgebase
'''

import os, sys, sqlite3, hashlib
from optparse import OptionParser

def gethash(path):
        scanfile = open("%s" % (path,), 'r')
        h = hashlib.new('sha256')
        h.update(scanfile.read())
        scanfile.close()
        return h.hexdigest()

def main(argv):
        parser = OptionParser()
	parser.add_option("-d", "--database", dest="db", help="path to database", metavar="FILE")
	parser.add_option("-c", "--chipset", dest="chipset", help="name of chipset", metavar="CHIPSET")
	parser.add_option("-f", "--firmwareversion", dest="fwversion", help="firmware version", metavar="FWVERSION")
	parser.add_option("-m", "--manufacturer", dest="vendor", help="name of manufacturer", metavar="MANUFACTURER")
	parser.add_option("-n", "--name", dest="name", help="name of device", metavar="NAME")
	parser.add_option("-p", "--firmware", dest="firmware", help="path to firmware", metavar="FILE")
	parser.add_option("-u", "--upstream", dest="upstream", help="upstream vendor (optional)", metavar="UPSTREAM")
	parser.add_option("-w", "--hardwareversion", dest="hwversion", help="hardware version", metavar="HWVERSION")
	(options, args) = parser.parse_args()

	if options.db == None:
                parser.error("Path to database file needed")
        try:
                conn = sqlite3.connect(options.db)
        except:
                print "Can't open database file"
                sys.exit(1)

	if options.chipset == None:
		parser.error("Need name of chipset")
	if options.fwversion == None:
		parser.error("Need firmware version")
	if options.hwversion == None:
		parser.error("Need hardware version")
	if options.vendor == None:
		parser.error("Need manufacturer name")
	if options.name == None:
		parser.error("Need device name")
	if options.upstream == None:
		options.upstream = ''
	if options.firmware == None:
		parser.error("Need path to firmware")
	else:
		try:
			firmware = open(options.firmware)
		except:
			print >>sys.stderr, "Can't open firmware"
			sys.exit(1)

	c = conn.cursor()

	t = (options.vendor, options.name, options.hwversion, options.chipset, options.upstream)
	c.execute('''insert into device(vendor, name, version,chipset, upstream) values (?, ?, ?, ?, ?)''', t)
	conn.commit()
	lastrow = c.lastrowid

	fwhash = gethash(options.firmware)
	c.execute('''insert into firmware (sha256, version, deviceid) values (?, ?, ?)''', (fwhash, options.fwversion, lastrow))
	conn.commit()
	c.close()

if __name__ == "__main__":
        main(sys.argv)
