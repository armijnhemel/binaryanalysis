#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Find XOR key using some very superdumb methods.

The idea is to exploit the idea that padding is used in firmwares. Usually padding
consists of NUL bytes. When XORing the key with NUL bytes the result will be the key.
Often it is very easy to see the key in plain sight using for example the command
"hexdump -C".

In this script it is assumed (for now) that the keylength is 16 and that there is just
one single key used. Manual inspection is definitely needed.
'''

import sys, os, collections
from optparse import OptionParser

def findpadding(firmware):
	counter = collections.Counter()
	fwfile = open(firmware)
	firmwarebytes = fwfile.read()
	fwfile.close()
	fwlen = len(firmwarebytes)
	blocks = fwlen/16
	byteblocks = []
	for i in xrange(0, blocks):
		byteblocks.append(firmwarebytes[i*16:i*16+16])
	counter.update(byteblocks)
	rank = 1
	reportamount = 10
	print "MOST COMMON, TOP %d" % reportamount
	for i in counter.most_common(reportamount):
		print rank, i[1], map(lambda x: hex(ord(x)), i[0])
		rank += 1

def main(argv):
	parser = OptionParser()
	parser.add_option("-f", "--firmware", action="store", dest="firmware", help="path to firmware", metavar="FILE")
	(options, args) = parser.parse_args()
	if options.firmware == None:
		parser.exit("Path to firmware not supplied, exiting")

	findpadding(options.firmware)

if __name__ == "__main__":
	main(sys.argv)
