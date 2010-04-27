#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import string, re

def searchLoadLin(path):
        try:
                binary = open(path, 'rb')
                lines = binary.read()
                if extractLoadLin(lines) != -1:
			return True
		else:
			return None
        except Exception, e:
                return None

def extractLoadLin(lines):
	markerStrings = [ 'Ooops..., size of "setup.S" has become too long for LOADLIN,'
			, 'LOADLIN started from $'
			]
	for marker in markerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1
