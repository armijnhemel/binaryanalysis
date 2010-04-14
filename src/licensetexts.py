#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import string, re
import extractor

# marker strings that can be found in wireless-tools
# add more to make it more robust
gplMarkerStrings = [ "Copyright (C) 1989, 1991-%d Free Software Foundation."
                   ]

def extractGPL(lines):
	for marker in gplMarkerStrings:
		res = lines.find(marker)
		if res != -1:
			return res
	return -1
