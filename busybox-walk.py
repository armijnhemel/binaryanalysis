#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import os, sys

def busyboxWalk(dir):
	busybox_applets = []

	osgen = os.walk(dir)

	try:
		while True:
			i = osgen.next()
			for p in i[2]:
				if os.path.basename(os.path.realpath(os.path.join(i[0], p))) == 'busybox':
					busybox_applets.append(p)
	except StopIteration:
		pass

	busybox_applets.sort()
	return busybox_applets
