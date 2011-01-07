#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This program can be used to walk a directory tree and report the names
of the applets that symlink to BusyBox. While not accurate (symlinks could
have been removed) it might come in handy as an extra tool.
'''

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
