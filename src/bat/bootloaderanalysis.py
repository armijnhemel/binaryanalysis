#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

import os, sys, string
import re, subprocess
import extractor

def searchRedBoot(path, blacklist=[]):
        try:
                redboot_binary = open(path, 'rb')
                redboot_lines = redboot_binary.read()
                if findRedBoot(redboot_lines) != -1:
                        return True
                else:
                        return None
        except Exception, e:
                return None

def findRedBoot(lines):
	return lines.find("Display RedBoot version information")

def searchUBoot(path, blacklist=[]):
        try:
                binary = open(path, 'rb')
                lines = binary.read()
                if findUBoot(lines) != -1:
                        return True
                else:
                        return None
        except Exception, e:
                return None

def findUBoot(lines):
        markerlines = [ "run script starting at addr"
                      , "Hit any key to stop autoboot: %2d"
                      , "## Binary (kermit) download aborted"
                      , "## Ready for binary (ymodem) download "
                      ]

        for i in markerlines:
                res = lines.find(i)
                if res != -1:
                        return res
        return -1
