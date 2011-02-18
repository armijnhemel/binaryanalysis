#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains a few convenience functions that are used throughout the code.
'''

import string

## Helper method to replace unprintable characters with spaces.
## This is useful for doing regular expressions to extract the BusyBox
## version, while retaining all offsets in the file.
def extract_printables(lines):
        printables = ""
        for i in lines:
                if i in string.printable:
                        printables += i
                else:
                        printables += " "
        return printables

## check if a word is surrounded by non-printable characters
def check_nonprintable(lines, offset, word):
        if lines[offset-1] not in string.printable:
                if lines[offset+len(word)] not in string.printable:
                        return True
        return False

## convenience method to check if the offset we find is in a blacklist
## Blacklists are composed of tuples (lower, upper) which mark a region
## in the parent file(!) as a no go area.
## This method returns the upperbound from the tuple for which
## lower <= offset < upper is True
def inblacklist(offset, blacklist):
	for bl in blacklist:
		if offset >= bl[0] and offset < bl[1]:
			return bl[1]
