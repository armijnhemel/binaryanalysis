#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2010-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sys, os, string, re
from optparse import OptionParser
import sqlite3
from bat import extractor

## TODO: replace by generic code from ranking.py

## some strings we are interested in can't be extracted using xgettext.
## We use a few regular expressions for them to extract them. Since there
## macros being introduced (and removed) from the kernel sources regularly
## we should try and keep this list up to date.
exprs = []

bugtrapexpr = re.compile("BUG_TRAP\s*\(([\w\s\.:<>\-+=~!@#$^%&*\[\]{}+?|/,'\(\)\\\]+)\);", re.MULTILINE)
