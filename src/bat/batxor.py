#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Sometimes some files like firmwares are encrypted. The level of encryption
varies with keys and verifying signatures at boot time to very simple
"encryption" by simply XORing with a byte string.

The code here scans binary files for certain known XOR parameters and applies
them, but only if no other scan succeeds.

For this we need to keep some state, possibly even delete the file only later,
by tagging it as 'temporary' and removing it later on.
'''

import sys, os, subprocess, os.path
import tempfile
import fsmagic, fssearch, extractor, fwunpack

## some of the signatures we know about:
## * Splashtop (fast boot environment)
## * Bococom router series (2.6.21, Ralink chipset)

## Finding new signatures is done by hand. A good helper tool can be found in
## the bat-visualisation directory in bat-extratools
