#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009, 2010 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
## Licensed under Apache 2.0, see LICENSE file for details

'''This file contains information about how to recognize certain
files, file systems, compression, and so on automatically and which
methods or functions to invoke to unpack these files for further
analysis.'''

## information from:
## 1. /usr/share/magic
## 2. include/linux/magic.h in the Linux kernel sources
## 3. http://www.squashfs-lzma.org/
## 4. http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=364260

## basically we are rebuilding the magic database here :(
## (name: identifier)

fsmagic = {
            'gzip':             '\x1f\x8b\x08',
            'bz2':              'BZh',
            'rar':              'Rar!',
            'zip':              '\x50\x4b\x03\04',
            'squashfs-le':      '\x68\x73\x71\x73', # hsqs
            'squashfs-be':      '\x73\x71\x73\x68', # sqsh
            'squashfs-le-lzma': '\x71\x73\x68\x73', # qshs
            'squashfs-be-lzma': '\x73\x68\x73\x71', # shsq
            'lzma_alone':       '\x5d\x00\x00',
            #'lzma_alone':       '\x5d\x00\x00\x80',
            #'jffs2-le':         '\x85\x19',
          }

squashcollection = ['squash-le', 'squash-be', 'squash-le-lzma', 'squash-be-lzma']
cpio = ['070707', '070701', '070702']
