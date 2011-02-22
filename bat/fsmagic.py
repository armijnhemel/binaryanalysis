#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2011 Armijn Hemel for LOCO (LOOHUIS CONSULTING)
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
            #'gzip':             '\x1f\x8b\x08',     # this excludes some gzip files!
            'gzip':             '\x1f\x8b',
            'bz2':              'BZh',
            'rar':              'Rar!',
            'zip':              '\x50\x4b\x03\04',
            'squashfs-le':      '\x68\x73\x71\x73', # hsqs
            'squashfs-be':      '\x73\x71\x73\x68', # sqsh
            'squashfs-le-lzma': '\x71\x73\x68\x73', # qshs
            'squashfs-be-lzma': '\x73\x68\x73\x71', # shsq
            'lzma_alone':       '\x5d\x00\x00',
            'xz':               '\xfd\x37\x7a\x58\x5a\x00',
            'lzip':             'LZIP',
            'cramfs':           '\x45\x3d\xcd\x28',
            #'lzma_alone':       '\x5d\x00\x00\x80',
            #'jffs2-le':         '\x85\x19',
            'ubifs':            '\x55\x42\x49\x23',
            'rpm':              '\xed\xab\xee\xdb',
            'ext2':             '\x53\xef',        # little endian
            'arj':              '\x60\xea',
            'cab':              'MSCF',
          }

squashtypes = ['squashfs-le', 'squashfs-be', 'squashfs-le-lzma', 'squashfs-be-lzma']
cpio = ['070707', '070701', '070702']
