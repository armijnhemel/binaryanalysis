#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2012 Armijn Hemel for Tjaldur Software Governance Solutions
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
            'gzip':             '\x1f\x8b\x08',     # x08 is the only compression method according to RFC 1952
            'bz2':              'BZh',
            'rar':              'Rar!',
            'zip':              '\x50\x4b\x03\04',
            'squashfs1':        '\x68\x73\x71\x73', # hsqs
            'squashfs2':        '\x73\x71\x73\x68', # sqsh
            'squashfs3':        '\x71\x73\x68\x73', # qshs
            'squashfs4':        '\x73\x68\x73\x71', # shsq
            'lzma_alone':       '\x5d\x00\x00',
            'lzma_alone_alt':   '\x6d\x00\x00',     # used in OpenWrt
            '7z':               '7z\xbc\xaf\x27\x1c',
            'xz':               '\xfd\x37\x7a\x58\x5a\x00',
            'xztrailer':        '\x59\x5a',
            'lzip':             'LZIP',
            'lzo':              '\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a',
            'cramfs':           '\x45\x3d\xcd\x28',
            #'lzma_alone':       '\x5d\x00\x00\x80',
            'jffs2_le':         '\x85\x19',
            'ubifs':            '\x55\x42\x49\x23',
            'rpm':              '\xed\xab\xee\xdb',
            'ext2':             '\x53\xef',        # little endian
            'arj':              '\x60\xea',
            'cab':              'MSCF',
            'installshield':    'ISc(',
            'png':              '\x89PNG\x0d\x0a\x1a\x0a',
            'pngtrailer':       'IEND',
            'cpiotrailer':      'TRAILER!!!',
            'jpeg':             '\xff\xd8',
            'jpegtrailer':      '\xff\xd9',
            'jfif':             'JFIF',
            'gif87':            'GIF87a',
            'gif89':            'GIF89a',
            'ico':              '\x00\x00\x01\x00',
            'cpio1':            '070701',
            'cpio2':            '070702',
            'cpio3':            '070707',
            'iso9660':          'CD001',
            'swf':              'CWS',
            'pdf':              '%PDF-',
            'pdftrailer':       '%%EOF',
            'ar':               '!<arch>',
            'tar1':             'ustar\x00',
            'tar2':             'ustar\x20',
            'java_serialized':  '\xac\xed\x00',
          }

## some offsets can be found after a certain number of bytes, but
## the actual file system or file starts earlier
correction = {
               'ext2':    0x438,
               'iso9660': 32769,
               'tar1':    0x101,
               'tar2':    0x101,
             }

## collection of markers that should be scanned together
squashtypes = ['squashfs1', 'squashfs2', 'squashfs3', 'squashfs4']
lzmatypes   = ['lzma_alone', 'lzma_alone_alt']
cpio        = ['cpio1', 'cpio2', 'cpio3']
gif         = ['gif87', 'gif89']
tar         = ['tar1', 'tar2']
