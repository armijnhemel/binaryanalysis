#!/usr/bin/python

import os, sys, string
import re, subprocess
import extractor

def searchRedBoot(path):
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

def searchUBoot(path):
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
        markerlines = [ "f_uboot_addr"
                      , "f_firmware_addr"
                      , "U-Boot 1.1.5-2.0"
                      ]
        for i in markerlines:
                res = lines.find(i)
                if res != -1:
                        return res
        return -1
