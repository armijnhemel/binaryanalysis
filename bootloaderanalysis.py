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
