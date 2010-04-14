#!/usr/bin/python

import os, sys, string
import re, subprocess
import extractor

def findRedBoot(lines):
	return lines.find("Display RedBoot version information")
