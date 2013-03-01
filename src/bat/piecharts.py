#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. It generates images of results
of the ranking scan, like piecharts and version charts.

This should be run as a postrun scan

Parameters for configuration file:

* BAT_IMAGEDIR :: location to where images should be written
'''

import os, os.path, sys, cPickle
from PIL import Image
import matplotlib
matplotlib.use('cairo')
import pylab

def generateImages((picklefile, pickledir, filehash, imagedir)):

	print >>sys.stderr, "generating for", filehash
	leaf_file = open(os.path.join(pickledir, picklefile), 'rb')
	(piedata, pielabels) = cPickle.load(leaf_file)
	leaf_file.close()

	pylab.figure(1, figsize=(6.5,6.5))
	ax = pylab.axes([0.2, 0.15, 0.6, 0.6])

	pylab.pie(piedata, labels=pielabels)

	pylab.savefig('%s/%s-piechart.png' % (imagedir, filehash))
	pylab.gcf().clear()
	os.unlink(os.path.join(pickledir, picklefile))
