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
import matplotlib
matplotlib.use('cairo')
import pylab

def generateImages(picklefile, pickledir, filehash, imagedir):

	leaf_file = open(os.path.join(pickledir, picklefile), 'rb')
	(piedata, pielabels) = cPickle.load(leaf_file)
	leaf_file.close()

	pylab.figure(1, figsize=(6.5,6.5))
	ax = pylab.axes([0.2, 0.15, 0.6, 0.6])

	pylab.pie(piedata, labels=pielabels)

	pylab.savefig('%s/%s-piechart.png' % (imagedir, filehash))
	pylab.gcf().clear()
	os.unlink(os.path.join(pickledir, picklefile))

'''
### This is just some dead code that was an attempt at generating better piecharts. It might be used in the future, so keep it here for reference.
					j_sorted = sorted(j[4], key=lambda x: j[4][x])
					max_y = j[4][j_sorted[-1]]
					xvalues = []
					yvalues = []
					for v in j_sorted:
						xvalues.append(v)
						yvalues.append(j[4][v])
						print >>sys.stderr, v, j[4][v], j[1], xvalues, yvalues, "max", max_y

					figsize = len(xvalues) * 1.0
					pylab.gcf().set_size_inches(figsize, 7)

					pylab.xlabel('version')
					pylab.ylabel('matches')
					pylab.title("Unique matches for %s" % j[1])
					## leave some space at the top
					pylab.gca().set_ylim(top=max_y + 1)
					x = pylab.arange(len(xvalues))
					b = pylab.bar(x, yvalues, width=0.6)
					for bb in b:
						print >>sys.stderr, bb.get_width(), bb.get_height()
					## center the text
					pylab.xticks(x+0.3, xvalues, rotation=270)

					pylab.savefig('%s/%s-%s-version.png' % (imagedir, unpackreport['sha256'], j[1]))
					pylab.gcf().clear()
'''
