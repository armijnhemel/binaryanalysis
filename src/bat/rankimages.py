#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. It generates images of results
of the ranking scan, like piecharts and version charts.

This should be run as a postrun scan

Parameters for configuration file:

* BAT_IMAGEDIR :: location to where images should be written
'''

import os, os.path, sys, subprocess, array, cPickle, tempfile, copy
from PIL import Image
import matplotlib
matplotlib.use('cairo')
import pylab

def generateImages(filename, unpackreport, leafscans, scantempdir, toplevelscandir, envvars={}):
	if not unpackreport.has_key('sha256'):
		return

	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	imagedir = scanenv.get('BAT_IMAGEDIR', "%s/%s" % (toplevelscandir, "images"))
	try:
		os.stat(imagedir)
	except:
		## BAT_IMAGEDIR does not exist
		try:
			os.makedirs(imagedir)
		except Exception, e:
			return

	## generate piechart and version information
	if leafscans.has_key('ranking'):
		## the ranking result is (res, dynamicRes, variablepvs)
		(res, dynamicRes, variablepvs) = leafscans['ranking']
		if res == None:
			return
		if res['reports'] != []:
			piedata = []
			pielabels = []
			totals = 0.0
			others = 0.0
			for j in res['reports']:
				## less than half a percent, that's not significant anymore
				if j[3] < 0.5:
					totals += j[3]
					others += j[3]
					if totals <= 99.0:
						continue
				if totals >= 99.0:
					pielabels.append("others")
					piedata.append(others + 100.0 - totals)
					break
				else:
					pielabels.append(j[1])
					piedata.append(j[3])
					totals += j[3]
			pylab.figure(1, figsize=(6.5,6.5))
			ax = pylab.axes([0.2, 0.15, 0.6, 0.6])

			pylab.pie(piedata, labels=pielabels)

			pylab.savefig('%s/%s-piechart.png' % (imagedir, unpackreport['sha256']))
			pylab.gcf().clear()
			for j in res['reports']:
				if j[4] != {}:
					'''
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
					tmppickle = tempfile.mkstemp()
					pickledata = []
					j_sorted = sorted(j[4], key=lambda x: j[4][x])
					for v in j_sorted:
						pickledata.append((v, j[4][v]))
					cPickle.dump(pickledata, os.fdopen(tmppickle[0], 'w'))
					p = subprocess.Popen(['bat-generate-version-chart.py', '-i', tmppickle[1], '-o', '%s/%s-%s-version.png' % (imagedir, unpackreport['sha256'], j[1])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
					(stanout, stanerr) = p.communicate()
					if p.returncode != 0:
						print >>sys.stderr, stanerr
					os.unlink(tmppickle[1])

	## generate version information
	if leafscans.has_key('ranking'):
		## the ranking result is (res, dynamicRes, variablepvs)
		(res, dynamicRes, variablepvs) = leafscans['ranking']
		if dynamicRes == {}:
			return
		if dynamicRes.has_key('packages'):
			for package in dynamicRes['packages']:
				packagedata = copy.copy(dynamicRes['packages'][package])
				tmppickle = tempfile.mkstemp()
				pickledata = []
				p_sorted = sorted(packagedata, key=lambda x: x[1])
				for v in p_sorted:
					pickledata.append(v)
				cPickle.dump(pickledata, os.fdopen(tmppickle[0], 'w'))
				p = subprocess.Popen(['bat-generate-version-chart.py', '-i', tmppickle[1], '-o', '%s/%s-%s-funcversion.png' % (imagedir, unpackreport['sha256'], package)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
				(stanout, stanerr) = p.communicate()
				if p.returncode != 0:
					print >>sys.stderr, stanerr
				os.unlink(tmppickle[1])
