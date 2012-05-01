#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2012 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This is a plugin for the Binary Analysis Tool. It generates images of files, both
full files and thumbnails. The files can be used for informational purposes, such
as detecting roughly where offsets can be found, if data is compressed or encrypted,
etc.

It also generates histograms, which show how different byte values are distributed.
This can provide another visual clue about how files are constructed. Binaries from
the same type (like ELF binaries) are actually quite similar, so binaries that
significantly deviate from this could mean something interesting.

This should be run as a postrun scan

Parameters for configuration file:

* BAT_IMAGE_MAXFILESIZE :: maximum size of the *source* file, to prevent
  ridiculously large files from being turned into even ridiculously larger
  pictures
* BAT_IMAGEDIR :: location to where images should be written
'''

import os, os.path, sys, subprocess, array, cPickle, tempfile
from PIL import Image
import matplotlib
matplotlib.use('cairo')
import pylab

def generateImages(filename, unpackreport, leafscans, scantempdir, toplevelscandir, envvars={}):
	if not unpackreport.has_key('sha256'):
		return
	ignorelist = ['graphics', 'text', 'compressed', 'pdf', 'xml', 'resources']
	## not interested in text files, graphics or compressed files
	## TODO: make this configurable
	for s in leafscans:
		if s.keys()[0] == 'tags':
			for i in ignorelist:
				if i in s['tags']:
					return

	scanenv = os.environ.copy()
	if envvars != None:
		for en in envvars.split(':'):
			try:
				(envname, envvalue) = en.split('=')
				scanenv[envname] = envvalue
			except Exception, e:
				pass

	## TODO: check if BAT_IMAGEDIR exists
	imagedir = scanenv.get('BAT_IMAGEDIR', "%s/%s" % (toplevelscandir, "images"))
	try:
		os.stat(imagedir)
	except:
		## BAT_IMAGEDIR does not exist
		try:
			os.makedirs(imagedir)
		except Exception, e:
			return

	maxsize = int(scanenv.get('BAT_IMAGE_MAXFILESIZE', sys.maxint))
	filesize = os.stat("%s/%s" % (scantempdir, filename)).st_size
	if filesize > maxsize:
		return
	## this stuff is easily cached
	if not os.path.exists("%s/%s.png" % (imagedir, unpackreport['sha256'])):
		fwfile = open("%s/%s" % (scantempdir, filename))

		## this is very inefficient for large files, but we *really* need all the data :-(
		fwdata = fwfile.read()
		fwfile.close()

		fwlen = len(fwdata)

		if fwlen > 512:
			height = 512
		else:
			height = fwlen
		width = fwlen/height

		## we might need to add some bytes so we can create a valid picture
		if fwlen%height > 0:
			width = width + 1
			for i in range(0, height - (fwlen%height)):
				fwdata = fwdata + chr(0)

		imgbuffer = buffer(bytearray(fwdata))

		im = Image.frombuffer("L", (height, width), imgbuffer, "raw", "L", 0, 1)
		im.save("%s/%s.png" % (imagedir, unpackreport['sha256']))
		'''
		if width > 100:
			imthumb = im.thumbnail((height/4, width/4))
			im.save("%s/%s-thumbnail.png" % (imagedir, unpackreport['sha256']))
		'''

	'''
	## generate histogram
	p = subprocess.Popen(['python', '/home/armijn/gpltool/trunk/bat-extratools/bat-visualisation/bat-generate-histogram.py', '-i', "%s/%s" % (scantempdir, filename), '-o', '%s/%s-histogram.png' % (imagedir, unpackreport['sha256'])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		print >>sys.stderr, stanerr
	'''

	## generate piechart and version information
	for i in leafscans:
		if i.keys()[0] == 'ranking':
			if i['ranking']['reports'] != []:
				piedata = []
				pielabels = []
				totals = 0.0
				others = 0.0
				for j in i['ranking']['reports']:
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
				for j in i['ranking']['reports']:
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
