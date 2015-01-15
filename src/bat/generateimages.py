#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import os, os.path, sys, subprocess, copy, cPickle, tempfile, hashlib, shutil, multiprocessing, piecharts
import math
import reportlab.rl_config as rl_config

## Ugly hack to register the right font with the system, because ReportLab really wants to find
## Times-Roman it seems. TODO: clean this up to make it more portable.
rl_config.T1SearchPath = ["/usr/share/fonts/liberation/", "/usr/share/fonts/truetype/liberation/"]

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

## Fedora
fontpath = os.path.join('/usr/share/fonts/liberation','LiberationSerif-Regular.ttf')

if not os.path.exists(fontpath):
	## Ubuntu
	fontpath = os.path.join('/usr/share/fonts/truetype/liberation/','LiberationSerif-Regular.ttf')

## TODO: more sanity checks

pdfmetrics.registerFont(TTFont('Times-Roman', fontpath))

from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib import colors
from reportlab.graphics import renderPM

'''
This plugin is used to generate pictures. It is run as an aggregate scan for
a reason: as it turns out many pictures that are generated are identical:
piecharts of programs from the same package are often the same, version
information is often the same since the same database is used.

This is especially true for Java class files where there are often just a few
strings or methods from a single class file, which can lead to 80% of the
pictures being exact duplicates.

Since generating pictures can have quite a bit of overhead (especially with
the current scripts) it makes sense to first deduplicate and then generate
pictures.

The method works as follows:

1. All data from pickles that is needed to generate pictures is extracted in
parallel.
2. The checksum of the pickle is computed and recorded. If there is a duplicate
the pickle is removed and it is recorded which file it originally belonged to.
3. Pictures are generated in parallel for the remaining pickle files.
4. The pictures are copied and renamed, or symlinked.
'''

def generatepiecharts((picklefile, pickledir, filehash, imagedir)):
	piecharts.generateImages(picklefile, pickledir, filehash, imagedir, "piechart")

def generateversionchart((versionpickle, picklehash, imagedir, pickledir)):
	datapickle = open(os.path.join(pickledir, versionpickle), 'rb')
	data = cPickle.load(datapickle)
	datapickle.close()

	## calculate the possible widths and heights of chart, bars, labels and so on
	maxversionstring = max(map(lambda x: len(x[0]), data))

	barwidth = 15
	chartwidth = len(data) * barwidth + 10 * len(data)

	maxvalue = max(map(lambda x: x[1], data))
	step = int(math.log(maxvalue,10))
	valueStep = pow(10,step)

	## calculate a possible good value for startx and starty so labels are not cut off
	startx = max(10 + step * 10, 30)

	## TODO: fiddle with values to create nicer looking graphs
	starty = maxversionstring * 10 + 20

	drawheight = 225 + starty
	drawwidth = chartwidth + startx + 10

	## create the drawing
	drawing = Drawing(drawwidth, drawheight)
	bc = VerticalBarChart()
	bc.x = startx
	bc.y = starty
	bc.height = 200
	bc.width = chartwidth
	bc.data = [tuple(map(lambda x: x[1], data))]
	bc.strokeColor = colors.white
	bc.valueAxis.valueMin = 0
	bc.valueAxis.labels.fontSize = 16
	bc.valueAxis.valueMax = maxvalue
	bc.valueAxis.valueStep = valueStep
	bc.categoryAxis.labels.boxAnchor = 'w'
	bc.categoryAxis.labels.dx = 0
	bc.categoryAxis.labels.dy = -2
	bc.categoryAxis.labels.angle = -90
	bc.categoryAxis.labels.fontSize = 16
	bc.categoryAxis.categoryNames = map(lambda x: x[0], data)
	bc.barWidth = barwidth

	drawing.add(bc)
	outname = os.path.join(imagedir, picklehash)

	renderPM.drawToFile(drawing, outname, fmt='PNG')
	return picklehash

def extractpickles((filehash, pickledir, topleveldir, unpacktempdir, minpercentagecutoff, maxpercentagecutoff)):
	leaf_file = open(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash), 'rb')
	leafreports = cPickle.load(leaf_file)
	leaf_file.close()

	if not leafreports.has_key('ranking'):
		return
	## the ranking result is (res, dynamicRes, variablepvs)
	(res, dynamicRes, variablepvs, language) = leafreports['ranking']
	if res == None and dynamicRes == {}:
		return

	pieresult = None
	statpieresult = None
	versionresults = []
	funcresults = []

	statpies = []

	if res != None:
		statpiedata = []
		statpielabels = []

		if res['unmatchedlines'] != 0:
			statpielabels.append("unmatched (%d)" % res['unmatchedlines'])
			statpiedata.append(res['unmatchedlines'])

		if res['matchednonassignedlines'] != 0:
			statpielabels.append("matched, not\nassigned (%d)" % res['matchednonassignedlines'])
			statpiedata.append(res['matchednonassignedlines'])

		if res['matchednotclonelines'] != 0:
			statpielabels.append("matched, not\nclones (%d)" % res['matchednotclonelines'])
			statpiedata.append(res['matchednotclonelines'])

		assignedoruniquematches = 0
		for j in res['nonUniqueAssignments']:
			statpielabels.append("%s -\nassigned (%d)" % (j, res['nonUniqueAssignments'][j]))
			statpiedata.append(res['nonUniqueAssignments'][j])
			assignedoruniquematches += res['nonUniqueAssignments'][j]
		for j in res['reports']:
			(rank, package, unique, uniquematcheslen, percentage, packageversions, packagelicenses, packagecopyrights) = j
			if len(unique) != 0:
				statpielabels.append("%s - unique (%d)" % (package,len(unique)))
				statpiedata.append(len(unique))
				assignedoruniquematches += len(unique)

		## TODO: add information about matched but unassigned
		## now dump the data to a pickle
		if statpielabels != [] and statpiedata != []:
			tmppickle = tempfile.mkstemp(dir=unpacktempdir)
			cPickle.dump((statpiedata, statpielabels), os.fdopen(tmppickle[0], 'w'))
			picklehash = gethash(tmppickle[1])
			statpieresult = (picklehash, tmppickle[1])

		## now process statistics for score piechart
		piedata = []
		pielabels = []
		totals = 0.0
		others = 0.0
		for j in res['reports']:
			(rank, package, unique, uniquematcheslen, percentage, packageversions, packagelicenses, packagecopyrights) = j
			## less than half a percent, that's not significant anymore
			if percentage < minpercentagecutoff:
				totals += percentage
				others += percentage
				if totals <= maxpercentagecutoff:
					continue
			if totals >= maxpercentagecutoff:
				pielabels.append("others")
				piedata.append(others + 100.0 - totals)
				break
			else:   
				pielabels.append(package)
				piedata.append(percentage)
				totals += percentage

		## now dump the data to a pickle
		if pielabels != [] and piedata != []:
			tmppickle = tempfile.mkstemp(dir=unpacktempdir)
			cPickle.dump((piedata, pielabels), os.fdopen(tmppickle[0], 'w'))
			picklehash = gethash(tmppickle[1])
			pieresult = (picklehash, tmppickle[1])

		## process match data for version information
		for j in res['reports']:
			(rank, package, unique, uniquematcheslen, percentage, packageversions, packagelicenses, packagecopyrights) = j
			if packageversions != {}:
				pickledata = []
				vals = list(set(packageversions.values()))
				if vals == []:
					continue
				vals.sort(reverse=True)
				tmppickle = tempfile.mkstemp(dir=unpacktempdir)
				for v in vals:
					j_sorted = filter(lambda x: x[1] == v, packageversions.items())
					j_sorted.sort()
					for v2 in j_sorted:
						pickledata.append(v2)
				cPickle.dump(pickledata, os.fdopen(tmppickle[0], 'w'))
				picklehash = gethash(tmppickle[1])
				versionresults.append((picklehash, tmppickle[1], package))

	## extract pickles with version information for functions
	if dynamicRes.has_key('packages'):
		for package in dynamicRes['packages']:
			packagedata = copy.copy(dynamicRes['packages'][package])
			pickledata = []
			p_sorted = sorted(packagedata, key=lambda x: x[1])
			vals = list(set(map(lambda x: x[1], p_sorted)))
			if vals == []:
				continue
			vals.sort(reverse=True)
			tmppickle = tempfile.mkstemp(dir=unpacktempdir)
			for v in vals:
				j_sorted = filter(lambda x: x[1] == v, p_sorted)
				j_sorted.sort()
				for v2 in j_sorted:
					pickledata.append(v2)
			cPickle.dump(pickledata, os.fdopen(tmppickle[0], 'w'))
			picklehash = gethash(tmppickle[1])
			funcresults.append((picklehash, tmppickle[1], package))

	return (filehash, pieresult, statpieresult, versionresults, funcresults)

## compute a SHA256 hash. This is done in chunks to prevent a big file from
## being read in its entirety at once, slowing down a machine.
def gethash(path):
	scanfile = open(path, 'r')
	h = hashlib.new('sha256')
	scanfile.seek(0)
	hashdata = scanfile.read(10000000)
	while hashdata != '':
		h.update(hashdata)
		hashdata = scanfile.read(10000000)
	scanfile.close()
	return h.hexdigest()

def generateimages(unpackreports, scantempdir, topleveldir, processors, scanenv, scandebug=False, unpacktempdir=None):
	if scanenv.has_key('overridedir'):
		try:
			del scanenv['BAT_IMAGEDIR']
		except:
			pass
		try:
			del scanenv['BAT_PICKLEDIR']
		except:
			pass

	imagedir = scanenv.get('BAT_IMAGEDIR', os.path.join(topleveldir, "images"))
	try:
		os.stat(imagedir)
	except:
		## BAT_IMAGEDIR does not exist
		try:
			os.makedirs(imagedir)
		except Exception, e:
			return

	pickledir = scanenv.get('BAT_PICKLEDIR', os.path.join(topleveldir, "pickles"))
	try:
		os.stat(pickledir)
	except:
		## BAT_PICKLEDIR does not exist
		try:
			os.makedirs(pickledir)
		except Exception, e:
			return

	symlinks = False
	if scanenv.get('AGGREGATE_IMAGE_SYMLINK', 0) == '1':
		symlinks = True

	filehashes = set()

	## filter out the files which don't have ranking results
	for i in unpackreports:
		if not unpackreports[i].has_key('sha256'):
			continue
		if not unpackreports[i].has_key('tags'):
			continue
		if not 'ranking' in unpackreports[i]['tags']:
			continue
		filehash = unpackreports[i]['sha256']
		if not os.path.exists(os.path.join(topleveldir, "filereports", "%s-filereport.pickle" % filehash)):
			continue
		filehashes.add(filehash)

	if len(filehashes) == 0:
		return

	pickles = set()
	piepickles = set()
	piepicklespackages = set()
	statpiepickles = set()
	statpiepicklespackages = set()
	funcpicklespackages = set()
	versionpicklespackages = set()
	picklehashes = {}
	pickletofile = {}
	funcfilehashpackage = {}
	verfilehashpackage = {}

	## default values for cut off percentages
	minpercentagecutoff = 0.5
	maxpercentagecutoff = 99.0

	if scanenv.has_key('MINIMUM_PERCENTAGE'):
		try:
			minpercentagecutoff = float(scanenv['MINIMUM_PERCENTAGE'])
		except:
			pass
	if scanenv.has_key('MAXIMUM_PERCENTAGE'):
		try:
			maxpercentagecutoff = float(scanenv['MAXIMUM_PERCENTAGE'])
		except:
			pass

	## extract pickles
	extracttasks = map(lambda x: (x, pickledir, topleveldir, unpacktempdir, minpercentagecutoff, maxpercentagecutoff), filehashes)
	pool = multiprocessing.Pool(processes=processors)
	res = filter(lambda x: x != None, pool.map(extractpickles, extracttasks))
	pool.terminate()

	for r in res:
		(filehash, pieresult, statpieresult, versionresults, funcresults) = r
		if pieresult != None:
			(picklehash, tmppickle) = pieresult
			if picklehash in piepickles:
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]
				piepicklespackages.add((picklehash, filehash))
				os.unlink(tmppickle)
			else:
				shutil.move(tmppickle, pickledir)
				piepickles.add(picklehash)
				piepicklespackages.add((picklehash, filehash))
				picklehashes[picklehash] = os.path.basename(tmppickle)
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]
		if statpieresult != None:
			(picklehash, tmppickle) = statpieresult
			if picklehash in statpiepickles:
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]
				statpiepicklespackages.add((picklehash, filehash))
				os.unlink(tmppickle)
			else:
				shutil.move(tmppickle, pickledir)
				statpiepickles.add(picklehash)
				statpiepicklespackages.add((picklehash, filehash))
				picklehashes[picklehash] = os.path.basename(tmppickle)
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]
		for v in versionresults:
			(picklehash, tmppickle, package) = v
			if verfilehashpackage.has_key(filehash):
				verfilehashpackage[filehash].append(package)
			else:
				verfilehashpackage[filehash] = [package]
			if picklehash in pickles:
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]
				versionpicklespackages.add((picklehash, package))
				os.unlink(tmppickle)
			else:
				shutil.move(tmppickle, pickledir)
				pickles.add(picklehash)
				versionpicklespackages.add((picklehash, package))
				picklehashes[picklehash] = os.path.basename(tmppickle)
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]

		for f in funcresults:
			(picklehash, tmppickle, package) = f
			if funcfilehashpackage.has_key(filehash):
				funcfilehashpackage[filehash].append(package)
			else:
				funcfilehashpackage[filehash] = [package]
			if picklehash in pickles:
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]
				funcpicklespackages.add((picklehash, package))
				os.unlink(tmppickle)
			else:
				shutil.move(tmppickle, pickledir)
				pickles.add(picklehash)
				funcpicklespackages.add((picklehash, package))
				picklehashes[picklehash] = os.path.basename(tmppickle)
				if pickletofile.has_key(picklehash):
					pickletofile[picklehash].append(filehash)
				else:
					pickletofile[picklehash] = [filehash]

	## create a pool and generate the images
	pool = multiprocessing.Pool(processes=processors)

	if piepicklespackages != []:
		pietasks = set(map(lambda x: (picklehashes[x[0]], pickledir, x[0], imagedir), piepicklespackages))
		results = pool.map(generatepiecharts, pietasks, 1)
		## first copy the file for every package that needs it
		for p in piepicklespackages:
			oldfilename = "%s-%s" % (p[0], "piechart.png")
			filename = "%s-%s" % (p[1], "piechart.png")
			if os.path.exists(os.path.join(imagedir, oldfilename)):
				shutil.copy(os.path.join(imagedir, oldfilename), os.path.join(imagedir, filename))
		## then remove the temporary files
		for p in piepicklespackages:
			try:
				filename = "%s-%s" % (p[0], "piechart.png")
				os.unlink(os.path.join(imagedir, filename))
			except Exception, e:
				#print >>sys.stderr, "ERR", e
				pass
	if statpiepicklespackages != []:
		pietasks = set(map(lambda x: (picklehashes[x[0]], pickledir, x[0], imagedir), statpiepicklespackages))
		results = pool.map(generatepiecharts, pietasks, 1)
		## first copy the file for every package that needs it
		for p in statpiepicklespackages:
			oldfilename = "%s-%s" % (p[0], "piechart.png")
			filename = "%s-%s" % (p[1], "statpiechart.png")
			if os.path.exists(os.path.join(imagedir, oldfilename)):
				shutil.copy(os.path.join(imagedir, oldfilename), os.path.join(imagedir, filename))
		## then remove the temporary files
		for p in statpiepicklespackages:
			try:
				filename = "%s-%s" % (p[0], "piechart.png")
				os.unlink(os.path.join(imagedir, filename))
			except Exception, e:
				#print >>sys.stderr, "ERR", e
				pass

	generatetasks = map(lambda x: (picklehashes[x[0]], x[0], imagedir, pickledir), funcpicklespackages) + map(lambda x: (picklehashes[x[0]], x[0], imagedir, pickledir), versionpicklespackages)

	results = pool.map(generateversionchart, set(generatetasks), 1)
	pool.terminate()

	results = filter(lambda x: x != None, results)

	funcpickletopackage = {}
	for r in funcpicklespackages:
		if funcpickletopackage.has_key(r[0]):
			funcpickletopackage[r[0]].add(r[1])
		else:
			funcpickletopackage[r[0]] = set([r[1]])
	
	versionpickletopackage = {}
	for r in versionpicklespackages:
		if versionpickletopackage.has_key(r[0]):
			versionpickletopackage[r[0]].add(r[1])
		else:
			versionpickletopackage[r[0]] = set([r[1]])

	for r in set(results):
		picklefilehash = r.split('.', 1)[0]
		unlinkpickle = True
		for f in pickletofile[picklefilehash]:
			if not funcpickletopackage.has_key(picklefilehash) and not versionpickletopackage.has_key(picklefilehash):
				## this should not happen
				continue
			if versionpickletopackage.has_key(picklefilehash):
				for e in versionpickletopackage[picklefilehash]:
					if not verfilehashpackage.has_key(f):
						continue
					if not e in verfilehashpackage[f]:
						continue
					extension = "version.png"
					filename = "%s-%s-%s" % (f, e, extension)
					if os.path.exists(os.path.join(imagedir, filename)):
						os.unlink(os.path.join(imagedir, filename))
					if symlinks and len(versionpickletopackage[picklefilehash]) != 1:
						oldcwd = os.getcwd()
                                		os.chdir(imagedir)
                                		os.symlink(r, filename)
                                		os.chdir(oldcwd)
						unlinkpickle = False
					else:
						shutil.copy(os.path.join(imagedir, r), os.path.join(imagedir, filename))
			if funcpickletopackage.has_key(picklefilehash):
				for e in funcpickletopackage[picklefilehash]:
					if not funcfilehashpackage.has_key(f):
						continue
					if not e in funcfilehashpackage[f]:
						continue
					extension = "funcversion.png"
					filename = "%s-%s-%s" % (f, e, extension)
					if os.path.exists(os.path.join(imagedir, filename)):
						os.unlink(os.path.join(imagedir, filename))
					if symlinks and len(funcpickletopackage[picklefilehash]) != 1:
						oldcwd = os.getcwd()
                                		os.chdir(imagedir)
                                		os.symlink(r, filename)
                                		os.chdir(oldcwd)
						unlinkpickle = False
					else:
						shutil.copy(os.path.join(imagedir, r), os.path.join(imagedir, filename))
		if unlinkpickle:
			os.unlink(os.path.join(imagedir, r))

	## cleanup
	cleanpickles = set()
	cleanpickles.update(map(lambda x: x[0], funcpicklespackages))
	cleanpickles.update(map(lambda x: x[0], versionpicklespackages))
	for i in cleanpickles:
		os.unlink(os.path.join(pickledir, picklehashes[i]))
