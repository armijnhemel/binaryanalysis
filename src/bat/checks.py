#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2009-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains a few methods that check for the presence of marker
strings that are likely to be found in certain programs. It is far from fool
proof and false positives are likely, so either check the results, or replace
it with your own more robust checks.
'''

import string, re, os, magic, subprocess, sys, tempfile, copy
import extractor
import xml.dom.minidom

## generic searcher for certain marker strings
def genericSearch(path, markerDict, blacklist=[], unpacktempdir=None):
	results = []
        try:
		## first see if the entire file has been blacklisted
		filesize = os.stat(path).st_size
		carved = False
		if blacklist != []:
			if extractor.inblacklist(0, blacklist) == filesize:
				return None
			datafile = open(path, 'rb')
			lastindex = 0
			databytes = ""
			datafile.seek(lastindex)
			## make a copy and add a bogus value for the last
			## byte to a temporary blacklist to make the loop work
			## well.
			blacklist_tmp = copy.deepcopy(blacklist)
			blacklist_tmp.append((filesize,filesize))
			for i in blacklist_tmp:
				if i[0] == lastindex:
					lastindex = i[1] - 1
					datafile.seek(lastindex)
					continue
				if i[0] > lastindex:
					## just concatenate the bytes
					data = datafile.read(i[0] - lastindex)
					databytes = databytes + data
					## set lastindex to the next
					lastindex = i[1] - 1
					datafile.seek(lastindex)
			datafile.close()
			if len(databytes) == 0:
				return None
			tmpfile = tempfile.mkstemp(dir=unpacktempdir)
			os.write(tmpfile[0], databytes)
			os.fdopen(tmpfile[0]).close()
			scanfile = tmpfile[1]
			carved = True
			path = tmpfile[1]

		datafile = open(path, 'rb')
		databuffer = []
		offset = 0
		datafile.seek(offset)
		databuffer = datafile.read(100000)
		while databuffer != '':
			for marker in markerDict.keys():
				for markerstring in markerDict[marker]:
					markeroffset = databuffer.find(markerstring)
					if markeroffset != -1:
						results.append(marker)
			## move the offset 100000
			datafile.seek(offset + 100000)
			databuffer = datafile.read(100000)
			offset = offset + len(databuffer)
		datafile.close()
		if carved:
			os.unlink(path)
        except Exception, e:
		print >>sys.stderr, e
                return None
	if results != []:
		return list(set(results))
	return None

## The result of this method is a list of library names that the file dynamically links
## with. The path of these libraries is not given, since this is usually not recorded
## in the binary (unless RPATH is used) but determined at runtime: it is dependent on
## the dynamic linker configuration on the device. With some mixing and matching it is
## nearly always to determine which library in which path is used, since most installations
## don't change the default search paths.
def searchDynamicLibs(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(path)
	ms.close()
	if "ELF" in mstype:
		libs = []
		p = subprocess.Popen(['readelf', '-d', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
                	return
		for line in stanout.split('\n'):
			if "Shared library:" in line:
				libs.append(line.split(': ')[1][1:-1])
		if libs == []:
			return None
		else:
			return (['libs'], libs)

def dynamicLibsPrettyPrint(res, root, envvars=None):
	tmpnode = root.createElement('libs')
	for lib in res:
		tmpnode2 = root.createElement('lib')
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = lib
		tmpnode2.appendChild(tmpnodetext)
		tmpnode.appendChild(tmpnode2)
	return tmpnode

## This method uses readelf to determine the architecture of the executable file.
## This is necessary because sometimes leftovers from different products (and
## different architectures) can be found in one firmware.
def scanArchitecture(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(path)
	ms.close()
	if "ELF" in mstype:
		p = subprocess.Popen(['readelf', '-h', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
			return
		for line in stanout.split('\n'):
			if "Machine:" in line:
				return (['architecture'], line.split(':')[1].strip())

def searchLoadLin(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'loadlin': [ 'Ooops..., size of "setup.S" has become too long for LOADLIN,'
			, 'LOADLIN started from $'
			]}
	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['loadlin'], True)

def searchIptables(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'iptables':[ 'iptables who? (do you need to insmod?)'
			, 'Will be implemented real soon.  I promise ;)'
			, 'can\'t initialize iptables table `%s\': %s'
			]}
	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['iptables'], True)

def searchDproxy(path, tags, blacklist=[], debug=False, envvars=None,unpacktempdir=None):
	markerStrings = {'dproxy': [ '# dproxy monitors this file to determine when the machine is'
			, '# If you want dproxy to log debug info specify a file here.'
			]}
	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['dproxy'], True)

def searchEzIpupdate(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'ez-ipupdate': [ 'ez-ipupdate Version %s, Copyright (C) 1998-'
			, '%s says that your IP address has not changed since the last update'
			, 'you must provide either an interface or an address'
			]}
	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['ez-ipupdate'], True)

def searchLibusb(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'libusb': [ 'Check that you have permissions to write to %s/%s and, if you don\'t, that you set up hotplug (http://linux-hotplug.sourceforge.net/) correctly.'
			, 'usb_os_find_busses: Skipping non bus directory %s'
			, 'usb_os_init: couldn\'t find USB VFS in USB_DEVFS_PATH'
			]}
	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['libusb'], True)

def searchVsftpd(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'vsftpd': [ 'vsftpd: version'
			, '(vsFTPd '
			, 'VSFTPD_LOAD_CONF'
			, 'run two copies of vsftpd for IPv4 and IPv6'
			]}

	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['vsftpd'], True)

def searchHostapd(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'hostapd': [ 'hostapd v'
			]}

	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['hostapd'], True)

def searchWpaSupplicant(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'wpasupplicant': [ 'wpa_supplicant v'
			]}

	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['wpasupplicant'], True)

def searchIproute(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'iproute2':[ 'Usage: tc [ OPTIONS ] OBJECT { COMMAND | help }'
			, 'tc utility, iproute2-ss%s'
			, 'Option "%s" is unknown, try "tc -help".'
			]}

	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['iproute2'], True)

def searchWirelessTools(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'wireless-tools': [ "Driver has no Wireless Extension version information."
			, "Wireless Extension version too old."
			, "Wireless-Tools version"
			, "Wireless Extension, while we are using version %d."
			, "Currently compiled with Wireless Extension v%d."
       	                ]}

	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['wireless-tools'], True)

def searchRedBoot(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	markerStrings = {'redboot': ["Display RedBoot version information"]}

	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['redboot'], True)

def searchUBoot(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
        markerStrings = {'uboot': [ "run script starting at addr"
			, "Hit any key to stop autoboot: %2d"
			, "## Binary (kermit) download aborted"
			, "## Ready for binary (ymodem) download "
			]}

	res = genericSearch(path, markerStrings, blacklist)
	if res != None:
		return (['uboot'], True)

## What actually do these dependencies mean?
## Are they dependencies of the installer itself, or of the programs that are
## installed by the installer?
def searchWindowsDependencies(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	## first determine if we are dealing with a MS Windows executable
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(path)
	ms.close()
	if not 'PE32 executable for MS Windows' in mstype and not "PE32+ executable for MS Windows" in mstype:
                return None
	deps = extractor.searchAssemblyDeps(path)
	if deps == None:
		return None
	if deps == []:
		return None
	else:
		return (['windowsdependencies'], deps)

def xmlPrettyPrintWindowsDeps(res, root, envvars=None):
	pass

## method to extract meta information from PDF files
def scanPDF(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	## we only want to scan whole PDF files. If anything has been carved from
	## it, we don't want to see it. Blacklists are a good indicator, but we
	## should have some way to prevent other scans from analysing this file.
	if blacklist != []:
		return None
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	mstype = ms.file(path)
	ms.close()
	if not 'PDF document' in mstype:
                return None
	else:
		p = subprocess.Popen(['pdfinfo', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
		(stanout, stanerr) = p.communicate()
		if p.returncode != 0:
                	return
		else:
			pdfinfo = {}
			pdflines = stanout.rstrip().split("\n")
			for pdfline in pdflines:
				pdfsplit = pdfline.split(":", 1)
				if len(pdfsplit) != 2:
					continue
				(tag, value) = pdfsplit
				if tag == "Title":
					pdfinfo['title'] = value.strip()
				if tag == "Author":
					pdfinfo['author'] = value.strip()
				if tag == "Creator":
					pdfinfo['creator'] = value.strip()
				if tag == "CreationDate":
					pdfinfo['creationdate'] = value.strip()
				if tag == "Producer":
					pdfinfo['producer'] = value.strip()
				if tag == "Tagged":
					pdfinfo['tagged'] = value.strip()
				if tag == "Pages":
					pdfinfo['pages'] = int(value.strip())
				if tag == "Page size":
					pdfinfo['pagesize'] = value.strip()
				if tag == "Encrypted":
					pdfinfo['encrypted'] = value.strip()
				if tag == "Optimized":
					pdfinfo['optimized'] = value.strip()
				if tag == "PDF version":
					pdfinfo['version'] = value.strip()
			return (['pdfinfo'], pdfinfo)

def pdfPrettyPrint(res, root, envvars=None):
	tmpnode = root.createElement('pdfinfo')
	for key in res:
		tmpnode2 = root.createElement(key)
		tmpnodetext = xml.dom.minidom.Text()
		tmpnodetext.data = str(res[key])
		tmpnode2.appendChild(tmpnodetext)
		tmpnode.appendChild(tmpnode2)
	return tmpnode

## scan for mentions of licenses
######################################
## !!! WARNING WARNING WARNING !!! ###
######################################
## This should only be used as an indicator for further investigation,
## never as proof that a binary is actually licensed under a license!
def scanLicenses(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	licenseidentifiers = {}

	## identifiers for any GNU license (could apply to multiple licenses)
	licenseidentifiers['GNU'] = ["General Public License", "http://www.gnu.org/licenses/", "http://gnu.org/licenses/", "http://www.gnu.org/gethelp/", "http://www.gnu.org/software/"]

	## identifiers for a version of GNU GPL
	licenseidentifiers['GPL'] = ["http://gnu.org/licenses/gpl.html", "http://www.gnu.org/licenses/gpl.html",
                                "http://www.gnu.org/licenses/gpl.txt", "http://www.opensource.org/licenses/gpl-license.php",
                                "http://www.gnu.org/copyleft/gpl.html"]

	## identifiers specifically for GPLv2
	licenseidentifiers['GPLv2'] = ["http://gnu.org/licenses/gpl-2.0.html", "http://www.gnu.org/licenses/old-licenses/gpl-2.0.html"]

	## identifiers specifically for LGPLv2.1
	licenseidentifiers['LGPLv2.1'] = ["http://gnu.org/licenses/old-licenses/lgpl-2.1.html"]

	## identifiers specifically for Apache 2.0
	licenseidentifiers['Apache2.0'] = ["http://www.apache.org/licenses/LICENSE-2.0", "http://opensource.org/licenses/apache2.0.php"]

	## identifiers for MPL license
	licenseidentifiers['MPL'] = ["http://www.mozilla.org/MPL/"]

	## identifiers for MIT license
	licenseidentifiers['MIT'] = ["http://www.opensource.org/licenses/mit-license.php"]

	## identifiers for BSD license
	licenseidentifiers['BSD'] = ["http://www.opensource.org/licenses/bsd-license.php"]

	## identifiers specifically for OpenOffice
	licenseidentifiers['OpenOffice'] = ["http://www.openoffice.org/license.html"]

	## identifiers specifically for BitTorrent
	licenseidentifiers['BitTorrent'] = ["http://www.bittorrent.com/license/"]

	## identifiers specifically for Tizen
	licenseidentifiers['Tizen'] = ["http://www.tizenopensource.org/license"]

	## identifiers specifically for OpenSSL
	licenseidentifiers['OpenSSL'] = ["http://www.openssl.org/source/license.html"]

	## identifiers specifically for Boost
	licenseidentifiers['Boost'] = ["http://www.boost.org/LICENSE_1_0.txt", "http://pocoproject.org/license.html"]

	## identifiers specifically for zlib
	licenseidentifiers['zlib'] = ["http://www.zlib.net/zlib_license.html"]

	## identifiers specifically for jQuery
	licenseidentifiers['jQuery'] = ["http://jquery.org/license"]

	## identifiers specifically for libxml
	licenseidentifiers['libxml'] = ["http://xmlsoft.org/FAQ.html#License"]

	## identifiers specifically for ICU
	licenseidentifiers['ICU'] = ["http://source.icu-project.org/repos/icu/icu/trunk/license.html"]

	licenseresults = genericSearch(path, licenseidentifiers, blacklist)

	if licenseresults != None:
		return (['licenses'], licenseresults)
	else:
		return None

def licensesPrettyPrint(res, root, envvars=None):
	tmpnode = root.createElement('licenses')
	for key in res:
		tmpnode2 = root.createElement(key)
		tmpnode.appendChild(tmpnode2)
	return tmpnode

## scan for mentions of several forges
## Some of the URLs of the forges no longer work or are redirected, but they
## might still pop up in binaries.
def scanForges(path, tags, blacklist=[], debug=False, envvars=None, unpacktempdir=None):
	forgeidentifiers = {}

	forgeidentifiers['sourceforge.net'] = ["sourceforge.net"]

	forgeidentifiers['freedesktop.org'] = ["http://cvs.freedesktop.org/", "http://cgit.freedesktop.org/"]

	forgeidentifiers['code.google.com'] = ["code.google.com", "googlecode.com"]

	forgeidentifiers['savannah.gnu.org'] = ["savannah.gnu.org/"]

	forgeidentifiers['github.com'] = ["github.com"]

	forgeidentifiers['bitbucket.org'] = ["bitbucket.org"]

	forgeidentifiers['tigris.org'] = ["tigris.org"]

	forgeidentifiers['svn.apache.org'] = ["http://svn.apache.org/"]

	## various gits:
	## http://git.fedoraproject.org/git/
	## https://fedorahosted.org/

	forgeresults = genericSearch(path, forgeidentifiers, blacklist)

	if forgeresults != None:
		return (['forges'], forgeresults)
	else:
		return None

def forgesPrettyPrint(res, root, envvars=None):
	tmpnode = root.createElement('forges')
	for key in res:
		tmpnode2 = root.createElement(key)
		tmpnode.appendChild(tmpnode2)
	return tmpnode

## experimental clamscan feature
## Always run freshclam before scanning to get the latest
## virus signatures!
def scanVirus(path, tags, blacklist=[], debug=False, envvars=None):
	p = subprocess.Popen(['clamscan', "%s" % (path,)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode == 0:
               	return
	else:
		## Oooh, virus found!
		viruslines = stanout.split("\n")
		## first line contains the report:
		virusname = viruslines[0].strip()[len(path) + 2:-6]
		return (['virus'], virusname)
