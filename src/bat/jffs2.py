import os, sys, subprocess, re, zlib, tempfile

## Binary Analysis Tool
## Copyright 2011-2013 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

## method to process output of jffs2dump and read all the inodes from a JFFS2 file system.
def readJFFS2Inodes(path, bigendian):
	## quick hack for systems that don't have /usr/sbin in $PATH (such as Debian and Ubuntu)
	unpackenv = os.environ.copy()
	unpackenv['PATH'] = unpackenv['PATH'] + ":/usr/sbin"

	if bigendian:
		p = subprocess.Popen(['jffs2dump', '-bcv', path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=unpackenv)
	else:
		p = subprocess.Popen(['jffs2dump', '-cv', path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=unpackenv)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return ([], [])
	st = stanout.split("\n")

	## (offset, size, parent, inode, name)
	direntries = {}

	## (offset, size, inode, name)
	nodeentries = []
	maxoffset = 0

	for s in st:
		if re.match("\s+Dirent", s) != None:
			(dirent, size, parentinode, version, inode, namesize, name) = s.split(',', 6)
			res = re.search("\s+Dirent\s*node\sat\s(\w+)", dirent)
			if res != None:
				offset = int(res.groups()[0], 16)
			res = re.search("\s+#pino\s*(\d+)", parentinode)
			if res != None:
				pinodenr = int(res.groups()[0])
			res = re.search("\s+#ino\s*(\d+)", inode)
			if res != None:
				inodenr = int(res.groups()[0])
			## use the namesize to get the name.
			res = re.search("\s+nsize\s*(\d+)", namesize)
			if res != None:
				namesize = int(res.groups()[0])
			nodename = name[-namesize:]
			direntries[inodenr] = {'offset': offset, 'size': 0, 'parent': pinodenr, 'name': nodename}
			if offset > maxoffset:
				maxoffset = offset
		elif re.match("\s+Inode", s) != None:
			(inodeent, size, inode, version, inodesize, csize, dsize, decompressedoffset) = s.split(',', 7)
			res = re.search("\s+dsize\s*(\d+)", dsize)
			if res != None:
				decompressedsize = int(res.groups()[0])
				if decompressedsize == 0: continue
			res = re.search("\s+csize\s*(\d+)", csize)
			if res != None:
				compressedsize = int(res.groups()[0])
			res = re.search("\s+Inode\s*node\sat\s(\w+)", inodeent)
			if res != None:
				offset = int(res.groups()[0], 16)
			res = re.search("\s+totlen\s(\w+)", size)
			if res != None:
				size = int(res.groups()[0], 16)
			res = re.search("\s+#ino\s*(\d+)", inode)
			if res != None:
				inodenr = int(res.groups()[0])
			nodeentries.append({'offset': offset, 'size': size, 'inode': inodenr, 'compressedsize': compressedsize, 'decompressedsize': decompressedsize})
			if offset > maxoffset:
				maxoffset = offset
	return (direntries, nodeentries, maxoffset)

def unpackJFFS2(path, tempdir=None, bigendian=False):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		tmpdir = tempdir

	res = readJFFS2Inodes(path, bigendian)
	if res == ({}, [], 0):
		## cleanup
		if tempdir == None:
			os.rmdir(tmpdir)
		return None
	(direntries, nodeentries, maxoffset) = res

	## first get all the entries for the direntries (a misnomer)
	directories = []
	for d in direntries.keys():
		directories.append(direntries[d]['parent'])
	directories = list(set(directories))
	directories.sort()

	pathinodes = {1: ''}

	data = open(path).read()

	jffs2size = maxoffset

	## An extra sanity check to see if we actually have a valid file system. For each parent inode
	## except '1' there should be an entry in direntries. If not, we have a dangling part of a JFFS2
	## system.
	for n in direntries.keys():
		if direntries[n].has_key('parent'):
			if not direntries[n]['parent'] in direntries.keys() and direntries[n]['parent'] != 1:
				return None

	entrynames = map(lambda x: direntries[x]['name'], direntries.keys())
	for n in direntries.keys():
		## recreate directory structure
		if n in directories:
			parentdirs = direntries[n]['name']
			parent = direntries[n]['parent']
			while parent != 1:
				parentdirs = direntries[parent]['name'] + "/" + parentdirs
				parent = direntries[parent]['parent']
			pathinodes[n] = parentdirs
			parentdirs = tmpdir + "/" +  parentdirs
			os.makedirs(parentdirs)
		## we have a leaf node, so we need to unpack data here. Data is zlib compressed per inode.
		else:
			unzfiledata = ""
			for node in nodeentries:
				if node['inode'] == n:
					filedata = data[node['offset'] + 0x44: node['offset'] + node['size']]
					if node['offset'] == maxoffset:
						jffs2size += node['size']
					try:
						unzfiledata = unzfiledata + zlib.decompress(filedata)
					except Exception, e:
						unzfiledata = unzfiledata + filedata
			if len(unzfiledata) <= 254 and len(unzfiledata) > 0:
				## a symlink is written as an ASCII file with the target of the symlink as the content of the file
				## TODO: handle properly
				unzsplit = unzfiledata.split('/')
				if unzsplit[-1] in entrynames:
					#continue
					pass
			datafile = open('%s/%s/%s' % (tmpdir, pathinodes[direntries[n]['parent']], direntries[n]['name']), 'w')
			datafile.write(unzfiledata)
			datafile.close()
	return (tmpdir, jffs2size)
