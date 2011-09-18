import os, sys, subprocess, re, zlib, tempfile


def readJFFS2Inodes(path):
	p = subprocess.Popen(['jffs2dump', '-cv', path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	(stanout, stanerr) = p.communicate()
	if p.returncode != 0:
		return ([], [])
	st = stanout.split("\n")

	## (offset, size, parent, inode, name)
	direntries = {}

	## (offset, size, inode, name)
	nodeentries = []

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
	return (direntries, nodeentries)

def unpackJFFS2(path, tempdir=None):
	if tempdir == None:
		tmpdir = tempfile.mkdtemp()
	else:
		## for now, change this
		tmpdir = tempfile.mkdtemp()
	(direntries, nodeentries) = readJFFS2Inodes(path)

	## first get all the entries for the direntries (a misnomer)
	directories = []
	for d in direntries.keys():
		directories.append(direntries[d]['parent'])
	directories = list(set(directories))
	directories.sort()

	pathinodes = {}

	for n in direntries.keys():
		## create directory structure
		if n in directories:
			parentdirs = direntries[n]['name']
			parent = direntries[n]['parent']
			while parent != 1:
				parentdirs = direntries[parent]['name'] + "/" + parentdirs
				parent = direntries[parent]['parent']
			##
			pathinodes[n] = parentdirs
			parentdirs = tmpdir + "/" +  parentdirs
			os.makedirs(parentdirs)
		## we have a leaf node, so we need to unpack data here
		else:
			pass
	print pathinodes
	return None

unpackJFFS2('/tmp/test.jffs2')

'''
bla = open('/tmp/test.jffs2').read()

unzfiledata = ""

for n in nodeentries:
	if n['inode'] == 8:
		filedata = bla[n['offset'] + 0x44: n['offset'] + n['size']]
		unzfiledata = unzfiledata + zlib.decompress(filedata)

blebber = open('/tmp/testroot.jffs2', 'w')
blebber.write(unzfiledata)
blebber.close()

## for each inode: isize == sum(dsize of all inode entries)
'''
