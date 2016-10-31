#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains methods to parse a Java class file

It returns the following information:

* method names
* field names
* class name
* string identifiers
* source file (if present)
* size of class file

Documentation on how to parse class files can be found here:

http://docs.oracle.com/javase/specs/jvms/se6/html/ClassFile.doc.html
https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html

Extra documentation:

https://tomcat.apache.org/tomcat-8.0-doc/api/constant-values.html
'''

import os, sys, struct

## some constants that are used in Java class files
UTF8 = 1
INTEGER = 3
FLOAT = 4
LONG = 5
DOUBLE = 6
CLASS = 7
STRING = 8
FIELDREFERENCE = 9
METHODREFERENCE = 10
INTERFACEMETHODREFERENCE = 11
NAMEANDTYPE = 12
METHODHANDLE = 15
METHODTYPE = 16
INVOKEDYNAMIC = 18

## parse a Java class
## returns:
## * method names
## * field names
## * class name
## * string identifiers
## * source file (if present)
## * size of class file
def parseJava(filename, offset):
	classfile = open(filename, 'rb')

	classfile.seek(offset)

	## read the first four bytes and check it with
	## the Java 'magic'. If these are not present it is not a
	## class file.
	javamagic = classfile.read(4)
	if javamagic != '\xca\xfe\xba\xbe':
		classfile.close()
		return None

	## The minor and major version of the Java class file format. These are not yet
	## used for checks, yet.
	classbytes = classfile.read(2)
	if len(classbytes) != 2:
		classfile.close()
		return None

	minorversion = struct.unpack('>H', classbytes)[0]

	classbytes = classfile.read(2)
	if len(classbytes) != 2:
		classfile.close()
		return None

	majorversion = struct.unpack('>H', classbytes)[0]

	## The amount of entries in the so called "constant pool", +1
	classbytes = classfile.read(2)
	if len(classbytes) != 2:
		classfile.close()
		return None

	constant_pool_count = struct.unpack('>H', classbytes)[0]

	lookup_table = {}
	class_lookups = []
	string_lookups = []

	class_lookup_table = {}

	## parse the constant pool and split data accordingly
	## Values that are not interesting are parsed, but not
	## stored.
	skip = False
	brokenclass = False
	for i in range(1, constant_pool_count):
		if brokenclass:
			classfile.close()
			return
		if skip:
			skip = False
			continue
		classbytes = classfile.read(1)
		if len(classbytes) != 1:
			brokenclass = True
			break
		constanttag = ord(classbytes)
		if constanttag == CLASS:
			## store the index of the class name for
			## later look up
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
			name_index = struct.unpack('>H', classbytes)[0]
			class_lookups.append(name_index)
			class_lookup_table[i] = name_index
		elif constanttag == FIELDREFERENCE or constanttag == METHODREFERENCE or constanttag == INTERFACEMETHODREFERENCE:
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
			class_index = struct.unpack('>H', classbytes)
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
			name_and_type_index = struct.unpack('>H', classbytes)[0]
		elif constanttag == STRING:
			## store the indexes for strings that need to
			## be looked up.
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
			string_index = struct.unpack('>H', classbytes)[0]
			string_lookups.append(string_index)
		elif constanttag == INTEGER or constanttag == FLOAT:
			classbytes = classfile.read(4)
			if len(classbytes) != 4:
				brokenclass = True
				break
			constantbytes = struct.unpack('>I', classbytes)
		elif constanttag == LONG or constanttag == DOUBLE:
			classbytes = classfile.read(4)
			if len(classbytes) != 4:
				brokenclass = True
				break
			highconstantbytes = struct.unpack('>I', classbytes)
			classbytes = classfile.read(4)
			if len(classbytes) != 4:
				brokenclass = True
				break
			lowconstantbytes = struct.unpack('>I', classbytes)
			## longs and doubles take up a bit more space, so skip
			## the next entry
			skip = True
		elif constanttag == NAMEANDTYPE:
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
			name_index = struct.unpack('>H', classbytes)
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
			descriptor_index = struct.unpack('>H', classbytes)
		elif constanttag == UTF8:
			## store strings that were found
			## so they can later be looked up.
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
			stringlength = struct.unpack('>H', classbytes)[0]
			utf8string = classfile.read(stringlength)
			if len(utf8string) != stringlength:
				brokenclass = True
				break
			lookup_table[i] = utf8string
		elif constanttag == METHODHANDLE:
			## reference kind
			classbytes = classfile.read(1)
			if len(classbytes) != 1:
				brokenclass = True
				break
			## reference index
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
		elif constanttag == METHODTYPE:
			## descriptor index
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
		elif constanttag == INVOKEDYNAMIC:
			## bootstrap_method_attr_index
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
			## name_and_type_index
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
	if brokenclass:
		classfile.close()
		return

	classbytes = classfile.read(2)
	if len(classbytes) != 2:
		classfile.close()
		return None
	accessflags = struct.unpack('>H', classbytes)[0]
	classbytes = classfile.read(2)
	if len(classbytes) != 2:
		classfile.close()
		return None
	thisclass = struct.unpack('>H', classbytes)[0]
	try:
		classname = lookup_table[class_lookup_table[thisclass]]
	except:
		classfile.close()
		return None

	classbytes = classfile.read(2)
	if len(classbytes) != 2:
		classfile.close()
		return None
	superclass = struct.unpack('>H', classbytes)[0]

	classbytes = classfile.read(2)
	if len(classbytes) != 2:
		classfile.close()
		return None
	interfaces_count = struct.unpack('>H', classbytes)[0]

	for i in range(0, interfaces_count+1):
		classbytes = classfile.read(2)

	fields_count = struct.unpack('>H', classbytes)[0]

	fieldnames = []
	brokenclass = False
	for i in range(0, fields_count):
		if brokenclass:
			classfile.close()
			return
		## access flags
		classbytes = classfile.read(2)
		if len(classbytes) != 2:
			brokenclass = True
			break
		## name_index
		classbytes = classfile.read(2)
		if len(classbytes) != 2:
			brokenclass = True
			break
		name_index = struct.unpack('>H', classbytes)[0]
		try:
			fieldname = lookup_table[name_index]
		except:
			classfile.close()
			return None
		if not '$' in fieldname:
			if fieldname != 'serialVersionUID':
				fieldnames.append(fieldname)
		## descriptor_index
		classbytes = classfile.read(2)
		if len(classbytes) != 2:
			brokenclass = True
			break
		descriptor_index = struct.unpack('>H', classbytes)[0]
		## attributes_count
		classbytes = classfile.read(2)
		if len(classbytes) != 2:
			brokenclass = True
			break
		attributes_count = struct.unpack('>H', classbytes)[0]
		for a in range(0, attributes_count):
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = True
				break
			attribute_name_index = struct.unpack('>H', classbytes)[0]
			classbytes = classfile.read(4)
			if len(classbytes) != 4:
				brokenclass = True
				break
			attribute_length = struct.unpack('>I', classbytes)[0]
			classbytes = classfile.read(attribute_length)
			if len(classbytes) != attribute_length:
				brokenclass = True
				break

	if brokenclass:
		classfile.close()
		return

	classbytes = classfile.read(2)
	if len(classbytes) != 2:
		classfile.close()
		return None
	method_count = struct.unpack('>H', classbytes)[0]

	methodnames = []
	brokenclass = False
	for i in range(0, method_count):
		if brokenclass:
			classfile.close()
			return
		## access flags
		classbytes = classfile.read(2)
		if len(classbytes) != 2:
			brokenclass = False
			break
		## name_index
		classbytes = classfile.read(2)
		if len(classbytes) != 2:
			brokenclass = False
			break
		name_index = struct.unpack('>H', classbytes)[0]
		try:
			method_name = lookup_table[name_index]
		except:
			classfile.close()
			return None
		if not method_name.startswith('access$'):
			if not method_name.startswith('<'):
				if not '$' in method_name:
					methodnames.append(method_name)
		## descriptor_index
		classbytes = classfile.read(2)
		if len(classbytes) != 2:
			brokenclass = False
			break
		descriptor_index = struct.unpack('>H', classbytes)[0]
		## attributes_count
		classbytes = classfile.read(2)
		if len(classbytes) != 2:
			brokenclass = False
			break
		attributes_count = struct.unpack('>H', classbytes)[0]
		for a in range(0, attributes_count):
			classbytes = classfile.read(2)
			if len(classbytes) != 2:
				brokenclass = False
				break
			attribute_name_index = struct.unpack('>H', classbytes)[0]
			classbytes = classfile.read(4)
			if len(classbytes) != 4:
				brokenclass = False
				break
			attribute_length = struct.unpack('>I', classbytes)[0]
			classbytes = classfile.read(attribute_length)
			if len(classbytes) != attribute_length:
				brokenclass = False
				break

	if brokenclass:
		classfile.close()
		return

	sourcefile = None
	classbytes = classfile.read(2)
	if len(classbytes) != 2:
		classfile.close()
		return None

	attributes_count = struct.unpack('>H', classbytes)[0]
	for a in range(0, attributes_count):
		classbytes = classfile.read(2)
		attribute_name_index = struct.unpack('>H', classbytes)[0]
		classbytes = classfile.read(4)
		attribute_length = struct.unpack('>I', classbytes)[0]
		classbytes = classfile.read(attribute_length)
		if lookup_table[attribute_name_index] == 'SourceFile':
			sourcefile_index = struct.unpack('>H', classbytes)[0]
			try:
				sourcefile = lookup_table[sourcefile_index]
			except:
				classfile.close()
				return None

	classsize = classfile.tell() - offset
	classfile.close()

	stringidentifiers = []
	for s in string_lookups:
		stringidentifiers.append(lookup_table[s])

	return {'methods': methodnames, 'fields': fieldnames, 'classname': classname, 'strings': stringidentifiers, 'sourcefile': sourcefile, 'size': classsize}
