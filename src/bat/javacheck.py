#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
This file contains methods to parse a Java class file

Documentation on how to parse class files can be found here:

http://docs.oracle.com/javase/specs/jvms/se6/html/ClassFile.doc.html
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

def parseJava(filename):
	classfile = open(filename, 'rb')

	classfile.seek(0)

	javamagic = classfile.read(4)
	if javamagic != '\xca\xfe\xba\xbe':
		return False

	classbytes = classfile.read(2)
	minorversion = struct.unpack('>H', classbytes)

	classbytes = classfile.read(2)
	majorversion = struct.unpack('>H', classbytes)

	classbytes = classfile.read(2)
	constant_pool_count = struct.unpack('>H', classbytes)[0]

	lookup_table = {}
	class_lookups = []
	string_lookups = []

	class_lookup_table = {}

	skip = False
	for i in range(1, constant_pool_count):
		if skip:
			skip = False
			continue
		classbytes = classfile.read(1)
		constanttag = ord(classbytes)
		if constanttag == CLASS:
			classbytes = classfile.read(2)
			name_index = struct.unpack('>H', classbytes)[0]
			class_lookups.append(name_index)
			class_lookup_table[i] = name_index
		elif constanttag == FIELDREFERENCE or constanttag == METHODREFERENCE or constanttag == INTERFACEMETHODREFERENCE:
			classbytes = classfile.read(2)
			class_index = struct.unpack('>H', classbytes)
			classbytes = classfile.read(2)
			name_and_type_index = struct.unpack('>H', classbytes)[0]
		elif constanttag == STRING:
			classbytes = classfile.read(2)
			string_index = struct.unpack('>H', classbytes)[0]
			string_lookups.append(string_index)
		elif constanttag == INTEGER or constanttag == FLOAT:
			classbytes = classfile.read(4)
			constantbytes = struct.unpack('>I', classbytes)
		elif constanttag == LONG or constanttag == DOUBLE:
			classbytes = classfile.read(4)
			highconstantbytes = struct.unpack('>I', classbytes)
			classbytes = classfile.read(4)
			lowconstantbytes = struct.unpack('>I', classbytes)
			## longs and doubles take up a bit more space, so skip
			## the next entry
			skip = True
		elif constanttag == NAMEANDTYPE:
			classbytes = classfile.read(2)
			name_index = struct.unpack('>H', classbytes)
			classbytes = classfile.read(2)
			descriptor_index = struct.unpack('>H', classbytes)
		elif constanttag == UTF8:
			classbytes = classfile.read(2)
			stringlength = struct.unpack('>H', classbytes)[0]
			utf8string = classfile.read(stringlength)
			lookup_table[i] = utf8string

	classbytes = classfile.read(2)
	accessflags = struct.unpack('>H', classbytes)[0]
	classbytes = classfile.read(2)
	thisclass = struct.unpack('>H', classbytes)[0]
	classname = lookup_table[class_lookup_table[thisclass]]

	classbytes = classfile.read(2)
	superclass = struct.unpack('>H', classbytes)[0]

	classbytes = classfile.read(2)
	interfaces_count = struct.unpack('>H', classbytes)[0]

	for i in range(0, interfaces_count+1):
		classbytes = classfile.read(2)

	fields_count = struct.unpack('>H', classbytes)[0]

	fieldnames = []
	for i in range(0, fields_count):
		## access flags
		classbytes = classfile.read(2)
		## name_index
		classbytes = classfile.read(2)
		name_index = struct.unpack('>H', classbytes)[0]
		fieldname = lookup_table[name_index]
		if not '$' in fieldname:
			if fieldname != 'serialVersionUID':
				fieldnames.append(fieldname)
		## descriptor_index
		classbytes = classfile.read(2)
		descriptor_index = struct.unpack('>H', classbytes)[0]
		## attributes_count
		classbytes = classfile.read(2)
		attributes_count = struct.unpack('>H', classbytes)[0]
		for a in range(0, attributes_count):
			classbytes = classfile.read(2)
			attribute_name_index = struct.unpack('>H', classbytes)[0]
			classbytes = classfile.read(4)
			attribute_length = struct.unpack('>I', classbytes)[0]
			classbytes = classfile.read(attribute_length)

	classbytes = classfile.read(2)
	method_count = struct.unpack('>H', classbytes)[0]

	methodnames = []
	for i in range(0, method_count):
		## access flags
		classbytes = classfile.read(2)
		## name_index
		classbytes = classfile.read(2)
		name_index = struct.unpack('>H', classbytes)[0]
		method_name = lookup_table[name_index]
		if not method_name.startswith('access$'):
			if not method_name.startswith('<'):
				if not '$' in method_name:
					methodnames.append(method_name)
		## descriptor_index
		classbytes = classfile.read(2)
		descriptor_index = struct.unpack('>H', classbytes)[0]
		## attributes_count
		classbytes = classfile.read(2)
		attributes_count = struct.unpack('>H', classbytes)[0]
		for a in range(0, attributes_count):
			classbytes = classfile.read(2)
			attribute_name_index = struct.unpack('>H', classbytes)[0]
			classbytes = classfile.read(4)
			attribute_length = struct.unpack('>I', classbytes)[0]
			classbytes = classfile.read(attribute_length)

	sourcefile = None
	classbytes = classfile.read(2)
	attributes_count = struct.unpack('>H', classbytes)[0]
	for a in range(0, attributes_count):
		classbytes = classfile.read(2)
		attribute_name_index = struct.unpack('>H', classbytes)[0]
		classbytes = classfile.read(4)
		attribute_length = struct.unpack('>I', classbytes)[0]
		classbytes = classfile.read(attribute_length)
		if lookup_table[attribute_name_index] == 'SourceFile':
			sourcefile_index = struct.unpack('>H', classbytes)[0]
			sourcefile = lookup_table[sourcefile_index]

	if not classfile.tell() == os.stat(filename).st_size:
		return False
	classfile.close()

	stringidentifiers = []
	for s in string_lookups:
		stringidentifiers.append(lookup_table[s])

	return {'methods': methodnames, 'fields': fieldnames, 'classname': classname, 'strings': stringidentifiers, 'sourcefile': sourcefile}
