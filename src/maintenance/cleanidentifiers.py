#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

import sqlite3, collections

conn = sqlite3.connect('/gpl/master2/master.sqlite3')
cursor = conn.cursor()

cursor.execute("select stringidentifier from extracted_string")

remove = set()

maxcutoff = 1000
mincutoff = 4

total = 0

counter = collections.Counter()
removetotalmax = 0
removetotalmin = 0

stringidentifiers = map(lambda x: x[0], cursor.fetchmany(100000))

while stringidentifiers != []:
	total += len(stringidentifiers)
	toremovemax = filter(lambda x: len(x) >= maxcutoff, stringidentifiers)
	toremovemin = filter(lambda x: len(x) <= mincutoff, stringidentifiers)
	removetotalmax += len(toremovemax)
	removetotalmin += len(toremovemin)
	remove.update(toremovemax)
	remove.update(toremovemin)
	counter.update(map(lambda x: len(x), stringidentifiers))

	stringidentifiers = map(lambda x: x[0], cursor.fetchmany(1000))

for r in remove:
	print r
	cursor.execute("delete from extracted_string where stringidentifier=?", (r,))
	print
conn.commit()

cursor.close()
conn.close()
