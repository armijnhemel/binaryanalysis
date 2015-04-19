#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Abstraction class for BAT databases. Currently supported: sqlite3
'''

import os.path

class BatDb():
	def __init__(self, dbbackend):
		self.conn = None
		self.dbbackend = dbbackend
	def getConnection(self, database):
		if not os.path.exists(database):
			return
		if self.dbbackend == 'sqlite3':
			import sqlite3
			self.conn = sqlite3.connect(database)
			self.conn.text_factory = str
		elif self.dbbackend == 'postgresql':
			import psycopg2
		return self.conn
