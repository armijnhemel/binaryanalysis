#!/usr/bin/python

## Binary Analysis Tool
## Copyright 2015 Armijn Hemel for Tjaldur Software Governance Solutions
## Licensed under Apache 2.0, see LICENSE file for details

'''
Abstraction class for BAT databases. Currently supported: sqlite3, postgresql
'''

import os.path

class BatDb():
	def __init__(self, dbbackend):
		self.conn = None
		self.dbbackend = dbbackend
	def getConnection(self, database):
		if self.dbbackend == 'sqlite3':
			## check if the database file exists
			if not os.path.exists(database):
				return
			import sqlite3
			self.conn = sqlite3.connect(database)
			self.conn.text_factory = str
		elif self.dbbackend == 'postgresql':
			import psycopg2
			## TODO: use environment variables for this instead of hardcoding
			self.conn = psycopg2.connect("dbname=bat user=bat password=bat")
		return self.conn
