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
	def getConnection(self, database, scanenv={}):
		if self.dbbackend == 'sqlite3':
			## check if the database file exists
			if not os.path.exists(database):
				return
			import sqlite3
			self.conn = sqlite3.connect(database)
			self.conn.text_factory = str
		elif self.dbbackend == 'postgresql':
			import psycopg2
			if not 'POSTGRESQL_USER' in scanenv:
				return
			if not 'POSTGRESQL_PASSWORD' in scanenv:
				return
			if not 'POSTGRESQL_DB' in scanenv:
				return
			try:
				self.conn = psycopg2.connect(database=scanenv['POSTGRESQL_DB'], user=scanenv['POSTGRESQL_USER'], password=scanenv['POSTGRESQL_PASSWORD'], host=scanenv.get('POSTGRESQL_HOST', None), port=scanenv.get('POSTGRESQL_PORT', None), hostaddr=scanenv.get('POSTGRESQL_HOSTADDR', None))
			except Exception, e:
				print e
				return
		return self.conn
	def getQuery(self, query):
		if self.dbbackend == 'sqlite3':
			query = query.replace('%s', '?')
			return query
		else:
			return query
