#!/usr/bin/env python

from distutils.core import setup
import glob
import os.path

setup(name='bat',
      version='1.0',
      description='Binary Analysis Tool',
      author='Loohuis Consulting',
      author_email='info@binaryanalysis.org',
      url='http://www.binaryanalysis.org/',
      packages=[''],
      scripts=['bruteforce.py', 'busybox-compare-configs.py'],
      data_files=[('/etc/bat/configs', glob.glob('configs/*')),
                  ('/etc/bat',  ['bruteforce-config']),
                  ('share/doc/bat-1.0',  glob.glob('../doc/*')),
                 ]
     )
