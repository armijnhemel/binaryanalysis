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
      packages=['', 'bat'],
      license="Apache 2.0",
      scripts=['appletname-extractor.py', 'bruteforce.py', 'busybox-compare-configs.py'],
      data_files=[('/etc/bat/configs', glob.glob('configs/*')),
                  ('/etc/bat',  ['bruteforce-config']),
                 ],
     long_description="""The Binary Analysis Tool is a modular framework that assists with auditing
the contents of compiled software. It makes it easier and cheaper to look
inside technology, and this helps compliance and due diligence activities.

The tool is freely available to everyone. The community can use it and
participate in further development, and work together to help reduce errors
when shipping devices or products containing Free and Open Source Software."""
     )
