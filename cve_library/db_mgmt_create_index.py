#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Script to check and ensure that the recommended index are created as recommended.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014 	psychedelys
# Copyright (c) 2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, "./lib/"))

import pymongo

import traceback

from Config import Configuration

db = Configuration.getMongoConnection()

try:
  db.cpe.ensure_index( 'id' )
  print('success to create index on cpe')
except Exception:
  print('failed to create index on cpe')
  traceback.print_exc()
  print('=======')
  pass

try:
  db.cpeother.ensure_index( 'id' )
  print('success to create index on cpeother')
except Exception:
  print('failed to create index on cpeother')
  traceback.print_exc()
  print('=======')
  pass

try:
  db.cves.ensure_index( 'id' )
  print('success to create index on cves')
except Exception:
  print('failed to create index on cves')
  traceback.print_exc()
  print('=======')
  pass

try:
  db.cves.ensure_index( 'vulnerable_configuration' )
  print('success to create index on cves vulnerable_configuration')
except Exception:
  print('failed to create index on cves vulnerable_configuration')
  traceback.print_exc()
  print('=======')
  pass

try:
  db.cves.ensure_index( 'Modified' )
  print('success to create index on cves Modified')
except Exception:
  print('failed to create index on cves Modified')
  traceback.print_exc()
  print('=======')
  pass

try:
  db.vfeed.ensure_index( 'id' )
  print('success to create index on vfeed')
except Exception:
  print('failed to create index on vfeed')
  traceback.print_exc()
  print('=======')
  pass

try:
  db.vendor.ensure_index( 'id' )
  print('success to create index on vendor')
except Exception:
  print('failed to create index on vendor')
  traceback.print_exc()
  print('=======')
  pass

try:
  db.d2sec.ensure_index( 'id' )
  print('success to create index on d2sec')
except Exception:
  print('failed to create index on d2sec')
  traceback.print_exc()
  print('=======')
  pass

try:
  db.mgmt_whitelist.ensure_index( 'id' )
  print('success to create index on mgmt_whitelist')
except Exception:
  print('failed to create index on mgmt_whitelist')
  traceback.print_exc()
  print('=======')
  pass

try:
  db.mgmt_blacklist.ensure_index( 'id' )
  print('success to create index on mgmt_blacklist')
except Exception:
  print('failed to create index on mgmt_blacklist')
  traceback.print_exc()
  print('=======')
  pass

