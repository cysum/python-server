#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Importing CPE entries in a Redis database to improve lookup
#
# Until now, this part is only used by the web interface to improve response time
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014 		Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, "./lib/"))

import pymongo
import redis

from Config import Configuration

# connect to db
db = Configuration.getMongoConnection()
cpe = db.cpe

try:
    r = Configuration.getRedisVendorConnection()
except:
    sys.exit(1)

for e in cpe.find({}):
    try:
        value = e['id']
        if e['id'].count(':') > 4:
            value = ":".join(str(x) for x in (value.split(':')[:5]))
        (prefix, cpetype, vendor, product, version) = value.split(':')
    except:
        pass
    r.sadd("prefix:"+prefix, cpetype)
    r.sadd("t:"+cpetype, vendor)
    r.sadd("v:"+vendor, product)
    r.sadd("p:"+product, version)
