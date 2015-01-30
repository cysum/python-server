#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
#
# Import script of cpe (Common Platform Enumeration) definition
# into a collection used for human readable lookup of product name.
# This is locating the cpe used inside the cve, but only the cpe
# not present inside the cpe official dictionary.
#
# Exemple:
#    CVE-2014-5446 -> cpe:/a:zohocorp:manageengine_netflow_analyzer:.*
#    but 'cpe:/a:zohocorp:manageengine_netflow_analyzer' is not in the
#    cpe official dictionary.
#
# Imported in cvedb in the collection named cpeother.
#
# The format of the collection is the following
#
# { "_id" : ObjectId("50a2739eae24ac2274eae7c0"),
#     "id" : "cpe:/a:zohocorp:manageengine_netflow_analyzer:10.2",
#      "title" : "cpe:/a:zohocorp:manageengine_netflow_analyzer:10.2"
# }
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014 psychedelys
# Copyright (c) 2014-2015 PidgeyL

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, "./lib/"))

import pymongo

from Config import Configuration

# connect to db
db = Configuration.getMongoConnection()
cpe = db.cpe
cpeother = db.cpeother
cve = db.cves
info = db.info

icve = info.find_one({'db': 'cve'})
icpeo = info.find_one({'db': 'cpeother'})

date = False
if icve is not None and icpeo is not None:
    # Go check date
    if icve['last-modified'] >= icpeo['last-modified']:
        sys.exit("Not modified")
    else:
        date = True

info.update({'db': 'cpeother'}, {"$set":{'last-modified': icve['last-modified']}}, upsert=True)

collections = []
if date:
    collections = cve.find({'last-modified': { '$gt': icve['last-modified']} })
else:
    collections = cve.find({})

for item in collections:
    for cpeentry in item['vulnerable_configuration']:
        checkdup = cpeother.find(({'id': cpeentry}))
        if checkdup.count() <= 0:
            entry = cpe.find(({'id': cpeentry}))
            if entry.count() <= 0:
                title = cpeentry
                title = title.replace('cpe:/a:', '')
                title = title.replace('cpe:/h:', '')
                title = title.replace('cpe:/o:', '')
                title = title.replace(':', ' ',10)
                title = title.replace('_', ' ',10)
                title = title.title()
                cpeother.insert({'id': cpeentry,'title': title})
#            else:
#                cpeother.update({'id': name}, {"$set":{'title': title}})
