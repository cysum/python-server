#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Blacklist feature to mark CVE's for CPE's of personal interest
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
# make sure these modules are available on your system
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, "./lib/"))

import pymongo

import argparse
import re

from Config import Configuration
from list import CPEList

# parse command line arguments
argparser = argparse.ArgumentParser(description='populate/update the blacklist used in webviews')
argparser.add_argument('-a', action='append', help='add one or more CPE to blacklist')
argparser.add_argument('-r', action='append', help='remove one or more CPE from blacklist')
argparser.add_argument('-i', help='filename of the blacklist to import')
argparser.add_argument('-e', help='filename of the blacklist to export')
argparser.add_argument('-d', action='store_true', help='drop the blacklist')
argparser.add_argument('-f', action='store_true', help='force an action')
argparser.add_argument('-v', action='store_true', help='verbose output')
args = argparser.parse_args()

# connect to db
db = Configuration.getMongoConnection()
collection = db.mgmt_blacklist

def importBlacklist(importFile):
    oList = CPEList(collection, args)
    oList.importList(importFile)

def exportBlacklist(exportFile):
    oList = CPEList(collection, args)
    oList.exportList(exportFile)

def dropBlacklist():
    oList = CPEList(collection, args)
    oList.dropCollection()

def countBlacklist():
    oList = CPEList(collection, args)
    return oList.countItems()

def checkBlacklist(cpe):
    oList = CPEList(collection, args)
    amount = oList.check(cpe)
    return amount

def insertBlacklist(cpe):
    oList = CPEList(collection, args)
    return oList.insert(cpe)

def removeBlacklist(cpe):
    oList = CPEList(collection, args)
    return oList.remove(cpe)

def updateBlacklist(cpeOld,cpeNew):
    oList = CPEList(collection,args)
    return oList.update(cpeOld,cpeNew)

if __name__=='__main__':
    oList = CPEList(collection, args)
    oList.process()
