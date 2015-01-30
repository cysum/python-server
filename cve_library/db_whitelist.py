#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Whitelist feature to mark CVE's for CPE's of personal interest
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
argparser = argparse.ArgumentParser(description='populate/update the whitelist used in webviews')
argparser.add_argument('-a', action='append', help='add one or more CPE to whitelist')
argparser.add_argument('-r', action='append', help='remove one or more CPE from whitelist')
argparser.add_argument('-i', help='filename of the whitelist to import')
argparser.add_argument('-e', help='filename of the whitelist to export')
argparser.add_argument('-d', action='store_true', help='drop the whitelist')
argparser.add_argument('-f', action='store_true', help='force an action')
argparser.add_argument('-v', action='store_true', help='verbose output')
args = argparser.parse_args()

# connect to db
db = Configuration.getMongoConnection()
collection = db.mgmt_whitelist

def importWhitelist(importFile):
    oList = CPEList(collection, args)
    oList.importList(importFile)

def exportWhitelist(exportFile):
    oList = CPEList(collection, args)
    oList.exportList(exportFile)

def dropWhitelist():
    oList = CPEList(collection, args)
    oList.dropCollection()

def countWhitelist():
    oList = CPEList(collection, args)
    return oList.countItems()

def checkWhitelist(cpe):
    oList = CPEList(collection, args)
    amount = oList.check(cpe)
    return amount

def insertWhitelist(cpe):
    oList = CPEList(collection, args)
    return oList.insert(cpe)

def removeWhitelist(cpe):
    oList = CPEList(collection, args)
    return oList.remove(cpe)

def updateWhitelist(cpeOld,cpeNew):
    oList = CPEList(collection,args)
    return oList.update(cpeOld,cpeNew)

if __name__=='__main__':
    oList = CPEList(collection, args)
    oList.process()
