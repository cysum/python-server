#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Manager for the database
#
# Copyright (c) 2012 		Wim Remens
# Copyright (c) 2012-2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
# make sure these modules are available on your system
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, "./lib/"))

import pymongo

import argparse
import datetime
from urllib.request import urlopen
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

from Config import Configuration

# parse command line arguments
argparser = argparse.ArgumentParser(description='populate/update the local CVE database')
argparser.add_argument('-u', action='store_true', help='update the database')
argparser.add_argument('-p', action='store_true', help='populate the database')
argparser.add_argument('-a', action='store_true', default=False, help='force populating the CVE database')
argparser.add_argument('-f', help='process a local xml file')
argparser.add_argument('-v', action='store_true', help='verbose output')
args = argparser.parse_args()


# init parts of the file names to enable looped file download
file_prefix = "nvdcve-2.0-"
file_suffix = ".xml"
file_mod = "modified"
file_rec = "recent"

# get the current year. This enables us to download all CVE's up to this year :-)
date = datetime.datetime.now()
year = date.year+1

# default config
defaultvalue = {}
defaultvalue['cvss'] = Configuration.getDefaultCVSS()
defaultvalue['cwe'] = "Unknown"

cveStartYear = Configuration.getCVEStartYear()

# define the CVE parser. Thanks to Meredith Patterson (@maradydd) for help on this one.

class CVEHandler(ContentHandler):
    def __init__(self):
        self.cves = []
        self.inCVSSElem = 0
        self.inSUMMElem = 0
        self.inDTElem = 0
        self.inPUBElem = 0
    def startElement(self, name, attrs):
        if name == 'entry':
            self.cves.append({'id': attrs.get('id'), 'references': [],'vulnerable_configuration': []})
            self.ref = attrs.get('id')
        elif name == 'cpe-lang:fact-ref':
            self.cves[-1]['vulnerable_configuration'].append(attrs.get('name'))
        elif name == 'cvss:score':
            self.inCVSSElem = 1
            self.CVSS = ""
        elif name == 'vuln:summary':
            self.inSUMMElem = 1
            self.SUMM = ""
        elif name == 'vuln:published-datetime':
            self.inDTElem = 1
            self.DT = ""
        elif name == 'vuln:last-modified-datetime':
            self.inPUBElem = 1
            self.PUB = ""
        elif name == 'vuln:reference':
            self.cves[-1]['references'].append(attrs.get('href'))
        elif name == 'vuln:cwe':
            self.cves[-1]['cwe'] = attrs.get('id')

    def characters(self, ch):
        if self.inCVSSElem:
            self.CVSS += ch
        if self.inSUMMElem:
            self.SUMM += ch
        if self.inDTElem:
            self.DT += ch
        if self.inPUBElem:
            self.PUB += ch

    def endElement(self, name):
        if name == 'cvss:score':
            self.inCVSSElem = 0
            self.cves[-1]['cvss'] = self.CVSS
        if name == 'vuln:summary':
            self.inSUMMElem = 0
            self.cves[-1]['summary'] = self.SUMM
        if name == 'vuln:published-datetime':
            self.inDTElem = 0
            self.cves[-1]['Published'] = self.DT
        if name == 'vuln:last-modified-datetime':
            self.inPUBElem = 0
            self.cves[-1]['Modified'] = self.PUB

if __name__=='__main__':
    # connect to the DB.
    db = Configuration.getMongoConnection()
    collection = db.cves
    info = db.info
    # get your parser on !!
    parser = make_parser()
    ch = CVEHandler()
    parser.setContentHandler(ch)
    # start here if it's an update.
    if args.u:
        # get the 'modified' file
        getfile = file_prefix+file_mod+file_suffix
        f = urlopen(Configuration.getCVEDict()+getfile)
        i = info.find_one({'db': 'cve'})
        if i is not None:
            if f.headers['last-modified'] == i['last-modified']:
                sys.exit("Not modified")
        info.update({'db': 'cve'}, {"$set":{'last-modified': f.headers['last-modified']}}, upsert=True)

        parser.parse(f)
        for item in ch.cves:
            # check if the CVE already exists.
            x=collection.find({'id': item['id']})
            # if so, update the entry.
            if x.count() > 0:
                if 'cvss' not in item:
                    item['cvss'] = defaultvalue['cvss']
                if 'cwe' not in item:
                    item['cwe'] = defaultvalue['cwe']
                collection.update({'id': item['id']}, {"$set": {'cvss': item['cvss'],'summary': item['summary'], 'references': item['references'], 'cwe': item['cwe'],  'vulnerable_configuration': item['vulnerable_configuration'], 'last-modified': item['Modified']}})
            else:
                collection.insert(item)
        # get the 'recent' file
        getfile = file_prefix+file_rec+file_suffix
        f = urlopen(Configuration.getCVEDict()+getfile)
        parser.parse(f)
        for item in ch.cves:
            # check if the CVE already exists.
            x=collection.find({'id': item['id']})
            # if so, update the entry.
            if x.count() > 0:
                if args.v:
                    print("item found : "+item['id'])
                if 'cvss' not in item:
                    item['cvss'] = defaultvalue['cvss']
                else:
                    item['cvss'] = float(item['cvss'])
                if 'cwe' not in item:
                    item['cwe'] = defaultvalue['cwe']
                collection.update({'id': item['id']}, {"$set": {'cvss': item['cvss'],'summary': item['summary'], 'references': item['references'], 'cwe': item['cwe'], 'vulnerable_configuration': item['vulnerable_configuration'], 'last-modified': item['Modified']}})
            # if not, create it.
            else:
                collection.insert(item)
    elif args.p:
        # populate is pretty straight-forward, just grab all the files from NVD
        # and dump them into a DB.
        c = collection.count()
        if args.v:
            print(str(c))
        if c > 0 and args.a is False:
            print("database already populated")
        else:
            print("Database population started")
            for x in range(cveStartYear,year):
                getfile = file_prefix+str(x)+file_suffix
                f = urlopen(Configuration.getCVEDict()+getfile)
                parser.parse(f)
                if args.v:
                    for item in ch.cves:
                        print(item['id'])
                for item in ch.cves:
                    if 'cvss' in item:
                        item['cvss'] = float(item['cvss'])
                # check if year is not cve-free
                if len(ch.cves) != 0:
                    ret = collection.insert(ch.cves)
                    if ret:
                        print ("Year "+ str(x) + " imported.")
                else:
                    print ("Year "+ str(x) + " has no CVE's.")