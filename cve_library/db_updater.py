#!/usr/bin/env python3
#
#
# Updater script of CVE/CPE database
#
# Copyright (c) 2012-2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, "./lib/"))

import shlex
import subprocess
import syslog
import argparse
import time

from Config import Configuration

sources = [{'name': "cpe",
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_cpe_dictionary.py")},
           {'name': "cves",
            'updater': "python3 " + os.path.join(runPath, "db_mgmt.py -u")},
           {'name': 'vfeed',
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_vfeed.py")},
           {'name': 'vendor',
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_vendorstatements.py")},
           {'name': 'cwe',
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_cwe.py")},
           {'name': 'redis-cache-cpe',
            'updater': "python3 " + os.path.join(runPath, "db_cpe_browser.py")},
           {'name': 'd2sec',
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_d2sec.py")}]
posts = [{'name': "ensureindex",
          'updater': "python3 " + os.path.join(runPath, "db_mgmt_create_index.py")}]

argParser = argparse.ArgumentParser(description='Database updater for cve-search')
argParser.add_argument('-v', action='store_true', help='Logging on stdout (default is syslog)')
argParser.add_argument('-l', action='store_true', help='Running at regular interval', default=False)
argParser.add_argument('-i', action='store_true', help='Indexing new cves entries in the fulltext indexer', default=False)
argParser.add_argument('-c', action='store_true', help='Enable CPE redis cache', default=False)

args = argParser.parse_args()

def nbelement(db = Configuration.getMongoDB(), collection = None):
    if collection is None:
        collection = "cves"
    c = Configuration.getMongoConnection()
    return c[collection].count()

def logging(message = None):
    if args.v:
        print (message)
    else:
        syslog.syslog(message)

loop = True
while (loop):
    if not args.l:
        loop = False
    newelement = 0
    for source in sources:
        if source['name'] is not "redis-cache-cpe":
            message = 'Starting ' + source['name']
            logging(message)
            before = nbelement(collection=source['name'])
            subprocess.Popen((shlex.split(source['updater']))).wait()
            after = nbelement(collection=source['name'])
            message = source['name'] + " has " + str(after) + " elements (" + str(after-before)+ " update)"
            newelement = str(after-before)
            logging(message)
        elif (args.c is True and source['name'] is "redis-cache-cpe"):
            message = 'Starting ' + source['name']
            logging(message)
            subprocess.Popen((shlex.split(source['updater']))).wait()
            message = source['name'] + " updated"
            logging(message)
    for post in posts:
        message = 'Starting ' + post['name']
        logging(message)
        subprocess.Popen((shlex.split(post['updater']))).wait()
    if args.i and int(newelement) > 0:
        subprocess.Popen((shlex.split("python3 db_fulltext.py -v -l"+newelement))).wait
    if args.l is not False:
        logging("Sleeping...")
        time.sleep(3600)
