#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Simple web interface to cve-search to display the last entries
# and view a specific CVE.
#
# Software is free software released under the "Modified BSD license"
#

# Copyright (c) 2013-2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# imports
import os
import sys
_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, "../lib/"))
sys.path.append(os.path.join(_runPath, ".."))

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from flask import Flask
from flask import render_template, url_for, request, redirect
from flask.ext.pymongo import PyMongo
from flask.ext.login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required, login_url
import pymongo
import redis
from passlib.hash import pbkdf2_sha256

from datetime import datetime
from dateutil import tz
import dateutil.parser
import base64
import re
import argparse
import time
import urllib
import random
import signal

from User import User
from Config import Configuration
import cves
from db_whitelist import *
from db_blacklist import *

# parse command line arguments
argparser = argparse.ArgumentParser(description='populate/update the whitelist used in webviews')
argparser.add_argument('-v', action='store_true', help='verbose output')
args = argparser.parse_args()

# variables
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['MONGO_DBNAME'] = Configuration.getMongoDB()
app.config['SECRET_KEY'] = str(random.getrandbits(256))
pageLength = Configuration.getPageLength()

# login manager 
login_manager = LoginManager()
login_manager.init_app(app)
# db connectors
mongo = PyMongo(app)
db = Configuration.getMongoConnection()
redisdb = Configuration.getRedisVendorConnection()

# functions
def matchFilePath(path):
    pattern = re.compile('^([a-zA-Z/ 0-9._-])+$')
    if pattern.match(path):
        return True
    else:
        return False

def getBrowseList(vendor):
    result = {}
    if (vendor is None) or type(vendor) == list:
        v1 = redisdb.smembers("t:/o")
        v2 = redisdb.smembers("t:/a")
        v3 = redisdb.smembers("t:/h")
        vendor = sorted(list(set(list(v1)+list(v2)+list(v3))))
        cpe=None
    else:
        cpenum = redisdb.scard("v:"+vendor)
        if cpenum < 1:
            return page_not_found(404)
        p = redisdb.smembers("v:"+vendor)
        cpe = sorted(list(p))
    result["vendor"]=vendor
    result["product"]=cpe
    return result

def getWhitelist():
    collection = db.mgmt_whitelist
    whitelist = collection.find()
    return whitelist

def getWhitelistRules():
    collection = db.mgmt_whitelist
    whitelist = collection.distinct('id')
    return whitelist

def whitelist_mark(cve):
    whitelistitems = getWhitelistRules()
    # ensures we're working with a list object, in case we get a pymongo.cursor object
    cve = list(cve)
    # check the cpes (full or partially) in the whitelist
    for cveid in cve:
        cpes=cveid['vulnerable_configuration']
        if len([i for e in whitelistitems for i in cpes if e in i])>0:
            cve[cve.index(cveid)]['whitelisted'] = 'yes'
    return cve

def blacklist_mark(cve):
    blacklistitems = getBlackRules()
    # ensures we're working with a list object, in case we get a pymongo.cursor object
    cve = list(cve)
    # check the cpes (full or partially) in the blacklist
    for cveid in cve:
        cpes=cveid['vulnerable_configuration']
        if len([i for e in blacklistitems for i in cpes if e in i])>0:
            cve[cve.index(cveid)]['blacklisted'] = 'yes'
    return cve

def getBlacklist():
    collection = db.mgmt_blacklist
    blacklist = collection.find()
    return blacklist

def getBlacklistRules():
    collection = db.mgmt_blacklist
    blacklist = collection.distinct('id')
    return blacklist

def getBlacklistRegexes():
    blacklist = getBlacklistRules()
    regexes = []
    for blacklistRule in blacklist:
        regexes.append(re.compile(blacklistRule))
    return regexes

def getWhitelistRegexes():
    whitelist = getWhitelistRules()
    regexes = []
    for whitelistRule in whitelist:
        regexes.append(re.compile(whitelistRule))
    return regexes

def addCPEToList(cpe, listType):
    cpe = urllib.parse.quote_plus(cpe).lower()
    cpe = cpe.replace("%3a",":")
    cpe = cpe.replace("%2f","/")
    if listType.lower() in ("blacklist", "black", "b", "bl"):
        if insertBlacklist(cpe):
            return True
        else:
            return False
    if listType.lower() in ("whitelist", "white", "w", "wl"):
        if insertWhitelist(cpe):
            return True
        else:
            return False

def getVersionsOfProduct(product):
    p = redisdb.smembers("p:"+product)
    return sorted(list(p))

def convertDateToDBFormat(string):
    result = None
    try:
        result = time.strptime(string, "%d-%m-%Y")
    except:
        pass
    try:
        result = time.strptime(string, "%d-%m-%y")
    except:
        pass
    try:
        result = time.strptime(string, "%d/%m/%Y")
    except:
        pass
    try:
        result = time.strptime(string, "%d/%m/%y")
    except:
        pass
    if result != None:
        result = time.strftime('%Y-%m-%d', result)
    return result

def filter_logic(blacklist, whitelist, unlisted, timeSelect, startDate, endDate,
                 timeTypeSelect, cvssSelect, cvss, rejectedSelect, limit, skip):
    collection = db.cves
    query = []
    # retrieving lists
    if blacklist == "on":
        regexes = getBlacklistRules()
        if len(regexes) != 0:
            exp = "^(?!" + "|".join(regexes) + ")";
            query.append({'$or':[{'vulnerable_configuration': re.compile(exp) },
                                 {'vulnerable_configuration':{'$exists': False}}, 
                                 {'vulnerable_configuration': []}
                                ]})
    if whitelist == "hide":
        regexes = getWhitelistRules()
        if len(regexes) != 0:
            exp = "^(?!" + "|".join(regexes) + ")";
            query.append({'$or':[{'vulnerable_configuration': re.compile(exp) },
                                 {'vulnerable_configuration':{'$exists': False}}, 
                                 {'vulnerable_configuration': []}
                                ]})
    if unlisted == "hide":
        wlregexes = getWhitelistRegexes()
        blregexes = getBlacklistRegexes()
        query.append({'$or':[{'vulnerable_configuration':{'$in':wlregexes}},
                             {'vulnerable_configuration':{'$in':blregexes}}]})
    if rejectedSelect == "hide":
        exp = "^(?!\*\* REJECT \*\*\s+DO NOT USE THIS CANDIDATE NUMBER.*)"
        query.append({'summary': re.compile(exp)})
    # cvss logic
    if cvssSelect != "all":
        if cvssSelect == "above":
            query.append({'cvss':{'$gt':float(cvss)}})
        if cvssSelect == "equals":
            query.append({'cvss':float(cvss)})
        if cvssSelect == "below":
            query.append({'cvss':{'$lt':float(cvss)}})
    # date logic
    if timeSelect != "all":
        startDate = convertDateToDBFormat(startDate)
        endDate = convertDateToDBFormat(endDate)
        if timeSelect == "from":
            query.append({timeTypeSelect:{'$gt':startDate}})
        if timeSelect == "until":
            query.append({timeTypeSelect:{'$lt':endDate}})
        if timeSelect == "between":
            query.append({timeTypeSelect:{'$gt':startDate, '$lt':endDate}})
        if timeSelect == "outside":
            query.append({'$or':[{timeTypeSelect:{'$lt':startDate}},{timeTypeSelect:{'$gt':endDate}}]})
    if len(query) ==0:
        cve = collection.find().sort("Modified", -1).limit(limit).skip(skip)
    elif len(query) == 1:
        cve = collection.find(query[0]).sort("Modified", -1).limit(limit).skip(skip)
    else:
        cve = collection.find({'$and':query}).sort("Modified", -1).limit(limit).skip(skip)
    # marking relevant records
    if whitelist == "on":
        cve = whitelist_mark(cve)
    if blacklist == "mark":
        cve = cve = blacklist_mark(cve)
    cve = list(cve)
    return cve

def markCPEs(cve):
    blacklist = getBlacklistRules()
    whitelist = getWhitelistRules()

    for conf in cve['vulnerable_configuration']:
        conf['list']='none'
        conf['match']='none'
        for w in whitelist:
            if w in conf['id']:
                conf['list']='white'
                conf['match']=w
        for b in blacklist:
            if b in conf['id']:
                conf['list']='black'
                conf['match']=b
    return cve

@login_manager.user_loader
def load_user(id):
    return User.get(id)

#routes
@app.route('/')
def filter():
    # get default page on HTTP get (navigating to page)
    blacklist="on"
    whitelist="on"
    unlisted="show"
    timeSelect="all"
    startDate=None
    endDate=None
    timeTypeSelect="Modified"
    cvssSelect="all"
    cvss=None
    rejectedSelect="hide"
    cve = filter_logic(blacklist, whitelist, unlisted, timeSelect, startDate, endDate,
          timeTypeSelect, cvssSelect, cvss, rejectedSelect, pageLength, 0)
    return render_template('index.html',cve=cve, r=0, pageLength=pageLength)

@app.route('/', methods = ['POST'])
def filterPost():
    blacklist=request.form.get('blacklistSelect')
    whitelist=request.form.get('whitelistSelect')
    unlisted=request.form.get('unlistedSelect')
    timeSelect=request.form.get('timeSelect')
    startDate=request.form.get('startDate')
    endDate=request.form.get('endDate')
    timeTypeSelect=request.form.get('timeTypeSelect')
    cvssSelect=request.form.get('cvssSelect')
    cvss=request.form.get('cvss')
    rejectedSelect=request.form.get('rejectedSelect')
    settings = {'blacklistSelect':blacklist,    'whitelistSelect':whitelist,
                'unlistedSelect':unlisted,      'timeSelect':timeSelect,
                'startDate':startDate,          'endDate':endDate,
                'timeTypeSelect':timeTypeSelect,'cvssSelect':cvssSelect,
                'cvss':cvss,                    'rejectedSelect':rejectedSelect}
    # retrieving data
    cve = filter_logic(blacklist, whitelist, unlisted, timeSelect, startDate, endDate,
          timeTypeSelect, cvssSelect, cvss, rejectedSelect, pageLength, 0)
    return render_template('index.html', settings=settings, cve=cve, r=0, pageLength=pageLength)

@app.route('/r/<int:r>', methods = ['POST'])
def filterLast(r):
    if not r:
        r = 0
    blacklist=request.form.get('blacklistSelect')
    whitelist=request.form.get('whitelistSelect')
    unlisted=request.form.get('unlistedSelect')
    timeSelect=request.form.get('timeSelect')
    startDate=request.form.get('startDate')
    endDate=request.form.get('endDate')
    timeTypeSelect=request.form.get('timeTypeSelect')
    cvssSelect=request.form.get('cvssSelect')
    cvss=request.form.get('cvss')
    rejectedSelect=request.form.get('rejectedSelect')
    settings = {'blacklistSelect':blacklist,    'whitelistSelect':whitelist,
                'unlistedSelect':unlisted,      'timeSelect':timeSelect,
                'startDate':startDate,          'endDate':endDate,
                'timeTypeSelect':timeTypeSelect,'cvssSelect':cvssSelect,
                'cvss':cvss,                    'rejectedSelect':rejectedSelect}
    # retrieving data
    cve = filter_logic(blacklist, whitelist, unlisted, timeSelect, startDate, endDate,
          timeTypeSelect, cvssSelect, cvss, rejectedSelect, pageLength, r)

    return render_template('index.html', settings=settings, cve=cve, r=r, pageLength=pageLength) 

@app.route('/cve/<cveid>')
def cve(cveid):
    cvesp = cves.last(rankinglookup = True, namelookup = True, vfeedlookup = True)
    cve = cvesp.getcve(cveid=cveid)
    cve = markCPEs(cve)
    if cve is None:
        return page_not_found(404)
    return render_template('cve.html', cve=cve)

@app.route('/browse/<vendor>')
@app.route('/browse/')
def browse(vendor=None):
    if vendor != None:
        vendor = urllib.parse.quote_plus(vendor).lower()
    browseList = getBrowseList(vendor)
    vendor = browseList["vendor"]
    product = browseList["product"]
    return render_template('browse.html', product=product, vendor=vendor)

@app.route('/search/<vendor>/<path:product>')
def search(vendor=None,product=None):
    collection = db.cves
    search = vendor+":"+product
    cve = collection.find({"vulnerable_configuration": {'$regex': search}}).sort("Modified",-1)
    return render_template('search.html', vendor=vendor, product=product, cve=cve)

@app.route('/admin')
def admin():
    status=["default","none"]
    if Configuration.loginRequired():
        if not current_user.is_authenticated():
            return render_template('login.html', status=status)
        else:
            return render_template('admin.html', status=status)
    else:
        person = User.get("_dummy_")
        login_user(person)
        return render_template('admin.html',status=status)

@app.route('/admin/updatedb')
@login_required
def updatedb():
    os.system("python3 " + os.path.join(_runPath, "../db_updater.py -civ"))
    status = ["db_updated","success"]
    return render_template('admin.html', status=status)

@app.route('/admin/whitelist/import', methods = ['POST'])
@login_required
def whitelistImport(force=None, path=None):
    path = request.form.get('file')
    force = request.form.get('force')
    if (matchFilePath(path)):
        if os.path.isfile(path):
            count = countWhitelist()
            if (count == 0) | (not count) | (force == "f"):
                dropWhitelist()
                importWhitelist(path)
                status=["wl_imported","success"]
            else:
                status=["wl_already_filled","info"]
        else:
            status=["invalid_path","error"]
    else:
        status=["invalid_path_format","error"]
    return render_template('admin.html', status=status)

@app.route('/admin/whitelist/export', methods = ['POST'])
@login_required
def whitelistExport(force=None, path=None):
    path = request.form.get('file')
    force = request.form.get('force')
    if (matchFilePath(path)):
        if (force=="df") and (os.path.isfile(path)):
            status=["wl_file_already_exists","warning"]
        else:
            if(os.path.isfile(path)):
                os.remove(path)
            exportWhitelist(path)
            status=["wl_exported","success"]
    else:
        status=["invalid_path","error"]
    return render_template('admin.html', status=status)

@app.route('/admin/whitelist/drop')
@login_required
def whitelistDrop():
    dropWhitelist()
    status=["wl_dropped","success"]
    return render_template('admin.html', status=status)

@app.route('/admin/whitelist/view')
@login_required
def whitelistView():
    whitelist = getWhitelist()
    status=["default","none"]
    return render_template('list.html', rules=whitelist, status=status, listType="Whitelist")

@app.route('/admin/whitelist/add', methods = ['POST'])
@login_required
def whitelistAdd():
    cpe = request.form.get('cpe')
    if addCPEToList(cpe, "whitelist"):
        status=["added","success"]
    else:
        status=["already_exists","info"]
    whitelist = getWhitelist()
    return render_template('list.html', rules=whitelist, status=status, listType="Whitelist")

@app.route('/admin/whitelist/remove', methods = ['POST'])
@login_required
def whitelistRemove():
    cpe = request.form.get('cpe')
    cpe = urllib.parse.quote_plus(cpe).lower()
    cpe = cpe.replace("%3a",":")
    cpe = cpe.replace("%2f","/")
    if (cpe != False):
        if (removeWhitelist(cpe) > 0):
            status=["removed","success"]
        else:
            status=["already_removed","info"]
    else:
        status=["invalid_url","error"]
    whitelist = getWhitelist()
    return render_template('list.html', rules=whitelist, status=status, listType="Whitelist")

@app.route('/admin/whitelist/edit', methods = ['POST'])
@login_required
def whitelistEdit():
    oldCPE=request.form.get('oldCPE')
    newCPE=request.form.get('cpe')
    if (oldCPE != False) and (newCPE != False):
        if (updateWhitelist(oldCPE,newCPE)):
            status=["updated","success"]
        else:
            status=["update_failed","error"]
    else:
        status=["invalid_url","error"]
    whitelist = getWhitelist()
    return render_template('list.html', rules=whitelist, status=status, listType="Whitelist")


@app.route('/admin/blacklist/import', methods = ['POST'])
@login_required
def blacklistImport():
    path = request.form.get('file')
    force = request.form.get('force')
    if (matchFilePath(path)):
        if os.path.isfile(path):
            count = countBlacklist()
            if (count == 0) | (not count) | (force == "f"):
                dropBlacklist()
                importBlacklist(path)
                status=["bl_imported","success"]
            else:
                status=["bl_already_filled","info"]
        else:
            status=["invalid_path","error"]
    else:
        status=["invalid_path_format","error"]
    return render_template('admin.html', status=status)

@app.route('/admin/blacklist/export', methods = ['POST'])
@login_required
def blacklistExport():
    path = request.form.get('file')
    force = request.form.get('force')
    if (matchFilePath(path)):
        if (force=="df") and (os.path.isfile(path)):
            status=["bl_file_already_exists","warning"]
        else:
            if(os.path.isfile(path)):
                os.remove(path)
            exportBlacklist(path)
            status=["bl_exported","success"]
    else:
        status=["invalid_path","error"]
    return render_template('admin.html', status=status)

@app.route('/admin/blacklist/drop')
@login_required
def blacklistDrop():
    dropBlacklist()
    status=["bl_dropped","success"]
    return render_template('admin.html', status=status)

@app.route('/admin/blacklist/view')
@login_required
def blacklistView():
    blacklist = getBlacklist()
    status=["default","none"]
    return render_template('list.html', rules=blacklist, status=status, listType="Blacklist")

@app.route('/admin/blacklist/add', methods = ['POST'])
@login_required
def blacklistAdd():
    cpe = request.form.get('cpe')
    if (cpe != False):
        if insertBlacklist(cpe):
            status=["added","success"]
        else:
            status=["already_exists","info"]
    else:
        status=["invalid_url","error"]
    blacklist = getBlacklist()
    return render_template('list.html', rules=blacklist, status=status, listType="Blacklist")

@app.route('/admin/blacklist/remove', methods = ['POST'])
@login_required
def blacklistRemove():
    cpe = request.form.get('cpe')
    cpe = urllib.parse.quote_plus(cpe).lower()
    cpe = cpe.replace("%3a",":")
    cpe = cpe.replace("%2f","/")
    if (cpe != False):
        if (removeBlacklist(cpe) > 0):
            status=["removed","success"]
        else:
            status=["already_removed","info"]
    else:
        status=["invalid_url","error"]
    blacklist = getBlacklist()
    return render_template('list.html', rules=blacklist, status=status, listType="Blacklist")

@app.route('/admin/blacklist/edit', methods = ['POST'])
@login_required
def blacklistEdit():
    oldCPE=request.form.get('oldCPE')
    newCPE=request.form.get('cpe')
    if (oldCPE != False) and (newCPE != False):
        if (updateBlacklist(oldCPE,newCPE)):
            status=["updated","success"]
        else:
            status=["update_failed","error"]
    else:
        status=["invalid_url","error"]
    blacklist = getBlacklist()
    return render_template('list.html', rules=blacklist, status=status, listType="Blacklist")

@app.route('/admin/listmanagement/add', methods = ['POST'])
@login_required
def listManagementAdd():
    # retrieve the separate item parts
    item = request.form.get('item')
    listType = request.form.get('list')
    vendor = None
    product = None
    version = None
    pattern = re.compile('^[a-z:/0-9.~_%-]+$')

    if pattern.match(item):
        item = item.split(":")
        added = False
        if len(item) == 1:
            # only vendor, so a check on cpe type is needed
            if redisdb.sismember("t:/o", item[0]):
                if addCPEToList("cpe:/o:"+item[0],listType):
                    added = True
            if redisdb.sismember("t:/a", item[0]):
                if addCPEToList("cpe:/a:"+item[0], listType):
                    added = True
            if redisdb.sismember("t:/h", item[0]):
                if addCPEToList("cpe:/h:"+item[0], listType):
                    added = True
            browseList = getBrowseList(None)
            vendor = browseList['vendor']
        elif 4 > len(item) >1:
            # cpe type can be found with a mongo regex query
            collection = db.cpe
            result = collection.find({'id':{'$regex':item[1]}})
            if result.count() != 0:
                prefix = ((result[0])['id'])[:7]
                if len(item) == 2:
                    if addCPEToList(prefix+item[0]+":"+item[1], listType):
                        added = True
                if len(item) == 3:
                    if addCPEToList(prefix+item[0]+":"+item[1]+":"+item[2], listType):
                        added = True
            vendor = item[0]
        if len(item) > 2:
            product = item[1]
            version = getVersionsOfProduct(product)
        else:
            product = (getBrowseList(vendor))['product']
        if added:
            status=["cpe_added","success"]
        else:
            status=["cpe_not_added","error"]
    else:
        browseList = getBrowseList(None)
        vendor = browseList['vendor']
        status=["invalid_cpe_format","error"]
    return render_template('listmanagement.html', status=status, listType=listType, vendor=vendor, product=product, version=version)

@app.route('/admin/listmanagement/<vendor>/<product>')
@app.route('/admin/listmanagement/<vendor>')
@app.route('/admin/listmanagement')
@login_required
def listManagement(vendor=None, product=None):
    if product == None:
        # no product selected yet, so same function as /browse can be used
        if vendor != None:
            vendor = urllib.parse.quote_plus(vendor).lower()
        browseList = getBrowseList(vendor)
        vendor = browseList["vendor"]
        product = browseList["product"]
        version = None
    else:
        # product selected, product versions required
        version = getVersionsOfProduct(urllib.parse.quote_plus(product).lower())
    status=["default","none"]
    return render_template('listmanagement.html', status=status, vendor=vendor, product=product, version=version)

@app.route('/login', methods=['post'])
def login_check():
    users = db.mgmt_users
    # validate username and password
    username = request.form.get('username')
    password =request.form.get('password')
    person = User.get(username)
    try:
        if person and pbkdf2_sha256.verify(password, person.password):
            login_user(person)
            return render_template('admin.html',status=["logged_in", "success"])
        else:
            return render_template('login.html', status=["wrong_combination", "warning"])
    except:
        return render_template('login.html', status=["outdated_database", "error"])


@app.route('/logout')
def logout():
    logout_user()
    return redirect("/")

# error handeling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# filters

@app.template_filter('currentTime')
def currentTime(utc):
    timezone = tz.tzlocal()
    utc = dateutil.parser.parse(utc)
    output = utc.astimezone(timezone)
    output = output.strftime('%d-%m-%Y - %H:%M')
    return output 

@app.template_filter('base64Enc')
def base64Encode(string):
    return base64.b64encode(bytes(string, "utf-8")).decode("utf-8")

@app.template_filter('htmlDecode')
def htmlDedode(string):
    return urllib.parse.unquote_plus(string)

@app.template_filter('htmlEncode')
def htmlEncode(string):
    return urllib.parse.quote_plus(string).lower()

def sig_handler(sig, frame):
    print('Caught signal: %s', sig)
    tornado.ioloop.IOLoop.instance().add_callback(shutdown)
 
def shutdown():
    MAX_WAIT_SECONDS_BEFORE_SHUTDOWN = 3
    print('Stopping http server')
    server.stop()

    print('Will shutdown in %s seconds ...', MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)
    io_loop = tornado.ioloop.IOLoop.instance()
    deadline = time.time() + MAX_WAIT_SECONDS_BEFORE_SHUTDOWN
 
    def stop_loop():
        now = time.time()
        if now < deadline and (io_loop._callbacks or io_loop._timeouts):
            io_loop.add_timeout(now + 1, stop_loop)
        else:
            io_loop.stop()
            print('Shutdown')
        stop_loop()

if __name__ == '__main__':
    # get properties
    flaskHost = Configuration.getFlaskHost()
    flaskPort = Configuration.getFlaskPort()
    flaskDebug = Configuration.getFlaskDebug()
    if flaskDebug:
        # start debug flask server
        app.run(host=flaskHost, port=flaskPort, debug=flaskDebug)
    else:
        # start asynchronous server using tornado wrapper for flask
        # ssl connection
        print("Server starting...")
        if Configuration.useSSL():
            cert = os.path.join(_runPath,"../", Configuration.getSSLCert())
            key = os.path.join(_runPath,"../", Configuration.getSSLKey())
            ssl_options = {"certfile": cert,
                           "keyfile": key}
        else:
            ssl_options = None
        http_server = HTTPServer(WSGIContainer(app), ssl_options=ssl_options )
        http_server.bind(flaskPort, address=flaskHost)
        signal.signal(signal.SIGTERM, sig_handler)
        signal.signal(signal.SIGINT, sig_handler) 
        http_server.start(0)  # Forks multiple sub-processes
        IOLoop.instance().start()
