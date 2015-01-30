cve-search
==========

We are using this to perform CPE searches for us

cve-search is a tool to import CVE (Common Vulnerabilities and Exposures) and
CPE (Common Platform Enumeration) into a MongoDB to facilitate search
and processing of CVEs.

The main objective of the software is to avoid doing direct and public lookup
into the public CVE databases. This is usually faster to do local lookups and
limits your sensitive queries via the Internet.

![cve-search visualization](https://farm9.staticflickr.com/8109/8603509755_c7690c2de4_n.jpg "CVE Keywords Visualization Using Data From cve-search")
http://www.foo.be/cve/

Requirements
------------

* Python3
* MongoDB
* redis server
* Pip3
  * PyMongo
  * Flask
  * Flask-PyMongo
  * Flask-Login
  * Tornado
  * Whoosh
  * Redis
  * Python-dateUtil
  * passlib
  * feedformater (for RSS and Atom dump_last) http://code.google.com/p/feedformatter/
  * Whoosh http://packages.python.org/Whoosh/ (If you're planning to use the Full-text indexer)

The requirements can be installed with pip:

    sudo pip3 install -r requirements.txt

Installation of MongoDB
-----------------------

First, you'll need to have a Python 3 installation (3.2 or 3.3 preferred).
Then you need to install MongoDB (2.2) from source (this should also work
with any standard packages from your favorite distribution). Don't forget
to install the headers for development while installing MongoDB.
You can go to http://docs.mongodb.org/manual/installation/ for to get the
packages for your distribution, or http://www.mongodb.org/downloads for
the source code.


Populating the database
-----------------------

For the initial run, you need to populate the CVE database by running:

    ./db_mgmt.py -p
    ./db_mgmt_cpe_dictionary.py
    ./db_updater.py -c
    ./db_mgmt_create_index.py

It will fetch all the existing XML files from the Common Vulnerabilities
and Exposures database and the Common Platform Enumeration.

By default, there is no secondary indexes created in MongoDB for the
CVE/CPE database. You might want to create indexes on the fields that are
commonly used for your searches. As the example, you can create the index
for the following collection and key:

    db.cpe.ensureIndex( {id:1 } )
    db.cves.ensureIndex( {id:1} )
    db.cves.ensureIndex( {vulnerable_configuration:1} )
    db.cves.ensureIndex( {Modified:1} )
    db.vfeed.ensureIndex( {id:1} )
    db.vendor.ensureIndex( {id:1} )
    db.d2sec.ensureIndex( {id:1} )

Database and collections
------------------------

The MongoDB database is called cvedb and there are 8 collections:

* cves (Common Vulnerabilities and Exposure items) - source NVD NIST
* cpe (Common Platform Enumeration items) - source NVD NIST
* vendor (Official Vendor Statements on CVE Vulnerabilities) - source NVD NIST
* cwe (Common Weakness Enumeration items) - source NVD NIST
* ranking (ranking rules per group) - local cve-search
* d2sec (Exploitation reference from D2 Elliot Web Exploitation Framework) - source d2sec.com
* vfeed (cross-references to CVE ids (e.g. OVAL, OpenVAS, ...)) - source vfeed
* info (metadata of each collection like last-modified) - local cve-search

Updating the database
---------------------

An updater script helps to start the db_mgmt_*  

    ./db_updater.py -v

You can run it in a crontab, logging is done in syslog by default.

Usage
-----

You can search the database using search.py

    ./search.py -p cisco:ios:12.4
    ./search.py -p cisco:ios:12.4 -o json
    ./search.py -f nagios -n
    ./search.py -p microsoft:windows_7 -o html

If you want to search all the WebEx vulnerabilities and only printing the official
references from the supplier.

    ./search.py -p webex: -o csv  -v "cisco"

You can also dump the JSON for a specific CVE ID.

    ./search.py -c CVE-2010-3333

Or you can use the XMPP bot

    ./search_xmpp.py -j mybot@jabber.org -p strongpassword

Or dump the last 2 CVE entries in RSS or Atom format

    ./dump_last.py -f atom -l 2

Or you can use the webinterface.

    ./web/index.py

Usage of the ranking database
-----------------------------

There is a ranking database allowing to rank software vulnerabilities based on
their common platform enumeration name. The ranking can be done per organization
or department within your organization or any meaningful name for you.

As an example, you can add a partial CPE name like "sap:netweaver" which is very
critical for your accounting department.

    ./python3.3 db_ranking.py  -c "sap:netweaver" -g "accounting" -r 3

and then you can lookup the ranking (-r option) for a specific CVE-ID:

    ./python3.3 search.py -c CVE-2012-4341  -r  -n

Advanced usage
--------------

As cve-search is based on a set of tools, it can be used and combined with standard Unix tools. If you ever wonder what are the top vendors using the term "unknown" for their vulnerabilities:

    python3 search_fulltext.py -q unknown -f | jq -r '. | .vulnerable_configuration[0]' | cut -f3 -d: | sort  | uniq -c  | sort -nr | head -10

    1500 oracle
    381 sun
    372 hp
    232 google
    208 ibm
    126 mozilla
    103 microsoft
    100 adobe
     78 apple
     68 linux

You can compare CVSS (Common Vulnerability Scoring System ) values of some products based on their CPE name. Like comparing oracle:java versus sun:jre and using R to make some statistics about their CVSS values:

    python3 search.py -p oracle:java -o json  | jq -r '.cvss' | Rscript -e 'summary(as.numeric(read.table(file("stdin"))[,1]))'
    Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
    1.800   5.350   9.300   7.832  10.000  10.000


    python3 search.py -p sun:jre -o json  | jq -r '.cvss' | Rscript -e 'summary(as.numeric(read.table(file("stdin"))[,1]))'
    Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
    0.000   5.000   7.500   7.333  10.000  10.000

Fulltext indexing
-----------------

If you want to index all the CVEs from your current MongoDB collection:

    ./python3.3 db_fulltext.py

and you query the fulltext index (to get a list of matching CVE-ID):

    ./python3.3 search_fulltext.py -q NFS -q Linux

or to query the fulltext index and output the JSON object for each CVE-ID:

    ./python3.3 search_fulltext.py -q NFS -q Linux -j

Fulltext visualization
----------------------

The fulltext indexer visualization is using the fulltext indexes to build
a list of the most common keywords used in CVE. [NLTK](http://nltk.org/) is
required to generate the keywords with the most common English
stopwords and lemmatize the output. [NTLK for Python 3](http://nltk.org/nltk3-alpha/)
exists but you need to use the alpha version of NLTK.

    ./python3.3 search_fulltext.py  -g -s >cve.json

You can see a visualization on the [demo site](http://www.foo.be/cve/).

Web interface
-------------

The web interface is a minimal interface to see the last CVE entries and
query a specific CVE. You'll need flask in order to run the website and [Flask-PyMongo](http://flask-pymongo.readthedocs.org/en/latest/). To start
the web interface:

    cd ./web
    ./python3.3 index.py

Then you can connect on http://127.0.0.1:5000/ to browser the last CVE.

Software using cve-search
-------------------------

* [cve-portal](https://www.github.com/CIRCL/cve-portal) which is a CVE notification portal

License
-------

cve-search is free software released under the "Modified BSD license"

    Copyright (c) 2012 Wim Remes - https://github.com/wimremes/
    Copyright (c) 2012-2014 Alexandre Dulaunoy - https://github.com/adulau/
    Copyright (c) 2014 Pieter-Jan Moreels - https://github.com/pidgeyl/

