import json
from py2neo import Graph, Node, Relationship

SERVER              =   "server"
SERVICE             =   "service"
PORT                =   "port"
PRODUCT             =   "product"
VERSION             =   "version"
CPE                 =   "cpe"
VULNERABILITY     =   "vulnerability"
CWE                 =   "cwe"
PUBLISHED           =   "published"
SUMMARY             =   "summary"
OPEN                =   "open"

KEY_STATUS          =   "status"
KEY_ADDRESSES       =   "addresses"
KEY_VENDOR          =   "vendor"
KEY_HOSTNAME        =   "hostname"
KEY_CVE             =   "id"
KEY_SUMMARY         =   "summary"
KEY_PUBLISHED       =   "Published"
KEY_VERSION         =   "version"
KEY_PRODUCT         =   "product"
KEY_CPE             =   "cpe"
KEY_STATE           =   "state"
KEY_VULNERABILITIES     =   "vulnerabilities"

HAS                 =   "HAS"
top_keys            =   [KEY_STATUS, KEY_ADDRESSES, KEY_VENDOR, KEY_HOSTNAME]

SAMPLE_DATA_PATH    =   "./sample_scan.json"

class Grapher:
    def __init__(self):
        self.graph = Graph()
    
    """Accepts a dict of scanning results and adds the server, its ports and vulerabilities in Neo4jDB"""
    def plot_scan_results(self, res):
        for host in res.keys():
            hostname = res[host][KEY_HOSTNAME]
            server  = Node(SERVER, id=host, address=host, hostname=hostname)
            for attr in res[host].keys():
                if attr not in top_keys:
                    for portno in res[host][attr]:
                        if res[host][attr][portno].get(KEY_STATE, "closed") == OPEN:
                            product = res[host][attr][portno][KEY_PRODUCT]
                            version = res[host][attr][portno][KEY_VERSION]
                            cpe     = res[host][attr][portno][KEY_CPE]
                            vulnerabilities = res[host][attr][portno][KEY_VULNERABILITIES]
                            port = Node(PORT, id=portno, number=portno, protocol=attr, product=product, version=version, cpe=cpe, state=OPEN)        
                            server_has_port = Relationship(server, HAS, port) 
                            self.graph.create(server_has_port)
                            for vulnerability in vulnerabilities:
                                published   = vulnerability[KEY_PUBLISHED]
                                cve         = vulnerability[KEY_CVE] 
                                summary     = vulnerability[KEY_SUMMARY] 
                                vuln        = Node(VULNERABILITY, id=cve, cve=cve, summary=summary, published=published)
                                port_has_vuln = Relationship(port, HAS, vuln)
                                self.graph.create(port_has_vuln)

def main():
    g = Grapher()
    res = json.load(open(SAMPLE_DATA_PATH))
    g.plot_scan_results(res)

if __name__ == "__main__":
    main()

