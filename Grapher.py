import json
from py2neo import Graph, Node, Relationship

SERVER              =   "server"
SERVICE             =   "service"
PORT                =   "port"
PRODUCT             =   "product"
VERSION             =   "version"
CPE                 =   "cpe"
VULNERABILITIES     =   "vulnerabilities"
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

top_keys            =   [KEY_STATUS, KEY_ADDRESSES, KEY_VENDOR, KEY_HOSTNAME]

SAMPLE_DATA_PATH    =   "./sample_scan.json"

class Grapher:
    def __init__(self):
        self.graph = Graph()

    def plot_scan_results(self, res):
        ports = []
        for host in res.keys():
            server_node = Node(SERVER, address=host, hostname=res[host][KEY_HOSTNAME])
            for attr in res[host].keys():
                if attr not in top_keys and res[host][attr].get(KEY_STATE, "closed") == OPEN:
                        product = res[host][attr][KEY_PRODUCT]
                        version = res[host][attr][KEY_VERSION]
                        cpe     = res[host][attr][KEY_CPE]
                        
                        #port_node = Node(PORT, number=attr, product=res        
            self.graph.create(server_node)
           


def main():
    g = Grapher()
    res = json.load(open(SAMPLE_DATA_PATH))
    g.plot_scan_results(res)

if __name__ == "__main__":
    main()

