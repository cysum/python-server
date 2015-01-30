import nmap, os, json

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def get_services(self, targets, ports):
        scan_results = self.nm.scan(targets, ports)['scan']


        for host in self.nm.all_hosts():
            # Only scans tcp at the moment
            for protocol in ['tcp']:
                ports = self.nm[host][protocol].keys()
                print(ports)
                for port in ports:
                    vulns = self.get_cpe_data(self.nm[host][protocol][port]['cpe'])
                    scan_results[host][protocol][port]['vulnerabilities'] = vulns

        return scan_results



    # Corrects malformed JSON returned by search function
    def make_list(self, multiroot_json):
        return '[' + multiroot_json.replace('}\n{', '},{') + ']'

    def get_cpe_data(self, cpe_string):
        command = "python3 ./cve_library/search.py -p " + cpe_string + " -o json"
        search_json = self.make_list(os.popen(command).read())
        results = json.loads(search_json)
        return results


def main():
    s = Scanner()
    print(s.get_services('insecure.org', '22'))

if __name__ == "__main__":
    main()

