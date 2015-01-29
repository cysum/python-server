import nmap

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def get_services(self, targets, ports):
        return self.nm.scan(targets, ports)['scan']


def main():
    s = Scanner()
    print(s.get_services('insecure.org', '22-443'))

if __name__ == "__main__":
    main()



