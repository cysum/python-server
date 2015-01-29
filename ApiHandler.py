from http.server import BaseHTTPRequestHandler, HTTPServer
from Scanner import Scanner
import json, urllib

class ApiHandler(BaseHTTPRequestHandler):
    s = Scanner()

    def get_services_json(self, targets, ports):
        data = self.s.get_services(targets, ports)
        return json.dumps(data, indent=4)


    def do_GET(self):
        query = urllib.parse.urlparse(self.path)[4]
        query_object = urllib.parse.parse_qs(query)
        print(query_object)

        targets = query_object['targets'][0]
        ports   = query_object['ports'][0]

        self.send_response(200)
        self.send_header('Content-type',    'application/json; charset=utf-8')
        self.end_headers()

        body = self.get_services_json(targets, ports)
        self.wfile.write(bytes(body, 'utf-8'))

        return



def main():
    try:
        server = HTTPServer(('', 80), ApiHandler)
        print('Started Server')
        server.serve_forever()
        print('still serving')
    except KeyboardInterrupt:
        print("^C received - stopping server.")
        server.socket.close()


if __name__ == "__main__":
    main()



