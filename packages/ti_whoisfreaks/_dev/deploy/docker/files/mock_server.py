"""Mock of the WhoisFreaks v3.3 and v3.4 stream endpoints for system tests."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json

COLS = [
    "num", "domain_name", "query_time", "create_date", "update_date", "expiry_date",
    "domain_registrar_id", "domain_registrar_name", "domain_registrar_whois",
    "domain_registrar_url", "name_server_1", "name_server_2",
    "domain_status_1", "domain_status_2",
]

DATA = {
    "gtld": [
        {"num": "1", "domain_name": "driveigo.world", "query_time": "2026-08-04 09:54:02",
         "create_date": "2026-08-03", "update_date": "2026-08-03", "expiry_date": "2027-08-03",
         "domain_registrar_id": "472", "domain_registrar_name": "Dynadot Inc",
         "domain_registrar_whois": "whois.dynadot.com", "domain_registrar_url": "http://www.dynadot.com",
         "name_server_1": "gabriella.ns.cloudflare.com", "name_server_2": "cris.ns.cloudflare.com",
         "domain_status_1": "addperiod", "domain_status_2": "clienttransferprohibited"},
        {"num": "2", "domain_name": "freshly-registered.io", "query_time": "2026-08-04 09:54:02",
         "create_date": "2026-08-04", "update_date": "2026-08-04", "expiry_date": "2027-08-04",
         "domain_registrar_id": "1479", "domain_registrar_name": "NameCheap Inc",
         "domain_registrar_whois": "whois.namecheap.com", "domain_registrar_url": "http://www.namecheap.com",
         "name_server_1": "dns1.registrar-servers.com", "name_server_2": "",
         "domain_status_1": "", "domain_status_2": ""},
    ],
    "cctld": [
        {"num": "1", "domain_name": "example.co.uk", "query_time": "2026-08-04 09:54:02",
         "create_date": "2019-05-01", "update_date": "2025-01-10", "expiry_date": "2027-08-03",
         "domain_registrar_id": "88", "domain_registrar_name": "Nominet UK",
         "domain_registrar_whois": "whois.nic.uk", "domain_registrar_url": "http://www.nominet.uk",
         "name_server_1": "ns1.example.net", "name_server_2": "",
         "domain_status_1": "", "domain_status_2": ""},
    ],
}

THREAT_DATA = {
    "malware": "027168.com,malware,1.0,2026-06-25 13:45:35.401434+00,2026-08-25 00:16:20.97521+00,1\n",
    "spam": "027168.com,spam,1.0,2026-06-25 13:45:35.401434+00,2026-08-25 00:16:20.97521+00,1\n",
    "phishing": "027168.com,phishing,1.0,2026-06-25 13:45:35.401434+00,2026-08-25 00:16:20.97521+00,1\n",
}


def csv_page(feed, offset):
    header = ",".join(COLS)
    if offset != 0:
        return header + "\n"
    lines = [header]
    for row in DATA.get(feed, []):
        lines.append(",".join('"%s"' % row.get(c, "") if c != "num" else row.get(c, "") for c in COLS))
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/healthcheck", "/v3.3/status"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        # Health check endpoint for Docker Compose / test runners
        if parsed.path in ("/", "/healthcheck"):
            self._send(200, "application/json", b'{"status":"ok"}')
            return

        if parsed.path == "/v3.3/status":
            body = json.dumps({
                "newly": {
                    "gtld": {"last_update": "2026-08-04", "available_from": "2026-05-01"},
                    "cctld": {"last_update": "2026-08-04", "available_from": "2026-05-01"},
                },
            }).encode()
            self._send(200, "application/json", body)
            return

        if parsed.path in ("/v3.3/stream/domainer/gtld", "/v3.3/stream/domainer/cctld"):
            feed = parsed.path.rsplit("/", 1)[1]
            offset = int(qs.get("offset", ["0"])[0])
            self._send(200, "text/plain; charset=UTF-8", csv_page(feed, offset).encode())
            return

        threat_prefix = "/v3.4/stream/threat-feed/"
        if parsed.path.startswith(threat_prefix):
            feed = parsed.path[len(threat_prefix):]
            offset = int(qs.get("offset", ["0"])[0])
            body = b"" if offset != 0 else THREAT_DATA.get(feed, "").encode()
            self._send(200, "text/plain; charset=UTF-8", body)
            return

        self._send(404, "application/json", b'{"status":404}')

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()