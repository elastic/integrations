#!/usr/bin/env python3
"""Local-only mock API and FortiGate sender for elastic-package system tests."""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import signal
import socket
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

TEST_KEY = "unit-test-key"
TEST_IP = "192.0.2.10"


class MockCriminalIP(BaseHTTPRequestHandler):
    def do_GET(self):
        request = urlsplit(self.path)
        params = parse_qs(request.query)
        if request.path == "/health":
            self._send(200, {"status": "ok"})
            return

        if request.path == "/v1/asset/ip/report":
            if self.headers.get("x-api-key") != TEST_KEY or not params.get("ip"):
                self._send(403, {"error": "invalid test credentials or missing IP"})
                return
            ip = params["ip"][0]
            if ip in ("192.0.2.30", "192.0.2.40"):
                self._send(200, {"status": 403 if ip == "192.0.2.30" else 200})
                return
            self._send(200, {
                "status": 200,
                "ip": ip,
                "score": {"inbound": "Critical", "outbound": "Low"},
                "issues": {"is_scanner": True},
            })
            return

        if request.path == "/ti/v1/feed/outbound":
            if params.get("key") != [TEST_KEY] or params.get("format") != ["json"]:
                self._send(403, {"error": "invalid test credentials or format"})
                return
            self._send(200, {"body": {"data": [{
                "ip": TEST_IP,
                "confidence": 80,
                "score": 95,
                "reason": "Synthetic integration system-test indicator",
                "first_seen": "2026-01-01 00:00:00",
                "last_seen": "2026-01-01 01:00:00",
            }, {
                "ip": "198.51.100.20",
            }]}})
            return

        self._send(404, {"error": "unknown test endpoint"})

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Do not print request URLs: the TI Feed test key is sent as a query.
        return


def run_api():
    server = ThreadingHTTPServer(("0.0.0.0", 8080), MockCriminalIP)
    print("Synthetic Criminal IP API mock listening on :8080", flush=True)
    server.serve_forever()


def fortigate_line():
    current = datetime.now(timezone.utc)
    return (
        f'date={current:%Y-%m-%d} time={current:%H:%M:%S} tz="+0000" '
        f"type=traffic subtype=forward srcip={TEST_IP} srcport=45001 "
        "dstip=198.51.100.20 dstport=443 proto=6 action=deny synthetic=true"
    )


def send_syslog(protocol, host, port):
    ready = threading.Event()

    def signal_ready(_signum, _frame):
        ready.set()

    signal.signal(signal.SIGUSR1, signal_ready)
    print("Waiting for elastic-package to apply the test policy", flush=True)
    if not ready.wait(timeout=180):
        raise TimeoutError("Timed out waiting for the system-test policy signal")

    payload = (fortigate_line() + "\n").encode("utf-8")
    deadline = time.monotonic() + 20
    while True:
        try:
            sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
            with socket.socket(socket.AF_INET, sock_type) as client:
                client.settimeout(2)
                if protocol == "tcp":
                    client.connect((host, port))
                    client.sendall(payload)
                else:
                    client.sendto(payload, (host, port))
            print(f"Sent one synthetic FortiGate event over {protocol.upper()}", flush=True)
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "api":
        run_api()
        return
    if len(sys.argv) == 5 and sys.argv[1] == "syslog":
        _, _, protocol, host, port = sys.argv
        if protocol not in {"tcp", "udp"}:
            raise ValueError(f"Unsupported test protocol: {protocol}")
        send_syslog(protocol, host, int(port))
        return
    raise SystemExit("usage: system_service.py api | syslog <tcp|udp> <host> <port>")


if __name__ == "__main__":
    main()
