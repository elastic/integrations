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
        params = parse_qs(request.query, keep_blank_values=True)
        if request.path.endswith('/query'):
            if (params.get('tenant') != ['a b', 'second'] or params.get('empty') != [''] or
                    (request.path.startswith('/v1/') and params.get('ip') != [TEST_IP]) or
                    (request.path.startswith('/ti/') and (
                        params.get('format') != ['json'] or params.get('key') != [TEST_KEY]))):
                self._send(400, {'error': 'query parameters were not preserved or replaced'})
                return
            request = request._replace(path=request.path.removesuffix('/query'))
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

        if request.path == "/ti/v1/feed/response-error":
            self._send(200, {"status": 403})
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
                "reason": "Missing IP must not discard the valid indicators",
            }, None, "invalid feed entry", {"ip": None}, {"ip": ""}, {"ip": "   "}, {
                "ip": "\t 198.51.100.20 \r\n",
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


def fortigate_line(source_port=45001):
    current = datetime.now(timezone.utc)
    return (
        f'date={current:%Y-%m-%d} time={current:%H:%M:%S} tz="+0000" '
        f"type=traffic subtype=forward srcip={TEST_IP} srcport={source_port} "
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
    if protocol == "udp":
        # The policy signal does not guarantee the UDP input has bound its port.
        # UDP sendto succeeds even without a receiver, so OSError retries alone
        # cannot prevent the first datagram from being lost during startup.
        time.sleep(5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(10):
                client.sendto(payload, (host, port))
                time.sleep(1)
        print("Sent ten synthetic FortiGate datagrams over UDP", flush=True)
        return

    deadline = time.monotonic() + 20
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                if protocol == "tcp":
                    client.connect((host, port))
                    frames = []
                    for source_port in (45001, 45002):
                        message = fortigate_line(source_port).encode("utf-8")
                        frames.append(str(len(message)).encode("ascii") + b" " + message)
                    # Also check legacy delimiter framing on the same connection.
                    frames.append((fortigate_line(45003) + "\n").encode("utf-8"))
                    client.sendall(b"".join(frames))
                    print("Sent two octet-counted and one newline-delimited FortiGate events; keeping TCP open", flush=True)
                    # Wait for the receiver to close at test teardown. Ingestion must
                    # finish without EOF flushing messages buffered by the input.
                    client.settimeout(None)
                    while client.recv(1):
                        pass
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
