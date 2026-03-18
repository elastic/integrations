"""Mock Dataminr Pulse API server for elastic-package system tests."""

import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

with open("/app/alerts_response.json", "r") as f:
    ALERTS_RESPONSE = f.read()


def make_token_response():
    expire_ms = int((time.time() + 3600) * 1000)
    return json.dumps({"dmaToken": "mock-test-token-abc123", "expire": expire_ms})


class MockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/auth/2/token":
            self._handle_token()
        else:
            self._send_json(404, {"error": "Not found"})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/pulse/v1/alerts":
            self._handle_alerts()
        else:
            self._send_json(404, {"error": "Not found"})

    def _handle_token(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        content_type = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            self._send_json(400, {"error": "Invalid content type"})
            return

        params = parse_qs(body)
        grant_type = params.get("grant_type", [None])[0]
        client_id = params.get("client_id", [None])[0]
        client_secret = params.get("client_secret", [None])[0]

        if grant_type != "api_key" or not client_id or not client_secret:
            self._send_json(401, {"error": "Invalid credentials"})
            return

        self._send_raw(200, make_token_response())

    def _handle_alerts(self):
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self._send_json(401, {"error": "Unauthorized"})
            return

        self._send_raw(200, ALERTS_RESPONSE)

    def _send_json(self, code, data):
        self._send_raw(code, json.dumps(data))

    def _send_raw(self, code, body_str):
        body = body_str.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"[MockServer] {format % args}")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), MockHandler)
    print("[MockServer] Starting Dataminr Pulse mock API on port 8080")
    server.serve_forever()
