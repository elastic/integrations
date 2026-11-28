import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class CursorState:
    def __init__(self):
        self.lock = threading.Lock()
        self.alert_requests = 0
        self.initial_window = None
        self.pending_window = None
        self.completed_to = None
        self.failed = None


STATE = CursorState()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with STATE.lock:
            if STATE.failed is not None:
                self.respond(409, {"detail": STATE.failed})
                return

            try:
                status, body = self.handle_request()
            except (AssertionError, KeyError, TypeError, ValueError) as error:
                STATE.failed = str(error)
                print(f"cursor assertion failed: {STATE.failed}", flush=True)
                self.respond(409, {"detail": STATE.failed})
                return

            self.respond(status, body)

    def handle_request(self):
        request = urlparse(self.path)
        assert request.path == "/rest/rules/es/events_tail/", (
            f"unexpected path: {request.path}"
        )
        assert self.headers.get("Authorization") == "Token test-token", (
            "missing or invalid authorization"
        )

        query = parse_qs(request.query)
        assert query["page_number"] == ["1"], f"unexpected page: {query}"
        assert query["page_size"] == ["2"], f"unexpected page size: {query}"

        phase = query["qfilter"][0]
        window = (query["from_date"][0], query["to_date"][0])
        assert int(window[1]) >= int(window[0]), f"inverted window: {window}"

        if phase == "event_type:alert":
            return self.handle_alert(window)
        if phase == "event_type:stamus":
            return self.handle_stamus(window)
        raise AssertionError(f"unexpected phase: {phase}")

    def handle_alert(self, window):
        STATE.alert_requests += 1

        # Six responses force one failure to escape the HTTP client's five
        # retry attempts. Every attempt must retain the exact initial window.
        if STATE.alert_requests <= 6:
            if STATE.initial_window is None:
                STATE.initial_window = window
            assert window == STATE.initial_window, (
                f"initial window changed during retry: "
                f"{STATE.initial_window} -> {window}"
            )
            return 503, {"detail": "Service temporarily unavailable."}

        if STATE.alert_requests == 7:
            assert window == STATE.initial_window, (
                f"recovery did not reuse failed window: "
                f"{STATE.initial_window} -> {window}"
            )
            STATE.pending_window = window
            return 200, envelope(
                {
                    "event_type": "alert",
                    "timestamp": "2024-01-15T17:00:00.000000+0000",
                    "src_ip": "198.51.100.30",
                    "dest_ip": "203.0.113.30",
                    "flow_id": 2019054435055807,
                    "alert": {
                        "signature": "SN Cursor Recovery Test",
                        "severity": 2,
                        "signature_id": 1000006,
                        "category": "Unknown Traffic",
                    },
                }
            )

        assert STATE.completed_to is not None, (
            "alert window advanced before the prior stamus phase completed"
        )
        assert window[0] == STATE.completed_to, (
            f"window did not advance from prior to_date: "
            f"{STATE.completed_to} -> {window}"
        )
        STATE.pending_window = window

        if STATE.alert_requests == 8:
            return 200, envelope(
                {
                    "event_type": "alert",
                    "timestamp": "2024-01-15T17:01:00.000000+0000",
                    "src_ip": "198.51.100.31",
                    "dest_ip": "203.0.113.31",
                    "flow_id": 2019054435055808,
                    "alert": {
                        "signature": "SN Cursor Progression Test",
                        "severity": 2,
                        "signature_id": 1000007,
                        "category": "Unknown Traffic",
                    },
                }
            )
        return 200, envelope()

    def handle_stamus(self, window):
        assert STATE.pending_window == window, (
            f"stamus phase did not reuse alert window: "
            f"{STATE.pending_window} -> {window}"
        )
        STATE.completed_to = window[1]
        STATE.pending_window = None
        return 200, envelope()

    def respond(self, status, body):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        print(format % args, flush=True)


def envelope(event=None):
    results = [] if event is None else [event]
    return {
        "count": len(results),
        "next": None,
        "previous": None,
        "results": results,
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8091"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
