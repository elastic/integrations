"""Run with Python 3 and Elastic's mito command on PATH (no live Zoom account).

The CEL programs are extracted from the input templates. Only the clock is
replaced, so pagination can cross midnight without waiting for a real rollover.
"""

import json
import re
import subprocess
import tempfile
import textwrap
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


PACKAGE = Path(__file__).resolve().parents[2]
STREAMS = {
    "activity": "activity_logs",
    "meeting_activity": "meeting_activity_logs",
    "operation": "operation_logs",
}


class PaginationTest(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.response = (200, "application/json", "{}")
        test = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                test.requests.append((parse_qs(urlsplit(self.path).query), self.headers))
                status, content_type, body = test.response
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join)
        self.addCleanup(self.server.shutdown)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def state(self, start="2026-10-28"):
        return {
            "url": f"http://127.0.0.1:{self.server.server_port}",
            "page_size": 300,
            "initial_interval": "72h",
            "activity_type": "All Activities",
            "cursor": {"poll_start": start},
            "want_more": False,
        }

    def evaluate(self, stream, state, now="2026-10-29T00:01:00Z"):
        source = (PACKAGE / "data_stream" / stream / "agent/stream/cel.yml.hbs").read_text()
        program = textwrap.dedent(source.split("program: |-\n", 1)[1].split("\ntags:", 1)[0])
        program = re.sub(r"\bnow\b", f'timestamp("{now}")', program)
        cel = Path(self.tmp.name) / "program.cel"
        data = Path(self.tmp.name) / "state.json"
        cel.write_text(program)
        data.write_text(json.dumps(state))
        result = subprocess.run(
            ["mito", "-max_executions", "1", "-data", str(data), str(cel)],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_midnight_keeps_both_window_dates(self):
        for stream, logs in STREAMS.items():
            for start in ("2026-10-28", "2026-05-01"):
                with self.subTest(stream=stream, start=start):
                    self.response = (200, "application/json", json.dumps({logs: [], "next_page_token": "page2"}))
                    first = self.evaluate(stream, self.state(start), "2026-10-28T23:59:00Z")
                    before = self.requests[-1][0]
                    second = self.evaluate(stream, first)
                    after = self.requests[-1][0]
                    self.assertEqual(after["from"], before["from"])
                    self.assertEqual(after["to"], before["to"])
                    self.assertEqual(after["next_page_token"], ["page2"])
                    self.assertEqual(second["cursor"], first["cursor"])

    def test_errors_clear_token_without_advancing_checkpoint(self):
        errors = (
            (400, "application/json", '{"code":300,"message":"The next page token is invalid or expired."}'),
            (200, "application/json", '{"code":300,"message":"The next page token is invalid or expired."}'),
            (200, "application/xml", '<error><code>300</code><message>Invalid token</message></error>'),
            (200, "text/html", "<html>Upstream error</html>"),
            (200, "application/json", '{"code":"300","message":"Invalid token"}'),
            (200, "application/json", "[]"),
            (429, "application/json", '{"code":429,"message":"Rate limit exceeded"}'),
        )
        for stream, logs in STREAMS.items():
            for error in errors:
                with self.subTest(stream=stream, response=error):
                    self.response = (200, "application/json", json.dumps({logs: [], "next_page_token": "expired"}))
                    first = self.evaluate(stream, self.state())
                    self.response = error
                    failed = self.evaluate(stream, first)
                    self.assertIn("error", failed["events"])
                    self.assertEqual(failed["next"], {})
                    self.assertFalse(failed["want_more"])
                    self.assertEqual(failed["cursor"], first["cursor"])
                    self.response = (200, "application/json", json.dumps({logs: []}))
                    self.evaluate(stream, failed)
                    retry, headers = self.requests[-1]
                    self.assertNotIn("next_page_token", retry)
                    self.assertEqual(retry["from"], [first["cursor"]["poll_start"]])
                    self.assertEqual(headers.get("Accept"), "application/json")

    def test_midnight_completion_starts_next_window(self):
        for stream, logs in STREAMS.items():
            with self.subTest(stream=stream):
                self.response = (200, "application/json", json.dumps({logs: [], "next_page_token": "page2"}))
                first = self.evaluate(stream, self.state(), "2026-10-28T23:59:00Z")
                self.response = (200, "application/json", json.dumps({logs: []}))
                completed = self.evaluate(stream, first)
                self.assertEqual(completed["cursor"], {"poll_start": "2026-10-28"})
                self.assertTrue(completed["want_more"])
                result = self.evaluate(stream, completed)
                query = self.requests[-1][0]
                self.assertEqual(query["from"], ["2026-10-28"])
                self.assertEqual(query["to"], ["2026-10-29"])
                self.assertNotIn("next_page_token", query)
                self.assertFalse(result["want_more"])

    def test_completed_window_advances_and_drops_token(self):
        for stream, logs in STREAMS.items():
            with self.subTest(stream=stream):
                self.response = (200, "application/json", json.dumps({logs: [{"id": "event1"}]}))
                result = self.evaluate(stream, self.state())
                self.assertEqual(result["cursor"], {"poll_start": "2026-10-29"})
                self.assertEqual(result["next"], {})
                self.assertFalse(result["want_more"])
                self.assertEqual(json.loads(result["events"][0]["message"]), {"id": "event1"})

    def test_restart_replays_incomplete_window(self):
        for stream, logs in STREAMS.items():
            with self.subTest(stream=stream):
                self.response = (200, "application/json", json.dumps({logs: [], "next_page_token": "page2"}))
                first = self.evaluate(stream, self.state())
                restarted = self.state()
                restarted["cursor"] = first["cursor"].copy()
                self.evaluate(stream, restarted)
                self.assertNotIn("next_page_token", self.requests[-1][0])
                self.assertEqual(self.requests[-1][0]["from"], ["2026-10-28"])


if __name__ == "__main__":
    unittest.main()
