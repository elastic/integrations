#!/usr/bin/env python3
"""A minimal Elasticsearch stand-in that accepts bulk requests and discards them.

The harness normally points the agent output at an unreachable Elasticsearch so decoded
events are never drained and stay resident. That isolates the cost of ONE page, but it
also stops the run after one page: the memory queue fills, the input blocks on publish,
and no further page is ever fetched.

Production does not behave that way. Both httpjson streams poll on a short interval with a
24h initial lookback, and the CEL stream re-enters immediately while `want_more` is true
with a 336h lookback, so a catching-up pod decodes page after page back-to-back. Each new
page is decoded while the previous one is still garbage the collector has not yet returned,
and GODEBUG=madvdontneed=1 keeps freed pages charged to the cgroup. That sustained state,
not a single cold page, is what the production working-set peaks show.

Draining the output is what lets the harness reach that state, so this serves just enough
of the Elasticsearch API for the beats output to consider the write successful:

  GET  /            version handshake the output performs before it will send anything
  POST /_bulk       accepts the batch and reports every action as created
  everything else   an empty 200, so an unmodelled probe cannot stall the output

The bulk reply must contain one item per action or the output treats the response as
malformed and retries forever instead of draining, so items are counted from the request
body (an action line plus a source line per document).

--max-eps throttles acknowledgement to a target events-per-second. Agentless applies a
ratelimit processor (rate 300, throttle_behavior delay) on the export path, so a real pod
cannot drain as fast as it can decode. That backpressure is itself a memory driver: the
queue stays fuller for longer and events stay resident. Draining at full speed measures a
pod that is faster than any real one, so it understates memory.

Discards all data. It is a load-bearing part of a memory measurement, not a test double
for anything functional.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = {
    "name": "fake-es",
    "cluster_name": "memcap-harness",
    "cluster_uuid": "memcap0000000000000000",
    "version": {
        "number": "8.18.0",
        "build_flavor": "default",
        "build_type": "docker",
        "build_hash": "0000000000000000000000000000000000000000",
        "build_date": "2024-01-01T00:00:00.000000000Z",
        "build_snapshot": False,
        "lucene_version": "9.9.0",
        "minimum_wire_compatibility_version": "7.17.0",
        "minimum_index_compatibility_version": "7.0.0",
    },
    "tagline": "You Know, for Search",
}


class Throttle:
    """Delays acknowledgement so the sustained document rate stays under max_eps.

    Shared across connections and serialised, which is what makes it a global rate rather
    than a per-connection one - the agentless ratelimit processor is likewise global.
    """

    def __init__(self, max_eps: float) -> None:
        self.max_eps = max_eps
        self.lock = threading.Lock()
        self.start = time.monotonic()
        self.docs = 0

    def account(self, n: int) -> None:
        if self.max_eps <= 0:
            return
        with self.lock:
            self.docs += n
            earliest = self.start + self.docs / self.max_eps
            delay = earliest - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    docs = 0
    bulks = 0
    throttle: Throttle | None = None

    def log_message(self, fmt, *args):  # keep stdout for the counter only
        pass

    def _send(self, payload: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Elastic-Product", "Elasticsearch")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(json.dumps(VERSION).encode())
        else:
            self._send(b"{}")

    def do_HEAD(self):
        self._send(b"")

    def do_PUT(self):
        self._read_body()
        self._send(b'{"acknowledged":true}')

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if self.headers.get("Content-Encoding") == "gzip" and body:
            try:
                body = gzip.decompress(body)
            except OSError:
                pass
        return body

    def do_POST(self):
        body = self._read_body()
        if "_bulk" not in self.path:
            self._send(b"{}")
            return
        # One item per action. A bulk body is action/source line pairs, so count the
        # action lines: those are the odd-numbered non-empty lines.
        lines = [ln for ln in body.split(b"\n") if ln.strip()]
        actions = 0
        expect_action = True
        for ln in lines:
            if expect_action:
                actions += 1
                # A delete action has no source line; everything the beats output sends
                # is create/index, which does.
                expect_action = b'"delete"' in ln[:32]
            else:
                expect_action = True
        Handler.docs += actions
        Handler.bulks += 1
        if Handler.bulks % 50 == 0:
            print(f"drained bulks={Handler.bulks} docs={Handler.docs}", flush=True)
        if Handler.throttle is not None:
            Handler.throttle.account(actions)
        items = [{"create": {"status": 201, "_index": "memcap", "_id": str(i)}} for i in range(actions)]
        self._send(json.dumps({"took": 1, "errors": False, "items": items}).encode())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--addr", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9200)
    ap.add_argument("--max-eps", type=float, default=0,
                    help="cap sustained documents/second (0 = unlimited); agentless applies 300")
    args = ap.parse_args()
    if args.max_eps > 0:
        Handler.throttle = Throttle(args.max_eps)
    srv = ThreadingHTTPServer((args.addr, args.port), Handler)
    srv.daemon_threads = True
    print(f"fake-es listening on {args.addr}:{args.port} max_eps={args.max_eps or 'unlimited'}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
