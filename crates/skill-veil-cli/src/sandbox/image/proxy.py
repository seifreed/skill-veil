#!/usr/bin/env python3
"""Recording-and-blocking forward proxy for the skill-veil sandbox.

Captures outbound HTTP(S) attempts (full URL + payload for HTTP, the
destination host for HTTPS CONNECT), logs each as a JSON line to stdout,
and BLOCKS the real egress -- it returns a stub and NEVER forwards.
Combined with running on an `--internal` Docker network, even a forwarding
attempt could not leave. The channel collects the log via `docker logs`
and turns captured requests into network behaviors with the destination
and (for HTTP) the data the skill tried to exfiltrate.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 4096


def emit(entry):
    sys.stdout.write(json.dumps(entry) + "\n")
    sys.stdout.flush()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _capture(self, method):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(min(length, MAX_BODY)) if length else b""
        emit({
            "method": method,
            "url": self.path,
            "host": self.headers.get("Host", ""),
            "body": body.decode("utf-8", "replace"),
        })
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self._capture("GET")

    def do_POST(self):
        self._capture("POST")

    def do_PUT(self):
        self._capture("PUT")

    def do_DELETE(self):
        self._capture("DELETE")

    def do_CONNECT(self):
        # HTTPS: we see only the destination host (no MITM). Log it and
        # refuse the tunnel so nothing leaves.
        emit({"method": "CONNECT", "url": self.path, "host": self.path, "body": ""})
        self.send_response(502)
        self.end_headers()

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("SV_PROXY_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
