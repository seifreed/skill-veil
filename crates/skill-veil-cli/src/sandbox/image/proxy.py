#!/usr/bin/env python3
"""Recording-and-blocking forward proxy for the skill-veil sandbox.

Default behaviour (no allowlist): captures every outbound HTTP/HTTPS
attempt as a JSON line on stdout and BLOCKS the real egress -- returns a
stub and NEVER forwards. HTTPS is MITM-decrypted with a per-host leaf cert
minted from an image-local throwaway CA so the exfiltrated payload is
recovered, not just the destination host.

Selective forwarding (agent-detonation mode): hosts matching
``SV_PROXY_ALLOWLIST`` (comma-separated substrings) are FORWARDED to the
real upstream -- a raw CONNECT tunnel for HTTPS (no MITM, no capture) and a
pass-through for plain HTTP -- so a real coding agent inside the sandbox
can reach its model gateway while the skill-under-analysis's own traffic
(everything NOT on the allowlist) is still captured and blocked. The
allowlist is the analysis operator's egress, never the malware's.
"""
import json
import os
import select
import socket
import ssl
import sys
import tempfile
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

MAX_BODY = 4096
CA_CERT = "/sv-ca/ca.crt"
CA_KEY = "/sv-ca/ca.key"
ALLOWLIST = [h.strip() for h in os.environ.get("SV_PROXY_ALLOWLIST", "").split(",") if h.strip()]

with open(CA_KEY, "rb") as _f:
    _CA_KEY = serialization.load_pem_private_key(_f.read(), password=None)
with open(CA_CERT, "rb") as _f:
    _CA_CERT = x509.load_pem_x509_certificate(_f.read())

_leaf_cache = {}
_leaf_lock = threading.Lock()


def emit(entry):
    sys.stdout.write(json.dumps(entry) + "\n")
    sys.stdout.flush()


def is_allowlisted(host):
    h = (host or "").split(":")[0].lower()
    return any(allowed.lower() in h for allowed in ALLOWLIST)


def leaf_cert_for(host):
    with _leaf_lock:
        cached = _leaf_cache.get(host)
        if cached:
            return cached
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(_CA_CERT.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(_CA_KEY, hashes.SHA256())
        )
        cdir = tempfile.mkdtemp()
        cpath = os.path.join(cdir, "leaf.crt")
        kpath = os.path.join(cdir, "leaf.key")
        with open(cpath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(kpath, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        _leaf_cache[host] = (cpath, kpath)
        return _leaf_cache[host]


def _relay(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 60)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _capture(self, method):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(min(length, MAX_BODY)) if length else b""
        host = self.headers.get("Host", "")
        if is_allowlisted(host):
            self._forward_plain(method, host, body)
            return
        emit({"method": method, "url": self.path, "host": host,
              "body": body.decode("utf-8", "replace")})
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def _forward_plain(self, method, host, body):
        url = self.path if self.path.startswith("http") else f"http://{host}{self.path}"
        try:
            req = urllib.request.Request(url, data=body or None, method=method)
            for k, v in self.headers.items():
                if k.lower() not in ("proxy-connection", "connection"):
                    req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except Exception:
            self.send_response(502)
            self.end_headers()

    def do_GET(self):
        self._capture("GET")

    def do_POST(self):
        self._capture("POST")

    def do_PUT(self):
        self._capture("PUT")

    def do_DELETE(self):
        self._capture("DELETE")

    def do_CONNECT(self):
        host = self.path.rsplit(":", 1)[0]
        port = int(self.path.rsplit(":", 1)[1]) if ":" in self.path else 443
        self.close_connection = True
        if is_allowlisted(host):
            self._tunnel(host, port)
            return
        self._mitm_capture(host)

    def _tunnel(self, host, port):
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError as exc:
            emit({"method": "CONNECT", "url": self.path, "host": host, "body": "",
                  "allowlisted": True, "forward_error": str(exc)})
            self.send_response(502)
            self.end_headers()
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        _relay(self.connection, upstream)
        try:
            upstream.close()
        except OSError:
            pass

    def _mitm_capture(self, host):
        self.send_response(200, "Connection Established")
        self.end_headers()
        try:
            cpath, kpath = leaf_cert_for(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cpath, kpath)
            tls = ctx.wrap_socket(self.connection, server_side=True)
        except Exception as exc:
            emit({"method": "CONNECT", "url": self.path, "host": host, "body": "",
                  "tls_error": str(exc)})
            return
        try:
            self._capture_decrypted(tls, host)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def _capture_decrypted(self, tls, host):
        reader = tls.makefile("rb")
        request_line = reader.readline(65536).decode("latin-1").strip()
        parts = request_line.split()
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else "/"
        length = 0
        while True:
            raw = reader.readline(65536)
            if raw in (b"\r\n", b"\n", b""):
                break
            text = raw.decode("latin-1")
            if ":" in text and text.split(":", 1)[0].strip().lower() == "content-length":
                length = int(text.split(":", 1)[1].strip() or 0)
        body = reader.read(min(length, MAX_BODY)) if length else b""
        emit({"method": method, "url": f"https://{host}{path}", "host": host,
              "body": body.decode("utf-8", "replace")})
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("SV_PROXY_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
