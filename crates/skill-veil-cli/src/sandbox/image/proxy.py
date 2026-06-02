#!/usr/bin/env python3
"""Recording-and-blocking forward proxy for the skill-veil sandbox.

Captures outbound HTTP and HTTPS attempts, logs each as a JSON line to
stdout, and BLOCKS the real egress -- it returns a stub and NEVER
forwards. Combined with running on an `--internal` Docker network, even a
forwarding attempt could not leave. The channel collects the log via
`docker logs` and turns captured requests into network behaviors with the
destination and the data the skill tried to exfiltrate.

HTTPS is intercepted (MITM): on CONNECT the proxy terminates TLS using a
per-host leaf certificate minted on the fly from an image-local throwaway
CA (trusted inside the sandbox image only), reads the decrypted request,
and captures method + URL + payload before refusing to forward. So the
exfiltrated DATA is recovered for HTTPS too, not just the destination host.
"""
import json
import os
import ssl
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

MAX_BODY = 4096
CA_CERT = "/sv-ca/ca.crt"
CA_KEY = "/sv-ca/ca.key"

with open(CA_KEY, "rb") as _f:
    _CA_KEY = serialization.load_pem_private_key(_f.read(), password=None)
with open(CA_CERT, "rb") as _f:
    _CA_CERT = x509.load_pem_x509_certificate(_f.read())

_leaf_cache = {}
_leaf_lock = threading.Lock()


def emit(entry):
    sys.stdout.write(json.dumps(entry) + "\n")
    sys.stdout.flush()


def leaf_cert_for(host):
    """Mint (and cache) a leaf cert+key PEM pair for `host`, signed by the
    image-local CA, written to a tmpfs path for `ssl.load_cert_chain`."""
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
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        _leaf_cache[host] = (cpath, kpath)
        return _leaf_cache[host]


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
        host = self.path.rsplit(":", 1)[0]
        self.close_connection = True
        self.send_response(200, "Connection Established")
        self.end_headers()
        try:
            cpath, kpath = leaf_cert_for(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cpath, kpath)
            tls = ctx.wrap_socket(self.connection, server_side=True)
        except Exception as exc:
            # Client may pin certs or speak non-HTTP over TLS; we still
            # captured the destination from the CONNECT line.
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
            if ":" in text:
                key, value = text.split(":", 1)
                if key.strip().lower() == "content-length":
                    length = int(value.strip() or 0)
        body = reader.read(min(length, MAX_BODY)) if length else b""
        emit({
            "method": method,
            "url": "https://{}{}".format(host, path),
            "host": host,
            "body": body.decode("utf-8", "replace"),
        })
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("SV_PROXY_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
