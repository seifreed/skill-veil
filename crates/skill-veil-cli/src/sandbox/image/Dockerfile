# Hardened base image for the dynamic-behavior sandbox.
#
# Minimal Debian slim + strace (portable syscall observation that works
# under both runc and gVisor; eBPF is unreliable under Docker Desktop /
# gVisor). The container is run with the isolation flags from
# `sandbox::policy` (read-only root, dropped caps, non-root user, no
# network). `/observe` runs the skill's scripts under strace and emits a
# single JSON document of observed behavior on stdout.
#
# The image also bakes a throwaway MITM CA (`gen_ca.py`) so the recording
# proxy (`proxy.py`) can decrypt the sandbox's outbound HTTPS and capture
# the exfiltrated payload, not just the destination host. The CA is
# trusted ONLY inside this image (added to its trust store below) and
# never on the host; a new build mints a new CA.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir cryptography

COPY gen_ca.py /gen_ca.py
RUN python3 /gen_ca.py \
    && cp /sv-ca/ca.crt /usr/local/share/ca-certificates/skill-veil-sandbox-ca.crt \
    && update-ca-certificates \
    && chmod -R a+rX /sv-ca

# Point the common HTTP clients at the system bundle (now containing the
# MITM CA) so HTTPS handshakes through the proxy verify and complete.
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

COPY observe.py /observe.py
COPY proxy.py /proxy.py

# Default entrypoint; the channel appends `--scripts` / `--agent`.
ENTRYPOINT ["python3", "/observe.py"]
