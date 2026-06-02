# Hardened base image for the dynamic-behavior sandbox.
#
# Minimal Debian slim + strace (portable syscall observation that works
# under both runc and gVisor; eBPF is unreliable under Docker Desktop /
# gVisor). The container is run with the isolation flags from
# `sandbox::policy` (read-only root, dropped caps, non-root user, no
# network). `/observe` runs the skill's scripts under strace and emits a
# single JSON document of observed behavior on stdout.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*

COPY observe.py /observe.py

# Default entrypoint; the channel appends `--scripts` / `--agent`.
ENTRYPOINT ["python3", "/observe.py"]
