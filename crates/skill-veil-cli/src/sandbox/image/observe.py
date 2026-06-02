#!/usr/bin/env python3
"""In-container observer for the skill-veil dynamic sandbox.

Runs a skill's shell scripts under ``strace`` and turns the observed
syscalls into the behavior JSON contract consumed by
``sandbox::observation``. Portable across runc and gVisor (both support
ptrace); no eBPF. Emits a single JSON document on stdout:

    {"behaviors": [{"class": ..., "detail": ..., "source": "script"}],
     "timed_out": false, "truncated": false}

Coverage: outbound INET connections (network_connect / dns_query),
process spawns (execve), sensitive reads, persistence and other writes,
and privilege-change attempts (setuid-family to root, capset, namespace
manipulation, ptrace, and connects to the container-runtime socket).
Privilege calls blocked by the seccomp profile still appear here because
strace records the attempt before the kernel returns EPERM.
"""
import glob
import json
import os
import re
import subprocess
import sys

SKILL_DIR = "/skill"
PER_SCRIPT_TIMEOUT_SECS = 20
MAX_BEHAVIORS = 500
TRACE_SYSCALLS = (
    "connect,execve,openat,open,"
    "setuid,setreuid,setresuid,setgid,setregid,setresgid,"
    "capset,setns,unshare,ptrace"
)

SENSITIVE_READ = re.compile(
    r"/etc/(passwd|shadow|sudoers)|/\.aws/|/\.ssh/|id_rsa|/\.env\b|credentials|\.netrc"
)
PERSISTENCE = re.compile(
    r"\.bashrc|\.bash_profile|\.zshrc|\.profile|/etc/cron|crontab|/\.config/autostart|"
    r"/Library/LaunchAgents|systemd/.*\.service"
)
WRITE_FLAGS = re.compile(r"O_WRONLY|O_RDWR|O_CREAT|O_APPEND")
# Benign writes to filter out: interpreter bytecode caches and
# system/library/pseudo-filesystem paths. Under the read-only root these
# all fail anyway; recording them would only produce noise findings.
NOISE_WRITE = re.compile(
    r"/__pycache__/|\.pyc(?:\.|$)|^/usr/|^/lib/|^/lib64/|^/proc/|^/sys/|^/dev/|/etc/ld\.so"
)

CONNECT_INET = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*'
    r'(?:sin6?_addr=inet_(?:addr|pton)\([^,]*"([^"]+)"\)|inet_pton\([^"]*"([^"]+)")'
)
CONNECT_UNIX = re.compile(r'connect\(\d+,\s*\{sa_family=AF_UNIX,\s*sun_path="([^"]+)"')
# Docker's embedded DNS resolver — infra noise, never the skill's intent.
DOCKER_RESOLVER = "127.0.0.11"
# Connecting to the container runtime's control socket is a classic escape
# attempt, not ordinary egress.
RUNTIME_SOCKET = re.compile(r"docker\.sock|containerd.*\.sock|crio\.sock|podman\.sock")
EXECVE = re.compile(r'execve\("([^"]+)",\s*\[([^\]]*)\]')
OPENAT = re.compile(r'openat?\([^,]*,\s*"([^"]+)"(?:,\s*([A-Z_|]+))?')
# capset / namespace / ptrace: no legitimate use from a skill script.
PRIV_ALWAYS = re.compile(r"\b(capset|setns|unshare|ptrace)\((.*?)\)\s*=")
# setuid-family escalation specifically toward root (first arg 0); a
# benign privilege *drop* to a higher uid is not flagged.
PRIV_ROOT = re.compile(
    r"\b(setuid|setreuid|setresuid|setgid|setregid|setresgid)\((0[^)]*)\)"
)


def main():
    args = set(sys.argv[1:])
    behaviors = []
    # The container observer covers script execution only; the
    # instrumented agent runs host-side (no container, mocked tools).
    if "--scripts" in args or not args:
        behaviors.extend(run_scripts())
    truncated = len(behaviors) > MAX_BEHAVIORS
    json.dump(
        {"behaviors": behaviors[:MAX_BEHAVIORS], "timed_out": False, "truncated": truncated},
        sys.stdout,
    )
    sys.stdout.flush()


def run_scripts():
    behaviors = []
    seen = set()
    scripts = sorted(glob.glob(f"{SKILL_DIR}/**/*.sh", recursive=True))
    for script in scripts:
        rel = os.path.relpath(script, SKILL_DIR)
        trace_path = f"/tmp/trace-{os.path.basename(script)}.log"
        try:
            subprocess.run(
                ["strace", "-f", "-qq", "-e", f"trace={TRACE_SYSCALLS}",
                 "-o", trace_path, "sh", script],
                cwd="/tmp",
                timeout=PER_SCRIPT_TIMEOUT_SECS,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            add(behaviors, seen, "process_spawn", f"{rel}: timed out (possible long-running payload)")
        except Exception:
            continue
        parse_trace(trace_path, behaviors, seen, rel)
    return behaviors


def add(behaviors, seen, klass, detail):
    key = (klass, detail)
    if key not in seen:
        seen.add(key)
        behaviors.append({"class": klass, "detail": detail, "source": "script"})


def parse_trace(path, behaviors, seen, script):
    try:
        with open(path, errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return
    first_exec_skipped = False
    for line in lines:
        m = CONNECT_INET.search(line)
        if m:
            port = m.group(1)
            host = m.group(2) or m.group(3) or "?"
            if host == DOCKER_RESOLVER:
                continue
            klass = "dns_query" if port == "53" else "network_connect"
            add(behaviors, seen, klass, f"{host}:{port}")
            continue
        m = CONNECT_UNIX.search(line)
        if m:
            path_arg = m.group(1)
            if RUNTIME_SOCKET.search(path_arg):
                add(behaviors, seen, "privilege_change", f"unix-socket: {path_arg}")
            continue
        m = PRIV_ALWAYS.search(line)
        if m:
            add(behaviors, seen, "privilege_change", f"{m.group(1)}({m.group(2)[:80]})")
            continue
        m = PRIV_ROOT.search(line)
        if m:
            add(behaviors, seen, "privilege_change", f"{m.group(1)}({m.group(2)[:80]})")
            continue
        m = EXECVE.search(line)
        if m:
            binary = m.group(1)
            argv = m.group(2).replace('"', "").strip()
            # The first execve is the `sh <script>` launcher itself.
            if not first_exec_skipped and binary in ("/bin/sh", "/usr/bin/sh"):
                first_exec_skipped = True
                continue
            add(behaviors, seen, "process_spawn", argv[:200] or binary)
            continue
        m = OPENAT.search(line)
        if m:
            target = m.group(1)
            flags = m.group(2) or ""
            if SENSITIVE_READ.search(target):
                add(behaviors, seen, "sensitive_file_read", target)
            elif WRITE_FLAGS.search(flags):
                if PERSISTENCE.search(target):
                    add(behaviors, seen, "persistence_write", target)
                elif not target.startswith("/tmp/") and not NOISE_WRITE.search(target):
                    add(behaviors, seen, "file_write", target)


if __name__ == "__main__":
    main()
