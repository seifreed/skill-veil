#!/usr/bin/env python3
"""In-container observer for the skill-veil dynamic sandbox.

Detonates a skill's referenced scripts under ``strace`` and turns the
observed syscalls into the behavior JSON contract consumed by
``sandbox::observation``. Portable across runc and gVisor (both support
ptrace); no eBPF. Emits a single JSON document on stdout:

    {"behaviors": [{"class": ..., "detail": ..., "source": "script"}],
     "timed_out": false, "truncated": false}

Skills ship code in several languages; the observer runs each supported
script with its interpreter (``.sh``→sh, ``.mjs``/``.js``→node,
``.py``→python3). When the package names an entrypoint-like file
(trigger/main/index/run/...) only those are run, so a multi-file package
detonates through its real entry rather than every library file; otherwise
all supported scripts are run, capped.

Coverage: outbound INET connections (network_connect / dns_query),
process spawns (execve), sensitive reads, persistence and other writes,
and privilege-change attempts (setuid-family to root, capset, namespace
manipulation, ptrace, and connects to the container-runtime socket).
Privilege calls blocked by the seccomp profile still appear because strace
records the attempt before the kernel returns EPERM.
"""
import glob
import json
import os
import re
import subprocess
import sys

SKILL_DIR = "/skill"
PER_SCRIPT_TIMEOUT_SECS = 15
MAX_BEHAVIORS = 500
MAX_SCRIPTS = 12
TRACE_SYSCALLS = (
    "connect,sendto,sendmsg,execve,openat,open,"
    "setuid,setreuid,setresuid,setgid,setregid,setresgid,"
    "capset,setns,unshare,ptrace"
)

# Extension -> interpreter argv prefix. The skill ecosystem ships shell,
# Node (ES modules + CommonJS), and Python entrypoints.
INTERPRETERS = {
    ".sh": ["sh"],
    ".mjs": ["node"],
    ".js": ["node"],
    ".py": ["python3"],
}
# Filename stems that denote a package entrypoint; when present we run only
# these (they import the rest) instead of detonating every library file.
ENTRYPOINT_STEMS = {
    "trigger", "main", "index", "run", "start", "cli", "app",
    "setup", "install", "bootstrap", "init", "__main__", "entry",
}

SENSITIVE_READ = re.compile(
    r"/etc/(passwd|shadow|sudoers)|/\.aws/|/\.ssh/|id_rsa|/\.env\b|credentials|\.netrc"
)
PERSISTENCE = re.compile(
    r"\.bashrc|\.bash_profile|\.zshrc|\.profile|/etc/cron|crontab|/\.config/autostart|"
    r"/Library/LaunchAgents|systemd/.*\.service"
)
WRITE_FLAGS = re.compile(r"O_WRONLY|O_RDWR|O_CREAT|O_APPEND")
NOISE_WRITE = re.compile(
    r"/__pycache__/|\.pyc(?:\.|$)|^/usr/|^/lib/|^/lib64/|^/proc/|^/sys/|^/dev/|/etc/ld\.so"
)

# connect() and the connectionless sendto()/sendmsg() render the INET
# sockaddr identically, so the host/port sub-pattern (capture 1 = port,
# captures 2/3 = address) is shared. AF_INET6 renders
# `sin6_flowinfo=htonl(0), ` between the port and the address; without this
# optional segment every IPv6 egress was missed, so IPv6 C2 / exfil produced
# no network behavior.
_SOCKADDR_INET = (
    r'\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*'
    r'(?:sin6_flowinfo=htonl\(\d+\),\s*)?'
    r'(?:sin6?_addr=inet_(?:addr|pton)\([^,]*"([^"]+)"\)|inet_pton\([^"]*"([^"]+)")'
)
CONNECT_INET = re.compile(r'connect\(\d+,\s*' + _SOCKADDR_INET)
CONNECT_UNIX = re.compile(r'connect\(\d+,\s*\{sa_family=AF_UNIX,\s*sun_path="([^"]+)"')
# Connectionless egress: a SOCK_DGRAM socket never calls connect(), it passes
# the destination inline to sendto()/sendmsg() (the latter wraps it in
# msg_name={...}). Without this, UDP C2 / exfil and UDP/53 DNS-tunnel egress
# produced no network behavior at all.
SENDTO_INET = re.compile(r'send(?:to|msg)\(.*?' + _SOCKADDR_INET)
DOCKER_RESOLVER = "127.0.0.11"
RUNTIME_SOCKET = re.compile(r"docker\.sock|containerd.*\.sock|crio\.sock|podman\.sock")
EXECVE = re.compile(r'execve\("([^"]+)",\s*\[([^\]]*)\]')
# `open` is also enrolled in TRACE_SYSCALLS, and its path is the FIRST
# argument (`open("/p", FLAGS)`), not the second as in `openat(AT_FDCWD,
# "/p", FLAGS)`. Two defects dropped every plain `open`: `openat?` parses
# as "opena" + optional "t" so it never matched the keyword "open" (needs
# the "a"), and the hard-coded `[^,]*,` assumed the openat 2-arg layout.
# `open(?:at)?` matches both keywords and the leading fd/dirfd segment is
# optional so the path parses as arg 1 (open) or arg 2 (openat).
OPENAT = re.compile(r'open(?:at)?\((?:[^,]*,\s*)?"([^"]+)"(?:,\s*([A-Z_|]+))?')
PRIV_ALWAYS = re.compile(r"\b(capset|setns|unshare|ptrace)\((.*?)\)\s*=")
PRIV_ROOT = re.compile(
    r"\b(setuid|setreuid|setresuid|setgid|setregid|setresgid)\((0[^)]*)\)"
)


def emit_behaviors(behaviors, timed_out):
    # The single behavior-JSON contract the Rust channel parses, shared by
    # script-mode (observe) and agent-detonation (detonate imports this).
    truncated = len(behaviors) > MAX_BEHAVIORS
    json.dump(
        {"behaviors": behaviors[:MAX_BEHAVIORS], "timed_out": timed_out, "truncated": truncated},
        sys.stdout,
    )
    sys.stdout.flush()


def main():
    args = set(sys.argv[1:])
    behaviors = []
    if "--scripts" in args or not args:
        behaviors.extend(run_scripts())
    emit_behaviors(behaviors, False)


def discover_scripts():
    found = []
    for ext in INTERPRETERS:
        found.extend(glob.glob(f"{SKILL_DIR}/**/*{ext}", recursive=True))
    found = sorted(set(found))
    entrypoints = [
        s for s in found
        if os.path.splitext(os.path.basename(s))[0].lower() in ENTRYPOINT_STEMS
    ]
    chosen = entrypoints if entrypoints else found
    return chosen[:MAX_SCRIPTS]


def run_scripts():
    behaviors = []
    seen = set()
    for index, script in enumerate(discover_scripts()):
        rel = os.path.relpath(script, SKILL_DIR)
        ext = os.path.splitext(script)[1].lower()
        interp = INTERPRETERS.get(ext)
        if not interp:
            continue
        trace_path = f"/tmp/trace-{index}.log"
        try:
            subprocess.run(
                ["strace", "-f", "-qq", "-e", f"trace={TRACE_SYSCALLS}",
                 "-o", trace_path, *interp, script],
                cwd="/tmp",
                timeout=PER_SCRIPT_TIMEOUT_SECS,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            add(behaviors, seen, "process_spawn",
                f"{rel}: timed out (possible long-running payload)")
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
        handle = open(path, errors="replace")
    except OSError:
        return
    launcher_exec_skipped = False
    # Stream line-by-line: a long agent detonation can emit a multi-GB
    # trace, and reading it whole would OOM the parser under the container
    # memory cap (empty stdout -> the channel sees no observation at all).
    for line in handle:
        if len(behaviors) > MAX_BEHAVIORS:
            break
        # connect() and the connectionless sendto()/sendmsg() share the same
        # sockaddr rendering and capture groups (port, host).
        m = CONNECT_INET.search(line) or SENDTO_INET.search(line)
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
            # The first execve in each trace is the interpreter launcher
            # (sh/node/python3) the observer itself invoked.
            if not launcher_exec_skipped:
                launcher_exec_skipped = True
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


def _self_test():
    # Contract for CONNECT_INET: capture host + port for both AF_INET and
    # AF_INET6 connect() lines. AF_INET6 carries an extra
    # `sin6_flowinfo=htonl(0), ` field between the port and the address; without
    # tolerating it every IPv6 connect was missed and IPv6 egress was invisible.
    # Run with `python3 observe.py --self-test` (the image has no pytest harness;
    # this keeps the egress-observation contract executable).
    ipv4 = ('connect(5, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("203.0.113.7")}, 16) = 0')
    ipv6 = ('connect(6, {sa_family=AF_INET6, sin6_port=htons(8443), '
            'sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700::6810:85e5", '
            '&sin6_addr), sin6_scope_id=0}, 28) = 0')
    m4 = CONNECT_INET.search(ipv4)
    assert m4 and m4.group(1) == "443" and (m4.group(2) or m4.group(3)) == "203.0.113.7", \
        "AF_INET connect must parse host+port"
    m6 = CONNECT_INET.search(ipv6)
    assert m6 and m6.group(1) == "8443" and (m6.group(2) or m6.group(3)) == "2606:4700::6810:85e5", \
        "AF_INET6 connect must parse host+port"
    assert not CONNECT_INET.search("connect(7, {sa_family=AF_UNIX, sun_path=\"/x\"}, 12)"), \
        "AF_UNIX must not match the INET parser"

    # Contract for OPENAT: parse the path from BOTH `open` (path is arg 1) and
    # `openat` (path is arg 2). A plain `open` to a persistence/sensitive path
    # must be observable, not dropped because the regex assumed the openat
    # layout.
    mo = OPENAT.search('open("/root/.bashrc", O_WRONLY|O_CREAT|O_APPEND) = 3')
    assert mo and mo.group(1) == "/root/.bashrc", "plain open() path must parse"
    moa = OPENAT.search('[pid 99] openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3')
    assert moa and moa.group(1) == "/etc/passwd", "openat() path must parse"

    # Contract for SENDTO_INET: connectionless UDP egress (a SOCK_DGRAM socket
    # never calls connect()) must still yield host+port, or UDP C2 / DNS-tunnel
    # exfil is invisible.
    udp = ('sendto(3, "exfil", 5, 0, {sa_family=AF_INET, sin_port=htons(9999), '
           'sin_addr=inet_addr("198.51.100.23")}, 16) = 5')
    ms = SENDTO_INET.search(udp)
    assert ms and ms.group(1) == "9999" and (ms.group(2) or ms.group(3)) == "198.51.100.23", \
        "sendto() UDP egress must parse host+port"
    udp6 = ('sendmsg(4, {msg_name={sa_family=AF_INET6, sin6_port=htons(53), '
            'sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700::1", &sin6_addr), '
            'sin6_scope_id=0}, msg_namelen=28, msg_iov=[...]}, 0) = 30')
    m6 = SENDTO_INET.search(udp6)
    assert m6 and m6.group(1) == "53" and (m6.group(2) or m6.group(3)) == "2606:4700::1", \
        "sendmsg() IPv6 egress must parse host+port"
    print("observe CONNECT_INET/OPENAT/SENDTO_INET self-test: OK")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        _self_test()
        sys.exit(0)
    main()
