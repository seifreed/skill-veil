#!/usr/bin/env python3
"""Mine accumulated sandbox reports for recurring malicious/suspicious
behavior patterns to feed new behavior_rules.yaml co-occurrence signatures."""
import glob
import json
import os
import re
from collections import Counter, defaultdict

OUT = "/root/sv-out/reports"
reports = []
for sub in ("dyn", "det"):
    for f in glob.glob(os.path.join(OUT, sub, "*.json")):
        try:
            d = json.load(open(f))
            d["_engine"] = sub
            d["_hash"] = os.path.basename(f)[:12]
            reports.append(d)
        except Exception:
            pass

print(f"reports: {len(reports)} ({sum(1 for r in reports if r['_engine']=='dyn')} dyn, "
      f"{sum(1 for r in reports if r['_engine']=='det')} det)")

cls_counter = Counter()
spawn_cmds = Counter()       # normalized first token / binary
net_hosts = Counter()
sensitive = Counter()
persistence = Counter()
priv = Counter()
sig_counter = Counter()
cooccur = Counter()          # frozenset of classes per skill (det only)

# malicious token taxonomy on process_spawn / network details
TOKENS = {
    "download_exec": re.compile(r"\b(curl|wget)\b.*\|\s*(bash|sh|python)|\b(curl|wget)\b.*-O", re.I),
    "pipe_to_shell": re.compile(r"\|\s*(bash|sh|zsh)\b"),
    "base64_decode": re.compile(r"base64\s+-d|b64decode|atob\(|--decode"),
    "eval_exec": re.compile(r"\beval\b|exec\(|python3?\s+-c|node\s+-e"),
    "reverse_shell": re.compile(r"/dev/tcp/|bash\s+-i|nc\s+.*-e|ncat|socat|mkfifo"),
    "chmod_exec": re.compile(r"chmod\s+(\+x|[0-7]*7[0-7]*)"),
    "crypto_miner": re.compile(r"xmrig|minerd|stratum\+tcp|nicehash|cpuminer|--coin"),
    "cred_access": re.compile(r"\.ssh|id_rsa|\.aws|credentials|\.env\b|\.netrc|keychain|wallet"),
    "recon": re.compile(r"\b(uname|whoami|\bid\b|hostname|ifconfig|lsb_release|systeminfo)\b"),
    "pkg_install": re.compile(r"pip\s+install|npm\s+install|apt(-get)?\s+install"),
    "disable_sec": re.compile(r"iptables|ufw\s+disable|setenforce\s+0|systemctl\s+stop"),
}
token_hits = Counter()
token_examples = defaultdict(set)

for r in reports:
    classes = set()
    for b in r.get("behaviors", []):
        c, detail = b.get("class", ""), b.get("detail", "")
        cls_counter[c] += 1
        classes.add(c)
        if c == "process_spawn":
            # normalize: strip /usr/bin/bash -c wrapper, take meaningful token
            d = detail.replace("/usr/bin/", "").replace("/bin/", "")
            m = re.search(r"bash,?\s*-c,?\s*(.+)", d)
            core = m.group(1) if m else d
            first = re.split(r"[,\s]+", core.strip())[0][:40]
            spawn_cmds[first] += 1
            for name, rx in TOKENS.items():
                if rx.search(detail):
                    token_hits[name] += 1
                    if len(token_examples[name]) < 4:
                        token_examples[name].add(detail[:90])
        elif c == "network_connect":
            host = detail.split()[-1] if " " in detail else detail
            host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
            net_hosts[host] += 1
            for name in ("cred_access", "reverse_shell"):
                if TOKENS[name].search(detail):
                    token_hits[name] += 1
        elif c == "sensitive_file_read":
            sensitive[detail[:50]] += 1
        elif c == "persistence_write":
            persistence[detail[:50]] += 1
        elif c == "privilege_change":
            priv[detail[:50]] += 1
    for cap in r.get("network_captures", []):
        h = cap.get("host", "")
        if h:
            net_hosts[h] += 1
    for s in r.get("matched_signatures", []):
        sig_counter[s.get("rule_id", "")] += 1
    if r["_engine"] == "det" and classes:
        cooccur[frozenset(classes)] += 1

# Hosts that are package/registry infra or the agent's own search/fetch —
# NOT skill malice. Suspicious = everything else.
BENIGN_INFRA = re.compile(
    r"(^|\.)(pypi\.org|pypi\.python\.org|pythonhosted\.org|pypa\.io|"
    r"python\.org|nodejs\.org|iojs\.org|"
    r"nodesource\.com|npmjs\.org|npmjs\.com|yarnpkg\.com|github\.com|"
    r"githubusercontent\.com|githubassets\.com|bing\.com|google\.com|"
    r"debian\.org|ubuntu\.com|ollama\.com|opencode\.ai|models\.dev|"
    r"crates\.io|rubygems\.org|golang\.org|pkg\.go\.dev)$|"
    r"^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"  # docker/private IPs
)
# download piped/redirected straight into a shell interpreter = the real
# download-and-execute pattern, distinct from a plain file download.
DL_TO_SHELL = re.compile(r"(curl|wget)\b[^|]*\|\s*(bash|sh|zsh|python3?|node)\b|"
                         r"(curl|wget)\b.*-o-?\s.*\|\s*(bash|sh)")

def show(title, counter, n=20):
    print(f"\n=== {title} ===")
    for k, v in counter.most_common(n):
        print(f"  {v:4d}  {k}")

show("behavior classes", cls_counter)
show("malicious-token hits (process_spawn/net)", token_hits)
print("\n  token examples:")
for name in token_hits:
    for ex in list(token_examples[name])[:3]:
        print(f"    [{name}] {ex}")
show("top spawn commands (normalized)", spawn_cmds, 30)
show("network hosts", net_hosts, 30)
show("sensitive reads", sensitive)
show("persistence writes", persistence)
show("privilege changes", priv)
show("matched signatures (already firing)", sig_counter)
print("\n=== class co-occurrence per detonation (combos) ===")
for combo, v in cooccur.most_common(15):
    print(f"  {v:3d}  {sorted(combo)}")

print("\n###### SUSPICIOUS SIGNAL (agent/infra noise filtered) ######")
susp_hosts = Counter({h: c for h, c in net_hosts.items()
                      if h and not BENIGN_INFRA.search(h)})
show("SUSPICIOUS network hosts (non-infra, candidate C2/exfil)", susp_hosts, 30)
dl_shell = []
for r in reports:
    for b in r.get("behaviors", []):
        if b.get("class") == "process_spawn" and DL_TO_SHELL.search(b.get("detail", "")):
            dl_shell.append((r["_hash"], b["detail"][:110]))
print(f"\n=== download-piped-to-shell (true download+exec): {len(dl_shell)} ===")
for h, d in dl_shell[:15]:
    print(f"  [{h}] {d}")

# The genuinely interesting malicious-runtime skills: those that fired one of
# the 5 behavioral CO-OCCURRENCE rules (not the per-behavior SANDBOX_* ones).
COOCCUR_RULES = {"SANDBOX_BEHAVIOR_EXFIL_SECRET_TO_NETWORK", "SANDBOX_BEHAVIOR_C2_KNOWN_PORT",
                 "SANDBOX_BEHAVIOR_RUNTIME_PERSISTENCE", "SANDBOX_BEHAVIOR_CONTAINER_ESCAPE_ATTEMPT",
                 "SANDBOX_BEHAVIOR_SECRET_THEN_SPAWN"}
hits = []
for r in reports:
    fired = {s.get("rule_id") for s in r.get("matched_signatures", [])} & COOCCUR_RULES
    if fired:
        hits.append((r["_hash"], r["_engine"], sorted(fired)))
print(f"\n=== skills firing a behavioral CO-OCCURRENCE rule: {len(hits)} ===")
for h, e, f in hits[:25]:
    print(f"  [{e} {h}] {f}")
