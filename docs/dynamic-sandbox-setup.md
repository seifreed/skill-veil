# Dynamic sandbox setup (Docker + gVisor)

The dynamic behavior sandbox (`--dynamic` / `--sandbox-detonate-agent`)
**executes untrusted skill code**, so it is gated behind a build feature
and a runtime flag and it needs a container runtime. This document covers
the host setup; the report format is documented separately in
[dynamic-sandbox-report.md](dynamic-sandbox-report.md).

## 1. Build with the sandbox feature

```bash
cargo build --release -p skill-veil --features sandbox
```

Without `--features sandbox` the `--dynamic` flags still parse but the
channel is a no-op with a one-line note, so scripts stay portable across
build variants.

## 2. Docker

A reachable Docker daemon is the only hard requirement. The CLI probes it
with `docker version`; if Docker is absent the sandbox skips with a note
and the rest of the scan is unaffected.

The hardened sandbox image is built automatically on first use from the
embedded build context (`crates/skill-veil-cli/src/sandbox/image/`). The
tag is content-addressed (`skill-veil-sandbox:sv<hash>`), so any change to
the image rebuilds rather than masking a stale `:latest`.

If your Docker uses BuildKit and the build fails on DNS, pre-build without
BuildKit:

```bash
DOCKER_BUILDKIT=0 docker build --network=host -t <printed-tag> \
  crates/skill-veil-cli/src/sandbox/image/
```

## 3. gVisor (`runsc`) — real isolation

gVisor is the primary isolation boundary (a user-space kernel). It is
**Linux-only**. The CLI auto-detects it via `docker info` and uses
`--runtime=runsc` when present.

Install it (Debian/Ubuntu; see <https://gvisor.dev/docs/user_guide/install/>
for other distros):

```bash
# Add the gVisor apt repo and key
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor \
  -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc

# Register runsc as a Docker runtime (writes /etc/docker/daemon.json) and reload
sudo runsc install
sudo systemctl restart docker

# Verify the daemon now advertises the runtime
docker info --format '{{.Runtimes}}'   # must contain "runsc"
```

When `runsc` is registered, `--dynamic` uses it automatically. The
container kernel reports as `4.19.0-gvisor` (the user-space kernel), not
the host kernel.

### No gVisor? Use the weaker runc fallback

gVisor cannot run on macOS (Docker Desktop exposes only `runc`) or on hosts
without `runsc`. By default the sandbox **refuses** to fall back silently.
Opt into the weaker `runc` isolation explicitly:

```bash
skill-veil scan-package ./suspicious-skill --dynamic --sandbox-allow-runc
```

Everything except the gVisor isolation strength still works under `runc`:
the image, observer, behavior capture, the recording proxy, and the
behavioral signatures. Use `runc` for development; use gVisor to actually
run untrusted samples.

## 4. The Docker MTU caveat (custom networks)

`--sandbox-record-network` and `--sandbox-detonate-agent` create **custom**
Docker networks (an `--internal` bridge plus an egress net for the proxy).
Custom bridge networks default to **MTU 1500**. On hosts whose underlay MTU
is smaller (e.g. Hetzner ≈ 1400), large transfers over those networks stall
or corrupt while small ones succeed — which silently breaks both the image
build (large apt index) and the detonation agent's model traffic (the LLM
request hangs until the proxy's relay times out).

If you see image builds or detonation hanging on large transfers, pin the
MTU for **both** the default bridge and user-created bridges in
`/etc/docker/daemon.json`:

```json
{
  "runtimes": { "runsc": { "path": "/usr/bin/runsc" } },
  "mtu": 1400,
  "default-network-opts": { "bridge": { "com.docker.network.driver.mtu": "1400" } }
}
```

Then `sudo systemctl restart docker`. `"mtu"` alone only fixes `docker0`;
`"default-network-opts"` is what applies to the sandbox's custom networks.

## 5. Running it

```bash
# Observe the skill's own scripts + a host-side mocked agent (no network)
skill-veil scan-package ./suspicious-skill --dynamic

# Capture exfil destination + payload (HTTPS MITM-decrypted), egress blocked
skill-veil scan-package ./suspicious-skill --dynamic --sandbox-record-network

# Detonate with a REAL coding agent inside the container that USES the skill
skill-veil scan-package ./suspicious-skill --sandbox-detonate-agent

# Write the full runtime evidence (behaviors + signatures + captures) to JSON
skill-veil scan-package ./suspicious-skill \
  --dynamic --sandbox-record-network --dynamic-report behavior.json
```

## 6. Detonation agent (`--sandbox-detonate-agent`)

This mode runs a real coding agent (OpenCode) inside the hardened container
that reads `SKILL.md` and actually carries out the skill's stated function,
so credential/arg/agent-gated malicious paths execute instead of staying
dormant under blind script execution.

- **Model.** Defaults to `opencode/deepseek-v4-flash-free` — a **free,
  keyless** model, so no API key is required out of the box. Override with
  `SV_DETONATE_MODEL`.
- **Other knobs.** `SV_DETONATE_PROMPT` overrides the detonation prompt;
  `SV_DETONATE_TIMEOUT` sets the in-container deadline (default 150s, kept
  shorter than the outer wall-clock cap so partial output is returned).
- **Egress.** Only the agent's model gateway and startup fetches are
  forwarded by the proxy; everything else is the skill's traffic and is
  captured + blocked. The forwarded allowlist is
  `opencode.ai, models.dev, github.com, registry.npmjs.org, githubusercontent.com`.
  If you point `SV_DETONATE_MODEL` at a different provider, that provider's
  host must be reachable through the proxy.

```bash
# Example: override the detonation model
SV_DETONATE_MODEL=opencode/deepseek-v4-flash-free \
  skill-veil scan-package ./suspicious-skill --sandbox-detonate-agent
```

## 7. Behavioral signatures

On top of the per-behavior `SANDBOX_*` findings, a malware-sandbox-style
signature layer fires on **co-occurring** behaviors within one run. These
are advisory (`ReviewSignal`) and never change the deterministic static
verdict. The embedded baseline ships:

| Signature | Fires on |
|---|---|
| `SANDBOX_BEHAVIOR_EXFIL_SECRET_TO_NETWORK` | a sensitive-file read **and** egress to a non-infrastructure host in the same run |
| `SANDBOX_BEHAVIOR_EXFIL_TO_ABUSE_CHANNEL` | egress to a known anonymous exfil / out-of-band relay (webhook.site, telegram bot API, discord webhooks, ngrok, interactsh/oast, transfer.sh, …) |
| `SANDBOX_BEHAVIOR_C2_KNOWN_PORT` | a connection to a port commonly used for C2 / reverse shells |
| `SANDBOX_BEHAVIOR_RUNTIME_PERSISTENCE` | a write to a persistence surface (cron / systemd / shell rc), excluding non-persistent `/tmp` writes |
| `SANDBOX_BEHAVIOR_CONTAINER_ESCAPE_ATTEMPT` | a runtime control-socket / namespace / capability escape primitive |
| `SANDBOX_BEHAVIOR_SECRET_THEN_SPAWN` | a sensitive-file read **and** a subprocess spawn in the same run |

The baseline lives in
`crates/skill-veil-cli/src/sandbox/behavior_rules.yaml`. Each rule matches a
co-occurrence of observed behavior classes with optional `detail_any`
(substring must be present) and `detail_none` (substring must be absent)
filters.

## 8. Troubleshooting

- **`--dynamic` does nothing.** Built without `--features sandbox`, or Docker
  is unreachable — both skip with a one-line note.
- **"gVisor required" / refuses to run.** `runsc` is not registered; either
  install it (§3) or pass `--sandbox-allow-runc`.
- **Image build hangs / detonation hangs on large transfers.** MTU; see §4.
- **No behaviors captured under gVisor with `--sandbox-record-network`.**
  The proxy is reached by IP (injected as `HTTP(S)_PROXY`), not the Docker
  DNS alias, because gVisor's netstack cannot reach Docker's embedded
  resolver — make sure you are on a build that injects the proxy IP.
