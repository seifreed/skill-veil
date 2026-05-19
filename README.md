<p align="center">
  <img src="https://img.shields.io/badge/skill--veil-Agent%20Extension%20Security-blue?style=for-the-badge" alt="skill-veil">
</p>

<h1 align="center">skill-veil</h1>

<p align="center">
  <strong>Static security and policy scanner for skills, prompts, MCP manifests, and agent-adjacent artifacts</strong>
</p>

<p align="center">
  <a href="https://github.com/seifreed/skill-veil/releases"><img src="https://img.shields.io/github/v/release/seifreed/skill-veil?style=flat-square&logo=github" alt="GitHub Release"></a>
  <a href="https://github.com/seifreed/skill-veil/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/skill-veil/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/skill-veil/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://github.com/seifreed/skill-veil/releases"><img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-informational?style=flat-square" alt="Platforms"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/skill-veil/stargazers"><img src="https://img.shields.io/github/stars/seifreed/skill-veil?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/skill-veil/issues"><img src="https://img.shields.io/github/issues/seifreed/skill-veil?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

<p align="center">
  <a href="benchmarks/vt-baseline.json"><img src="https://img.shields.io/badge/recall-95.31%25-brightgreen?style=flat-square&label=VT%20corpus%20recall" alt="Recall"></a>
  <a href="benchmarks/vt-baseline.json"><img src="https://img.shields.io/badge/precision-99.86%25-brightgreen?style=flat-square" alt="Precision"></a>
  <a href="benchmarks/vt-baseline.json"><img src="https://img.shields.io/badge/FPR-11.11%25%20(4%2F36)-yellow?style=flat-square" alt="False Positive Rate"></a>
  <a href="benchmarks/vt-baseline.json"><img src="https://img.shields.io/badge/corpus-2976%20samples-blue?style=flat-square" alt="Corpus Size"></a>
</p>

---

## Overview

**skill-veil** is an open source static analysis and policy tool for the agent
extension supply chain.

It helps answer a narrow but useful operational question:

> should this skill, prompt pack, instruction file, MCP manifest, or related
> artifact be allowed, reviewed, or blocked before it lands in a repo or CI
> pipeline?

It is strongest as a **static security and policy layer**, not as a universal
malware engine.

### Key Features

| Feature | Description |
|---------|-------------|
| **Agent Extension Coverage** | First-class support for `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `SYSTEM.md`, prompt packs, and MCP manifests |
| **Artifact Analysis** | Inspects referenced scripts, manifests, lockfiles, Docker artifacts, and operational configs |
| **Policy Engine** | `log`, `require_approval`, `block` with profiles, waivers, baselines, and overrides |
| **CI-Friendly Output** | Text, JSON, SARIF, SHIELD, diff mode, compact CI summary, and PR gating support |
| **External Rule Packs** | Versioned `official` and `community` rule packs with fixtures and validation |
| **Benchmarking** | Labeled corpus, confidence calibration, threshold tuning, and release history dashboard |
| **VirusTotal Integration** | Bulk download, report caching, and cross-check between skill-veil verdicts and VT Code Insight |
| **PromptIntel Integration** | Curated jailbreak corpus + agent-feed IOC enrichment + threat-intel report submission with persistent rate-limit tracker |
| **LLM Enrichment** | Optional third scoring engine across Ollama, LM Studio, OpenAI, Anthropic, and Ollama Cloud |
| **LLM Adjudication** | Gated, ≥2-of-3 consensus reconciliation: taint-FP `Malicious→Suspicious` downgrade and the symmetric FN `Suspicious→Malicious` upgrade; immutable core verdict; single-provider-flip prompt-injection signal; offline replay tooling (`adjudication-eval`) |
| **Analyst Feedback** | Append-only disposition overlay that turns production triage into a bounded, allowlist-only learned signal (never escalates an action) |
| **Ground-Truth Corpus** | Curated gold corpus (3-LLM consensus + human review of disputes) scored by the same pipeline as the regression baseline |
| **Native NOVA Semantics** | `semantics:` patterns run on-device by default via a local sentence-embedding model; opt out with `--no-nova-semantics` |
| **Inline Suppressions** | `# skill-veil:ignore`, `nosem`, and `nosemgrep` markers with optional rule-id and reason |
| **Unified Config** | Single `~/.skill-veil.toml` for VT, LLM, and PromptIntel providers; per-flag overrides on the CLI |

### What It Detects

```
Behavior        Remote execution, install hooks, deferred execution, persistence
Composite       Fake-dependency dropper, crypto wallet-drainer staging,
                C2 beacon staging (k-of-n; each signal benign alone)
Supply Chain    Unpinned dependencies, missing lockfiles, remote MCP endpoints
Taint           Secret/identity access reaching an external network (source→sink)
LLM Integrity   Single-provider benign flip vs ≥2 dissenters (prompt injection
                against the adjudication path)
Prompt Risk     Persistent instruction tampering, cognitive rootkits, prompt packs
Tooling Risk    Tool abuse, autonomy escalation, approval bypass patterns
Runtime Risk    Privileged containers, host mounts, process execution, secret access
Artifacts       package.json, requirements.txt, pyproject.toml, Cargo.toml,
                Dockerfile, docker-compose, lockfiles, Makefile, .npmrc, pip.conf
```

---

## Why a dedicated scanner for agent skills?

Generic malware scanners (VirusTotal, ClamAV, YARA-on-binaries) are
designed for executables, archives, and URL/network reputation. Agent
skills are markdown manifests where the malicious payload is *prose* —
natural-language instructions that read credential files, persist
across sessions, fetch remote "instructions" to execute, or bypass
approval flows.

Skill-veil's rule pack targets that surface:

| Threat class | Skill-veil signals (examples) |
|---|---|
| Prompt injection (multilingual) | `OFFICIAL_PROMPT_TAMPERING_OVERRIDE_*`, XML interaction-config |
| Autonomy bypass | unbounded loops, "without confirmation" idioms (EN/PT/ES) |
| Persistence | cron / heartbeat / callback to remote URL |
| Credential exposure | reads of `~/.ssh`, `~/.aws`, `.env`, browser cookies |
| Remote instruction download | multi-section fetch + execute |
| Agent neutralization | rewrites of agent config to invalid endpoints |
| Hostile narrative | ransom protocols, coercive framings |

### Benchmark on the VT-flagged corpus

We ran skill-veil over 2976 skills VirusTotal had labelled `malicious`
(corpus and SHAs in `benchmarks/vt-corpus.yaml`). Treating VT's labels
as ground truth, skill-veil reaches **91.73% recall** at **100%
precision** (zero false positives on this corpus —
2730 TP / 246 FN / 0 FP).

For the residual false-negative bucket we ran a strict multi-provider
LLM cross-check. A sample is treated as a VT mislabel only when **all**
of the following hold:

1. Every provider in the panel returns `verdict == benign`.
2. Every provider's confidence is ≥ 0.85.
3. At least one provider's confidence is ≥ 0.90.

The committed overrides + audit (`benchmarks/vt-baseline-overrides.yaml`,
`benchmarks/multi-llm-audit.yaml`) are the **2026-04-28 run with a
two-provider panel (Grok + OpenAI**, `grok-4-fast` / `gpt-4o-mini`).
The current default panel in `scripts/llm_filter_fns.py` is
**three providers (Grok + OpenAI + Anthropic)** — re-running the
override pipeline will use that panel; the figures below are from the
recorded two-provider April run and are refreshed on each
`regenerate_baseline.py`.

Of 246 samples submitted in that run, **36 passed consensus** (e.g.,
`chart-image`, `mineru-pdf`-style helpers); 210 were rejected (203 had
at least one provider disagree, 6 were below the confidence floor, 1
was a binary-disguised file the LLMs could not analyse). Treating the
36 passing samples as VT mislabels lifts recall to **92.86%** at 100%
precision *as recorded on 2026-04-28*. Each override carries its
per-provider verdicts, confidences, and timestamps in
`benchmarks/vt-baseline-overrides.yaml`; the full audit including
rejected samples is in `benchmarks/multi-llm-audit.yaml`.

A previous single-LLM pass (lmstudio only) accepted 131 of those
246 samples. Roughly three-quarters of that set did **not** survive
the multi-provider consensus — a useful reminder that one model's
opinion is not ground truth.

We are *not* claiming skill-veil outperforms VirusTotal. The two tools
answer different questions:

- **VirusTotal** aggregates dozens of AV engines and network/URL
  signals — strongest on binary reputation, supply-chain, and IOC
  correlation.
- **skill-veil** reads the manifest prose itself — strongest on
  prompt-layer attacks that don't show up in static binary scanners.

A sufficiently adversarial skill could craft prose that fools both
engines, which is why `benchmarks/CLAUDE.md` requires human review
for any override touching secrets, credentials, or remote execution.

Use them together, not as substitutes.

---

## Installation

### From Source

```bash
git clone https://github.com/seifreed/skill-veil.git
cd skill-veil
cargo install --path crates/skill-veil-cli
```

### From a GitHub Release

```bash
# Example
tar -xzf skill-veil-linux-x86_64.tar.gz
install -m 0755 skill-veil "$HOME/.local/bin/skill-veil"
```

Full installation notes: [docs/installation.md](docs/installation.md)

---

## Quick Start

```bash
# One-time setup: download and verify the latest signed rule pack into
# the user cache. Pinned to a release tag with --version vX.Y.Z if needed.
skill-veil init

# Scan a strict entrypoint
skill-veil scan-file examples/malicious-skill/SKILL.md

# Scan a package with manifests and related artifacts
skill-veil scan-package examples/manifest-package --format text

# Scan agent-extension targets beyond SKILL.md
skill-veil scan-file examples/agent-instructions/AGENTS.md
skill-veil scan-package examples/prompt-pack
skill-veil scan-package examples/mcp-server
```

`skill-veil init` is optional — the binary ships an embedded baseline
that scans work without any setup — but running it pulls in the latest
[`skill-veil-rules`](https://github.com/seifreed/skill-veil-rules)
release, verifies its Ed25519 signature against an embedded public key,
and unpacks it into `~/.cache/skill-veil/rules/<version>/`. The scanner
then picks up the verified packs automatically. See
[Rule packs](#rule-packs) for the full distribution model.

---

## Rule packs

There is **no single bundle**. Rules reach the scanner through two
*independent* releases plus a runtime-fetched signed pack:

| Release | What it is | Where |
|---|---|---|
| **`skill-veil` binary** | The program, with an **embedded rule snapshot** compiled in (`include_str!`) | `cargo install` / GitHub Release of this repo |
| **`skill-veil-rules`** | The Ed25519-**signed** rule tarball (`manifest.json` + `manifest.json.sig` + `skill-veil-rules-vX.Y.Z.tar.gz`) | GitHub Releases of the separate [`skill-veil-rules`](https://github.com/seifreed/skill-veil-rules) repo |

The binary release does **not** package the rules-repo tarball inside
its archive. The "bundle" is the snapshot compiled into the executable;
the signed pack is downloaded **separately, at runtime**.

### How it resolves at scan time

1. **No setup (offline, zero-config).** A freshly installed binary
   scans immediately using the **embedded snapshot**
   (`resources/official/{core,behavioral}.yaml`, `builtin_rules.yaml`,
   `taint_rules.yaml`) — no network, no `init`. This is why the
   embedded mirror exists and cannot be removed.
2. **`skill-veil init`.** Downloads the latest signed
   `skill-veil-rules` release, verifies its signature against the
   public keys embedded in the binary, and unpacks it into
   `~/.cache/skill-veil/rules/<version>/`. It also pulls the pinned
   NOVA pack (third channel, separate upstream, pinned by commit SHA).
3. **Precedence.** A verified pack in `~/.cache/skill-veil/rules/…`
   wins if present; otherwise the scanner falls back to the embedded
   snapshot. (Dev builds also fall back to a sibling
   `./rules/official/` working tree.)

So: download the binary → it scans now (embedded snapshot from the
binary's build). Run `skill-veil init` → it fetches the fresher
**signed** pack without re-releasing the binary. `skill-veil rules
status` shows the installed version and trusted key.

### Source of truth & the `taint` nuance

[`skill-veil-rules`](https://github.com/seifreed/skill-veil-rules) is
the **single source of truth**. The embedded snapshot is a *verified
mirror*, resynced on each binary release and locked by a drift check
(`embedded_baseline_mirrors_canonical_rules_repo`) so it can never
silently diverge.

One exception in mechanics: the `ARTIFACT_TAINT_*` pack
(`skill-veil-rules/taint/taint.yaml`) uses a distinct schema consumed
by a bespoke loader, so the binary **always** reads its *embedded*
copy (it is not loaded from the `init` cache). For taint, the rules
repo is the edit/source-of-truth and the drift check guarantees the
embedded copy stays identical.

Editing rules → always in `skill-veil-rules`; see
[Rule pack development](#rule-pack-development).

---

## Usage

### Command Line Interface

```bash
# Auto scan
skill-veil scan ./examples

# Strict explicit-entrypoint scan
skill-veil scan-file examples/safe-skill/SKILL.md

# Package scan
skill-veil scan-package . --format json --output current.json

# Dataset / marketplace / monorepo mode
skill-veil scan-dataset ./examples --preset ci --format text
```

### Common Commands

| Command | Description |
|--------|-------------|
| `scan` | Auto-discover and scan files or directories |
| `scan-file` | Scan a strict explicit entrypoint |
| `scan-package` | Scan a package without promoting docs to entrypoints |
| `scan-dataset` | Scan many packages in a repo, dataset, or marketplace mirror |
| `benchmark` | Run the labeled benchmark corpus |
| `baseline create` | Create a baseline from a JSON report |
| `baseline update` | Update a baseline safely |
| `waivers validate` | Validate waiver configuration |
| `diff` | Compare two JSON reports with baseline/waiver awareness |
| `init` | Download + verify both rule sources: (1) latest signed `skill-veil-rules` release (Ed25519 + per-file SHA-256), (2) latest `Nova-Hunting/nova-rules` commit pinned by SHA |
| `rules update` | Re-run `init` to refresh both locally installed packs |
| `rules status` | Show installed versions of both sources (skill-veil-rules + nova-rules with commit SHA + tarball SHA-256 + file count) |
| `rules validate` | Validate external rule packs |
| `rules test` | Test one rule against inline content |
| `rules test-pack` | Run pack fixtures |
| `rules pack-info` | Summarize external rule packs |
| `policy validate` | Validate a policy file |
| `vt download` | Bulk-download a corpus from VirusTotal Intelligence with cached reports |
| `vt report` | Fetch and cache the VT report for a single hash |
| `vt cross-check` | Compare skill-veil verdicts against VT Code Insight on a downloaded corpus |
| `promptintel download` | Bulk-download the PromptIntel jailbreak corpus into a scannable directory |
| `promptintel cross-check` | Scan the downloaded corpus and report per-severity detection gaps; supports `--fail-below FLOAT` as a CI gate |
| `promptintel feed sync` | Pull the agent-feed threat intel into the local cache (incremental by default; `--full` for revocation propagation) |
| `promptintel feed list` | Render the cached feed entries |
| `promptintel feed budget` | Show the persisted client-side rate-limit budget per endpoint |
| `promptintel report submit` | Submit a threat-intel report (5/h, 20/d) with client-side validation and `--dry-run` |
| `promptintel report list` | List reports the authenticated agent has previously submitted |
| `promptintel coverage` | Audit which threats in the official taxonomy are covered by at least one rule (offline; renders gaps per bucket) |
| `adjudication-eval` | Offline replay of recorded LLM-provider verdicts; reports ΔFP/ΔFN, precision/recall and exact-label transitions with and without each adjudication lever (zero live calls) |
| `gold build` | Seed a curated gold corpus from a recorded LLM-consensus rollup (no live calls); `--vt-reports <dir>` populates `vt_label` and derives disputes |
| `gold review` | Resolve a disputed gold sample with a human adjudication |
| `gold stats` | Admitted / disputed / per-label counts for a gold manifest |
| `disposition record` | Append an analyst disposition (true-positive / false-positive / benign) for a finding to the overlay |
| `disposition list` | List recorded dispositions (optionally filtered by rule) |
| `disposition stats` | Per-rule TP/FP counts plus the derived, bounded confidence delta / allowlist |

### Useful Options

| Option | Description |
|--------|-------------|
| `--format text/json/sarif/shield` | Output format |
| `--preset local/ci/strict/enterprise/triage` | Apply output and policy presets; `triage` = local plus both LLM-adjudication levers on (CI/strict/enterprise stay adjudication-OFF so deterministic verdicts never depend on an LLM) |
| `--quiet-summary` | Compact text output |
| `--explain-policy` | Focus on policy reasoning instead of finding details |
| `--baseline` | Accepted findings baseline |
| `--waivers` | Waiver file |
| `--policy` | Policy file |
| `--ci-summary` | Compact diff summary for CI |
| `--fail-on <mode>` | CI diff failure mode (`new-active` or `new-blocking`) |
| `--dashboard-output` | Write benchmark history dashboard |
| `--no-vt-enrich` | Skip VT enrichment even when `~/.skill-veil.toml` provides an apikey |
| `--no-llm-enrich` | Skip LLM enrichment even when an `[llm]` section is configured |
| `--no-promptintel-enrich` | Skip the offline PromptIntel feed-cache lookup |
| `--no-nova` | Skip running NOVA rules even if a NOVA pack is installed (benchmark isolation) |
| `--no-nova-semantics` | Opt out of the on-device NOVA `semantics:` model (default-on); falls back to the skipped-capability stub |
| `--llm-adjudicate-taint` | Re-check a taint-only `Malicious` via ≥2-of-3 LLM consensus; `Malicious→Suspicious` if benign consensus. Never mutates the core verdict (JSON/SARIF unchanged); affects the appended block + exit code only |
| `--llm-adjudicate-upgrade` | Symmetric mirror: re-check a single-FN-rule `Suspicious` via consensus; `Suspicious→Malicious` if ≥2 judge malicious. Single-provider benign flip blocks the downgrade and fails |
| `--disposition <path>` | Apply an analyst-feedback overlay (bounded confidence + allowlist, never escalates an action) |
| `--no-update-check` | Skip the once-per-day GitHub query that notifies you when newer rule sources are available (also via `SKILL_VEIL_NO_UPDATE_CHECK=1`) |
| `--llm-provider <name>` | Override the active LLM provider for one scan (`ollama`, `lmstudio`, `openai`, `anthropic`, `ollama-cloud`) |
| `--cache-dir` | Override the base directory for VT, LLM, and PromptIntel enrichment caches |

---

## Examples

### Review a suspicious package

```bash
skill-veil scan-package examples/suspicious-skill --format text
```

### Generate a report for CI

```bash
skill-veil scan-package . --preset ci --format json --output current.json
skill-veil scan-package . --preset ci --format sarif --output current.sarif
```

### Baseline + diff workflow

```bash
skill-veil baseline create current.json --output .skill-veil/baseline.json
skill-veil diff prev.json current.json --baseline .skill-veil/baseline.json --ci-summary --fail-on new-active
```

### Benchmark with history and dashboard

```bash
skill-veil benchmark benchmarks/corpus.yaml \
  --format json \
  --output benchmarks/history/latest.json \
  --history-file benchmarks/history/releases.json \
  --release-id local-dev \
  --dashboard-output benchmarks/history/dashboard.md
```

### Rule pack development

The rule packs live in their own repo,
[`skill-veil-rules`](https://github.com/seifreed/skill-veil-rules).
For local authoring, clone it next to skill-veil and point the
validators at the working tree:

```bash
git clone https://github.com/seifreed/skill-veil-rules ../skill-veil-rules

skill-veil rules validate --rules-dir ../skill-veil-rules/official
skill-veil rules test-pack \
  --rules-dir ../skill-veil-rules/official \
  --fixtures ../skill-veil-rules/fixtures/behavioral.yaml
skill-veil rules pack-info --rules-dir ../skill-veil-rules/official
```

Once your changes land in `skill-veil-rules`, a maintainer cuts a new
signed release; downstream `skill-veil init` picks it up on the next
run. The full contributor checklist lives in
[skill-veil-rules/CONTRIBUTING.md](https://github.com/seifreed/skill-veil-rules/blob/main/CONTRIBUTING.md).

### VirusTotal corpus and cross-check

```bash
# One-time setup: ~/.skill-veil.toml
# [vt]
# apikey = "..."

# Download a labeled corpus from VT Intelligence (reports + samples).
skill-veil vt download \
  --query 'entity:file has:codeinsight codeinsight_verdict:malicious' \
  --dest data --limit 200

# Pull a single VT report into the cache.
skill-veil vt report deadbeef0123...0123

# Compare skill-veil verdicts against VT Code Insight for a downloaded corpus.
skill-veil vt cross-check --dir data --format markdown --only-mismatches
```

### PromptIntel: jailbreak corpus, agent-feed enrichment, threat-intel reports

[PromptIntel](https://promptintel.novahunting.ai/) is the curated
threat-intel platform from [NovaHunting](https://novahunting.ai/) —
maintained by [Thomas Roccia (@fr0gger_)](https://x.com/fr0gger_) and
the PromptIntel community. It hosts a labelled jailbreak / abuse
corpus, the official 4-bucket / 38-threat taxonomy, and a public
agent-feed of community-submitted IOCs.

skill-veil integrates with all three — the corpus pins detection
regression tests, the feed enriches every scan with offline IOC
matching, and the report endpoints close the feedback loop.

**The taxonomy, corpus, and threat-intel feed are PromptIntel's work**;
skill-veil consumes them and renders them locally. Anyone running
`promptintel feed sync` should sign up at
[promptintel.novahunting.ai](https://promptintel.novahunting.ai/) for
their own API key.

```bash
# One-time setup: ~/.skill-veil.toml
# [promptintel]
# apikey = "ak_..."
# (or export PROMPTINTEL=ak_...)

# Download the curated jailbreak corpus.
skill-veil promptintel download --dest data/promptintel

# Scan the corpus and report per-severity detection gaps.
skill-veil promptintel cross-check

# Use the corpus as a CI gate (exit 1 below threshold).
skill-veil promptintel cross-check --fail-below 0.95

# Pull the agent-feed threat-intel into the local cache.
skill-veil promptintel feed sync                # incremental
skill-veil promptintel feed sync --full         # full pull (revocation
                                                # propagation; the
                                                # ?since= filter does
                                                # not return revoked
                                                # entries)

# Inspect the cached entries and the persisted rate-limit budget.
skill-veil promptintel feed list
skill-veil promptintel feed budget

# Audit which PromptIntel threats are covered by at least one rule.
skill-veil promptintel coverage
# === PromptIntel Rule Coverage ===
# rules total: 204  with promptintel_threats tag: 6
#   [Prompt Manipulation]  5/7 threats covered
#     [GAP ] Model Behavior Manipulation via Feedback Loops    rules: (none)
#     [OK  ] Jailbreak                                         rules: OFFICIAL_JAILBREAK_GAME_OVERWRITE_ALIGNMENT_ZERO
#     ...

# Subsequent scan-package runs automatically match scan IOCs (URLs,
# domains, IPs, file hashes) against the cache; no extra API call.
skill-veil scan-package examples/manifest-package
# → ... existing scanner output ...
# === PromptIntel Feed Enrichment (informational; does not affect skill-veil verdict) ===
# matches: 1 / 55 cached feed entries
#   [critical] block            5d1f9928-...
#     title       : Claude Code 'Leak' Lure distributing Vidar and GhostSocks
#     matched ip   : 147.45.197.92

# Validate a draft report locally before spending hourly quota (5/h, 20/d).
skill-veil promptintel report submit --file draft.json --dry-run

# Submit the report once the dry-run looks good.
skill-veil promptintel report submit --file draft.json

# List your prior submissions (60/h).
skill-veil promptintel report list
```

The vendored snapshot at `benchmarks/promptintel-corpus/` keeps the
detection numbers reproducible: a regression test asserts
`critical 100% / high ≥94% / medium ≥80% / overall ≥98%` against the
pinned 55-entry corpus, so any rule change that drops detection on
the curated set fails CI.

The rate-limit tracker persists to
`<cache_root>/promptintel-feed/ratelimit.json` and enforces the
documented per-endpoint quotas (`agent-feed` 120/h, `agents/reports/mine`
60/h, `agents/reports` 5/h + 20/d). Failed calls do not spend quota.

The cross-check renderer groups threats by the official 4-bucket
taxonomy (`Prompt Manipulation` / `Abusing Legitimate Functions` /
`Suspicious Prompt Patterns` / `Abnormal Outputs`) so coverage gaps
surface per group instead of in an alphabetical jumble. The
`coverage` command builds the same audit from the rule pack: rules
opt in by adding `promptintel_threats: ["Jailbreak", ...]` to their
YAML, and any threat name that's not in the canonical taxonomy
surfaces in a separate `[Drift]` block to flag upstream renames.

`cross-check --strict-taxonomy` promotes drift to a CI gate failure
(exit 1), pairing well with `--fail-below` for tight regression
tracking.

### LLM enrichment as a third scoring engine

```bash
# Add to ~/.skill-veil.toml:
# [llm]
# provider = "ollama"
#
# [llm.ollama]
# model = "llama3.1:8b"
# # base_url = "http://127.0.0.1:11434"   # optional

# Enrichment runs automatically alongside the rule + verdict engines.
skill-veil scan-package examples/manifest-package --format json --output current.json

# Override provider for a single run without touching the config.
skill-veil scan-package . --llm-provider openai

# Skip enrichment entirely (CI runs that should not depend on a network model).
skill-veil scan-package . --no-vt-enrich --no-llm-enrich --no-promptintel-enrich
```

Supported providers out of the box: **Ollama**, **LM Studio**, **OpenAI**,
**Anthropic**, and **Ollama Cloud**. Each provider exposes its own section in
`~/.skill-veil.toml` (`[llm.ollama]`, `[llm.openai]`, etc.) for model name,
optional base URL, and provider-specific parameters.

### Inline suppressions in scanned content

```markdown
# skill-veil:ignore SKILL_REMOTE_EXEC_CURL_BASH because: vendor install script reviewed manually
curl -sSL https://example.com/install.sh | bash
```

skill-veil also recognises `nosem`, `nosem-next-line`, `nosemgrep`, and
`nosemgrep-next-line` for compatibility with existing toolchains. An optional
`because:` / `reason:` clause is captured in the finding metadata so reviewers
can audit waivers later.

### Optional YARA support

```bash
cargo run -p skill-veil --features yara -- \
  rules validate --rules-dir ../skill-veil-rules/official
```

YARA usage notes and an example rule live in:

- [docs/yara.md](docs/yara.md)
- [docs/examples/example-rule.yar](docs/examples/example-rule.yar)

### External dataset validation

For marketplace mirrors or local corpora that are intentionally kept out of Git:

- [docs/dataset-validation.md](docs/dataset-validation.md)

### Curated example packages

- safe skill: `examples/safe-skill/`
- suspicious skill: `examples/suspicious-skill/`
- malicious skill: `examples/malicious-skill/`
- manifest-heavy package: `examples/manifest-package/`
- referenced script package: `examples/referenced-script-package/`
- agent instructions: `examples/agent-instructions/`
- prompt pack: `examples/prompt-pack/`
- MCP manifest: `examples/mcp-server/`

### Daily analyst triage

```bash
skill-veil scan-dataset ./mirror \
  --dataset-view verdicts \
  --analyst-summary \
  --preset local \
  --format text
```

That view is intentionally short and stable for daily review:

- package id
- verdict
- package health
- blast radius
- top rule
- strongest scope/reason

---

## Use Cases

### 1. Review a third-party skill before installing it

Use this when someone shares a `SKILL.md`, `AGENTS.md`, or similar entrypoint
and you want a fast local decision.

```bash
skill-veil scan-file path/to/SKILL.md --format text
```

What you get:

- findings grouped by severity and category
- a final action: `log`, `require_approval`, or `block`
- policy escalation reasons if the artifact implies extra blast radius

### 2. Review a whole package, not only the root document

Use this when a skill repo also contains manifests, install hooks, scripts, or
container files.

```bash
skill-veil scan-package /path/to/repo --format text
```

This is the most important mode for real reviews because it inspects:

- the explicit entrypoint
- referenced scripts
- manifests and lockfiles
- Docker and runtime artifacts

### 3. Scan agent instruction files and prompt packs

Use this when the risky part is not a classic skill but a persistent
instruction surface.

```bash
skill-veil scan-file examples/agent-instructions/AGENTS.md
skill-veil scan-package examples/prompt-pack
```

This is useful for:

- persistent prompt tampering
- cognitive rootkits
- approval bypass patterns
- prompt-pack review before publishing or importing

### 4. Review an MCP manifest before enabling a server

Use this when you want to inspect an MCP server descriptor for remote
connectivity, command execution, or tool-scope concerns.

```bash
skill-veil scan-package examples/mcp-server --format json
```

### 5. Add a CI gate to block only new active findings

Use this when you already have accepted debt and only want to stop regressions.

```bash
skill-veil scan-package . --preset ci --format json --output current.json
skill-veil diff prev.json current.json --baseline .skill-veil/baseline.json --ci-summary --fail-on new-active
```

This is the practical workflow for teams because it separates:

- existing accepted findings
- waived findings
- new active findings

### 6. Manage accepted risk with baseline and waivers

Use this when some findings are known and reviewed, but you still want the tool
to stay strict about new ones.

```bash
skill-veil baseline create current.json --output .skill-veil/baseline.json
skill-veil waivers validate .skill-veil/waivers.yaml
skill-veil scan-package . --baseline .skill-veil/baseline.json --waivers .skill-veil/waivers.yaml
```

### 7. Scan a catalog, dataset, or marketplace mirror

Use this when you have many packages and want aggregate review instead of
single-file analysis.

```bash
skill-veil scan-dataset ./examples --preset ci --format text
```

This is the right mode for:

- internal marketplaces
- downloaded skill corpora
- large monorepos of agent extensions

### 8. Measure whether the scanner got better or worse

Use this when changing rules, scoring, or analyzers.

```bash
skill-veil benchmark benchmarks/corpus.yaml \
  --format json \
  --output benchmarks/history/latest.json \
  --history-file benchmarks/history/releases.json \
  --release-id local-dev \
  --dashboard-output benchmarks/history/dashboard.md
```

This tells you:

- precision and recall
- false positive rate
- exact label accuracy
- confidence calibration
- threshold recommendations
- release-to-release trend

---

## Output Formats

| Format | Use Case |
|--------|----------|
| `text` | Local review |
| `json` | Automation, baselines, diff, dashboards |
| `sarif` | GitHub Code Scanning |
| `shield` | Policy-oriented markdown |

---

## Benchmarking

The repository ships with a labeled benchmark corpus and release history.

Current benchmark reporting includes:

- precision
- recall
- false positive rate
- accuracy
- exact label accuracy
- TP / FP / TN / FN
- corpus coverage by label and focus category
- confidence calibration by evidence, category, and signal pair
- threshold recommendations
- markdown dashboard for release-to-release comparison

Methodology: [docs/benchmark-methodology.md](docs/benchmark-methodology.md)

---

## Rule Packs

skill-veil consumes **two independent rule sources**, both installed
by `skill-veil init` into `~/.cache/skill-veil/rules/`:

1. [**skill-veil-rules**](https://github.com/seifreed/skill-veil-rules)
   — distributed as **signed GitHub releases** (Ed25519 + per-file
   SHA-256 manifest). The primary detection set, owned by this
   project.
2. [**Nova-Hunting/nova-rules**](https://github.com/Nova-Hunting/nova-rules)
   — community NOVA prompt-pattern-matching rules from
   [Thomas Roccia (@fr0gger_)](https://x.com/fr0gger_). Distributed
   from the upstream repo with commit-SHA pinning. Rules cover
   prompt injection, jailbreaks, malicious code generation, scams,
   reconnaissance, and bias/toxicity buckets — see
   [the NOVA blog post](https://medium.com/securitybreak/introducing-nova-the-prompt-pattern-matching-9d3fd50d44b2)
   for details.

End users do not clone either repo — `skill-veil init` downloads
both, verifies them, and writes the result to the user cache.

### How verification works

Each release ships three artefacts:

| Artefact | Purpose |
|----------|---------|
| `skill-veil-rules-<version>.tar.gz` | All rule files, fixtures, schema, YARA |
| `manifest.json` | Per-file SHA-256 digests + version metadata |
| `manifest.json.sig` | Detached Ed25519 signature over `manifest.json` |

`skill-veil init` does the following before exposing any rule to the
scanner:

1. Resolves the latest release tag (or `--version vX.Y.Z` to pin) and
   downloads the three artefacts into a temporary staging dir.
2. Verifies the Ed25519 signature against a public key embedded in the
   skill-veil binary at compile time. Rotation policy is documented in
   [skill-veil-rules/KEYS.md](https://github.com/seifreed/skill-veil-rules/blob/main/KEYS.md).
3. Extracts the tarball with hardened path-traversal, symlink, and
   size protections.
4. Verifies every extracted file's SHA-256 against the manifest, and
   rejects any extracted file the manifest does not declare (blocks
   the smuggling attack where a signed manifest covers only some of
   the tarball's contents).
5. Atomically renames the verified tree into
   `~/.cache/skill-veil/rules/<version>/` and updates the `current`
   pointer the scanner reads at startup.

Any failure at steps 2–4 aborts the install — the cache is never
mutated with unverified content.

### Discovery order at scan time

The scanner probes for external skill-veil-rules overlays in this order:

1. `$SKILL_VEIL_RULES_DIR` (colon-separated, takes precedence —
   handy for CI).
2. `~/.cache/skill-veil/rules/<current_version>/official/` (populated
   by `skill-veil init`).
3. `./rules/official/` (legacy / dev-mode fallback for working against
   a sibling checkout of `skill-veil-rules`).

If none of these resolve, the scanner falls back to the embedded
baseline — `skill-veil scan` always works without `init`.

NOVA rules are loaded separately from
`~/.cache/skill-veil/rules/nova-<sha>/` (populated by `init`); they
run as an additional channel and produce a `--- NOVA rule matches ---`
block after the primary scan output. Disable per-scan with `--no-nova`.

### NOVA execution model

NOVA rules support three orthogonal matching modes — keyword regex,
semantic similarity, and LLM judgement. The current build executes
**keyword matches natively** (regex / literal substring with the same
engine used for skill-veil rules) and surfaces a one-line note when a
rule's `condition:` requires `semantics.*` or `llm.*`, listing which
capabilities were skipped. Pending future work:

- Native sentence-embedding inference (likely `candle` or `ort` +
  `all-MiniLM-L6-v2`) to enable `semantics:` evaluation.
- Routing NOVA `llm:` sections to the existing
  `~/.skill-veil.toml [llm]` provider chain (OpenAI, Anthropic,
  Ollama, LM Studio, Ollama-Cloud).

A rule whose `condition:` is satisfied by keywords alone fires today;
a rule that requires `semantics.X AND llm.Y` correctly does NOT fire
on a keyword hit alone.

### Auto-update notifier

`skill-veil scan` checks once per 24 hours whether either rule source
has a newer pin upstream and emits a single line on stderr:

```
[skill-veil] update available:
  - skill-veil-rules: installed v0.1.0, latest v0.1.1 (run: skill-veil rules update)
  - nova-rules: installed 9249cf4, latest abc1234 (run: skill-veil rules update)
```

The check is best-effort — never blocks the scan, never errors. CI
runs that want zero outbound chatter beyond the scan itself can set
`--no-update-check` or `SKILL_VEIL_NO_UPDATE_CHECK=1`.

### Rule pack docs

- [docs/rule-authoring.md](docs/rule-authoring.md)
- [skill-veil-rules/README.md](https://github.com/seifreed/skill-veil-rules/blob/main/README.md)
- [skill-veil-rules/CONTRIBUTING.md](https://github.com/seifreed/skill-veil-rules/blob/main/CONTRIBUTING.md)
- [skill-veil-rules/KEYS.md](https://github.com/seifreed/skill-veil-rules/blob/main/KEYS.md)

---

## Documentation

- [docs/architecture.md](docs/architecture.md)
- [docs/changelog.md](docs/changelog.md)
- [docs/roadmap.md](docs/roadmap.md)
- [docs/threat-model.md](docs/threat-model.md)
- [docs/usage-local.md](docs/usage-local.md)
- [docs/usage-ci.md](docs/usage-ci.md)
- [docs/agent-extensions.md](docs/agent-extensions.md)
- [docs/policy-model.md](docs/policy-model.md)
- [docs/policy-presets.md](docs/policy-presets.md)
- [docs/finding-model.md](docs/finding-model.md)
- [docs/verdict-model.md](docs/verdict-model.md)
- [docs/analyst-interpretation.md](docs/analyst-interpretation.md)
- [docs/json-report-schema-v3.md](docs/json-report-schema-v3.md)
- [docs/artifact-analysis.md](docs/artifact-analysis.md)
- [docs/release-process.md](docs/release-process.md)

---

## Contributing

Contributions are welcome.

Start here:

- [docs/maintainers.md](docs/maintainers.md)
- [docs/governance.md](docs/governance.md)
- [docs/versioning.md](docs/versioning.md)
- [docs/support.md](docs/support.md)

---

## Acknowledgments

skill-veil stands on third-party threat-intel platforms and open
research. Specifically:

- **PromptIntel / NovaHunting** — [Thomas Roccia (@fr0gger_)](https://x.com/fr0gger_)
  and the [PromptIntel](https://promptintel.novahunting.ai/) community.
  They publish the curated jailbreak corpus, the official 4-bucket /
  38-threat taxonomy used by `promptintel cross-check` and `promptintel
  coverage`, and the agent-feed of community-submitted IOCs that powers
  the `promptintel feed` enrichment block. The taxonomy, corpus, and
  feed are their work; skill-veil only consumes them. Operators who
  run `promptintel feed sync` should grab their own API key at
  [promptintel.novahunting.ai](https://promptintel.novahunting.ai/).
- **NOVA (The Prompt Pattern Matching)** — also by Thomas Roccia.
  The [Nova-Hunting/nova-rules](https://github.com/Nova-Hunting/nova-rules)
  catalogue ships the prompt-pattern rules `skill-veil init` pulls in
  as a second rule channel. Rule semantics (`keywords`/`semantics`/
  `llm` sections, `condition:` DSL, severity tags) follow the
  [upstream NOVA framework](https://github.com/fr0gger/nova-framework)
  and the [introductory blog post](https://medium.com/securitybreak/introducing-nova-the-prompt-pattern-matching-9d3fd50d44b2);
  skill-veil reimplements the parser + condition evaluator natively in
  Rust without depending on the Python runtime.
- **VirusTotal / Google** — for the VT Intelligence corpus and Code
  Insight verdicts that the `vt download / report / cross-check`
  family integrates with.
- **The LLM cohort** — the v6/v7 detection rules were drafted with help
  from a multi-LLM consultation: Grok-4-fast (xAI), GPT-4o (OpenAI),
  DeepSeek-v3.1:671b, and Qwen3-coder:480b (both via Ollama Cloud).
  Co-authoring credit lives in the relevant commit messages.

---

## Support the Project

If `skill-veil` is useful to you, consider supporting its maintenance:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

skill-veil is an independent open-source project. PromptIntel,
VirusTotal, and the LLM providers listed under
[Acknowledgments](#acknowledgments) are external services accessed via
their respective APIs and are governed by their own terms; this
repository does not redistribute their content beyond the curated
benchmark snapshots explicitly checked into
`benchmarks/promptintel-corpus/`.

**Attribution:**
- Repository: [github.com/seifreed/skill-veil](https://github.com/seifreed/skill-veil)
- Threat-intel taxonomy + corpus: PromptIntel / NovaHunting (Thomas Roccia)

---

<p align="center">
  <sub>Built for agent extension supply-chain review and CI enforcement</sub>
</p>
