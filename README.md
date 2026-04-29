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
  <a href="benchmarks/vt-baseline.json"><img src="https://img.shields.io/badge/recall-92.86%25-brightgreen?style=flat-square&label=VT%20corpus%20recall" alt="Recall"></a>
  <a href="benchmarks/vt-baseline.json"><img src="https://img.shields.io/badge/precision-100%25-brightgreen?style=flat-square" alt="Precision"></a>
  <a href="benchmarks/vt-baseline.json"><img src="https://img.shields.io/badge/FPR-0%25-brightgreen?style=flat-square" alt="False Positive Rate"></a>
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
| **LLM Enrichment** | Optional third scoring engine across Ollama, LM Studio, OpenAI, Anthropic, and Ollama Cloud |
| **Inline Suppressions** | `# skill-veil:ignore`, `nosem`, and `nosemgrep` markers with optional rule-id and reason |
| **Unified Config** | Single `~/.skill-veil.toml` for VT and LLM providers; per-flag overrides on the CLI |

### What It Detects

```
Behavior        Remote execution, install hooks, deferred execution, persistence
Supply Chain    Unpinned dependencies, missing lockfiles, remote MCP endpoints
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
LLM cross-check (Grok + OpenAI, default models `grok-4-fast` and
`gpt-4o-mini`). A sample is treated as a VT mislabel only when **all**
of the following hold:

1. Both providers return `verdict == benign`.
2. Both providers' confidence is ≥ 0.85.
3. At least one provider's confidence is ≥ 0.90.

Of 246 samples submitted, **36 passed consensus** (e.g., `chart-image`,
`mineru-pdf`-style helpers); 210 were rejected (203 had at least one
provider disagree, 6 were below the confidence floor, 1 was a
binary-disguised file the LLMs could not analyse). Treating the 36
passing samples as VT mislabels lifts recall to **92.86%** at the same
100% precision. Each override carries its per-provider verdicts,
confidences, and timestamps in
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
# Scan a strict entrypoint
skill-veil scan-file examples/malicious-skill/SKILL.md

# Scan a package with manifests and related artifacts
skill-veil scan-package examples/manifest-package --format text

# Scan agent-extension targets beyond SKILL.md
skill-veil scan-file examples/agent-instructions/AGENTS.md
skill-veil scan-package examples/prompt-pack
skill-veil scan-package examples/mcp-server
```

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
| `rules validate` | Validate external rule packs |
| `rules test` | Test one rule against inline content |
| `rules test-pack` | Run pack fixtures |
| `rules pack-info` | Summarize external rule packs |
| `policy validate` | Validate a policy file |
| `vt download` | Bulk-download a corpus from VirusTotal Intelligence with cached reports |
| `vt report` | Fetch and cache the VT report for a single hash |
| `vt cross-check` | Compare skill-veil verdicts against VT Code Insight on a downloaded corpus |

### Useful Options

| Option | Description |
|--------|-------------|
| `--format text/json/sarif/shield` | Output format |
| `--preset local/ci/strict/enterprise` | Apply output and policy presets |
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
| `--llm-provider <name>` | Override the active LLM provider for one scan (`ollama`, `lmstudio`, `openai`, `anthropic`, `ollama-cloud`) |
| `--cache-dir` | Override the base directory for VT and LLM enrichment caches |

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

```bash
skill-veil rules validate --rules-dir rules/official
skill-veil rules test-pack --rules-dir rules/official --fixtures rules/fixtures/behavioral.yaml
skill-veil rules pack-info --rules-dir rules/official
```

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
skill-veil scan-package . --no-vt-enrich --no-llm-enrich
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
cargo run -p skill-veil --features yara -- rules validate --rules-dir rules/official
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

External versioned packs under `rules/official/` are the primary default rule
source. Embedded rules are a fallback only.

Rule pack docs:

- [docs/rule-authoring.md](docs/rule-authoring.md)
- [rules/official/README.md](rules/official/README.md)
- [rules/community/README.md](rules/community/README.md)

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

## Support the Project

If `skill-veil` is useful to you, consider supporting its maintenance:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

**Attribution:**
- Repository: [github.com/seifreed/skill-veil](https://github.com/seifreed/skill-veil)

---

<p align="center">
  <sub>Built for agent extension supply-chain review and CI enforcement</sub>
</p>
