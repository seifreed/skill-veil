# Next Execution Plan

This plan turns the next major investment in `skill-veil` into a sequence of
deliverable phases that can be shipped incrementally without stalling the
current product.

## Principles

- Preserve the current static scanner contract while deepening semantics.
- Prefer observable execution-path evidence over more regex volume.
- Expand ecosystem coverage only when the new artifact type is actually wired
  into discovery, graphing, policy, and tests.
- Ship benchmark and corpus growth alongside detector changes.

## Phase A: Semantic Script Analysis

Goal: move script and command analysis from substring heuristics to lightweight
language-aware tokenization and command extraction.

Scope:
- add tokenization/extraction for Bash, PowerShell, JavaScript/TypeScript, and
  Python,
- normalize pipelines, wrappers, quoted strings, simple variable expansion, and
  indirect exec patterns,
- detect chained behaviors such as download + exec, secret read + outbound
  network, and persistence writes with stronger evidence than raw regex,
- keep the existing heuristic findings as fallback signals where parsing fails.

Deliverables:
- semantic script analysis module,
- normalized command facts attached to findings and capability inference,
- regression tests for wrappers, variables, pipelines, and obfuscated command
  assembly.

Exit criteria:
- lower false positives on benign shell snippets and install docs,
- improved recall for indirect execution and chained behaviors across the
  supported languages.

## Phase B: Ecosystem-Wide Dataset Discovery

Goal: make `scan-dataset` discover every supported package shape, not only
  packages rooted by `SKILL.md`.

Scope:
- discover package roots from `AGENTS.md`, `CLAUDE.md`, `SYSTEM.md`,
  `PERSONA.md`, `SOUL.md`, `*.prompt.md`, `prompts/`, `mcp.json`,
  `mcp.yaml`, and `mcp.yml`,
- align dataset fallback discovery with the same entrypoint logic used by
  `scan-package`,
- improve dataset summaries and error messages so they do not imply
  `SKILL.md`-only coverage.

Deliverables:
- unified package-root detection utility shared by package and dataset modes,
- dataset fixtures for prompt packs, MCP packages, and instruction-only repos.

Exit criteria:
- dataset mode finds all supported agent-extension package shapes in mixed
  corpora,
- dataset reporting no longer claims only `SKILL.md` coverage.

## Phase C: Artifact And Format Expansion

Goal: widen supply-chain and operational coverage beyond the current manifest
set.

Scope:
- add analysis for `Gemfile`, `go.mod`, `go.sum`, `composer.json`,
  `pnpm-workspace.yaml`, `.env.example`, `docker-bake.hcl`,
  GitHub Actions workflows, and `pre-commit` hooks,
- infer relations, capability facts, and lockfile/companion expectations for
  the new formats,
- add focused findings for remote actions, mutable dependencies, secret
  placeholders, privileged runners, and workflow-triggered execution.

Deliverables:
- new artifact analyzers wired through dispatch,
- examples and regression fixtures for each newly supported artifact family.

Exit criteria:
- new formats participate in findings, graph construction, verdicting, and SBOM
  output.

## Phase D: Recursive Package And Archive Analysis

Goal: make dataset and package scanning useful on marketplace mirrors and
artifact dumps.

Scope:
- support `tar`, `tar.gz`, `tgz`, and nested archive extraction,
- recurse into referenced local archives and packaged attachments where safe,
- cache extracted packages and record extraction provenance,
- prevent archive traversal and oversized extraction abuse.

Deliverables:
- archive extraction service with cache markers and provenance records,
- nested package discovery tests,
- analyst-visible extraction warnings and provenance notes.

Exit criteria:
- mixed archive corpora can be scanned without manual unpacking,
- nested package contents feed normal package discovery and analysis.

## Phase E: Trust And Provenance Model

Goal: let decisions depend on who shipped the artifact, not only what text it
contains.

Scope:
- publisher allowlists and deny rules,
- domain reputation and source provenance signals,
- signed or checksummed external rule packs,
- dependency provenance facts and policy selectors by origin.

Deliverables:
- provenance schema additions,
- policy selectors for publisher/domain/source,
- trust-focused findings and audit output.

Exit criteria:
- policy can differentiate reviewed internal publishers from unknown external
  sources,
- external rule packs can be verified before loading.

## Phase F: Higher-Fidelity Capability Modeling

Goal: score and explain dangerous chains, not only isolated signals.

Scope:
- derive composite capabilities such as `secret_access + network_access`,
  `shell_exec + download`, `browser + write`, and `remote_mcp + no_auth`,
- propagate capabilities across artifact edges,
- score chain severity with explainable path summaries.

Deliverables:
- capability-composition engine,
- graph-path based risk drivers,
- policy hooks for composite capability rules.

Exit criteria:
- package verdicts can cite behavior chains rather than unrelated findings,
- capability policy can trigger on combinations, not only single facts.

## Phase G: Corpus And Validation Expansion

Goal: keep precision and recall honest as coverage grows.

Scope:
- expand benign, suspicious, and malicious corpora with evasive and noisy real
  patterns,
- add dataset-scale validation fixtures for new artifact families and archives,
- track per-family metrics for the new semantic detectors.

Deliverables:
- larger benchmark corpus,
- updated thresholds and calibration reports,
- release gating tied to corpus health.

Exit criteria:
- quality does not regress as new formats and semantic detectors land,
- every new analyzer ships with corpus evidence.

## Recommended Delivery Order

1. Phase A
2. Phase B
3. Phase C
4. Phase D
5. Phase F
6. Phase E
7. Phase G

## First Implementation Slice

The first code slice should cover the lowest-risk, highest-leverage work:

- Phase A foundation: lightweight tokenization and normalized command facts for
  Bash, PowerShell, JavaScript, and Python,
- Phase B: dataset discovery parity with package discovery,
- Phase C initial formats: `Gemfile`, `go.mod`, `composer.json`,
  `.env.example`, GitHub Actions workflows, and `pre-commit` config,
- Phase D foundation: `tar.gz` and `tgz` extraction plus nested archive
  discovery.

## Second Implementation Slice

The second code slice should cover the first enforcement-oriented upgrades:

- Phase E foundation: provenance summary and trust-level classification derived
  from remote origins, package sources, and opaque control-plane indicators,
- Phase E policy hooks: provenance policy rules and audit output,
- Phase F foundation: composite capability derivation for
  `secret_exfiltration`, `shell_download_exec`, `browser_write_chain`, and
  `remote_mcp_no_auth`,
- Phase F policy hooks: capability policies that can match composite
  capabilities,
- Phase G validation: benchmark fixtures that exercise provenance and composite
  capability chains.

## Third Implementation Slice

The remaining trust-model work should close the biggest enforcement gaps left
after the first two slices:

- Phase E publisher selectors: derive publisher identities from supported
  manifests and expose them through provenance summaries,
- Phase E policy enforcement: allow provenance policies to match on publisher
  patterns in addition to domains, trust levels, and package ids,
- Phase E external pack integrity: verify external YAML rule packs via optional
  sidecar `*.sha256` files before loading and surface integrity status in CLI
  validation/info output,
- Phase E signed pack integrity: verify detached Ed25519 signatures for rule
  packs using local trusted public keys,
- Phase E local reputation: classify known malicious publishers as untrusted and
  known package registries as trusted provenance without requiring network
  lookups,
- Phase G validation: add regression tests for publisher-based provenance
  policies and checksum verification failures/success paths.

## Current Progress Snapshot

The current implementation pass has now landed the following Semgrep-inspired
improvements without reusing Semgrep code:

- stricter rule-pack parsing with schema-aware validation, path-aware YAML error
  reporting, condition-tree validation, and early regex validation,
- expanded DSL combinators for `!either`, `!not`, `!none`, `!unless`,
  `!implies`, and `!at_least`,
- `.skill-veilignore` support with `.semgrepignore` fallback across package,
  dataset, manifest, and lockfile targeting,
- normalized manifest and lockfile inventory attached to provenance summaries,
- coverage tests for ignore matching and the new rule combinators.

Remaining follow-up work is iterative rather than foundational:

- tighten ignore semantics further toward full gitignore parity if needed,
- enrich normalized dependency inventory with deeper direct/transitive counts per
  ecosystem,
- continue replacing the remaining high-noise config heuristics with deeper
  parsers only where the lightweight structured pass is still insufficient.

The latest pass also closed the previously open parser/config hardening gap:

- Bash semantics now normalize line continuations and strip shell comments
  before extracting command facts,
- Dockerfile analysis now parses instruction streams instead of relying only on
  raw line regexes, covering `FROM`, `RUN`, `ADD`, and `USER` more precisely,
- GitHub Actions workflows now use structured YAML traversal for triggers,
  runners, permissions, `uses`, and block `run` steps,
- structured parse warnings now cover workflows, pre-commit config, and
  malformed Dockerfiles in addition to the earlier JSON/TOML/YAML targets.
