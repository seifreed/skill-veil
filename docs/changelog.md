# Changelog

All notable changes to `skill-veil` will be documented in this file.

The project aims to follow Keep a Changelog and semantic versioning once the
release process is formalized.

## [Unreleased]

### Added

**SkillSpector-parity detectors (native)**
- Unicode deception pass across all artifacts: zero-width/invisible
  characters (`UNICODE_INVISIBLE_CHARS`), bidirectional overrides /
  Trojan Source (`UNICODE_BIDI_OVERRIDE`), tag-block ASCII smuggling
  (`UNICODE_TAG_BLOCK`), and Latin↔Cyrillic/Greek homoglyph tokens
  (`UNICODE_HOMOGLYPH_MIX`).
- AST script analysis (default-on) for Python/JavaScript/TypeScript via
  a tree-sitter adapter: dynamic eval, process spawning, dynamic imports,
  indirect builtin access, and string→eval flows.
- MCP manifest detector with least-privilege and tool-poisoning signals
  (`MCP_WILDCARD_CAPABILITY`, `MCP_UNDERDECLARED_CAPABILITY`,
  `MCP_TOOL_DESCRIPTION_HIDDEN_INSTRUCTION`, and the remote/auth/scope
  `MCP_*` family).
- OSV.dev CVE lookup (opt-in, advisory-only): `--osv` /
  `SKILL_VEIL_OSV=1` / `[osv]` config, on-disk TTL cache with an offline
  mode. Never changes the verdict.

### Changed
- Native detector rule IDs (`UNICODE_*`, `MCP_*`) are now a documented
  public-compatibility surface, registered in `NATIVE_DETECTOR_RULE_IDS`
  and pinned by a frozen-registry test plus an E2E fixture corpus.

### Fixed
- OSV detail-fetch budget (`MAX_ADVISORY_DETAILS`) no longer counts cache
  hits as network fetches, so a large set of already-cached advisories can
  no longer starve an uncached advisory of its single lookup (it was
  silently degraded to an ID-only row).
- OSV advisory IDs from the `querybatch` response are validated before
  being interpolated into the `/vulns/{id}` request path; a value carrying
  path/query metacharacters is rejected instead of shaping the request URL.
- NOVA rule parsing no longer panics on a body-less regex keyword value
  (`/` or `/i`): the `value[1..0]` slice is guarded and the line is reported
  as malformed, so a single bad rule file can no longer abort the whole scan.
- SARIF output is now deterministic: the `tool.driver.rules` array was built
  from a `HashMap` and emitted in randomised per-process order; it is now
  sorted by rule id, so identical inputs produce byte-identical SARIF.
- Ollama context-length parsing now saturates an over-`usize` `context_length`
  to `usize::MAX` (matching its documented contract) instead of discarding the
  value via `.ok()`; the prior behaviour failed its own contract on 32-bit
  targets.
- Diff output now sanitises a finding's `reason` and `rule_id` (not only
  `artifact_path`) before printing to the terminal, closing an ANSI-escape
  injection path where a malicious package could repaint a CI operator's
  terminal via control bytes carried in a finding's reason.
- An empty-string entry in an IOC feed (`domains`/`ips`/`filenames`) is now
  dropped instead of compiling into an empty-alternation regex that matched
  every byte of every document — which had flagged every scan as malicious
  and emitted one finding per character.
- `rules test-pack` no longer reports success for a fixture pack with no cases,
  a case with no expectation, or an `expected_severity`/`action`/`category`
  that vacuously passes because the rule produced no findings — closing silent
  holes that let an under-specified fixture mask a broken rule.
- The PromptIntel rate-limit tracker now records a call attempt even when the
  request fails, matching its documented "record on every attempt" contract, so
  a saturating endpoint actually backs off instead of only counting successes.

## [0.2.0] - 2026-05-20

This release expands skill-veil's threat coverage with a new community
rule channel (NOVA), an analyst-curated jailbreak corpus (PromptIntel)
with a 4-LLM cohort reaching 50/50 coverage, an opt-in LLM adjudication
layer for borderline taint findings (ADR-0029), a k-of-n composite
detector framework with three new zero-FP families, and 333 soft-FNs
recovered via conclusive single-rule escalation. Rule packs now ship
as a separate Ed25519-signed distribution repository verified by keys
embedded in the binary. CI/CD and documentation are reinforced with a
`ci-local/` Docker harness that verifies deployment + detection
end-to-end, a Bitbucket Pipelines template, and a CI guide covering
offline operation, `init`, exit codes, and the machine-output contract.

### Added

**Rule pack distribution (signed external)**
- `skill-veil init` downloads + Ed25519-verifies the latest signed
  `skill-veil-rules` release against keys embedded in the binary
  (`skill-veil-rules-2026`) and installs into
  `~/.cache/skill-veil/rules/<version>/`.
- NOVA rule pack: `init` also pulls `Nova-Hunting/nova-rules` pinned
  by commit SHA as a community channel.
- `rules update` / `rules status` to manage installed packs.

**NOVA engine (community rules)**
- Native NOVA rule engine: parser, condition AST, evaluators.
- Keyword/regex evaluators wired natively; `--nova-semantics`
  default-on (`--no-nova-semantics` opt-out) using `fastembed`
  (all-MiniLM-L6-v2 ONNX) behind the `nova-semantics` feature.
- `--nova-llm` opt-in via the existing LLM provider chain.
- NOVA matches injected as Findings into both JSON and SARIF output.

**PromptIntel integration (jailbreak corpus)**
- Vendored 50-prompt corpus snapshot + regression test
  (`promptintel cross-check --fail-below N`).
- `promptintel feed sync` with rate-limit tracker, incremental mode,
  and local IOC cache that enriches scans.
- `promptintel report submit/list` with the rate-limit budget
  enforced client-side.
- `promptintel coverage`: taxonomy-grouped reports, rule→threat
  mapping, drift detection.
- Every shipped rule tagged with its `promptintel_threats` mapping.
- Seven iterative rule-pack rounds with a 4-LLM cohort (GPT-4o-mini,
  Grok-4-fast, DeepSeek-v4-pro, Qwen3.5) lifting detection from the
  initial 10-rule baseline to **50/50 (100%)** on the corpus.

**LLM-adjudicated verdict layer (ADR-0029)**
- `--llm-adjudicate-taint` (opt-in, default OFF): downgrades
  Malicious→Suspicious when ≥2-of-3 LLMs disagree.
- `--llm-adjudicate-upgrade` symmetric FN lever:
  Suspicious→Malicious when ≥2-of-3 LLMs agree.
- `--preset triage` turns both levers on; the four deterministic CI
  presets (`local`/`ci`/`strict`/`enterprise`) stay adjudication-OFF.
- Unified `~/.skill-veil.toml [llm]` config with five providers
  (Ollama, LMStudio, OpenAI, Anthropic, Ollama-Cloud).
- Consensus discrepancy + prompt-injection signal extraction.
- Offline `adjudication-eval` subcommand: replays recorded LLM
  verdicts against labelled corpora, reports ΔFP/ΔFN per lever
  without calling a provider.

**Composite-detector framework**
- k-of-n composite-family scaffold for multi-signal detectors.
- New zero-FP families: fake-dependency / paste-site dropper
  (2-of-3), crypto-drainer, C2-beacon.
- New IOC: `SKILL_TELEGRAM_BOT_TOKEN_HARDCODED` (conclusive).

**Gold corpus + analyst feedback loop**
- `gold build/review/stats`: ground-truth manifest via 3-LLM
  consensus + human adjudication of disputes, decoupled from
  VT-label noise.
- VT-label enrichment in `gold build`.
- `disposition record/list/stats`: bounded, allowlist-only
  per-finding analyst feedback overlay.
- Disposition overlay wired into the scan path (`--disposition`).

**Verdict calibration**
- Conclusive single-rule escalation: 16 zero-FP rules promoted to
  `CONCLUSIVE_SINGLE_RULE_IDS`, recovering 333 soft-FNs at zero FP
  cost.
- `SKILL_FAKE_DEPENDENCY_DROPPER` joins the conclusive set.

**VT integration**
- `vt cross-check --format baseline` for canonical baselines.
- `vt --clean` corpus flag.
- Refreshed `benchmarks/vt-baseline.json`,
  `benchmarks/vt-clean-corpus.yaml`, multi-LLM audit panel +
  provenance corrections.

**CI / DevOps**
- `ci-local/` Docker harness: multi-stage Dockerfile + offline smoke
  gate (`network_mode: none`) + `harness-online` service exercising
  the full signed-pack init path. GitLab runner via `gitlab-ci-local`
  and GitHub Actions runner via `act` provide local end-to-end
  pipeline verification.
- `examples/ci/bitbucket-pipelines.yml`: new Bitbucket Pipelines
  template mirroring the GitLab PR-gate template.
- `docs/usage-ci.md`: expanded with engine-specific sections (GitLab,
  Bitbucket, Jenkins), exit-code semantics, machine-output gotcha,
  offline/air-gapped CI guarantees, and `init` first-time setup.
- Per-matrix-row `cargo_features` in `.github/workflows/ci.yml`
  unblocks Intel-Mac CI by skipping `--all-features` on `macos-x64`
  (`ort-sys` ships no prebuilt for `x86_64-apple-darwin`).
- Regression tests pinning CI template invocations and `--fail-on`
  flag form (`shipped_ci_template_invocations_parse_under_current_cli`,
  `diff_fail_on_accepts_value_form_and_rejects_flag_suffix_form`).
- Root `.dockerignore` keeps Docker build context to the ~7 MB
  git-tracked tree.

### Changed

- Rule discovery prioritises the installed external pack at
  `~/.cache/skill-veil/rules/<version>/official/` over the embedded
  baseline. The embedded baseline remains `include_str!`-bundled for
  offline / air-gapped operation.
- `nova-semantics` is default-on (`--no-nova-semantics` opt-out).
- `--preset triage` bundles both LLM adjudication levers; the four
  deterministic CI presets stay adjudication-OFF for reproducibility.
- VT cross-check now scans the extraction cache instead of the bare
  `--dir`, matching what `vt download` populates.
- VT API key resolves from the unified `~/.skill-veil.toml [vt]`
  section (`~/.vt.toml` still accepted).

### Fixed

- Four rounds of false-positive calibration across taint
  (`secret/identity → network`), `TRUSTED_API_HOSTS` expansion,
  doc-host stripping, trust-aware compound chains, and five
  `LLM_FP` rule eliminations.
- Conclusive escalation now gates on `Block` action only, not on
  `signal_class`.
- `examples/ci/*` no longer ship the stale `--fail-on-new-active`
  flag; corrected to the supported `--fail-on new-active` value form.
- `docs/json-report-schema-v3.md`: absolute filesystem links
  replaced with relative paths; stale `policy.rs` target corrected
  to `policy/reports.rs`.

### Security

- `wasmtime` bumped 43.0.1 → 43.0.2 and `rand` 0.8.5 → 0.8.6 to pull
  current security advisories.

### Removed

- Four stale docs dropped from `docs/`:
  - `skill-sbom.md` (documented a `sbom` subcommand that does not
    exist).
  - `phase1-exit-criteria.md` (phase closed; thresholds live in the
    `labeled_corpus_meets_phase1_baseline` test).
  - `dataset-validation-2026-03-11.md` (snapshot superseded by
    `dataset-validation.md`).
  - `phase-next-execution-plan.md` (April planning artifact, no
    longer reflects current direction).

## [0.1.3] - 2026-05-05

### Fixed

- Made cache override tests portable on Windows while preserving Unix
  broken-symlink coverage, unblocking the full CI matrix.
- Added crates.io-compatible version metadata for the optional `yara-x`
  dependency while preserving the pinned upstream git revision.

### Added

- strict `scan-file` and package-oriented `scan-package`
- labeled regression corpus and benchmark command
- findings model with evidence kind, artifact kind, remediation, and action
- threat model document
- artifact graph with declared and observed capabilities
- manifest analyzers for `package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `Dockerfile`, and `docker-compose`
- context policies for `install`, `network`, `secrets`, `code_modification`, and `external_comms`
- baseline, waivers, and diff support
- policy file schema with configurable profiles and auditable overrides
- CI-oriented diff summary and fail policies
- rule-pack fixtures and external pack test runner
- GitHub CI workflow and release workflow
- local and CI usage documentation

### Changed

- policy precedence is now explicit: waiver -> baseline -> override -> profile/context escalation
- CLI text output now includes context policies and suppression summaries
- README now documents installation, examples, CI usage, and release model

### Fixed

- logical bug in composite rule handling
- profile-based `fail_on` enforcement in scan filtering
- noisy README promotion when explicit skill entrypoints exist
