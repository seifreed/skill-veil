# skill-veil Roadmap

This roadmap turns `skill-veil` into an open source security layer for agent supply chain analysis.

## Phase 1: Harden The Core

Goal: make the scanner correct before making it ambitious.

Scope:
- Fix logical bugs in the rule engine.
- Reduce false positives in file discovery.
- Separate documentation from executable skill entrypoints.
- Add regression tests with a labeled corpus.
- Measure baseline precision, recall, and false positive rate.

Deliverables:
- regression suite with benign, suspicious, and malicious samples,
- strict `scan-file` mode for explicit skill entrypoints,
- `scan-package` mode that analyzes a package without promoting README/docs to payload entrypoints.

Exit criteria:
- narrative README files are not marked critical by default when a package already exposes an explicit `SKILL.md`,
- gray-area samples move to `review/approval` instead of arbitrary `block`.

## Phase 2: Threat Model And Typology

Goal: move from a bag of regexes to a coherent taxonomy.

Scope:
- formal threat model for agent ecosystems,
- categories for remote execution, supply chain, prompt tampering, secret access, tool abuse, autonomy escalation, data exfiltration, and social manipulation,
- severity/confidence semantics by evidence type,
- distinction between IOC, behavior, intent, and context.

Deliverables:
- `docs/threat-model.md`,
- findings schema v2,
- more explainable scoring model.

## Phase 3: Deep Artifact Analysis

Goal: stop looking only at Markdown.

Scope:
- analyze referenced scripts,
- traverse package artifacts,
- inspect `package.json`, `requirements.txt`, `Cargo.toml`, `Dockerfile`, and shell scripts,
- detect unpinned dependencies, dangerous install hooks, remote binaries, deferred execution, persistence, and excessive permissions.

Deliverables:
- artifact graph,
- findings on attached artifacts, not only the root document.

## Phase 4: Maintainable Rule Engine

Goal: make rules portable and contributor-friendly.

Scope:
- version rules outside the binary,
- stable support for regex, structural semantics, `all/any/not`, file/section context, IOC feeds, and optional YARA,
- rule fixtures and dedicated rule test runner.

Deliverables:
- official `rules/` packs,
- `skill-veil rules test`,
- rule changelog.

## Phase 5: Policy Engine

Goal: help teams decide, not only observe.

Scope:
- policy levels: allow, warn, require-approval, block,
- explicit and auditable overrides,
- profiles for personal, team, enterprise, and research usage,
- policy contexts for install, network, secrets, code modification, and external communications.

Deliverables:
- stable policy format,
- baselines and waivers,
- scan diff support.

## Phase 6: Open Source UX

Goal: make adoption possible in 10 minutes.

Scope:
- strong README and quickstart,
- curated examples,
- architecture docs,
- contributor guide,
- rule authoring guide,
- reproducible releases and prebuilt binaries.

Deliverables:
- adoption-focused `README.md`,
- `docs/architecture.md`,
- `docs/rule-authoring.md`,
- GitHub Releases.

## Phase 7: Ecosystem Integration

Goal: place the tool where decisions are made.

Scope:
- official GitHub Action,
- strong SARIF support,
- pre-commit hook,
- CI integrations,
- repo/package scanning for real skill ecosystems,
- dataset and marketplace modes.

Deliverables:
- official action,
- CI templates,
- PR gating examples.

## Phase 8: Modern Agent Extension Coverage

Goal: evolve beyond Markdown skill scanning.

Scope:
- support for MCP servers,
- tool manifests,
- persistent prompts,
- instruction files such as `AGENTS.md`, `CLAUDE.md`, and `SYSTEM.md`,
- detection of cognitive rootkits and semantic persistence,
- analysis of declared vs effective permissions.

Deliverables:
- target types for skill, prompt-pack, mcp-server, and agent-extension,
- unified findings model.

## Phase 9: Signal Quality And Intelligence

Goal: compete on precision, not rule count.

Scope:
- serious benign dataset in addition to malicious corpus,
- public benchmark,
- metrics tracked per release,
- better explainability,
- finding deduplication,
- calibrated confidence scores.

Deliverables:
- open benchmark,
- simple quality dashboard,
- labeled corpus.

## Phase 10: Open Source Governance

Goal: make the project sustainable.

Scope:
- clear license,
- security policy and disclosure process,
- maintainer ownership,
- public roadmap,
- official and community rule packs,
- semantic versioning.

Deliverables:
- `SECURITY.md`,
- `CONTRIBUTING.md`,
- public roadmap and proposal templates.
