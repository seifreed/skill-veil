# GitHub Copilot Instructions

## Build, Test & Lint

```bash
# Build everything
cargo build --all-targets

# Full test suite (matches CI — treats warnings as errors)
RUSTFLAGS="-Dwarnings" cargo test --all-targets --all-features

# Single test by name
cargo test test_name_here

# Tests in a specific crate
cargo test -p skill-veil-core
cargo test -p skill-veil

# Regression corpus test (precision/recall gates)
cargo test -p skill-veil-core labeled_corpus_meets_phase1_baseline

# Lint
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings

# Format
cargo fmt --all

# Run CLI against an example
cargo run -p skill-veil -- scan-file examples/malicious-skill/SKILL.md
cargo run -p skill-veil -- scan-package examples/manifest-package --format text

# Benchmark corpus
cargo run -p skill-veil -- benchmark benchmarks/corpus.yaml --format text

# Validate / test external rule packs
cargo run -p skill-veil -- rules validate --rules-dir rules/official
cargo run -p skill-veil -- rules test-pack --rules-dir rules/official --fixtures rules/fixtures/behavioral.yaml

# Build with optional YARA support (feature-gated via yara-x)
cargo build --all-targets --features yara
```

A `.pre-commit-config.yaml` is provided that runs `cargo fmt --all --check` and `cargo clippy --all-targets --all-features -- -D warnings` before each commit. Install with `pre-commit install`.

## Workspace Layout

Two crates in a Cargo workspace:

- **`crates/skill-veil-core`** — library: all analysis logic, domain types, rules, verdicts, policy
- **`crates/skill-veil-cli`** — binary (`skill-veil`): CLI commands, output formatting, dataset tooling

External rule packs live in `rules/official/` and `rules/community/`. Benchmark corpus is at `benchmarks/corpus.yaml`. Regression fixtures are at `crates/skill-veil-core/tests/fixtures/`.

## Architecture

The core crate follows a **hexagonal / ports-and-adapters** design. Domain logic never touches concrete I/O; it depends on traits in `ports.rs`:

| Trait | Default impl | Purpose |
|---|---|---|
| `MarkdownParser` | `PulldownMarkdownParser` | Parse markdown → sections |
| `PatternMatcher` | `RegexPatternMatcher` | Regex matching |
| `FileSystemProvider` | `StdFileSystemProvider` | File I/O |

`Scanner<F: FileSystemProvider, P: MarkdownParser>` is generic over these traits, which makes unit tests possible without touching the real filesystem.

### Scan Pipeline (`scanner_execution.rs`)

1. **Parse** — `SkillDocument::from_file_with_provider` → sections, code blocks, referenced files
2. **Rule evaluation** — `RuleEngine::evaluate` applies `builtin_rules.yaml` + loaded rule packs
3. **Artifact scanning** — referenced files get the same rule pass + `artifact_analysis` service
4. **Artifact graph** — `artifact_graph.rs` builds a capability/dependency graph across all artifacts
5. **Taint analysis** — `artifact_taint.rs` runs source→sink taint rules over the graph (e.g., secret → external network = exfiltration)
6. **Deduplication** — `deduplicate_findings`; stronger finding wins on same key
7. **Inline suppression / policy filters** — baselines, waivers, overrides from `policy.rs`
8. **Verdict** — `PackageAssessmentPipeline` → `VerdictCalibration` → `Benign | Suspicious | Malicious`

### Key Document Types (`analyzer.rs`)

`SkillDocument` is the central parse result: `path`, `name`, `extension_kind`, `code_blocks`, `sections`, `referenced_files`, `decode_warning`, `parse_warning`.

`AgentExtensionKind` classifies what kind of document is being scanned:
- `Skill`, `AgentInstruction`, `PromptPack`, `McpServer`, `SYSTEM`, `GenericMarkdown`, `Other`

This drives which rules and artifact analyzers apply.

### Architecture Tests (`architecture_tests/naming_contracts.rs`)

The `architecture_tests` module contains source-level structural contracts that assert internal module layout conventions (e.g., that `network.rs` delegates to `patterns.rs`, `relations.rs`, `targets.rs`, `webhook.rs`). These tests will fail if internal modules are restructured without updating the contracts. Check them when refactoring service internals.

### Key Domain Types (`findings/model.rs`)

- **`Finding`** — single detected signal: `rule_id`, `severity`, `confidence`, `signal_class`, `recommended_action`, `artifact_scope`
- **`SignalClass`** — `Hygiene | ReviewSignal | SuspiciousPackageBehavior | MaliciousBehavior`
- **`ThreatCategory`** — `RemoteExec | SupplyChain | CredentialExposure | DataExfiltration | ...`
- **`RecommendedAction`** — `Log | RequireApproval | Block`
- **`CompositeCapability`** — cross-artifact chains: `SecretExfiltration`, `ShellDownloadExec`, `BrowserSessionExfiltration`
- **`FindingSummary`** — `weighted_score()` per finding + graph capability bonuses, clamped 0–100

### Verdict Calibration (`verdict_calibration.rs`)

Prevents false positives from isolated weak signals. Key rule: **declared network access alone (`DECLARED_PERMISSION_NETWORK_ACCESS`) does not escalate the verdict** unless corroborated by stronger behavior. When adding new rules that might produce standalone low-confidence findings, check whether calibration logic needs a corresponding guard.

## Key Conventions

### Rule Schema

Rules live in YAML (`builtin_rules.yaml`, `rules/official/*.yaml`, `rules/community/*.yaml`). Each rule requires:

```yaml
- id: UPPERCASE_SNAKE_CASE_ID     # must be globally unique
  category: remote_exec           # maps to ThreatCategory
  severity: critical | high | medium | low
  confidence: 0.0–1.0
  when: !regex
    pattern: "..."                # or !all / !any with nested conditions
  action: block | require_approval | log
  reason: "Human-readable description"
  enabled: true
  tags:
    - tag_name
```

External rule packs add `schema_version: skill-veil.dev/rules/v1alpha1` and a `metadata:` block. The `official` pack treats rules as compatibility-sensitive and benchmark-reviewed.

**When adding a rule:** add at least one positive and one negative fixture. Rule IDs in the official pack must not be removed or renamed — treat them as public API. Append changes to `rules/CHANGELOG.md`.

### Testing Patterns

- Unit tests use `tempfile` (`NamedTempFile`, `tempdir`) to write fixture content inline — no reliance on the real filesystem in unit tests.
- The regression corpus test (`labeled_corpus_meets_phase1_baseline`) asserts hard precision/recall/FPR thresholds — don't land changes that break these without updating the corpus.
- `scanner_tests.rs` and `policy_tests.rs` are `#[cfg(test)]` modules inside source files.
- Integration tests live in `crates/skill-veil-core/tests/`.

### Error Handling

- Uses `thiserror` for typed errors on port traits (`ParserError`, `FileSystemError`, `PatternError`, `ScanError`).
- Uses `anyhow` in the CLI crate for propagation.
- `unsafe_code = "forbid"` is enforced workspace-wide.

### Clippy & Style

- `clippy::all` + `clippy::pedantic` are both set to `warn` and then promoted to errors by CI (`-D warnings`). Every new function should pass pedantic without `#[allow(...)]` unless there is a clear reason.
- Enums that appear in serialized output use `#[serde(rename_all = "snake_case")]` and `#[strum(serialize_all = "snake_case")]`.
- Scoring constants are named `*_WEIGHT_*` and live in `findings/model.rs`. Add new weights there; don't inline magic numbers into scoring logic.

### Code Comments

**Default: write no comment.** A comment must justify its existence.
The bar for keeping one is *"removing this would make a careful reader
misunderstand the code"* — not *"this might help someone."* If you
cannot point to a specific reader who would be confused without it,
delete it.

Only these comments are admissible:

- A non-obvious **invariant** the type system does not encode (e.g.
  `// lower.len() == original.len()` — load-bearing for a slice index
  downstream).
- A **why** that is genuinely surprising: a workaround for a specific
  bug (cite the issue/CVE), a security trade-off, an ordering that
  another module silently relies on.
- Public-API **doc-comments** (`///`, `//!`) on items that ship outside
  the crate.

Forbidden in this codebase:

- Comments that **paraphrase the next line** (`// loop over rules`
  above `for rule in rules`). Rename the variable instead.
- Comments that **narrate intent** in marketing register: "Cleanly
  handles…", "Robustly validates…", "Gracefully degrades…", "Elegant
  solution for…", "Comprehensive…", "This ensures…", "Note that…".
  These are AI-prose tells; strip them.
- Comments that **reference the current task or PR**: "added for the
  fingerprinting flow", "fix for issue #123", "used by the new webhook
  handler". That belongs in the commit message — it rots in source.
- Trailing **section banners** (`// === HELPERS ===`, `// --- end of
  validation ---`). Use module/function structure.
- **Commented-out code.** Git preserves history.
- `// TODO` / `// FIXME` left behind. Open an issue and link it, or
  delete.

**No AI smell.** A reviewer should not be able to tell a comment was
written by a model. Concretely: no hedged second-person ("you might
want to…"), no enumerations of obvious cases, no "for clarity" /
"for safety" suffixes, no triple-summary openings ("This function
does X. It does this by Y. The reason is Z."). When in doubt: delete
the comment and let the code speak.

Doc-comments follow the same rule. A `///` that restates the function
name is worse than no doc-comment because it lies about being
informative — write the contract or omit it.
