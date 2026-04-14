# AGENTS.md

Guidance for agentic coding agents working on skill-veil.

## Build, Lint & Test

```bash
# Build everything
cargo build --all-targets

# Run all tests (mirrors CI)
RUSTFLAGS="-Dwarnings" cargo test --all-targets --all-features

# Run a single test by name
cargo test test_name_here

# Run tests in a specific crate
cargo test -p skill-veil-core
cargo test -p skill-veil

# Run the regression corpus test
cargo test -p skill-veil-core labeled_corpus_meets_phase1_baseline

# Lint (must pass CI)
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings

# Format code
cargo fmt --all

# Build with optional YARA support
cargo build --all-targets --features yara

# Run CLI against examples
cargo run -p skill-veil -- scan-file examples/malicious-skill/SKILL.md
cargo run -p skill-veil -- scan-package examples/manifest-package --format text
```

A `.pre-commit-config.yaml` is provided. Install with `pre-commit install`.

## Workspace Structure

Two crates in a Cargo workspace:

- **`crates/skill-veil-core`** — library: all analysis logic, domain types, rules, verdicts, policy
- **`crates/skill-veil-cli`** — binary (`skill-veil`): CLI commands, output formatting, dataset tooling

External rule packs: `rules/official/` and `rules/community/`.
Benchmark corpus: `benchmarks/corpus.yaml`.
Regression fixtures: `crates/skill-veil-core/tests/fixtures/`.

## Architecture

Hexagonal (ports & adapters) design. Domain logic depends on traits in `ports.rs`:

| Trait | Default impl | Purpose |
|---|---|---|
| `MarkdownParser` | `PulldownMarkdownParser` | Parse markdown → sections |
| `PatternMatcher` | `RegexPatternMatcher` | Regex matching |
| `FileSystemProvider` | `StdFileSystemProvider` | File I/O |

`Scanner<F: FileSystemProvider, P: MarkdownParser>` is generic over these traits for testability.

### Core Pipeline (`scanner_execution.rs`)

1. Parse → `SkillDocument` (sections, code blocks, referenced files)
2. Rule evaluation → `RuleEngine::evaluate` applies `builtin_rules.yaml` + loaded rule packs
3. Artifact scanning → referenced files get rule pass + `artifact_analysis` service
4. Artifact graph → capability/dependency graph across all artifacts
5. Taint analysis → source→sink taint rules (e.g., secret → network = exfiltration)
6. Deduplication → `deduplicate_findings`
7. Policy filters → baselines, waivers, overrides
8. Verdict → `PackageAssessmentPipeline` → `Benign | Suspicious | Malicious`

### Key Domain Types (`findings/model.rs`)

- **`Finding`** — detected signal: `rule_id`, `severity`, `confidence`, `signal_class`, `recommended_action`, `artifact_scope`
- **`SignalClass`** — `Hygiene | ReviewSignal | SuspiciousPackageBehavior | MaliciousBehavior`
- **`ThreatCategory`** — `RemoteExec | SupplyChain | CredentialExposure | DataExfiltration | ...`
- **`RecommendedAction`** — `Log | RequireApproval | Block`
- **`Verdict`** — `Benign | Suspicious | Malicious`
- **`ArtifactScope`** — `AgentEntrypoint | PackageRootArtifact | SupportingArtifact`

## Code Style

### Imports

```rust
use std::path::{Path, PathBuf};

use crate::adapters::{PulldownMarkdownParser, StdFileSystemProvider};
use crate::analyzer::SkillDocument;
use crate::ports::MarkdownParser;
use crate::findings::{Finding, Severity, ThreatCategory};
use thiserror::Error;

use serde::{Deserialize, Serialize};
```

Group order:
1. `std::`
2. External crates (alphabetical)
3. `crate::` modules (alphabetical)
4. Current module items

No wildcards except `#[cfg(test)]` test imports.

### Formatting

- `cargo fmt --all` enforces standard formatting.
- No `unsafe_code` — workspace-wide `unsafe_code = "forbid"`.
- Max line width: default (100).

### Types & Enums

- Enums that serialize use `#[serde(rename_all = "snake_case")]` and `#[strum(serialize_all = "snake_case")]`.
- Public enums derive: `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display`.
- Public structs derive: `Debug, Clone, Serialize, Deserialize`.
- Constants for weights/scores: `SEVERITY_WEIGHT_CRITICAL`, `CAPABILITY_WEIGHT_NETWORK_ACCESS`, etc. in `findings/model.rs`. No inline magic numbers.

```rust
// Good
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

// Good - constants with descriptive names
pub const SEVERITY_WEIGHT_CRITICAL: u32 = 90;
pub const CAPABILITY_WEIGHT_NETWORK_ACCESS: u32 = 6;
pub const SIGNAL_WEIGHT_MALICIOUS: f32 = 1.0;

// Bad - inline magic number
let score = severity.weight() * 1.0 * confidence; // NO
```

### Naming Conventions

- Types: `PascalCase` — `Finding`, `ScanResult`, `ArtifactKind`
- Functions/Methods: `snake_case` — `scan_file`, `build_artifact_graph`, `calibrate_verdict`
- Constants: `SCREAMING_SNAKE_CASE` — `SEVERITY_WEIGHT_CRITICAL`, `DEFAULT_RULE_CONFIDENCE`
- Module names: `snake_case` — `scanner_execution`, `artifact_taint`, `verdict_calibration`
- Test functions: `test_<verb>_<noun>` — `test_scan_malicious_skill`, `test_generate_shield_md`
- Builder pattern: `FindingBuilder`, `Finding::builder(...)` fluent API

### Error Handling

- **Library crate (`skill-veil-core`)**: Use `thiserror` for typed errors on port traits and domain boundaries:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Failed to read file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid skill entrypoint: {0}")]
    InvalidSkillEntrypoint(String),
}
```

- **CLI crate (`skill-veil-cli`)**: Use `anyhow` for propagation with context:

```rust
use anyhow::{Context, Result};

let result = some_operation().context("failed during operation")?;
```

- Error enum variants: `PascalCase` — `IoError`, `InvalidRule`, `LoadError`
- All error types must implement `Debug` and `Error` traits.

### Documentation

- **Module docs**: `//!` doc comments at module top describing purpose.
- **Public items**: `///` doc comments with examples for public functions, structs, enums.
- Use `# Examples:` sections in doc comments.
- No orphan comments — every comment must be attached to code.

```rust
/// Scanner for analyzing skills and related agent-extension packages.
///
/// # Examples
///
/// ```
/// use skill_veil_core::Scanner;
/// let scanner = Scanner::new().unwrap();
/// let result = scanner.scan_file("test.md").unwrap();
/// ```
pub struct Scanner<F, P> { ... }
```

### Testing Patterns

- **Unit tests**: Inline `#[cfg(test)]` modules in source files (`scanner_tests.rs`, `policy_tests.rs`).
- **Integration tests**: `crates/skill-veil-core/tests/` directory.
- **Temp fixtures**: Use `tempfile` crate for inline test fixtures. Never touch real filesystem in tests.

```rust
use tempfile::NamedTempFile;
use std::io::Write;

#[test]
fn test_scan_file() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "# Test Skill\n## Setup\n```bash\necho hi\n```").unwrap();
    
    let scanner = Scanner::new().unwrap();
    let result = scanner.scan_file(file.path()).unwrap();
    
    assert!(!result.findings.is_empty());
}
```

- **Regression corpus**: `labeled_corpus_meets_phase1_baseline` test enforces precision/recall thresholds. Don't break it without updating the corpus.
- **Architecture tests**: `architecture_tests/` module has structural contracts. Check them when refactoring.

### Rules (YAML)

Rules are defined in YAML (`builtin_rules.yaml`, `rules/official/*.yaml`):

```yaml
- id: UPPERCASE_SNAKE_CASE_ID
  category: remote_exec
  severity: critical | high | medium | low
  confidence: 0.0-1.0
  when: !regex
    pattern: "..."
  action: block | require_approval | log
  reason: "Human-readable description"
  enabled: true
  tags: [tag_name]
```

- Rule IDs in `official/` pack are public API — never rename/remove them.
- Add positive/negative fixtures for new rules.
- Append changes to `rules/CHANGELOG.md`.

### Code Comments

- No `//` comments that explain "what" — code should be self-documenting.
- Use `// TODO:` and `// FIXME:` sparingly. Open an issue instead.
- No commented-out code in production.
- Prefer extracting complex logic into well-named helper functions over inline comments.

### Functions & Methods

- Prefer pure functions with explicit inputs/outputs over methods with side effects.
- Use `#[must_use]` on types like `Result` and `Option` that shouldn't be silently discarded.
- Parameters: `impl Into<String>` for strings in builders:

```rust
pub fn reason(mut self, reason: impl Into<String>) -> Self {
    self.reason = reason.into();
    self
}
```

- Return `Result<T, E>` for fallible operations. Never panic in library code.

### CI Requirements

All commits must pass:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTFLAGS="-Dwarnings" cargo test --all-targets --all-features
```

`-D warnings` promotes all warnings to errors. Fix clippy pedantic lints rather than `#[allow(...)]`.

## Key Files

- `CLAUDE.md` — Detailed architecture and pipeline docs for Claude Code
- `.github/copilot-instructions.md` — GitHub Copilot instructions (this file consolidates similar info)
- `crates/skill-veil-core/src/lib.rs` — Public API exports
- `crates/skill-veil-core/src/ports.rs` — Trait definitions for dependency injection
- `crates/skill-veil-core/src/findings/model.rs` — Core finding/severity/verdict types
- `crates/skill-veil-core/src/rules.rs` — Rule engine and YAML rule definitions
- `crates/skill-veil-core/src/scanner.rs` — Scanner orchestration
- `crates/skill-veil-core/src/verdict_calibration.rs` — Verdict calibration logic

## Quick Reference

- Add new finding type → `findings/model.rs`, add to `SignalClass` or `ThreatCategory` enum.
- Add new rule → `builtin_rules.yaml`, add fixtures to `rules/fixtures/behavioral.yaml`.
- Add new artifact analyzer → `services/artifact_analysis/`, wire up in `artifact_analysis.rs`.
- Add new port trait → `ports.rs`, implement in `adapters/`.
- Run single test: `cargo test test_name_here`.