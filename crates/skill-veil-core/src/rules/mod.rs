//! Rule engine for detecting security signals in skills
//!
//! Provides declarative rule definitions and evaluation logic for analyzing
//! skill documents. Rules are defined declaratively in YAML and can detect
//! patterns using regex, section content matching, or code block language detection.
//!
//! # Example
//!
//! ```
//! use skill_veil_core::rules::RuleEngine;
//! use skill_veil_core::analyzer::SkillDocument;
//! use skill_veil_core::adapters::{
//!     PulldownMarkdownParser, RegexPatternMatcher, StdFileSystemProvider,
//! };
//! use std::path::PathBuf;
//! use std::sync::Arc;
//!
//! // Compose adapters at the application boundary, then hand them to the
//! // domain layer through the injected ports. External rule-overlay
//! // directories are resolved by the composition root and passed in; an
//! // empty list loads only the embedded baseline.
//! let fs = StdFileSystemProvider::new();
//! let runtime_dirs: Vec<PathBuf> = Vec::new();
//! let engine = RuleEngine::with_defaults_and_matcher(
//!     Arc::new(RegexPatternMatcher::new()),
//!     &fs,
//!     &runtime_dirs,
//! )
//! .unwrap();
//! assert!(engine.rule_count() > 0);
//!
//! // Parse a skill document
//! let parser = PulldownMarkdownParser::new();
//! let doc = SkillDocument::parse_with_parser(
//!     PathBuf::from("test.md"),
//!     "# My Skill\n\n## Setup\n```bash\necho hello\n```".to_string(),
//!     &parser,
//! ).unwrap();
//!
//! // Evaluate rules against the document
//! let findings = engine.evaluate(&doc);
//! ```

mod builtin;
mod compiled;
mod condition;
mod ioc;
mod parser;
mod schema;

use crate::ports::{FileSystemError, FileSystemProvider, MarkdownParser, PatternMatcher};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::warn;

pub use compiled::CompiledRule;
pub use condition::RuleCondition;
pub use parser::{is_supported_rule_pack_schema, parse_rules_file};
pub use schema::{IocFeedFile, Rule, RulePackFile, RulePackKind, RulePackMetadata, ShieldHint};

/// Versioned schema string for external rule packs.
pub const RULE_PACK_SCHEMA_VERSION: &str = "skill-veil.dev/rules/v1alpha1";

/// Default confidence score for rules (0.0 - 1.0)
pub const DEFAULT_RULE_CONFIDENCE: f32 = 0.9;

/// Error type for rule operations
///
/// Encapsulates errors that can occur during rule loading, compilation,
/// and evaluation.
#[derive(Error, Debug)]
pub enum RuleError {
    /// Rule configuration is invalid
    #[error("Invalid rule configuration: {0}")]
    InvalidRule(String),
    /// Failed to compile a pattern through the matcher port
    #[error("Pattern compilation failed: {0}")]
    PatternError(#[from] crate::ports::PatternError),
    /// I/O error during file operations
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// Two embedded built-in rule packs define the same rule id with
    /// divergent content. This is always a developer bug in the source YAML
    /// and must not be silently deduplicated at runtime.
    #[error(
        "Duplicate built-in rule id `{id}` in `{first}` and `{second}` — \
         remove or rename one of the definitions"
    )]
    DuplicateBuiltinRule {
        id: String,
        first: String,
        second: String,
    },
    /// A user-supplied rule pack declared a rule id that collides with an
    /// already-loaded rule. Only surfaced when strict mode is enabled.
    #[error(
        "Duplicate external rule id `{id}` in `{path}` — \
         already loaded; rename or remove the duplicate (strict mode)"
    )]
    DuplicateUserRule { id: String, path: String },
    /// External rule pack body's SHA-256 digest does not match the value
    /// recorded in the `<pack>.sha256` sidecar. The pack is rejected to
    /// prevent silently loading tampered rules.
    #[error(
        "Rule pack `{path}` failed integrity check: \
         expected sha256 `{expected}`, computed `{actual}` — \
         the pack body changed since the sidecar was issued; \
         re-issue the sidecar or revert the body"
    )]
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    /// External rule pack has no `<pack>.sha256` sidecar and the engine is
    /// running with `ChecksumPolicy::Required`. Operators who want to load
    /// unsigned packs (development, ad-hoc tooling) can opt out via
    /// `set_checksum_policy(ChecksumPolicy::Lenient)` or
    /// `ChecksumPolicy::WarnOnMissing`.
    #[error(
        "Rule pack `{path}` has no sha256 sidecar and ChecksumPolicy::Required \
         is in effect — generate `{path}.sha256` containing the hex digest \
         of the pack body"
    )]
    MissingChecksum { path: String },
}

/// Suffix appended to a rule pack path to locate its SHA-256 sidecar.
/// `<pack>.yaml` therefore resolves to `<pack>.yaml.sha256`. Mirrors the
/// `sha256sum` convention so operators can issue and verify sidecars
/// with stock tooling: `sha256sum pack.yaml > pack.yaml.sha256`.
const RULE_PACK_CHECKSUM_SUFFIX: &str = ".sha256";

/// Compute the SHA-256 hex digest of `bytes`. Used for both the
/// integrity verification and the regression tests that pin the sidecar
/// format. Pure; no allocation beyond the returned string.
fn sha256_hex_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Parse the body of a `.sha256` sidecar. Accepts both the bare-digest
/// form (`<hex>\n`) and the canonical `sha256sum` form (`<hex>  <name>\n`)
/// — the latter is what stock `sha256sum > pack.yaml.sha256` produces.
/// Returns `None` if no plausible 64-char hex digest is found.
fn parse_checksum_sidecar(body: &str) -> Option<String> {
    let first_token = body.split_whitespace().next()?;
    if first_token.len() == 64 && first_token.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(first_token.to_ascii_lowercase())
    } else {
        None
    }
}

/// Verify a rule pack body against its sidecar according to `policy`.
///
/// - [`ChecksumPolicy::Lenient`]: never reads the sidecar, never fails.
/// - [`ChecksumPolicy::WarnOnMissing`]: if the sidecar exists, verify;
///   if it is missing, emit a `tracing::warn!` and continue.
/// - [`ChecksumPolicy::Required`]: the sidecar MUST exist and match;
///   any other state surfaces as `RuleError::MissingChecksum` or
///   `RuleError::ChecksumMismatch`.
fn verify_pack_checksum<F: FileSystemProvider>(
    fs: &F,
    pack_path: &Path,
    body: &[u8],
    policy: ChecksumPolicy,
) -> Result<(), RuleError> {
    if matches!(policy, ChecksumPolicy::Lenient) {
        return Ok(());
    }
    let sidecar_path = {
        let mut buf = pack_path.as_os_str().to_os_string();
        buf.push(RULE_PACK_CHECKSUM_SUFFIX);
        std::path::PathBuf::from(buf)
    };
    let sidecar_bytes = match fs.read_file_bytes(&sidecar_path) {
        Ok(bytes) => bytes,
        Err(FileSystemError::PathNotFound(_)) => match policy {
            ChecksumPolicy::Required => {
                return Err(RuleError::MissingChecksum {
                    path: pack_path.display().to_string(),
                });
            }
            ChecksumPolicy::WarnOnMissing => {
                warn!(
                    pack = %pack_path.display(),
                    sidecar = %sidecar_path.display(),
                    "rule pack loaded without integrity verification — \
                     issue a `<pack>.sha256` sidecar to silence this warning"
                );
                return Ok(());
            }
            ChecksumPolicy::Lenient => unreachable!("handled above"),
        },
        Err(FileSystemError::IoError(io)) => return Err(RuleError::IoError(io)),
    };
    let sidecar_text = String::from_utf8(sidecar_bytes.as_bytes().to_vec()).map_err(|err| {
        RuleError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    })?;
    let expected = parse_checksum_sidecar(&sidecar_text).ok_or_else(|| {
        RuleError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "rule pack sidecar `{}` does not contain a 64-char hex SHA-256 digest",
                sidecar_path.display()
            ),
        ))
    })?;
    let actual = sha256_hex_of(body);
    if expected != actual {
        return Err(RuleError::ChecksumMismatch {
            path: pack_path.display().to_string(),
            expected,
            actual,
        });
    }
    Ok(())
}

/// Verification policy applied to external rule pack bodies during
/// `load_rules_file`. The default — [`ChecksumPolicy::WarnOnMissing`] —
/// emits a `tracing::warn!` when a pack ships without a `<path>.sha256`
/// sidecar but does not block the load. Operators running production
/// scans against untrusted rule directories should flip to
/// [`ChecksumPolicy::Required`] to enforce integrity verification at the
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumPolicy {
    /// Skip integrity verification entirely; do not warn on missing sidecars.
    /// Use only for built-in / embedded packs that the binary itself ships.
    Lenient,
    /// Verify the sidecar when present; emit `tracing::warn!` when absent.
    /// Default for runtime overlays so operators can incrementally adopt
    /// signed packs without breaking existing deployments.
    WarnOnMissing,
    /// Verify the sidecar when present; reject the pack if the sidecar is
    /// missing. Recommended for production scans against rule directories
    /// that any user can write to.
    Required,
}

/// Rule engine for loading and evaluating rules
///
/// The engine is generic over the pattern matcher implementation, allowing
/// different matching strategies to be used (regex, literal, etc.).
///
/// # Example
///
/// ```
/// use skill_veil_core::rules::RuleEngine;
/// use skill_veil_core::adapters::{RegexPatternMatcher, StdFileSystemProvider};
/// use std::path::PathBuf;
/// use std::sync::Arc;
///
/// // Compose adapters at the application boundary; the engine receives
/// // them through the injected ports. The composition root resolves the
/// // external rule-overlay directories (empty here loads the baseline).
/// let fs = StdFileSystemProvider::new();
/// let runtime_dirs: Vec<PathBuf> = Vec::new();
/// let engine = RuleEngine::with_defaults_and_matcher(
///     Arc::new(RegexPatternMatcher::new()),
///     &fs,
///     &runtime_dirs,
/// )
/// .unwrap();
/// assert!(engine.rule_count() > 0);
/// ```
pub struct RuleEngine<M: PatternMatcher + ?Sized> {
    rules: Vec<CompiledRule>,
    rules_dir: Option<std::path::PathBuf>,
    matcher: Arc<M>,
    /// When true, `load_rules_file` / `add_rule` return
    /// `RuleError::DuplicateUserRule` on an id collision instead of logging
    /// a `warn!()` and skipping. Default: **true** as of round-5 hardening.
    ///
    /// # Why strict by default
    ///
    /// The previous lenient default meant that an external pack with an ID
    /// colliding with a built-in (or with another loaded pack) was silently
    /// dropped with only a `tracing::warn!()` line. Maintainers writing
    /// override packs in `rules/official/` would have no visible signal
    /// that their rule was discarded — they had to grep logs at runtime.
    /// Strict-by-default surfaces the collision at load time as a hard
    /// error with file path context, matching how `cargo` treats duplicate
    /// crate names and how `eslint` treats duplicate rule definitions.
    ///
    /// Pre-flight: `comm` of `rules/official/*.yaml` IDs against
    /// `builtin_rules.yaml` IDs at the time of the flip showed 0
    /// collisions, so flipping the default does not break the canonical
    /// distribution.
    ///
    /// # Opt-out
    ///
    /// Callers who *intentionally* want the silent-skip behaviour (e.g.
    /// experimental tooling that loads many overlapping packs) must call
    /// `set_strict_mode(false)` explicitly. The opt-out is preserved so
    /// no consumer is forced to rename rules unilaterally.
    strict_mode: bool,
    /// Integrity verification policy for external rule pack bodies. See
    /// [`ChecksumPolicy`] for the three modes. Default is
    /// `ChecksumPolicy::WarnOnMissing` so operators are informed about
    /// unverified packs without breaking existing deployments that have
    /// not yet shipped sidecars.
    checksum_policy: ChecksumPolicy,
}

impl<M: PatternMatcher + ?Sized> RuleEngine<M> {
    /// Create a new rule engine with a custom pattern matcher.
    #[must_use]
    pub fn with_matcher(matcher: Arc<M>) -> Self {
        Self {
            rules: Vec::new(),
            rules_dir: None,
            matcher,
            strict_mode: true,
            checksum_policy: ChecksumPolicy::WarnOnMissing,
        }
    }

    /// Override the integrity verification policy for external rule
    /// pack bodies. See [`ChecksumPolicy`] for the three modes. Default
    /// is `WarnOnMissing`.
    pub fn set_checksum_policy(&mut self, policy: ChecksumPolicy) {
        self.checksum_policy = policy;
    }

    /// Toggle strict mode. When enabled, loading an external pack with a
    /// duplicate rule id returns `RuleError::DuplicateUserRule` instead of
    /// emitting a `tracing::warn!()` and skipping.
    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    /// Create a rule engine with built-in rules plus an optional runtime
    /// overlay loaded through the injected `FileSystemProvider`.
    ///
    /// # Load order contract
    ///
    /// Built-in rules are loaded first, runtime overrides second. The
    /// non-strict duplicate-skip means inverting the order would silently
    /// discard canonical detections.
    ///
    /// # Hexagonal boundary
    ///
    /// `runtime_overlay_fs` and `runtime_overlay_dirs` are injected so the
    /// domain layer never instantiates a concrete adapter. Production
    /// callers compose them in the application layer (typically
    /// `Scanner::with_std_adapters`) by pairing `StdFileSystemProvider`
    /// with `default_external_rule_dirs()`.
    #[must_use = "RuleEngine::with_defaults_and_matcher() returns a Result that should be used"]
    pub fn with_defaults_and_matcher<F: FileSystemProvider>(
        matcher: Arc<M>,
        runtime_overlay_fs: &F,
        runtime_overlay_dirs: &[std::path::PathBuf],
    ) -> Result<Self, RuleError> {
        Self::with_defaults_and_matcher_runtime_strict(
            matcher,
            runtime_overlay_fs,
            runtime_overlay_dirs,
            false,
        )
    }

    /// Create a rule engine with built-in rules plus runtime overlays,
    /// choosing whether duplicate IDs in those overlays are hard errors.
    #[must_use = "RuleEngine::with_defaults_and_matcher_runtime_strict() returns a Result that should be used"]
    pub fn with_defaults_and_matcher_runtime_strict<F: FileSystemProvider>(
        matcher: Arc<M>,
        runtime_overlay_fs: &F,
        runtime_overlay_dirs: &[std::path::PathBuf],
        strict_runtime_overlays: bool,
    ) -> Result<Self, RuleError> {
        let mut engine = Self::with_matcher(matcher);
        engine.load_builtin_rules()?;
        let initial_strict_mode = engine.strict_mode;
        engine.load_runtime_default_rules(
            runtime_overlay_fs,
            runtime_overlay_dirs,
            strict_runtime_overlays,
        )?;
        debug_assert_eq!(
            engine.strict_mode, initial_strict_mode,
            "runtime overlay loading must preserve the caller's strict-mode state"
        );
        Ok(engine)
    }

    fn load_builtin_rules(&mut self) -> Result<(), RuleError> {
        for rule in builtin::get_builtin_rules()? {
            self.add_rule(rule)?;
        }
        Ok(())
    }

    /// Load rules from a directory through a `FileSystemProvider`. Going
    /// through the port preserves the hexagonal contract: this loader
    /// reads YAML rule packs from disk, but the domain layer never
    /// reaches `std::fs` directly.
    pub fn load_from_dir<F: FileSystemProvider>(
        &mut self,
        fs: &F,
        dir: impl AsRef<Path>,
    ) -> Result<(), RuleError> {
        let dir = dir.as_ref();
        self.rules_dir = Some(dir.to_path_buf());

        for pattern in &["*.yaml", "*.yml"] {
            let mut paths = fs.list_files(dir, pattern, true).map_err(|err| match err {
                FileSystemError::IoError(io) => RuleError::IoError(io),
                FileSystemError::PathNotFound(missing) => RuleError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("path not found: {}", missing.display()),
                )),
            })?;
            paths.sort();
            debug_assert!(
                paths.windows(2).all(|pair| pair[0] <= pair[1]),
                "rule pack paths must load in deterministic sorted order"
            );
            for path in paths {
                self.load_rules_file(fs, &path)?;
            }
        }

        Ok(())
    }

    /// Load rules from a YAML file.
    ///
    /// In **strict mode** (default — see `RuleEngine.strict_mode` doc-comment
    /// for rationale), an ID that collides with an already-loaded rule
    /// (built-in or earlier-loaded external) returns
    /// `RuleError::DuplicateUserRule { id, path }`. The pre-flight at the
    /// time of the round-5 strict-mode flip showed 0 collisions between
    /// the embedded official packs and the `rules/official/` packs.
    ///
    /// Callers that intentionally want the legacy "warn-and-skip" behaviour
    /// (e.g. tooling that loads many overlapping experimental packs) must
    /// opt out via `set_strict_mode(false)`.
    pub fn load_rules_file<F: FileSystemProvider>(
        &mut self,
        fs: &F,
        path: impl AsRef<Path>,
    ) -> Result<(), RuleError> {
        let bytes = fs.read_file_bytes(path.as_ref()).map_err(|err| match err {
            FileSystemError::IoError(io) => RuleError::IoError(io),
            FileSystemError::PathNotFound(missing) => RuleError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("path not found: {}", missing.display()),
            )),
        })?;
        verify_pack_checksum(fs, path.as_ref(), bytes.as_bytes(), self.checksum_policy)?;
        let content = String::from_utf8(bytes.as_bytes().to_vec()).map_err(|err| {
            RuleError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        })?;
        for rule in parse_rules_file(&content)? {
            let compiled = CompiledRule::compile(rule)?;
            if self
                .rules
                .iter()
                .any(|existing| existing.rule.id == compiled.rule.id)
            {
                if self.strict_mode {
                    return Err(RuleError::DuplicateUserRule {
                        id: compiled.rule.id.clone(),
                        path: path.as_ref().display().to_string(),
                    });
                }
                warn!(
                    rule_id = %compiled.rule.id,
                    path = %path.as_ref().display(),
                    "skipping duplicate rule ID (existing rule takes priority)"
                );
            } else {
                self.rules.push(compiled);
            }
        }

        Ok(())
    }

    /// Add a single rule.
    ///
    /// Skips the rule if one with the same ID already exists.
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), RuleError> {
        let compiled = CompiledRule::compile(rule)?;
        if self
            .rules
            .iter()
            .any(|existing| existing.rule.id == compiled.rule.id)
        {
            if self.strict_mode {
                return Err(RuleError::DuplicateUserRule {
                    id: compiled.rule.id.clone(),
                    path: "<programmatic add_rule>".to_string(),
                });
            }
            warn!(
                rule_id = %compiled.rule.id,
                "skipping duplicate rule ID (existing rule takes priority)"
            );
        } else {
            self.rules.push(compiled);
        }
        Ok(())
    }

    /// Get all loaded rules.
    pub fn rules(&self) -> Vec<&Rule> {
        self.rules.iter().map(|cr| &cr.rule).collect()
    }

    /// Evaluate all rules against a document.
    pub fn evaluate(&self, doc: &crate::analyzer::SkillDocument) -> Vec<crate::findings::Finding> {
        let mut all_findings = Vec::new();

        for compiled_rule in &self.rules {
            let findings = compiled_rule.matches(doc, self.matcher.as_ref());
            all_findings.extend(findings);
        }

        all_findings
    }

    /// Get rule count.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Test a rule against sample content.
    ///
    /// The caller injects the `MarkdownParser` adapter so the domain layer
    /// stays free of concrete adapter dependencies. Production callers in
    /// the CLI pass `&PulldownMarkdownParser::new()`; tests pass whichever
    /// parser their fixture exercises.
    pub fn test_rule(
        &self,
        rule_id: &str,
        content: &str,
        parser: &dyn MarkdownParser,
    ) -> Result<Vec<crate::findings::Finding>, RuleError> {
        let doc = crate::analyzer::SkillDocument::parse_with_parser(
            std::path::PathBuf::from("test.md"),
            content.to_string(),
            parser,
        )
        .map_err(|e| RuleError::InvalidRule(e.to_string()))?;

        let findings = self
            .rules
            .iter()
            .filter(|cr| cr.rule.id == rule_id)
            .flat_map(|cr| cr.matches(&doc, self.matcher.as_ref()))
            .collect();

        Ok(findings)
    }

    /// Load runtime overlay rule directories through the injected
    /// `FileSystemProvider`. Each directory is loaded only if it exists;
    /// non-existent paths are skipped silently so callers can pass a
    /// canonical list (`default_external_rule_dirs()`) regardless of
    /// whether the overlay is present in the current working directory.
    ///
    /// # Strictness contract
    ///
    /// Normal scans load default overlays leniently so a repo-local
    /// `./rules/official/` copy of the embedded packs does not abort
    /// startup. Strict scans pass `strict_runtime_overlays = true`, which
    /// makes `$SKILL_VEIL_RULES_DIR`, the installed cache overlay, and the
    /// legacy dev fallback obey the same duplicate-ID policy as `--rules-dir`.
    fn load_runtime_default_rules<F: FileSystemProvider>(
        &mut self,
        fs: &F,
        dirs: &[std::path::PathBuf],
        strict_runtime_overlays: bool,
    ) -> Result<bool, RuleError> {
        if strict_runtime_overlays {
            self.load_existing_runtime_dirs(fs, dirs)
        } else {
            self.with_strict_mode(false, |engine| engine.load_existing_runtime_dirs(fs, dirs))
        }
    }

    fn load_existing_runtime_dirs<F: FileSystemProvider>(
        &mut self,
        fs: &F,
        dirs: &[std::path::PathBuf],
    ) -> Result<bool, RuleError> {
        let mut loaded = false;
        for dir in dirs {
            if fs.exists(dir) {
                self.load_from_dir(fs, dir)?;
                loaded = true;
            }
        }
        Ok(loaded)
    }

    /// Run `f` with `self.strict_mode` temporarily set to `temporary`,
    /// restoring the previous value before returning. The closure receives
    /// `&mut self` so it can call existing `&mut self` methods that consult
    /// `strict_mode` (e.g. `load_from_dir` → `add_rule`) and observe the
    /// override.
    ///
    /// # Why a helper instead of inline mutation
    ///
    /// The previous implementation inlined `std::mem::replace` plus a
    /// post-loop restore in the caller. Co-locating the override window
    /// here makes the contract a named operation ("run this block with
    /// `strict=false`") instead of an open-coded mutation pattern, in
    /// keeping with the CLAUDE.md guidance to prefer explicit inputs
    /// over hidden state. The restore happens on both success and error
    /// paths, mirroring the previous behaviour.
    fn with_strict_mode<R>(
        &mut self,
        temporary: bool,
        f: impl FnOnce(&mut Self) -> Result<R, RuleError>,
    ) -> Result<R, RuleError> {
        let previous = std::mem::replace(&mut self.strict_mode, temporary);
        let result = f(self);
        self.strict_mode = previous;
        result
    }
}

#[cfg(test)]
mod tests;
