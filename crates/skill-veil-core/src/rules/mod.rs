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
//! use skill_veil_core::adapters::PulldownMarkdownParser;
//! use std::path::PathBuf;
//!
//! // Create a rule engine with default built-in rules
//! let engine = RuleEngine::with_defaults().unwrap();
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

use crate::adapters::{PulldownMarkdownParser, RegexPatternMatcher};
use crate::ports::PatternMatcher;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::warn;

pub use compiled::CompiledRule;
pub use condition::RuleCondition;
pub use parser::{default_external_rule_dirs, is_supported_rule_pack_schema, parse_rules_file};
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
    /// Failed to load rules from a file or directory
    #[error("Failed to load rules: {0}")]
    LoadError(String),
    /// Rule configuration is invalid
    #[error("Invalid rule configuration: {0}")]
    InvalidRule(String),
    /// Failed to compile a regex pattern
    #[error("Regex compilation failed: {0}")]
    RegexError(#[from] regex::Error),
    /// Failed to parse YAML rule file
    #[error("YAML parsing error: {0}")]
    YamlError(#[from] serde_yaml::Error),
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
///
/// // Create with default rules
/// let engine = RuleEngine::with_defaults().unwrap();
/// assert!(engine.rule_count() > 0);
/// ```
pub struct RuleEngine<M: PatternMatcher = RegexPatternMatcher> {
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
}

impl RuleEngine<RegexPatternMatcher> {
    /// Create a new empty rule engine with the default `RegexPatternMatcher`.
    ///
    /// The engine starts with no rules loaded. Use [`add_rule`], [`load_rules_file`],
    /// or [`load_from_dir`] to add rules, or use [`with_defaults`] to start with
    /// built-in rules.
    ///
    /// [`add_rule`]: RuleEngine::add_rule
    /// [`load_rules_file`]: RuleEngine::load_rules_file
    /// [`load_from_dir`]: RuleEngine::load_from_dir
    /// [`with_defaults`]: RuleEngine::with_defaults
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            rules_dir: None,
            matcher: Arc::new(RegexPatternMatcher::new()),
            strict_mode: true,
        }
    }

    /// Create a rule engine with default rules and default `RegexPatternMatcher`.
    ///
    /// This is the recommended way to create a rule engine for most use cases.
    /// It loads all built-in rules that detect common security patterns.
    ///
    /// # Example
    ///
    /// ```
    /// use skill_veil_core::rules::RuleEngine;
    ///
    /// let engine = RuleEngine::with_defaults().unwrap();
    /// assert!(engine.rule_count() > 0);
    /// ```
    /// # Load order contract
    ///
    /// Builtin rules MUST be loaded BEFORE runtime defaults (`rules/official/`).
    /// Non-strict mode silently skips duplicates, so inverting the order would
    /// cause the canonical embedded ruleset to be discarded whenever the dev
    /// directory `rules/official/` exists with overlapping IDs. Tests in
    /// `tests::with_defaults_loads_full_builtin_set` guard this contract.
    #[must_use = "RuleEngine::with_defaults() returns a Result that should be used"]
    pub fn with_defaults() -> Result<Self, RuleError> {
        let mut engine = Self::new();
        engine.load_builtin_rules()?;
        engine.load_runtime_default_rules()?;
        Ok(engine)
    }
}

impl<M: PatternMatcher> RuleEngine<M> {
    /// Create a new rule engine with a custom pattern matcher.
    #[must_use]
    pub fn with_matcher(matcher: Arc<M>) -> Self {
        Self {
            rules: Vec::new(),
            rules_dir: None,
            matcher,
            strict_mode: true,
        }
    }

    /// Toggle strict mode. When enabled, loading an external pack with a
    /// duplicate rule id returns `RuleError::DuplicateUserRule` instead of
    /// emitting a `tracing::warn!()` and skipping.
    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    /// Create a rule engine with default rules and a custom pattern matcher.
    /// # Load order contract
    ///
    /// Same contract as `with_defaults`: builtin rules first, runtime
    /// overrides second. The non-strict duplicate-skip means inverting the
    /// order silently discards canonical detections.
    #[must_use = "RuleEngine::with_defaults_and_matcher() returns a Result that should be used"]
    pub fn with_defaults_and_matcher(matcher: Arc<M>) -> Result<Self, RuleError> {
        let mut engine = Self::with_matcher(matcher);
        engine.load_builtin_rules()?;
        engine.load_runtime_default_rules()?;
        Ok(engine)
    }

    fn load_builtin_rules(&mut self) -> Result<(), RuleError> {
        for rule in builtin::get_builtin_rules()? {
            self.add_rule(rule)?;
        }
        Ok(())
    }

    /// Load rules from a directory.
    pub fn load_from_dir(&mut self, dir: impl AsRef<Path>) -> Result<(), RuleError> {
        let dir = dir.as_ref();
        self.rules_dir = Some(dir.to_path_buf());

        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| match e {
                Ok(entry) => Some(entry),
                Err(err) => {
                    warn!(
                        "Skipping entry while loading rule packs from {}: {err}",
                        dir.display()
                    );
                    None
                }
            })
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "yaml" || ext == "yml")
                    .unwrap_or(false)
            })
        {
            self.load_rules_file(entry.path())?;
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
    /// the embedded `builtin_rules.yaml` and the `rules/official/` packs.
    ///
    /// Callers that intentionally want the legacy "warn-and-skip" behaviour
    /// (e.g. tooling that loads many overlapping experimental packs) must
    /// opt out via `set_strict_mode(false)`.
    pub fn load_rules_file(&mut self, path: impl AsRef<Path>) -> Result<(), RuleError> {
        let content = std::fs::read_to_string(path.as_ref())?;
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
    pub fn test_rule(
        &self,
        rule_id: &str,
        content: &str,
    ) -> Result<Vec<crate::findings::Finding>, RuleError> {
        let parser = PulldownMarkdownParser::new();
        let doc = crate::analyzer::SkillDocument::parse_with_parser(
            std::path::PathBuf::from("test.md"),
            content.to_string(),
            &parser,
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

    /// Load `rules/official/` overlays from the current working directory.
    ///
    /// The runtime overlay is a *development* copy of the embedded packs at
    /// `crates/skill-veil-core/resources/official/`. When the binary runs from
    /// the repo root (CI, `cargo run`, local dev) the overlay paths happen to
    /// resolve and re-introduce IDs already loaded from the embedded packs.
    /// Strict mode would surface those overlaps as `DuplicateUserRule` and
    /// abort startup. The intent of the runtime overlay is "skip duplicates;
    /// the embedded canonical version wins" (see `with_defaults` doc-comment),
    /// so we run this stage with strict mode forced off and restore the
    /// caller's preference afterwards. Callers passing `--rules-dir` go
    /// through `load_from_dir` directly and keep whatever strict setting
    /// `set_strict_mode` last applied.
    fn load_runtime_default_rules(&mut self) -> Result<bool, RuleError> {
        let mut loaded = false;
        let prev_strict = std::mem::replace(&mut self.strict_mode, false);
        let result: Result<(), RuleError> = (|| {
            for dir in default_external_rule_dirs() {
                if dir.exists() {
                    self.load_from_dir(&dir)?;
                    loaded = true;
                }
            }
            Ok(())
        })();
        self.strict_mode = prev_strict;
        result?;
        Ok(loaded)
    }
}

impl Default for RuleEngine<RegexPatternMatcher> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
