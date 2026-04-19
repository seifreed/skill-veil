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
    #[must_use = "RuleEngine::with_defaults() returns a Result that should be used"]
    pub fn with_defaults() -> Result<Self, RuleError> {
        let mut engine = Self::new();
        if !engine.load_runtime_default_rules()? {
            engine.load_builtin_rules()?;
        }
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
        }
    }

    /// Create a rule engine with default rules and a custom pattern matcher.
    #[must_use = "RuleEngine::with_defaults_and_matcher() returns a Result that should be used"]
    pub fn with_defaults_and_matcher(matcher: Arc<M>) -> Result<Self, RuleError> {
        let mut engine = Self::with_matcher(matcher);
        if !engine.load_runtime_default_rules()? {
            engine.load_builtin_rules()?;
        }
        Ok(engine)
    }

    fn load_builtin_rules(&mut self) -> Result<(), RuleError> {
        let builtin_rules = builtin::get_builtin_rules()?;
        for rule in builtin_rules {
            self.rules.push(CompiledRule::compile(rule)?);
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
    /// Rules whose ID already exists in the engine are silently skipped,
    /// giving builtins (loaded first) priority over external packs.
    pub fn load_rules_file(&mut self, path: impl AsRef<Path>) -> Result<(), RuleError> {
        let content = std::fs::read_to_string(path.as_ref())?;
        for rule in parse_rules_file(&content)? {
            let compiled = CompiledRule::compile(rule)?;
            if self
                .rules
                .iter()
                .any(|existing| existing.rule.id == compiled.rule.id)
            {
                warn!(
                    rule_id = %compiled.rule.id,
                    path = %path.as_ref().display(),
                    "skipping duplicate rule ID (builtin takes priority)"
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

    fn load_runtime_default_rules(&mut self) -> Result<bool, RuleError> {
        let mut loaded = false;
        for dir in default_external_rule_dirs() {
            if dir.exists() {
                self.load_from_dir(&dir)?;
                loaded = true;
            }
        }
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
