use crate::findings::{ArtifactKind, RecommendedAction, Severity, ThreatCategory};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Versioned schema string for external rule packs.
pub const RULE_PACK_SCHEMA_VERSION: &str = "skill-veil.dev/rules/v1alpha1";

/// Default confidence score for rules (0.0 - 1.0)
pub const DEFAULT_RULE_CONFIDENCE: f32 = 0.9;

#[derive(Error, Debug)]
pub enum RuleError {
    #[error("Failed to load rules: {0}")]
    LoadError(String),
    #[error("Invalid rule configuration: {0}")]
    InvalidRule(String),
    #[error("Regex compilation failed: {0}")]
    RegexError(#[from] regex::Error),
    #[error("YAML parsing error: {0}")]
    YamlError(#[from] serde_yaml::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldHint {
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub category: ThreatCategory,
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(rename = "when")]
    pub condition: RuleCondition,
    pub action: RecommendedAction,
    pub reason: String,
    #[serde(default)]
    pub shield: Option<ShieldHint>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePackKind {
    Official,
    Community,
    IocFeed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulePackMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: Option<RulePackKind>,
    #[serde(default)]
    pub compatibility: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePackFile {
    #[serde(default = "default_rule_pack_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub metadata: RulePackMetadata,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocFeedFile {
    #[serde(default = "default_rule_pack_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub metadata: RulePackMetadata,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub filenames: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
}

fn default_confidence() -> f32 {
    DEFAULT_RULE_CONFIDENCE
}

fn default_enabled() -> bool {
    true
}

fn default_rule_pack_schema_version() -> String {
    RULE_PACK_SCHEMA_VERSION.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCondition {
    Regex { pattern: String },
    SectionContains { section: String, values: Vec<String> },
    SectionRegex { section: String, pattern: String },
    ArtifactKind { kinds: Vec<ArtifactKind> },
    #[cfg(feature = "yara")]
    Yara { rule: String },
    Any(Vec<RuleCondition>),
    All(Vec<RuleCondition>),
    CodeLanguage { languages: Vec<String> },
}
