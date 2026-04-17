use crate::findings::ArtifactKind;
use serde::{Deserialize, Serialize};

/// Condition for rule matching
///
/// Conditions define when a rule should trigger. Multiple condition types
/// are supported, and conditions can be combined using `Any` or `All`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCondition {
    /// Match a regex pattern
    Regex { pattern: String },
    /// Match content in a specific section
    SectionContains {
        section: String,
        values: Vec<String>,
    },
    /// Match a regex within a specific section
    SectionRegex { section: String, pattern: String },
    /// Restrict the rule to a specific artifact class
    ArtifactKind { kinds: Vec<ArtifactKind> },
    /// Match a YARA rule (requires yara feature)
    #[cfg(feature = "yara")]
    Yara { rule: String },
    /// Any of the conditions must match
    Any(Vec<RuleCondition>),
    /// All conditions must match
    All(Vec<RuleCondition>),
    /// Match specific code block languages
    CodeLanguage { languages: Vec<String> },
}
