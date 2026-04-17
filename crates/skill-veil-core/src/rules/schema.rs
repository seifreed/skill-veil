use super::condition::RuleCondition;
use crate::findings::{RecommendedAction, Severity, ThreatCategory};
use serde::{Deserialize, Serialize};

/// Shield hint for policy generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldHint {
    /// Scope for the shield policy
    pub scope: String,
}

/// A security detection rule
///
/// Rules define security patterns to detect in skill documents. Each rule
/// specifies a condition to match, the threat category, severity level, and
/// recommended action when matched.
///
/// Rules are typically defined in YAML format and loaded by the [`super::RuleEngine`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier
    pub id: String,
    /// Threat category
    pub category: ThreatCategory,
    /// Severity level
    pub severity: Severity,
    /// Confidence score (0.0 - 1.0)
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// Condition that triggers the rule
    #[serde(rename = "when")]
    pub condition: RuleCondition,
    /// Recommended action
    pub action: RecommendedAction,
    /// Human-readable reason
    pub reason: String,
    /// Shield policy hint
    #[serde(default)]
    pub shield: Option<ShieldHint>,
    /// Whether the rule is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Tags for filtering
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
    pub schema_version: String,
    #[serde(default)]
    pub metadata: RulePackMetadata,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocFeedFile {
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
    super::DEFAULT_RULE_CONFIDENCE
}

fn default_enabled() -> bool {
    true
}
