use crate::findings::{
    FindingSummary, OperationalContext, RecommendedAction, Severity, ThreatCategory,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProfile {
    Personal,
    Team,
    Enterprise,
    Research,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyProfiles {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personal: Option<ConfiguredProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<ConfiguredProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise: Option<ConfiguredProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub research: Option<ConfiguredProfile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfiguredProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_on: Option<Severity>,
    #[serde(default)]
    pub context_actions: Vec<ContextActionOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextActionOverride {
    pub context: OperationalContext,
    pub action: RecommendedAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<OperationalContext>,
    pub action: RecommendedAction,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedPolicyOverride {
    pub finding_fingerprint: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_id: Option<String>,
    pub original_action: RecommendedAction,
    pub effective_action: RecommendedAction,
    pub specificity: usize,
    pub reason: String,
    #[serde(default)]
    pub matched_contexts: Vec<OperationalContext>,
}

pub const POLICY_AUDIT_PRECEDENCE: [&str; 4] = [
    "inline_suppressions",
    "waivers",
    "baseline",
    "policy_overrides",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAudit {
    pub precedence_order: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_fail_on: Option<Severity>,
    #[serde(default)]
    pub applied_overrides: Vec<AppliedPolicyOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub profiles: PolicyProfiles,
    #[serde(default)]
    pub overrides: Vec<PolicyOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPolicy {
    pub context: OperationalContext,
    pub action: RecommendedAction,
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuppressionSummary {
    pub baseline_suppressed: usize,
    pub waiver_suppressed: usize,
    #[serde(default)]
    pub inline_suppressed: usize,
    /// Count of findings with actionable recommendations (Block or RequireApproval).
    /// Excludes Log-level findings which are informational only.
    pub active_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub new_findings: Vec<DiffEntry>,
    pub resolved_findings: Vec<DiffEntry>,
    pub waived_findings: Vec<DiffEntry>,
    pub baselined_findings: Vec<DiffEntry>,
    /// Count of findings present in both the current and previous scan that remain
    /// active (not waived or baselined). This is purely informational; the total
    /// `new + resolved + waived + baselined + unchanged` may not equal the union of
    /// all findings across both scans.
    pub unchanged_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub category: ThreatCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldPolicy {
    pub id: String,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub confidence: f32,
    pub action: RecommendedAction,
    pub recommendation_agent: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

pub(crate) fn default_policy_schema_version() -> String {
    super::POLICY_SCHEMA_VERSION.to_string()
}

pub(crate) fn empty_finding_summary() -> FindingSummary {
    FindingSummary::from_findings(&[])
}
