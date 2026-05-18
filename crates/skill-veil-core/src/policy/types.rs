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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ConfiguredProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_on: Option<Severity>,
    #[serde(default)]
    pub context_actions: Vec<ContextActionOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextActionOverride {
    pub context: OperationalContext,
    pub action: RecommendedAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct PolicyAudit {
    pub precedence_order: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_fail_on: Option<Severity>,
    #[serde(default)]
    pub applied_overrides: Vec<AppliedPolicyOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub profiles: PolicyProfiles,
    #[serde(default)]
    pub overrides: Vec<PolicyOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPolicy {
    pub context: OperationalContext,
    pub action: RecommendedAction,
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionSummary {
    pub baseline_suppressed: usize,
    pub waiver_suppressed: usize,
    #[serde(default)]
    pub inline_suppressed: usize,
    /// Findings whose confidence was adjusted by the analyst-feedback
    /// overlay. Additive: old on-disk reports omit it.
    #[serde(default)]
    pub disposition_adjusted: usize,
    /// Findings demoted to `Log` by a learned allowlist promotion.
    #[serde(default)]
    pub disposition_allowlisted: usize,
    /// Count of findings with actionable recommendations (Block or RequireApproval).
    /// Excludes Log-level findings which are informational only.
    pub active_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct DiffEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub category: ThreatCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[cfg(test)]
mod deny_unknown_fields_tests {
    use super::*;

    /// # Contract
    ///
    /// `PolicyOverride` MUST reject unknown fields so that typos like
    /// `artifact_pat` instead of `artifact_path` produce a clear error
    /// rather than silently defaulting `artifact_path` to `None`, which
    /// would make the override match ALL artifacts (a policy bypass).
    #[test]
    fn policy_override_rejects_unknown_fields() {
        let yaml = r#"
action: log
reason: approved
artifact_pat: "src/main.rs"
"#;
        let result: Result<PolicyOverride, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "PolicyOverride MUST reject unknown field 'artifact_pat'; \
             pre-fix, this was silently accepted and artifact_path defaulted to None"
        );
    }

    /// # Contract
    ///
    /// `PolicyFile` MUST reject unknown top-level fields so that typos like
    /// `overides` instead of `overrides` are caught at load time.
    #[test]
    fn policy_file_rejects_unknown_fields() {
        let yaml = "schema_version: \"1\"\noverides: []\n";
        let result: Result<PolicyFile, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "PolicyFile MUST reject unknown field 'overides'; \
             pre-fix, this was silently accepted and overrides defaulted to empty"
        );
    }

    /// # Contract
    ///
    /// `ShieldPolicy` MUST reject unknown fields so that typos in security
    /// policy descriptors are caught at load time.
    #[test]
    fn shield_policy_rejects_unknown_fields() {
        let yaml = r#"
id: shield-1
category: RemoteExec
severity: High
confidence: 0.9
action: Block
recommendation_agent: []
revoked: false
revokd: true
"#;
        let result: Result<ShieldPolicy, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "ShieldPolicy MUST reject unknown field 'revokd'; \
             pre-fix, this was silently accepted and revoked kept its intended value"
        );
    }
}
