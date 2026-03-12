use crate::analyzer::{
    AgentExtensionKind, ArtifactClassification, ArtifactIdentitySource, StructuralValidity,
};
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{
    Finding, FindingSummary, OperationalContext as PolicyContext, PackageVerdictReport,
    RecommendedAction, Severity, ThreatCategory, Verdict,
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
    pub context: PolicyContext,
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
    pub context: Option<PolicyContext>,
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
    pub matched_contexts: Vec<PolicyContext>,
}

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
    pub context: PolicyContext,
    pub action: RecommendedAction,
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuppressionSummary {
    pub baseline_suppressed: usize,
    pub waiver_suppressed: usize,
    pub active_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    pub entries: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverFile {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    pub waivers: Vec<WaiverEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<PolicyContext>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub new_findings: Vec<DiffEntry>,
    pub resolved_findings: Vec<DiffEntry>,
    pub waived_findings: Vec<DiffEntry>,
    pub baselined_findings: Vec<DiffEntry>,
    pub unchanged_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub fingerprint: String,
    pub rule_id: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    pub skill_name: String,
    pub skill_path: String,
    pub extension_kind: AgentExtensionKind,
    pub classification: ArtifactClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,
    pub identity_source: ArtifactIdentitySource,
    pub structural_validity: StructuralValidity,
    pub heuristic_score: u8,
    pub timestamp: DateTime<Utc>,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub primary_findings: Vec<Finding>,
    #[serde(default)]
    pub supporting_findings: Vec<Finding>,
    pub summary: FindingSummary,
    #[serde(default = "empty_finding_summary")]
    pub primary_summary: FindingSummary,
    #[serde(default = "empty_finding_summary")]
    pub supporting_summary: FindingSummary,
    pub verdict: Verdict,
    pub verdict_report: PackageVerdictReport,
    pub artifact_graph: ArtifactGraph,
    pub policies: Vec<ShieldPolicy>,
    pub context_policies: Vec<ContextPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<PolicyProfile>,
    #[serde(default)]
    pub suppression_summary: SuppressionSummary,
    #[serde(default)]
    pub policy_audit: PolicyAudit,
}

pub struct PolicyGenerator {
    pub(crate) skill_name: String,
    pub(crate) skill_path: String,
    pub(crate) extension_kind: AgentExtensionKind,
    pub(crate) classification: ArtifactClassification,
    pub(crate) package_id: Option<String>,
    pub(crate) identity_source: ArtifactIdentitySource,
    pub(crate) structural_validity: StructuralValidity,
    pub(crate) heuristic_score: u8,
    pub(crate) findings: Vec<Finding>,
    pub(crate) artifact_graph: ArtifactGraph,
    pub(crate) profile: Option<PolicyProfile>,
    pub(crate) policy: Option<PolicyFile>,
    pub(crate) suppression_summary: SuppressionSummary,
    pub(crate) policy_audit: PolicyAudit,
}

pub(crate) fn default_policy_schema_version() -> String {
    crate::policy::POLICY_SCHEMA_VERSION.to_string()
}

pub(crate) fn empty_finding_summary() -> FindingSummary {
    FindingSummary::from_findings(&[])
}
