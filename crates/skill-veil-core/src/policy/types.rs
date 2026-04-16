use crate::analyzer::{
    AgentExtensionKind, ArtifactClassification, ArtifactIdentitySource, StructuralValidity,
};
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{
    ArtifactKind, Finding, FindingSummary, OperationalContext, PackageVerdictReport,
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
    pub context: Option<OperationalContext>,
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
    skill_name: String,
    skill_path: String,
    primary_artifact_kind: ArtifactKind,
    extension_kind: AgentExtensionKind,
    classification: ArtifactClassification,
    package_id: Option<String>,
    identity_source: ArtifactIdentitySource,
    structural_validity: StructuralValidity,
    heuristic_score: u8,
    findings: Vec<Finding>,
    artifact_graph: ArtifactGraph,
    profile: Option<PolicyProfile>,
    policy: Option<PolicyFile>,
    suppression_summary: SuppressionSummary,
    policy_audit: PolicyAudit,
    /// Pre-computed verdict report from the scan pipeline.
    /// When present, serializers reuse this instead of re-deriving the verdict.
    verdict_report: Option<PackageVerdictReport>,
}

impl PolicyGenerator {
    /// The name of the skill being analyzed.
    #[must_use]
    pub fn skill_name(&self) -> &str {
        &self.skill_name
    }

    /// Path to the primary skill artifact.
    #[must_use]
    pub fn skill_path(&self) -> &str {
        &self.skill_path
    }

    /// The artifact kind of the primary entrypoint.
    #[must_use]
    pub fn primary_artifact_kind(&self) -> ArtifactKind {
        self.primary_artifact_kind
    }

    /// The extension kind (Skill, AgentInstruction, etc.).
    #[must_use]
    pub fn extension_kind(&self) -> AgentExtensionKind {
        self.extension_kind
    }

    /// The artifact classification result.
    #[must_use]
    pub fn classification(&self) -> ArtifactClassification {
        self.classification
    }

    /// Optional package identifier.
    #[must_use]
    pub fn package_id(&self) -> Option<&str> {
        self.package_id.as_deref()
    }

    /// How the artifact identity was determined.
    #[must_use]
    pub fn identity_source(&self) -> ArtifactIdentitySource {
        self.identity_source
    }

    /// Structural validity of the analyzed artifact.
    #[must_use]
    pub fn structural_validity(&self) -> StructuralValidity {
        self.structural_validity
    }

    /// Heuristic score assigned during analysis.
    #[must_use]
    pub fn heuristic_score(&self) -> u8 {
        self.heuristic_score
    }

    /// The findings produced by analysis.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The artifact dependency/capability graph.
    #[must_use]
    pub fn artifact_graph(&self) -> &ArtifactGraph {
        &self.artifact_graph
    }

    /// The active policy profile, if any.
    #[must_use]
    pub fn profile(&self) -> Option<PolicyProfile> {
        self.profile
    }

    /// The loaded policy file, if any.
    #[must_use]
    pub fn policy(&self) -> Option<&PolicyFile> {
        self.policy.as_ref()
    }

    /// Summary of suppressed findings.
    #[must_use]
    pub fn suppression_summary(&self) -> &SuppressionSummary {
        &self.suppression_summary
    }

    /// The policy audit trail.
    #[must_use]
    pub fn policy_audit(&self) -> &PolicyAudit {
        &self.policy_audit
    }

    /// Pre-computed verdict report, if available.
    #[must_use]
    pub fn verdict_report(&self) -> Option<&PackageVerdictReport> {
        self.verdict_report.as_ref()
    }

    pub fn new(
        skill_name: impl Into<String>,
        skill_path: impl Into<String>,
        findings: Vec<Finding>,
        artifact_graph: ArtifactGraph,
    ) -> Self {
        Self {
            skill_name: skill_name.into(),
            skill_path: skill_path.into(),
            primary_artifact_kind: ArtifactKind::SkillDocument,
            extension_kind: AgentExtensionKind::Skill,
            classification: ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: ArtifactIdentitySource::ExplicitName,
            structural_validity: StructuralValidity::Confirmed,
            heuristic_score: 0,
            findings,
            artifact_graph,
            profile: None,
            policy: None,
            suppression_summary: SuppressionSummary::default(),
            policy_audit: PolicyAudit::default(),
            verdict_report: None,
        }
    }

    #[must_use]
    pub fn with_primary_artifact_kind(mut self, artifact_kind: ArtifactKind) -> Self {
        self.primary_artifact_kind = artifact_kind;
        self
    }

    #[must_use]
    pub fn with_profile(mut self, profile: PolicyProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    #[must_use]
    pub fn with_extension_kind(mut self, extension_kind: AgentExtensionKind) -> Self {
        self.extension_kind = extension_kind;
        self
    }

    #[must_use]
    pub fn with_artifact_classification(
        mut self,
        classification: ArtifactClassification,
        package_id: Option<String>,
        identity_source: ArtifactIdentitySource,
        structural_validity: StructuralValidity,
        heuristic_score: u8,
    ) -> Self {
        self.classification = classification;
        self.package_id = package_id;
        self.identity_source = identity_source;
        self.structural_validity = structural_validity;
        self.heuristic_score = heuristic_score;
        self
    }

    #[must_use]
    pub fn with_policy(mut self, policy: PolicyFile) -> Self {
        self.policy = Some(policy);
        self
    }

    #[must_use]
    pub fn with_suppression_summary(mut self, suppression_summary: SuppressionSummary) -> Self {
        self.suppression_summary = suppression_summary;
        self
    }

    #[must_use]
    pub fn with_policy_audit(mut self, policy_audit: PolicyAudit) -> Self {
        self.policy_audit = policy_audit;
        self
    }

    #[must_use]
    pub fn with_verdict_report(mut self, verdict_report: PackageVerdictReport) -> Self {
        self.verdict_report = Some(verdict_report);
        self
    }

    pub fn generate_shield_md(&self) -> String {
        super::serializers::generate_shield_md(self)
    }

    pub fn generate_json(&self) -> JsonReport {
        super::serializers::generate_json(self)
    }

    pub fn generate_sarif(&self) -> SarifReport {
        super::serializers::generate_sarif(self)
    }
}

pub(crate) fn default_policy_schema_version() -> String {
    super::POLICY_SCHEMA_VERSION.to_string()
}

pub(crate) fn empty_finding_summary() -> FindingSummary {
    FindingSummary::from_findings(&[])
}
