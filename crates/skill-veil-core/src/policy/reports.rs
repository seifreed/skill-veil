use super::empty_finding_summary;
use super::sarif::SarifReport;
use super::types::{
    ContextPolicy, PolicyAudit, PolicyFile, PolicyProfile, ShieldPolicy, SuppressionSummary,
};
use crate::analyzer::{
    AgentExtensionKind, ArtifactClassification, ArtifactIdentitySource, StructuralValidity,
};
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{ArtifactKind, Finding, FindingSummary, PackageVerdictReport, Verdict};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    pub fn with_classification(mut self, classification: ArtifactClassification) -> Self {
        self.classification = classification;
        self
    }

    #[must_use]
    pub fn with_package_id(mut self, package_id: Option<String>) -> Self {
        self.package_id = package_id;
        self
    }

    #[must_use]
    pub fn with_identity_source(mut self, identity_source: ArtifactIdentitySource) -> Self {
        self.identity_source = identity_source;
        self
    }

    #[must_use]
    pub fn with_structural_validity(mut self, structural_validity: StructuralValidity) -> Self {
        self.structural_validity = structural_validity;
        self
    }

    #[must_use]
    pub fn with_heuristic_score(mut self, heuristic_score: u8) -> Self {
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
