//! Policy generation for SHIELD.md and other output formats
//!
//! Generates security policies based on analysis findings. Supports multiple
//! output formats for different use cases:
//!
//! - **SHIELD.md**: Human-readable markdown policy document
//! - **JSON**: Machine-readable report for CI integration
//! - **SARIF**: GitHub Code Scanning compatible format
//!
//! # Example
//!
//! ```
//! use skill_veil_core::policy::PolicyGenerator;
//! use skill_veil_core::artifact_graph::ArtifactGraph;
//! use skill_veil_core::findings::{Finding, ThreatCategory, Severity, MatchTarget};
//!
//! let findings = vec![
//!     Finding::builder("RULE_001", ThreatCategory::RemoteExec)
//!         .severity(Severity::High)
//!         .matched_on(MatchTarget::Document)
//!         .match_value("curl | bash")
//!         .reason("Remote code execution detected")
//!         .build()
//! ];
//!
//! let generator = PolicyGenerator::new("my-skill", "skill.md", findings, ArtifactGraph::new());
//!
//! // Generate different formats
//! let shield_md = generator.generate_shield_md();
//! let json_report = generator.generate_json();
//! let sarif_report = generator.generate_sarif();
//! ```

use crate::analyzer::{
    AgentExtensionKind, ArtifactClassification, ArtifactIdentitySource, StructuralValidity,
};
use crate::artifact_graph::{ArtifactCapability, ArtifactGraph};
use crate::findings::{
    default_operational_contexts, derive_package_verdict, ArtifactKind, Finding, FindingSummary,
    OperationalContext as PolicyContext, PackageVerdictReport, RecommendedAction, Severity,
    ThreatCategory, Verdict,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Default number of days until a shield policy expires
const POLICY_EXPIRY_DAYS: i64 = 365;
/// Version string for persisted policy-related schemas.
pub const POLICY_SCHEMA_VERSION: &str = "skill-veil.dev/v1alpha1";
/// Human-readable precedence order applied by the policy engine.
pub const POLICY_PRECEDENCE_ORDER: [&str; 5] = [
    "waiver",
    "baseline",
    "override",
    "profile_context",
    "graph_escalation",
];

/// Predefined policy profile for CI enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProfile {
    Personal,
    Team,
    Enterprise,
    Research,
}

impl PolicyProfile {
    #[must_use]
    pub fn default_fail_on(self) -> Option<Severity> {
        match self {
            Self::Personal => Some(Severity::Critical),
            Self::Team => Some(Severity::High),
            Self::Enterprise => Some(Severity::Medium),
            Self::Research => None,
        }
    }

    #[must_use]
    pub fn default_action_for_context(self, context: PolicyContext) -> RecommendedAction {
        match self {
            Self::Personal => RecommendedAction::RequireApproval,
            Self::Team => match context {
                PolicyContext::Secrets => RecommendedAction::Block,
                _ => RecommendedAction::RequireApproval,
            },
            Self::Enterprise => match context {
                PolicyContext::Install | PolicyContext::Secrets | PolicyContext::ExternalComms => {
                    RecommendedAction::Block
                }
                PolicyContext::Network | PolicyContext::CodeModification => {
                    RecommendedAction::RequireApproval
                }
            },
            Self::Research => match context {
                PolicyContext::Secrets | PolicyContext::ExternalComms => {
                    RecommendedAction::RequireApproval
                }
                _ => RecommendedAction::Log,
            },
        }
    }
}

/// Versioned policy configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub profiles: PolicyProfiles,
    #[serde(default)]
    pub overrides: Vec<PolicyOverride>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            schema_version: default_policy_schema_version(),
            profiles: PolicyProfiles::default(),
            overrides: Vec::new(),
        }
    }
}

impl PolicyFile {
    #[must_use]
    pub fn profile_config(&self, profile: PolicyProfile) -> Option<&ConfiguredProfile> {
        match profile {
            PolicyProfile::Personal => self.profiles.personal.as_ref(),
            PolicyProfile::Team => self.profiles.team.as_ref(),
            PolicyProfile::Enterprise => self.profiles.enterprise.as_ref(),
            PolicyProfile::Research => self.profiles.research.as_ref(),
        }
    }

    #[must_use]
    pub fn resolve_fail_on(&self, profile: PolicyProfile) -> Option<Severity> {
        self.profile_config(profile)
            .and_then(|config| config.fail_on)
            .or_else(|| profile.default_fail_on())
    }

    #[must_use]
    pub fn resolve_context_action(
        &self,
        profile: PolicyProfile,
        context: PolicyContext,
    ) -> RecommendedAction {
        self.profile_config(profile)
            .and_then(|config| {
                config
                    .context_actions
                    .iter()
                    .find(|entry| entry.context == context)
                    .map(|entry| entry.action)
            })
            .unwrap_or_else(|| profile.default_action_for_context(context))
    }
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

impl Default for PolicyAudit {
    fn default() -> Self {
        Self {
            precedence_order: POLICY_PRECEDENCE_ORDER
                .iter()
                .map(ToString::to_string)
                .collect(),
            effective_fail_on: None,
            applied_overrides: Vec::new(),
        }
    }
}

/// Aggregated policy decision for one operational context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPolicy {
    pub context: PolicyContext,
    pub action: RecommendedAction,
    pub rationale: Vec<String>,
}

/// Summary of findings suppressed by baseline or waivers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuppressionSummary {
    pub baseline_suppressed: usize,
    pub waiver_suppressed: usize,
    pub active_findings: usize,
}

/// Persisted baseline of accepted findings.
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

/// Persisted waiver definitions.
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

/// Diff between two report snapshots.
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

/// A SHIELD policy entry
///
/// Represents a security policy recommendation derived from scan findings.
/// Policies are aggregated by rule ID and contain the highest severity/confidence
/// from matching findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldPolicy {
    /// Unique policy identifier
    pub id: String,
    /// Threat category
    pub category: ThreatCategory,
    /// Severity level
    pub severity: Severity,
    /// Confidence score
    pub confidence: f32,
    /// Recommended action
    pub action: RecommendedAction,
    /// Agent-specific recommendations
    pub recommendation_agent: Vec<String>,
    /// Policy expiration date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the policy is revoked
    pub revoked: bool,
}

/// SARIF 2.1.0 output format for GitHub Code Scanning
///
/// The Static Analysis Results Interchange Format (SARIF) is a standard
/// format for static analysis tool output. This format is compatible with
/// GitHub Code Scanning and other SARIF-aware tools.
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

/// JSON output format for CI integration
///
/// A comprehensive report containing all scan results, suitable for
/// programmatic processing in CI/CD pipelines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    /// Skill name
    pub skill_name: String,
    /// Skill path
    pub skill_path: String,
    /// Unified agent-extension kind for the scanned target
    pub extension_kind: AgentExtensionKind,
    /// Confidence-oriented artifact classification
    pub classification: ArtifactClassification,
    /// Stable package identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,
    /// How the artifact identity was recognized
    pub identity_source: ArtifactIdentitySource,
    /// Structural validity of the artifact as an extension candidate
    pub structural_validity: StructuralValidity,
    /// Numeric agent-likeness / structural confidence score for the entry artifact.
    pub heuristic_score: u8,
    /// Analysis timestamp
    pub timestamp: DateTime<Utc>,
    /// All findings
    pub findings: Vec<Finding>,
    /// Findings observed directly on the primary artifact
    #[serde(default)]
    pub primary_findings: Vec<Finding>,
    /// Findings observed on supporting artifacts such as scripts and manifests
    #[serde(default)]
    pub supporting_findings: Vec<Finding>,
    /// Summary statistics
    pub summary: FindingSummary,
    /// Summary for the primary artifact only
    #[serde(default = "empty_finding_summary")]
    pub primary_summary: FindingSummary,
    /// Summary for supporting artifacts only
    #[serde(default = "empty_finding_summary")]
    pub supporting_summary: FindingSummary,
    /// Final package-level verdict
    pub verdict: Verdict,
    /// Structured reasons and grouped causes behind the verdict
    pub verdict_report: PackageVerdictReport,
    /// Graph of related artifacts discovered during analysis
    pub artifact_graph: ArtifactGraph,
    /// Generated policies
    pub policies: Vec<ShieldPolicy>,
    /// Context-level enforcement decisions derived from findings and capabilities
    pub context_policies: Vec<ContextPolicy>,
    /// Policy profile used for enforcement
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<PolicyProfile>,
    /// Suppression counts applied before policy generation
    #[serde(default)]
    pub suppression_summary: SuppressionSummary,
    /// Auditable policy precedence and override information
    #[serde(default)]
    pub policy_audit: PolicyAudit,
}

/// Policy generator for creating output formats
///
/// Takes scan findings and generates formatted reports in various formats.
/// The generator aggregates findings by rule ID to create unified policies.
pub struct PolicyGenerator {
    skill_name: String,
    skill_path: String,
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
}

fn empty_finding_summary() -> FindingSummary {
    FindingSummary::from_findings(&[])
}

impl PolicyGenerator {
    /// Create a new policy generator
    ///
    /// # Arguments
    /// * `skill_name` - Name of the skill being analyzed
    /// * `skill_path` - Path to the skill file
    /// * `findings` - Findings from the scan
    pub fn new(
        skill_name: impl Into<String>,
        skill_path: impl Into<String>,
        findings: Vec<Finding>,
        artifact_graph: ArtifactGraph,
    ) -> Self {
        Self {
            skill_name: skill_name.into(),
            skill_path: skill_path.into(),
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
        }
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

    /// Generate SHIELD.md content
    ///
    /// Creates a human-readable markdown document containing security
    /// policies with YAML-formatted policy entries.
    pub fn generate_shield_md(&self) -> String {
        let mut output = String::new();
        output.push_str("# SHIELD Policy\n\n");
        output.push_str(&format!("Generated for: `{}`\n\n", self.skill_name));
        output.push_str("---\n\n");

        let policies = self.generate_policies();
        let context_policies = self.generate_context_policies();

        for policy in &policies {
            output.push_str(&format!("## {}\n\n", policy.id));
            output.push_str("```yaml\n");
            output.push_str(&format!("id: {}\n", policy.id));
            output.push_str(&format!("category: {}\n", policy.category));
            output.push_str(&format!("severity: {}\n", policy.severity));
            output.push_str(&format!("confidence: {:.2}\n", policy.confidence));
            output.push_str(&format!("action: {}\n", policy.action));
            output.push_str("recommendation_agent:\n");
            for rec in &policy.recommendation_agent {
                output.push_str(&format!("  - {}\n", rec));
            }
            if let Some(expires) = &policy.expires_at {
                output.push_str(&format!("expires_at: {}\n", expires.format("%Y-%m-%d")));
            }
            output.push_str(&format!("revoked: {}\n", policy.revoked));
            output.push_str("```\n\n");
        }

        if !context_policies.is_empty() {
            output.push_str("## Context Policies\n\n");
            for policy in &context_policies {
                output.push_str(&format!(
                    "- context: {}\n  action: {}\n",
                    context_label(policy.context),
                    policy.action
                ));
                for rationale in &policy.rationale {
                    output.push_str(&format!("  rationale: {}\n", rationale));
                }
                output.push('\n');
            }
        }

        output.push_str("## Policy Precedence\n\n");
        for stage in &self.policy_audit.precedence_order {
            output.push_str(&format!("- {}\n", stage));
        }
        output.push('\n');

        if !self.policy_audit.applied_overrides.is_empty() {
            output.push_str("## Applied Overrides\n\n");
            for applied in &self.policy_audit.applied_overrides {
                output.push_str(&format!(
                    "- {}: {} -> {} ({})\n",
                    applied.rule_id, applied.original_action, applied.effective_action, applied.reason
                ));
            }
            output.push('\n');
        }

        output
    }

    /// Generate JSON report
    ///
    /// Creates a structured JSON report with all findings, summary statistics,
    /// and generated policies. Suitable for CI/CD integration.
    pub fn generate_json(&self) -> JsonReport {
        let summary = FindingSummary::from_findings_and_graph(&self.findings, &self.artifact_graph);
        let primary_findings = self
            .findings
            .iter()
            .filter(|finding| {
                finding.artifact_path.as_deref().is_none_or(|artifact_path| {
                    artifact_path == self.skill_path
                }) && matches!(
                    finding.artifact_kind,
                    ArtifactKind::SkillDocument
                        | ArtifactKind::AgentInstruction
                        | ArtifactKind::PromptPackDocument
                        | ArtifactKind::McpServerManifest
                        | ArtifactKind::PackageManifest
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let supporting_findings = self
            .findings
            .iter()
            .filter(|finding| {
                !(finding.artifact_path.as_deref().is_none_or(|artifact_path| {
                    artifact_path == self.skill_path
                }) && matches!(
                    finding.artifact_kind,
                    ArtifactKind::SkillDocument
                        | ArtifactKind::AgentInstruction
                        | ArtifactKind::PromptPackDocument
                        | ArtifactKind::McpServerManifest
                        | ArtifactKind::PackageManifest
                ))
            })
            .cloned()
            .collect::<Vec<_>>();
        let primary_summary = FindingSummary::from_findings(&primary_findings);
        let supporting_summary = FindingSummary::from_findings(&supporting_findings);
        let verdict_report =
            derive_package_verdict(&self.findings, &primary_summary, &supporting_summary, &summary);
        let policies = self.generate_policies();
        let context_policies = self.generate_context_policies();

        JsonReport {
            skill_name: self.skill_name.clone(),
            skill_path: self.skill_path.clone(),
            extension_kind: self.extension_kind,
            classification: self.classification,
            package_id: self.package_id.clone(),
            identity_source: self.identity_source,
            structural_validity: self.structural_validity,
            heuristic_score: self.heuristic_score,
            timestamp: Utc::now(),
            findings: self.findings.clone(),
            primary_findings,
            supporting_findings,
            summary,
            primary_summary,
            supporting_summary,
            verdict: verdict_report.verdict,
            verdict_report,
            artifact_graph: self.artifact_graph.clone(),
            policies,
            context_policies,
            profile: self.profile,
            suppression_summary: self.suppression_summary.clone(),
            policy_audit: self.policy_audit.clone(),
        }
    }

    /// Generate SARIF report for GitHub Code Scanning
    ///
    /// Creates a SARIF 2.1.0 formatted report compatible with GitHub Code
    /// Scanning and other SARIF-aware security tools.
    pub fn generate_sarif(&self) -> SarifReport {
        // Collect unique rules
        let mut rules_map: HashMap<String, &Finding> = HashMap::new();
        for finding in &self.findings {
            rules_map.entry(finding.rule_id.clone()).or_insert(finding);
        }

        let rules: Vec<SarifRule> = rules_map
            .iter()
            .map(|(id, finding)| SarifRule {
                id: id.clone(),
                name: id.clone(),
                short_description: SarifMessage {
                    text: finding.reason.clone(),
                },
                full_description: SarifMessage {
                    text: format!("{} (Category: {})", finding.reason, finding.category),
                },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(finding.severity),
                },
            })
            .collect();
        let summary = FindingSummary::from_findings_and_graph(&self.findings, &self.artifact_graph);
        let mut rules = rules;
        if !summary.action_triggers.is_empty() {
            rules.push(SarifRule {
                id: "SKILL_VEIL_ACTION_TRIGGER".to_string(),
                name: "SKILL_VEIL_ACTION_TRIGGER".to_string(),
                short_description: SarifMessage {
                    text: "Contextual policy escalation".to_string(),
                },
                full_description: SarifMessage {
                    text: "Explains why contextual artifact capabilities escalated the recommended action".to_string(),
                },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(match summary.recommended_action {
                        RecommendedAction::Block => Severity::High,
                        RecommendedAction::RequireApproval => Severity::Medium,
                        RecommendedAction::Log => Severity::Low,
                    }),
                },
            });
        }
        rules.push(SarifRule {
            id: "SKILL_VEIL_PACKAGE_VERDICT".to_string(),
            name: "SKILL_VEIL_PACKAGE_VERDICT".to_string(),
            short_description: SarifMessage {
                text: "Final package verdict".to_string(),
            },
            full_description: SarifMessage {
                text: "Explains the final benign/suspicious/malicious package judgment".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: severity_to_sarif_level(match self.generate_json().verdict {
                    Verdict::Malicious => Severity::High,
                    Verdict::Suspicious => Severity::Medium,
                    Verdict::Benign => Severity::Low,
                }),
            },
        });

        let report = self.generate_json();
        let mut results: Vec<SarifResult> = self
            .findings
            .iter()
            .map(|finding| SarifResult {
                rule_id: finding.rule_id.clone(),
                level: severity_to_sarif_level(finding.severity),
                message: SarifMessage {
                    text: format!("{}: {}", finding.reason, finding.match_value),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: finding
                                .artifact_path
                                .clone()
                                .unwrap_or_else(|| self.skill_path.clone()),
                        },
                        region: finding
                            .line_number
                            .map(|line| SarifRegion { start_line: line }),
                    },
                }],
                properties: Some(serde_json::json!({
                    "artifact_kind": finding.artifact_kind,
                    "artifact_scope": finding.artifact_scope,
                    "signal_class": finding.signal_class,
                    "evidence_kind": finding.evidence_kind,
                    "recommended_action": finding.recommended_action,
                    "package_verdict": report.verdict,
                })),
            })
            .collect();
        results.extend(summary.action_triggers.iter().map(|trigger| SarifResult {
            rule_id: "SKILL_VEIL_ACTION_TRIGGER".to_string(),
            level: severity_to_sarif_level(match trigger.action {
                RecommendedAction::Block => Severity::High,
                RecommendedAction::RequireApproval => Severity::Medium,
                RecommendedAction::Log => Severity::Low,
            }),
            message: SarifMessage {
                text: trigger.rationale.clone(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: self.skill_path.clone(),
                    },
                    region: None,
                },
            }],
            properties: Some(serde_json::json!({
                "recommended_action": trigger.action,
                "trigger_factor": trigger.factor,
                "package_verdict": report.verdict,
            })),
        }));
        results.push(SarifResult {
            rule_id: "SKILL_VEIL_PACKAGE_VERDICT".to_string(),
            level: severity_to_sarif_level(match report.verdict {
                Verdict::Malicious => Severity::High,
                Verdict::Suspicious => Severity::Medium,
                Verdict::Benign => Severity::Low,
            }),
            message: SarifMessage {
                text: format!("Final package verdict: {}", report.verdict),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: self.skill_path.clone(),
                    },
                    region: None,
                },
            }],
            properties: Some(serde_json::json!({
                "verdict": report.verdict,
                "verdict_reasons": report.verdict_report.verdict_reasons,
                "root_cause_groups": report.verdict_report.root_cause_groups,
                "top_risk_drivers": report.verdict_report.top_risk_drivers,
                "heuristic_score": report.heuristic_score,
                "artifact_scope": "package",
            })),
        });

        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "skill-veil".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/seifreed/skill-veil".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    /// Generate shield policies from findings
    fn generate_policies(&self) -> Vec<ShieldPolicy> {
        let summary = FindingSummary::from_findings_and_graph(&self.findings, &self.artifact_graph);
        let mut policy_map: HashMap<String, ShieldPolicy> = HashMap::new();

        for finding in &self.findings {
            let policy_id = format!("{}-{}", finding.rule_id.to_lowercase(), self.skill_name);

            let recommendation = format!(
                "{}: skill name equals \"{}\"",
                finding.severity.action_str(),
                self.skill_name
            );

            policy_map
                .entry(finding.rule_id.clone())
                .and_modify(|p| {
                    if !p.recommendation_agent.contains(&recommendation) {
                        p.recommendation_agent.push(recommendation.clone());
                    }
                    // Keep highest severity
                    if finding.severity > p.severity {
                        p.severity = finding.severity;
                    }
                    // Keep highest confidence
                    if finding.confidence > p.confidence {
                        p.confidence = finding.confidence;
                    }
                    // Keep strongest recommended action
                    p.action = RecommendedAction::max(p.action, finding.recommended_action);
                })
                .or_insert(ShieldPolicy {
                    id: policy_id,
                    category: finding.category,
                    severity: finding.severity,
                    confidence: finding.confidence,
                    action: finding.recommended_action,
                    recommendation_agent: vec![recommendation],
                    expires_at: Some(Utc::now() + chrono::Duration::days(POLICY_EXPIRY_DAYS)),
                    revoked: false,
                });
        }

        let mut policies: Vec<_> = policy_map
            .into_values()
            .map(|mut policy| {
                policy.action = RecommendedAction::max(policy.action, summary.recommended_action);
                policy
            })
            .collect();
        policies.sort_by(|left, right| left.id.cmp(&right.id));
        policies
    }

    fn generate_context_policies(&self) -> Vec<ContextPolicy> {
        let mut context_map: HashMap<PolicyContext, ContextPolicy> = HashMap::new();

        for finding in &self.findings {
            for context in contexts_for_finding(finding) {
                let action = RecommendedAction::max(
                    finding.recommended_action,
                    self.profile
                        .map(|profile| {
                            self.policy
                                .as_ref()
                                .map_or_else(
                                    || profile.default_action_for_context(context),
                                    |policy| policy.resolve_context_action(profile, context),
                                )
                        })
                        .unwrap_or(RecommendedAction::Log),
                );
                let rationale = format!(
                    "{} via {} ({})",
                    finding.rule_id, finding.reason, finding.category
                );
                upsert_context_policy(&mut context_map, context, action, rationale);
            }
        }

        for node in &self.artifact_graph.nodes {
            for capability in &node.capabilities {
                for context in contexts_for_capability(capability.capability).iter().copied() {
                    let action = self
                        .profile
                        .map(|profile| {
                            self.policy
                                .as_ref()
                                .map_or_else(
                                    || profile.default_action_for_context(context),
                                    |policy| policy.resolve_context_action(profile, context),
                                )
                        })
                        .unwrap_or(RecommendedAction::Log);
                    let rationale = format!(
                        "{} exposes {:?} ({:?})",
                        node.path, capability.capability, capability.source
                    );
                    upsert_context_policy(&mut context_map, context, action, rationale);
                }
            }
        }

        let mut policies: Vec<_> = context_map.into_values().collect();
        policies.sort_by_key(|policy| context_sort_key(policy.context));
        policies
    }
}

fn upsert_context_policy(
    context_map: &mut HashMap<PolicyContext, ContextPolicy>,
    context: PolicyContext,
    action: RecommendedAction,
    rationale: String,
) {
    context_map
        .entry(context)
        .and_modify(|policy| {
            policy.action = RecommendedAction::max(policy.action, action);
            if !policy.rationale.contains(&rationale) {
                policy.rationale.push(rationale.clone());
            }
        })
        .or_insert(ContextPolicy {
            context,
            action,
            rationale: vec![rationale],
        });
}

fn context_sort_key(context: PolicyContext) -> u8 {
    match context {
        PolicyContext::Install => 0,
        PolicyContext::Network => 1,
        PolicyContext::Secrets => 2,
        PolicyContext::CodeModification => 3,
        PolicyContext::ExternalComms => 4,
    }
}

fn context_label(context: PolicyContext) -> &'static str {
    match context {
        PolicyContext::Install => "install",
        PolicyContext::Network => "network",
        PolicyContext::Secrets => "secrets",
        PolicyContext::CodeModification => "code_modification",
        PolicyContext::ExternalComms => "external_comms",
    }
}

fn contexts_for_finding(finding: &Finding) -> Vec<PolicyContext> {
    if finding.policy_contexts.is_empty() {
        default_operational_contexts(finding.category, finding.artifact_kind)
    } else {
        finding.policy_contexts.clone()
    }
}

fn contexts_for_capability(capability: ArtifactCapability) -> &'static [PolicyContext] {
    match capability {
        ArtifactCapability::InstallExecution | ArtifactCapability::ExposesBinary => {
            &[PolicyContext::Install]
        }
        ArtifactCapability::NetworkAccess => {
            &[PolicyContext::Network, PolicyContext::ExternalComms]
        }
        ArtifactCapability::BrowserAccess => {
            &[PolicyContext::Network, PolicyContext::CodeModification]
        }
        ArtifactCapability::IdentityAccess => &[PolicyContext::Secrets, PolicyContext::ExternalComms],
        ArtifactCapability::InboundNetworkSurface => {
            &[PolicyContext::Network, PolicyContext::ExternalComms]
        }
        ArtifactCapability::PrivilegedRuntime | ArtifactCapability::HostFilesystemAccess => {
            &[PolicyContext::CodeModification]
        }
        ArtifactCapability::ProcessExecution | ArtifactCapability::FilesystemWrite => {
            &[PolicyContext::CodeModification]
        }
        ArtifactCapability::SecretAccess => &[PolicyContext::Secrets],
        ArtifactCapability::PersistenceSurface => {
            &[PolicyContext::CodeModification, PolicyContext::ExternalComms]
        }
    }
}

fn finding_contexts(finding: &Finding) -> Vec<PolicyContext> {
    contexts_for_finding(finding)
}

fn default_policy_schema_version() -> String {
    POLICY_SCHEMA_VERSION.to_string()
}

fn waiver_matches_finding(waiver: &WaiverEntry, finding: &Finding, now: DateTime<Utc>) -> bool {
    if waiver.expires_at.is_some_and(|expires_at| expires_at < now) {
        return false;
    }

    let rule_matches = waiver
        .rule_id
        .as_ref()
        .map_or(true, |rule_id| rule_id == &finding.rule_id);
    let path_matches = waiver.artifact_path.as_ref().map_or(true, |path| {
        finding
            .artifact_path
            .as_ref()
            .is_some_and(|artifact_path| artifact_path.ends_with(path))
    });
    let context_matches = waiver.context.map_or(true, |context| {
        finding_contexts(finding).contains(&context)
    });

    rule_matches && path_matches && context_matches
}

fn policy_override_specificity(policy_override: &PolicyOverride) -> usize {
    usize::from(policy_override.rule_id.is_some())
        + usize::from(policy_override.artifact_path.is_some())
        + usize::from(policy_override.context.is_some())
}

fn policy_override_matches(
    policy_override: &PolicyOverride,
    finding: &Finding,
    now: DateTime<Utc>,
) -> bool {
    if policy_override
        .expires_at
        .is_some_and(|expires_at| expires_at < now)
    {
        return false;
    }

    let rule_matches = policy_override
        .rule_id
        .as_ref()
        .map_or(true, |rule_id| rule_id == &finding.rule_id);
    let path_matches = policy_override.artifact_path.as_ref().map_or(true, |path| {
        finding
            .artifact_path
            .as_ref()
            .is_some_and(|artifact_path| artifact_path.ends_with(path))
    });
    let context_matches = policy_override.context.map_or(true, |context| {
        finding_contexts(finding).contains(&context)
    });

    rule_matches && path_matches && context_matches
}

fn baseline_matches_finding(entry: &BaselineEntry, finding: &Finding) -> bool {
    entry.fingerprint == finding_fingerprint(finding)
}

fn finding_to_diff_entry(finding: &Finding) -> DiffEntry {
    DiffEntry {
        fingerprint: finding_fingerprint(finding),
        rule_id: finding.rule_id.clone(),
        artifact_path: finding.artifact_path.clone(),
        reason: finding.reason.clone(),
    }
}

#[must_use]
pub fn finding_fingerprint(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.rule_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(finding.reason.as_bytes());
    hasher.update(b"\n");
    hasher.update(finding.match_value.as_bytes());
    hasher.update(b"\n");
    hasher.update(
        finding
            .artifact_path
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    format!("{:x}", hasher.finalize())
}

#[must_use]
pub fn baseline_from_reports(reports: &[JsonReport]) -> BaselineFile {
    let entries = reports
        .iter()
        .flat_map(|report| report.findings.iter())
        .map(|finding| BaselineEntry {
            fingerprint: finding_fingerprint(finding),
            rule_id: finding.rule_id.clone(),
            artifact_path: finding.artifact_path.clone(),
            reason: finding.reason.clone(),
        })
        .collect();

    BaselineFile {
        schema_version: default_policy_schema_version(),
        entries,
    }
}

#[must_use]
pub fn apply_baseline(findings: Vec<Finding>, baseline: Option<&BaselineFile>) -> Vec<Finding> {
    let Some(baseline) = baseline else {
        return findings;
    };

    findings
        .into_iter()
        .filter(|finding| {
            let fingerprint = finding_fingerprint(finding);
            !baseline
                .entries
                .iter()
                .any(|entry| entry.fingerprint == fingerprint)
        })
        .collect()
}

#[must_use]
pub fn apply_waivers(findings: Vec<Finding>, waivers: Option<&WaiverFile>) -> Vec<Finding> {
    let Some(waivers) = waivers else {
        return findings;
    };

    let now = Utc::now();
    findings
        .into_iter()
        .filter(|finding| !waivers.waivers.iter().any(|waiver| waiver_matches_finding(waiver, finding, now)))
        .collect()
}

#[must_use]
pub fn apply_policy_overrides(findings: Vec<Finding>, policy: Option<&PolicyFile>) -> Vec<Finding> {
    apply_policy_overrides_with_audit(findings, policy).0
}

#[must_use]
pub fn apply_policy_overrides_with_audit(
    findings: Vec<Finding>,
    policy: Option<&PolicyFile>,
) -> (Vec<Finding>, Vec<AppliedPolicyOverride>) {
    let Some(policy) = policy else {
        return (findings, Vec::new());
    };

    let now = Utc::now();
    let mut audit = Vec::new();
    let findings = findings
        .into_iter()
        .map(|mut finding| {
            let selected = policy
                .overrides
                .iter()
                .enumerate()
                .filter(|(_, policy_override)| policy_override_matches(policy_override, &finding, now))
                .max_by_key(|(index, policy_override)| (policy_override_specificity(policy_override), *index))
                .map(|(_, policy_override)| policy_override);

            if let Some(policy_override) = selected {
                let original_action = finding.recommended_action;
                finding.recommended_action = policy_override.action;
                audit.push(AppliedPolicyOverride {
                    finding_fingerprint: finding_fingerprint(&finding),
                    rule_id: finding.rule_id.clone(),
                    artifact_path: finding.artifact_path.clone(),
                    override_id: policy_override.id.clone(),
                    original_action,
                    effective_action: policy_override.action,
                    specificity: policy_override_specificity(policy_override),
                    reason: policy_override.reason.clone(),
                    matched_contexts: finding_contexts(&finding),
                });
            }

            finding
        })
        .collect();
    (findings, audit)
}

pub fn load_baseline(path: &Path) -> Result<BaselineFile, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?)
}

pub fn load_waivers(path: &Path) -> Result<WaiverFile, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?)
}

pub fn load_policy(path: &Path) -> Result<PolicyFile, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let policy = serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    validate_policy(&policy)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(policy)
}

pub fn validate_policy(policy: &PolicyFile) -> Result<(), String> {
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(format!(
            "Unsupported policy schema_version '{}', expected '{}'",
            policy.schema_version, POLICY_SCHEMA_VERSION
        ));
    }

    let mut seen = std::collections::HashSet::new();
    for policy_override in &policy.overrides {
        if policy_override.rule_id.is_none()
            && policy_override.artifact_path.is_none()
            && policy_override.context.is_none()
        {
            return Err(
                "Each policy override must define at least one selector: rule_id, artifact_path, or context"
                    .to_string(),
            );
        }
        if policy_override.reason.trim().is_empty() {
            return Err("Policy overrides must define a non-empty reason".to_string());
        }
        let key = format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}",
            policy_override.id,
            policy_override.rule_id,
            policy_override.artifact_path,
            policy_override.context,
            policy_override.expires_at
        );
        if !seen.insert(key) {
            return Err("Duplicate policy override entries detected".to_string());
        }
    }

    Ok(())
}

pub fn validate_waivers(waivers: &WaiverFile) -> Result<(), String> {
    if waivers.schema_version != POLICY_SCHEMA_VERSION {
        return Err(format!(
            "Unsupported waiver schema_version '{}', expected '{}'",
            waivers.schema_version, POLICY_SCHEMA_VERSION
        ));
    }

    let mut seen = std::collections::HashSet::new();
    for waiver in &waivers.waivers {
        if waiver.rule_id.is_none() && waiver.artifact_path.is_none() && waiver.context.is_none() {
            return Err("Each waiver must define at least one selector: rule_id, artifact_path, or context".to_string());
        }
        let key = format!(
            "{:?}|{:?}|{:?}|{:?}",
            waiver.rule_id, waiver.artifact_path, waiver.context, waiver.expires_at
        );
        if !seen.insert(key) {
            return Err("Duplicate waiver entries detected".to_string());
        }
    }

    Ok(())
}

#[must_use]
pub fn diff_reports(previous: &[JsonReport], current: &[JsonReport]) -> DiffReport {
    diff_reports_with_policy_state(previous, current, None, None)
}

#[must_use]
pub fn diff_reports_with_policy_state(
    previous: &[JsonReport],
    current: &[JsonReport],
    baseline: Option<&BaselineFile>,
    waivers: Option<&WaiverFile>,
) -> DiffReport {
    let now = Utc::now();
    let previous_map: HashMap<_, _> = previous
        .iter()
        .flat_map(|report| report.findings.iter())
        .map(|finding| (finding_fingerprint(finding), finding_to_diff_entry(finding)))
        .collect();

    let mut active_current = HashMap::new();
    let mut waived_findings = Vec::new();
    let mut baselined_findings = Vec::new();

    for finding in current.iter().flat_map(|report| report.findings.iter()) {
        let fingerprint = finding_fingerprint(finding);
        if baseline.is_some_and(|baseline_file| {
            baseline_file
                .entries
                .iter()
                .any(|entry| baseline_matches_finding(entry, finding))
        }) {
            baselined_findings.push(finding_to_diff_entry(finding));
            continue;
        }

        if waivers.is_some_and(|waiver_file| {
            waiver_file
                .waivers
                .iter()
                .any(|waiver| waiver_matches_finding(waiver, finding, now))
        }) {
            waived_findings.push(finding_to_diff_entry(finding));
            continue;
        }

        active_current.insert(fingerprint, finding_to_diff_entry(finding));
    }

    let new_findings = active_current
        .iter()
        .filter(|(fingerprint, _)| !previous_map.contains_key(*fingerprint))
        .map(|(_, entry)| entry.clone())
        .collect();
    let resolved_findings = previous_map
        .iter()
        .filter(|(fingerprint, _)| !active_current.contains_key(*fingerprint))
        .filter(|(fingerprint, _)| {
            !waived_findings
                .iter()
                .chain(baselined_findings.iter())
                .any(|entry| &entry.fingerprint == *fingerprint)
        })
        .map(|(_, entry)| entry.clone())
        .collect();
    let unchanged_findings = active_current
        .keys()
        .filter(|fingerprint| previous_map.contains_key(*fingerprint))
        .count();

    DiffReport {
        new_findings,
        resolved_findings,
        waived_findings,
        baselined_findings,
        unchanged_findings,
    }
}

fn severity_to_sarif_level(severity: Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::Low => "note".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_graph::{
        ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactGraph,
    };
    use crate::findings::{ArtifactKind, MatchTarget, PackageVerdictReport, Verdict};

    #[test]
    fn test_generate_shield_md() {
        let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
            .severity(Severity::High)
            .confidence(0.95)
            .matched_on(MatchTarget::Document)
            .match_value("curl | bash")
            .reason("Test finding")
            .build()];

        let generator = PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new());
        let shield = generator.generate_shield_md();

        assert!(shield.contains("SHIELD Policy"));
        assert!(shield.contains("test-skill"));
        // Policy ID is lowercase: test_rule-test-skill
        assert!(shield.to_lowercase().contains("test_rule"));
    }

    #[test]
    fn test_generate_json() {
        let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
            .severity(Severity::High)
            .confidence(0.95)
            .matched_on(MatchTarget::Document)
            .match_value("curl | bash")
            .reason("Test finding")
            .build()];

        let generator = PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new());
        let json = generator.generate_json();

        assert_eq!(json.skill_name, "test-skill");
        assert_eq!(json.findings.len(), 1);
        assert!(json.artifact_graph.nodes.is_empty());
        assert!(json.context_policies.iter().any(|policy| policy.context == PolicyContext::Install));
    }

    #[test]
    fn test_generate_sarif() {
        let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
            .severity(Severity::High)
            .confidence(0.95)
            .matched_on(MatchTarget::Document)
            .match_value("curl | bash")
            .reason("Test finding")
            .build()];

        let generator = PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new());
        let sarif = generator.generate_sarif();

        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].results.len(), 2);
    }

    #[test]
    fn test_generate_policies_uses_strongest_recommended_action() {
        let findings = vec![
            Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
                .severity(Severity::Low)
                .action(RecommendedAction::RequireApproval)
                .matched_on(MatchTarget::Document)
                .match_value("bin")
                .reason("Needs review")
                .build(),
            Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
                .severity(Severity::Low)
                .action(RecommendedAction::Log)
                .matched_on(MatchTarget::Document)
                .match_value("context")
                .reason("Context only")
                .build(),
        ];

        let generator =
            PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new());
        let json = generator.generate_json();

        assert_eq!(json.policies.len(), 1);
        assert_eq!(json.policies[0].action, RecommendedAction::RequireApproval);
    }

    #[test]
    fn test_generate_json_escalates_summary_from_graph_capabilities() {
        let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .matched_on(MatchTarget::Document)
            .match_value("note")
            .reason("note")
            .build()];

        let mut graph = ArtifactGraph::new();
        graph.add_node_with_capabilities(
            "docker-compose.yml",
            crate::findings::ArtifactKind::PackageManifest,
            vec![
                ArtifactCapabilityFact {
                    capability: ArtifactCapability::PrivilegedRuntime,
                    source: ArtifactCapabilitySource::Declared,
                },
                ArtifactCapabilityFact {
                    capability: ArtifactCapability::HostFilesystemAccess,
                    source: ArtifactCapabilitySource::Declared,
                },
            ],
        );

        let generator = PolicyGenerator::new("test-skill", "test.md", findings, graph);
        let json = generator.generate_json();

        assert_eq!(json.summary.recommended_action, RecommendedAction::Block);
        assert!(json
            .summary
            .score_breakdown
            .iter()
            .any(|factor| factor.factor == "capability_combo:privileged_host_filesystem"));
        assert!(json
            .policies
            .iter()
            .all(|policy| policy.action == RecommendedAction::Block));
    }

    #[test]
    fn test_generate_json_includes_context_policies_from_profile() {
        let findings = vec![Finding::builder("TEST_SECRET", ThreatCategory::CredentialExposure)
            .severity(Severity::Medium)
            .matched_on(MatchTarget::Document)
            .match_value("api_key")
            .reason("Embedded secret")
            .build()];

        let generator = PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new())
            .with_profile(PolicyProfile::Team);
        let json = generator.generate_json();

        let policy = json
            .context_policies
            .iter()
            .find(|policy| policy.context == PolicyContext::Secrets)
            .expect("missing secrets context policy");
        assert_eq!(policy.action, RecommendedAction::Block);
        assert_eq!(json.policy_audit.effective_fail_on, None);
    }

    #[test]
    fn test_generate_sarif_includes_action_trigger_results() {
        let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .matched_on(MatchTarget::Document)
            .match_value("note")
            .reason("note")
            .build()];

        let mut graph = ArtifactGraph::new();
        graph.add_node_with_capabilities(
            "docker-compose.yml",
            crate::findings::ArtifactKind::PackageManifest,
            vec![
                crate::artifact_graph::ArtifactCapabilityFact {
                    capability: ArtifactCapability::PrivilegedRuntime,
                    source: crate::artifact_graph::ArtifactCapabilitySource::Declared,
                },
                crate::artifact_graph::ArtifactCapabilityFact {
                    capability: ArtifactCapability::HostFilesystemAccess,
                    source: crate::artifact_graph::ArtifactCapabilitySource::Declared,
                },
            ],
        );

        let generator = PolicyGenerator::new("test-skill", "test.md", findings, graph);
        let sarif = generator.generate_sarif();

        assert!(sarif.runs[0]
            .results
            .iter()
            .any(|result| result.rule_id == "SKILL_VEIL_ACTION_TRIGGER"));
    }

    #[test]
    fn test_apply_baseline_filters_known_findings() {
        let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
            .matched_on(MatchTarget::Document)
            .match_value("x")
            .reason("x")
            .build();
        let baseline = BaselineFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            entries: vec![BaselineEntry {
                fingerprint: finding_fingerprint(&finding),
                rule_id: finding.rule_id.clone(),
                artifact_path: finding.artifact_path.clone(),
                reason: finding.reason.clone(),
            }],
        };

        let filtered = apply_baseline(vec![finding], Some(&baseline));
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_apply_waivers_filters_matching_findings() {
        let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
            .artifact(crate::findings::ArtifactKind::ReferencedArtifact, Some("scripts/install.sh".to_string()))
            .matched_on(MatchTarget::Document)
            .match_value("x")
            .reason("x")
            .build();
        let waivers = WaiverFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            waivers: vec![WaiverEntry {
                rule_id: Some("TEST_RULE".to_string()),
                artifact_path: Some("install.sh".to_string()),
                context: None,
                reason: "accepted".to_string(),
                expires_at: None,
            }],
        };

        let filtered = apply_waivers(vec![finding], Some(&waivers));
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_apply_waivers_filters_matching_context() {
        let finding = Finding::builder("TEST_SECRET", ThreatCategory::CredentialExposure)
            .matched_on(MatchTarget::Document)
            .match_value("token")
            .reason("secret")
            .build();
        let waivers = WaiverFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            waivers: vec![WaiverEntry {
                rule_id: Some("TEST_SECRET".to_string()),
                artifact_path: None,
                context: Some(PolicyContext::Secrets),
                reason: "accepted".to_string(),
                expires_at: None,
            }],
        };

        let filtered = apply_waivers(vec![finding], Some(&waivers));
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_apply_policy_overrides_uses_most_specific_match() {
        let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
            .artifact(ArtifactKind::ReferencedArtifact, Some("scripts/install.sh".to_string()))
            .matched_on(MatchTarget::Document)
            .match_value("x")
            .reason("x")
            .action(RecommendedAction::Block)
            .build();
        let policy = PolicyFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            profiles: PolicyProfiles::default(),
            overrides: vec![
                PolicyOverride {
                    id: None,
                    rule_id: Some("TEST_RULE".to_string()),
                    artifact_path: None,
                    context: None,
                    action: RecommendedAction::RequireApproval,
                    reason: "broad override".to_string(),
                    expires_at: None,
                },
                PolicyOverride {
                    id: None,
                    rule_id: Some("TEST_RULE".to_string()),
                    artifact_path: Some("install.sh".to_string()),
                    context: Some(PolicyContext::Install),
                    action: RecommendedAction::Log,
                    reason: "specific override".to_string(),
                    expires_at: None,
                },
            ],
        };

        let overridden = apply_policy_overrides(vec![finding], Some(&policy));
        assert_eq!(overridden[0].recommended_action, RecommendedAction::Log);
    }

    #[test]
    fn test_apply_policy_overrides_with_audit_records_override() {
        let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
            .artifact(ArtifactKind::ReferencedArtifact, Some("scripts/install.sh".to_string()))
            .matched_on(MatchTarget::Document)
            .match_value("x")
            .reason("x")
            .action(RecommendedAction::Block)
            .build();
        let policy = PolicyFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            profiles: PolicyProfiles::default(),
            overrides: vec![PolicyOverride {
                id: Some("override-1".to_string()),
                rule_id: Some("TEST_RULE".to_string()),
                artifact_path: Some("install.sh".to_string()),
                context: Some(PolicyContext::Install),
                action: RecommendedAction::Log,
                reason: "specific override".to_string(),
                expires_at: None,
            }],
        };

        let (overridden, audit) = apply_policy_overrides_with_audit(vec![finding], Some(&policy));
        assert_eq!(overridden[0].recommended_action, RecommendedAction::Log);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].override_id.as_deref(), Some("override-1"));
    }

    #[test]
    fn test_policy_file_can_override_profile_context_action() {
        let policy = PolicyFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            profiles: PolicyProfiles {
                team: Some(ConfiguredProfile {
                    fail_on: Some(Severity::Medium),
                    context_actions: vec![ContextActionOverride {
                        context: PolicyContext::Network,
                        action: RecommendedAction::Block,
                    }],
                }),
                ..PolicyProfiles::default()
            },
            overrides: Vec::new(),
        };

        assert_eq!(policy.resolve_fail_on(PolicyProfile::Team), Some(Severity::Medium));
        assert_eq!(
            policy.resolve_context_action(PolicyProfile::Team, PolicyContext::Network),
            RecommendedAction::Block
        );
    }

    #[test]
    fn test_validate_policy_rejects_selectorless_override() {
        let policy = PolicyFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            profiles: PolicyProfiles::default(),
            overrides: vec![PolicyOverride {
                id: None,
                rule_id: None,
                artifact_path: None,
                context: None,
                action: RecommendedAction::Log,
                reason: "invalid".to_string(),
                expires_at: None,
            }],
        };

        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_diff_reports_detects_new_and_resolved_findings() {
        let previous = JsonReport {
            skill_name: "a".to_string(),
            skill_path: "a".to_string(),
            timestamp: Utc::now(),
            extension_kind: AgentExtensionKind::Skill,
            classification: ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: ArtifactIdentitySource::ExplicitName,
            structural_validity: StructuralValidity::Confirmed,
            heuristic_score: 0,
            findings: vec![Finding::builder("OLD_RULE", ThreatCategory::Generic)
                .matched_on(MatchTarget::Document)
                .match_value("old")
                .reason("old")
                .build()],
            primary_findings: Vec::new(),
            supporting_findings: Vec::new(),
            summary: FindingSummary::from_findings(&[]),
            primary_summary: FindingSummary::from_findings(&[]),
            supporting_summary: FindingSummary::from_findings(&[]),
            artifact_graph: ArtifactGraph::new(),
            policies: Vec::new(),
            context_policies: Vec::new(),
            profile: None,
            suppression_summary: SuppressionSummary::default(),
            policy_audit: PolicyAudit::default(),
            verdict: Verdict::Benign,
            verdict_report: PackageVerdictReport {
                verdict: Verdict::Benign,
                package_health: crate::findings::PackageHealth::Healthy,
                hygiene_summary: crate::findings::HygieneSummary::default(),
                declared_permissions: Vec::new(),
                effective_capabilities: Vec::new(),
                blast_radius_summary: crate::findings::BlastRadiusSummary::default(),
                verdict_reasons: Vec::new(),
                root_cause_groups: Vec::new(),
                top_risk_drivers: Vec::new(),
            },
        };
        let current = JsonReport {
            skill_name: "a".to_string(),
            skill_path: "a".to_string(),
            timestamp: Utc::now(),
            extension_kind: AgentExtensionKind::Skill,
            classification: ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: ArtifactIdentitySource::ExplicitName,
            structural_validity: StructuralValidity::Confirmed,
            heuristic_score: 0,
            findings: vec![Finding::builder("NEW_RULE", ThreatCategory::Generic)
                .matched_on(MatchTarget::Document)
                .match_value("new")
                .reason("new")
                .build()],
            primary_findings: Vec::new(),
            supporting_findings: Vec::new(),
            summary: FindingSummary::from_findings(&[]),
            primary_summary: FindingSummary::from_findings(&[]),
            supporting_summary: FindingSummary::from_findings(&[]),
            artifact_graph: ArtifactGraph::new(),
            policies: Vec::new(),
            context_policies: Vec::new(),
            profile: None,
            suppression_summary: SuppressionSummary::default(),
            policy_audit: PolicyAudit::default(),
            verdict: Verdict::Benign,
            verdict_report: PackageVerdictReport {
                verdict: Verdict::Benign,
                package_health: crate::findings::PackageHealth::Healthy,
                hygiene_summary: crate::findings::HygieneSummary::default(),
                declared_permissions: Vec::new(),
                effective_capabilities: Vec::new(),
                blast_radius_summary: crate::findings::BlastRadiusSummary::default(),
                verdict_reasons: Vec::new(),
                root_cause_groups: Vec::new(),
                top_risk_drivers: Vec::new(),
            },
        };

        let diff = diff_reports(&[previous], &[current]);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.waived_findings.len(), 0);
        assert_eq!(diff.baselined_findings.len(), 0);
        assert_eq!(diff.unchanged_findings, 0);
    }

    #[test]
    fn test_diff_reports_classifies_waived_and_baselined_findings() {
        let current_finding = Finding::builder("CUR_RULE", ThreatCategory::CredentialExposure)
            .artifact(ArtifactKind::ReferencedArtifact, Some("scripts/install.sh".to_string()))
            .matched_on(MatchTarget::Document)
            .match_value("token")
            .reason("current")
            .build();
        let current_report = JsonReport {
            skill_name: "a".to_string(),
            skill_path: "a".to_string(),
            timestamp: Utc::now(),
            extension_kind: AgentExtensionKind::Skill,
            classification: ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: ArtifactIdentitySource::ExplicitName,
            structural_validity: StructuralValidity::Confirmed,
            heuristic_score: 0,
            findings: vec![current_finding.clone()],
            primary_findings: Vec::new(),
            supporting_findings: Vec::new(),
            summary: FindingSummary::from_findings(&[]),
            primary_summary: FindingSummary::from_findings(&[]),
            supporting_summary: FindingSummary::from_findings(&[]),
            artifact_graph: ArtifactGraph::new(),
            policies: Vec::new(),
            context_policies: Vec::new(),
            profile: None,
            suppression_summary: SuppressionSummary::default(),
            policy_audit: PolicyAudit::default(),
            verdict: Verdict::Suspicious,
            verdict_report: PackageVerdictReport {
                verdict: Verdict::Suspicious,
                package_health: crate::findings::PackageHealth::NeedsReview,
                hygiene_summary: crate::findings::HygieneSummary::default(),
                declared_permissions: Vec::new(),
                effective_capabilities: Vec::new(),
                blast_radius_summary: crate::findings::BlastRadiusSummary::default(),
                verdict_reasons: Vec::new(),
                root_cause_groups: Vec::new(),
                top_risk_drivers: Vec::new(),
            },
        };
        let baseline = BaselineFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            entries: vec![BaselineEntry {
                fingerprint: finding_fingerprint(&current_finding),
                rule_id: current_finding.rule_id.clone(),
                artifact_path: current_finding.artifact_path.clone(),
                reason: current_finding.reason.clone(),
            }],
        };
        let waived_finding = Finding::builder("WAIVE_RULE", ThreatCategory::CredentialExposure)
            .matched_on(MatchTarget::Document)
            .match_value("secret")
            .reason("waive me")
            .build();
        let waived_report = JsonReport {
            skill_name: "b".to_string(),
            skill_path: "b".to_string(),
            timestamp: Utc::now(),
            extension_kind: AgentExtensionKind::Skill,
            classification: ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: ArtifactIdentitySource::ExplicitName,
            structural_validity: StructuralValidity::Confirmed,
            heuristic_score: 0,
            findings: vec![waived_finding.clone()],
            primary_findings: Vec::new(),
            supporting_findings: Vec::new(),
            summary: FindingSummary::from_findings(&[]),
            primary_summary: FindingSummary::from_findings(&[]),
            supporting_summary: FindingSummary::from_findings(&[]),
            artifact_graph: ArtifactGraph::new(),
            policies: Vec::new(),
            context_policies: Vec::new(),
            profile: None,
            suppression_summary: SuppressionSummary::default(),
            policy_audit: PolicyAudit::default(),
            verdict: Verdict::Suspicious,
            verdict_report: PackageVerdictReport {
                verdict: Verdict::Suspicious,
                package_health: crate::findings::PackageHealth::NeedsReview,
                hygiene_summary: crate::findings::HygieneSummary::default(),
                declared_permissions: Vec::new(),
                effective_capabilities: Vec::new(),
                blast_radius_summary: crate::findings::BlastRadiusSummary::default(),
                verdict_reasons: Vec::new(),
                root_cause_groups: Vec::new(),
                top_risk_drivers: Vec::new(),
            },
        };
        let waivers = WaiverFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            waivers: vec![WaiverEntry {
                rule_id: Some("WAIVE_RULE".to_string()),
                artifact_path: None,
                context: Some(PolicyContext::Secrets),
                reason: "approved".to_string(),
                expires_at: None,
            }],
        };

        let diff = diff_reports_with_policy_state(
            &[],
            &[current_report, waived_report],
            Some(&baseline),
            Some(&waivers),
        );

        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.waived_findings.len(), 1);
        assert_eq!(diff.baselined_findings.len(), 1);
    }
}
