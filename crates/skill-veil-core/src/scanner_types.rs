use crate::analyzer::{
    AgentExtensionKind, AnalyzerError, ArtifactClassification, ArtifactIdentitySource,
    StructuralValidity,
};
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{
    ArtifactKind, DeduplicationSummary, Finding, FindingSummary, PackageVerdictReport, Severity,
    Verdict,
};
use crate::policy::{
    JsonReport, PolicyAudit, PolicyFile, PolicyGenerator, PolicyProfile, SarifReport,
    SuppressionSummary,
};
use crate::rules::RuleError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Analyzer error: {0}")]
    Analyzer(#[from] AnalyzerError),
    #[error("Rule error: {0}")]
    Rule(#[from] RuleError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),
    #[error("Not a strict skill entrypoint: {0}")]
    InvalidSkillEntrypoint(PathBuf),
    #[error("No explicit skill entrypoints found in package: {0}")]
    NoSkillEntrypoints(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanTargetMode {
    #[default]
    Auto,
    File,
    Package,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub min_severity: Option<Severity>,
    pub fail_on: Option<Severity>,
    pub rules_dir: Option<PathBuf>,
    pub profile: Option<PolicyProfile>,
    pub baseline_path: Option<PathBuf>,
    pub waivers_path: Option<PathBuf>,
    pub policy_path: Option<PathBuf>,
    pub include_rules: Vec<String>,
    pub exclude_rules: Vec<String>,
    pub recursive: bool,
    pub target_mode: ScanTargetMode,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            min_severity: None,
            fail_on: None,
            rules_dir: None,
            profile: None,
            baseline_path: None,
            waivers_path: None,
            policy_path: None,
            include_rules: Vec::new(),
            exclude_rules: Vec::new(),
            recursive: true,
            target_mode: ScanTargetMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: PathBuf,
    pub name: String,
    pub extension_kind: AgentExtensionKind,
    pub classification: ArtifactClassification,
    pub package_id: Option<String>,
    pub identity_source: ArtifactIdentitySource,
    pub structural_validity: StructuralValidity,
    pub heuristic_score: u8,
    pub primary_artifact_kind: ArtifactKind,
    pub findings: Vec<Finding>,
    pub primary_findings: Vec<Finding>,
    pub supporting_findings: Vec<Finding>,
    pub summary: FindingSummary,
    pub primary_summary: FindingSummary,
    pub supporting_summary: FindingSummary,
    pub verdict: Verdict,
    pub verdict_report: PackageVerdictReport,
    pub deduplication_summary: DeduplicationSummary,
    pub artifact_graph: ArtifactGraph,
    pub profile: Option<PolicyProfile>,
    pub policy: Option<PolicyFile>,
    pub suppression_summary: SuppressionSummary,
    pub policy_audit: PolicyAudit,
    pub should_fail: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanErrorEntry {
    pub path: PathBuf,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageScanResult {
    pub results: Vec<ScanResult>,
    pub errors: Vec<ScanErrorEntry>,
}

impl PackageScanResult {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.results.is_empty() && self.errors.is_empty()
    }

    pub fn total_count(&self) -> usize {
        self.results.len() + self.errors.len()
    }
}

impl Default for PackageScanResult {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanResult {
    pub fn has_severity(&self, severity: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= severity)
    }

    pub fn findings_by_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= severity)
            .collect()
    }

    pub(crate) fn split_findings_by_scope(
        path: &Path,
        primary_artifact_kind: ArtifactKind,
        findings: &[Finding],
    ) -> (Vec<Finding>, Vec<Finding>) {
        crate::findings::split_findings_by_scope(path, primary_artifact_kind, findings)
    }

    fn policy_generator(&self) -> PolicyGenerator {
        let mut generator = PolicyGenerator::new(
            &self.name,
            self.path.to_string_lossy(),
            self.findings.clone(),
            self.artifact_graph.clone(),
        )
        .with_primary_artifact_kind(self.primary_artifact_kind)
        .with_extension_kind(self.extension_kind)
        .with_artifact_classification(
            self.classification,
            self.package_id.clone(),
            self.identity_source,
            self.structural_validity,
            self.heuristic_score,
        );
        if let Some(profile) = self.profile {
            generator = generator.with_profile(profile);
        }
        if let Some(policy) = &self.policy {
            generator = generator.with_policy(policy.clone());
        }
        generator
            .with_suppression_summary(self.suppression_summary.clone())
            .with_policy_audit(self.policy_audit.clone())
            .with_verdict_report(self.verdict_report.clone())
    }

    pub fn to_shield_md(&self) -> String {
        self.policy_generator().generate_shield_md()
    }

    pub fn to_json_report(&self) -> JsonReport {
        self.policy_generator().generate_json()
    }

    pub fn to_sarif_report(&self) -> SarifReport {
        self.policy_generator().generate_sarif()
    }

    pub fn context_policies(&self) -> Vec<crate::policy::ContextPolicy> {
        self.policy_generator().generate_context_policies()
    }
}
