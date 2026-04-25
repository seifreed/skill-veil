use crate::analyzer::{
    AgentExtensionKind, AnalyzerError, ArtifactClassification, ArtifactIdentitySource,
    StructuralValidity,
};
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{
    ArtifactKind, DeduplicationSummary, Finding, FindingSummary, PackageVerdictReport, Severity,
    Verdict,
};
use crate::policy::{PolicyAudit, PolicyFile, PolicyGenerator, PolicyProfile, SuppressionSummary};
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
    /// When true, a duplicate rule id encountered while loading an external
    /// pack is promoted from a tracing warning to a hard error. Useful in CI
    /// to catch pack-authoring mistakes early. Default: false (warn only).
    #[serde(default)]
    pub strict_rules: bool,
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
            strict_rules: false,
        }
    }
}

/// Identity and classification metadata for a scanned artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub path: PathBuf,
    pub name: String,
    pub extension_kind: AgentExtensionKind,
    pub classification: ArtifactClassification,
    pub package_id: Option<String>,
    pub identity_source: ArtifactIdentitySource,
    pub structural_validity: StructuralValidity,
    pub heuristic_score: u8,
    pub primary_artifact_kind: ArtifactKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub metadata: ArtifactMetadata,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suppressed_findings: Vec<Finding>,
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
    /// Indicators of compromise extracted from the primary artifact and its
    /// supporting artifacts. Populated offline by the scanner; downstream
    /// enrichment tooling (e.g. `skill-veil vt enrich`) consumes it.
    #[serde(
        default,
        skip_serializing_if = "crate::ioc_extraction::ExtractedIocs::is_empty"
    )]
    pub extracted_iocs: crate::ioc_extraction::ExtractedIocs,
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

    pub fn policy_generator(&self) -> PolicyGenerator {
        let m = &self.metadata;
        let base = PolicyGenerator::new(
            &m.name,
            m.path.to_string_lossy(),
            self.findings.clone(),
            self.artifact_graph.clone(),
        )
        .with_primary_artifact_kind(m.primary_artifact_kind)
        .with_extension_kind(m.extension_kind)
        .with_classification(m.classification)
        .with_package_id(m.package_id.clone())
        .with_identity_source(m.identity_source)
        .with_structural_validity(m.structural_validity)
        .with_heuristic_score(m.heuristic_score);
        let base = match self.profile {
            Some(p) => base.with_profile(p),
            None => base,
        };
        let base = match &self.policy {
            Some(p) => base.with_policy(p.clone()),
            None => base,
        };
        base.with_suppression_summary(self.suppression_summary.clone())
            .with_policy_audit(self.policy_audit.clone())
            .with_verdict_report(self.verdict_report.clone())
    }
}
