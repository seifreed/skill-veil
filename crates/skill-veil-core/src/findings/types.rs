use super::enums::BlastRadiusLevel;
use super::enums::{
    ArtifactKind, ArtifactScope, EvidenceKind, MatchTarget, OperationalContext, PackageHealth,
    RecommendedAction, SignalClass, ThreatCategory, Verdict,
};
use super::permissions::DeclaredPermission;
use super::summary::RiskFactor;
use serde::{Deserialize, Serialize};

/// Structured reason contributing to the final verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictReason {
    pub scope: ArtifactScope,
    pub category: ThreatCategory,
    pub signal_class: SignalClass,
    pub rationale: String,
}

/// Aggregated root-cause cluster for package-level reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseGroup {
    pub scope: ArtifactScope,
    pub category: ThreatCategory,
    pub signal_class: SignalClass,
    pub finding_count: usize,
    pub strongest_action: RecommendedAction,
    pub representative_rules: Vec<String>,
}

/// A security finding from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// The rule ID that generated this finding
    pub rule_id: String,
    /// Threat category
    pub category: ThreatCategory,
    /// Severity level
    pub severity: super::enums::Severity,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Raw confidence before evidence/category calibration.
    pub raw_confidence: f32,
    /// Explanation of how confidence was calibrated.
    pub confidence_rationale: String,
    /// What was matched
    pub matched_on: MatchTarget,
    /// The actual matched value/text
    pub match_value: String,
    /// Human-readable reason/explanation
    pub reason: String,
    /// Explicit remediation guidance for triage or mitigation.
    pub remediation: String,
    /// Explicit recommendation for triage or enforcement.
    pub recommended_action: RecommendedAction,
    /// Evidence class for explainability.
    pub evidence_kind: EvidenceKind,
    /// Artifact type where the evidence was found.
    pub artifact_kind: ArtifactKind,
    /// High-level artifact scope within the package.
    pub artifact_scope: ArtifactScope,
    /// Coarse signal family for package-level verdicts.
    pub signal_class: SignalClass,
    /// Path to the artifact where the evidence was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// Operational contexts impacted by this finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operational_contexts: Vec<OperationalContext>,
    /// Line number if available
    pub line_number: Option<usize>,
}

/// A note explaining how calibration adjusted a root cause group or risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictCalibrationNote {
    pub rule_id: String,
    pub effect: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVerdictReport {
    pub verdict: Verdict,
    pub package_health: PackageHealth,
    pub hygiene_summary: HygieneSummary,
    pub declared_permissions: Vec<DeclaredPermission>,
    pub effective_capabilities: Vec<String>,
    pub blast_radius_summary: BlastRadiusSummary,
    pub verdict_reasons: Vec<VerdictReason>,
    pub root_cause_groups: Vec<RootCauseGroup>,
    pub top_risk_drivers: Vec<RiskFactor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calibration_notes: Vec<VerdictCalibrationNote>,
    /// Net score adjustment applied by calibration (negative = reduced risk).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub calibration_risk_adjustment: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlastRadiusSummary {
    pub level: BlastRadiusLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_permissions: Vec<DeclaredPermission>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HygieneSummary {
    pub package_root_findings: usize,
    pub entrypoint_findings: usize,
    pub supporting_findings: usize,
    pub top_rules: Vec<String>,
}

fn is_zero(value: &i32) -> bool {
    *value == 0
}
