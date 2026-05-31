use super::enums::BlastRadiusLevel;
use super::enums::{
    ArtifactKind, ArtifactScope, EvidenceKind, MatchTarget, OperationalContext, PackageHealth,
    RecommendedAction, SignalClass, ThreatCategory, Verdict,
};
use super::permissions::DeclaredPermission;
use super::summary::RiskFactor;
use super::taxonomy::TaxonomyTag;
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

/// Audit record set on a finding when it is suppressed by an inline annotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRecord {
    /// Suppression kind: `"inline_comment"` or `"inline_json"`.
    pub kind: String,
    /// Rule ID that was suppressed (`"*"` for wildcard suppressions).
    pub rule_id: String,
    /// Reason declared in the annotation, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    /// Named taxonomy labels carried over from the rule that produced this
    /// finding. Orthogonal to `category`: communication-only, never feeds
    /// verdict scoring. Additive field — older caches deserialise to empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxonomy_tags: Vec<TaxonomyTag>,
    /// Free-form taxonomy labels applied by an operator-supplied
    /// `--threat-mapping` file (keyed on `rule_id`). Like
    /// [`Self::taxonomy_tags`] this is communication-only and NEVER feeds
    /// verdict scoring; it exists so operators can overlay their own
    /// vocabulary without touching the frozen [`TaxonomyTag`] registry.
    /// Additive field — older caches deserialise to empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_taxonomy: Vec<String>,
    /// Line number if available
    pub line_number: Option<usize>,
    /// Set when this finding was suppressed by an inline annotation; absent for active findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression: Option<SuppressionRecord>,
}

/// A note explaining how calibration adjusted a root cause group or risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictCalibrationNote {
    pub rule_id: String,
    pub effect: String,
    pub rationale: String,
    /// Scope of the root cause group this note applies to. Lets verdict
    /// predicates filter notes by group when deciding whether calibration
    /// affects a specific isolated weak signal — without this, an unrelated
    /// `downgraded_*` note in another group blocks the Benign downgrade for
    /// the isolated group.
    #[serde(default = "default_calibration_note_scope")]
    pub scope: ArtifactScope,
    /// Category of the root cause group this note applies to. Paired with
    /// `scope` for per-group note filtering in verdict predicates.
    #[serde(default = "default_calibration_note_category")]
    pub category: ThreatCategory,
    /// Signal class of the root cause group this note applies to, captured
    /// *after* any reclassification. Enables precise per-group filtering
    /// so that a `downgraded_*` note from a group with one signal class
    /// does not contaminate the Benign-downgrade check for a different
    /// group that happens to share `(scope, category)`. Using the
    /// post-reclassification value ensures that verdict predicates
    /// filtering on `(scope, category, signal_class)` see the value that
    /// matches the calibrated root cause groups.
    #[serde(default = "default_calibration_note_signal_class")]
    pub signal_class: SignalClass,
}

fn default_calibration_note_scope() -> ArtifactScope {
    ArtifactScope::PackageRootArtifact
}

fn default_calibration_note_category() -> ThreatCategory {
    ThreatCategory::Generic
}

fn default_calibration_note_signal_class() -> SignalClass {
    SignalClass::Hygiene
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
