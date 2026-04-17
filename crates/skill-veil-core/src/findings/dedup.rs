use super::{ArtifactKind, ArtifactScope, Finding};
use serde::{Deserialize, Serialize};

/// Summary of the scanner deduplication pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeduplicationSummary {
    pub original_findings: usize,
    pub unique_findings: usize,
    pub duplicates_removed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FindingDedupKey {
    rule_id: String,
    category: super::ThreatCategory,
    matched_on: String,
    match_value: String,
    artifact_kind: ArtifactKind,
    artifact_scope: ArtifactScope,
    artifact_path: Option<String>,
}

/// Split findings into primary (entrypoint) and supporting (referenced artifacts) groups.
///
/// A finding is considered primary if it matches the primary path and artifact kind,
/// or if it is a path-less finding whose artifact kind matches the primary kind.
pub(crate) fn split_findings_by_scope(
    path: &std::path::Path,
    primary_artifact_kind: ArtifactKind,
    findings: &[Finding],
) -> (Vec<Finding>, Vec<Finding>) {
    let primary_path = path.display().to_string();
    findings.iter().cloned().partition(|finding| {
        finding.artifact_kind == primary_artifact_kind
            && (finding.artifact_path.is_none()
                || finding
                    .artifact_path
                    .as_deref()
                    .is_some_and(|artifact_path| {
                        let pp = std::path::Path::new(&primary_path);
                        let ap = std::path::Path::new(artifact_path);
                        ap == pp || pp.ends_with(artifact_path)
                    }))
    })
}

/// Deduplicate findings that match on the same rule, category, match target,
/// artifact kind, and artifact path.
///
/// # Merge Semantics
///
/// - **Severity**: Takes the maximum severity
/// - **Confidence**: Takes the maximum confidence score
/// - **RecommendedAction**: Takes the maximum action (Block > RequireApproval > Log)
/// - **Reason/Remediation**: Preserves from the stronger finding
/// - **Line number**: Preserves first non-None value encountered
#[must_use]
pub fn deduplicate_findings(findings: Vec<Finding>) -> (Vec<Finding>, DeduplicationSummary) {
    let original_findings = findings.len();
    let mut deduped = std::collections::HashMap::<FindingDedupKey, Finding>::new();

    for finding in findings {
        let key = FindingDedupKey {
            rule_id: finding.rule_id.clone(),
            category: finding.category,
            matched_on: finding.matched_on.to_string(),
            match_value: finding.match_value.clone(),
            artifact_kind: finding.artifact_kind,
            artifact_scope: finding.artifact_scope,
            artifact_path: finding.artifact_path.clone(),
        };

        deduped
            .entry(key)
            .and_modify(|existing| {
                let finding_is_stronger = finding.severity > existing.severity
                    || (finding.severity == existing.severity
                        && finding.confidence > existing.confidence);
                let confidence_from_new = finding.confidence > existing.confidence;

                existing.severity = existing.severity.max(finding.severity);
                existing.confidence = existing.confidence.max(finding.confidence);
                existing.recommended_action =
                    existing.recommended_action.max(finding.recommended_action);

                if finding_is_stronger {
                    existing.signal_class = finding.signal_class;
                    existing.evidence_kind = finding.evidence_kind;
                }
                // Take raw_confidence and confidence_rationale from the finding that
                // contributed the max calibrated confidence, keeping them aligned.
                if confidence_from_new {
                    existing.raw_confidence = finding.raw_confidence;
                    existing.confidence_rationale = finding.confidence_rationale.clone();
                }

                if finding_is_stronger
                    || (finding.severity == existing.severity
                        && finding.reason.len() > existing.reason.len())
                {
                    existing.reason = finding.reason.clone();
                }
                if finding_is_stronger
                    || (finding.severity == existing.severity
                        && finding.remediation.len() > existing.remediation.len())
                {
                    existing.remediation = finding.remediation.clone();
                }
                if existing.line_number.is_none() {
                    existing.line_number = finding.line_number;
                }
            })
            .or_insert(finding);
    }

    let mut unique_findings: Vec<_> = deduped.into_values().collect();
    unique_findings.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then_with(|| left.artifact_path.cmp(&right.artifact_path))
            .then_with(|| left.line_number.cmp(&right.line_number))
            .then_with(|| left.match_value.cmp(&right.match_value))
    });

    let unique_count = unique_findings.len();
    (
        unique_findings,
        DeduplicationSummary {
            original_findings,
            unique_findings: unique_count,
            duplicates_removed: original_findings.saturating_sub(unique_count),
        },
    )
}
