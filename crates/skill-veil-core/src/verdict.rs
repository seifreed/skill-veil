mod blast_radius;
mod capabilities;
mod compound;
mod hygiene;
mod permissions;
mod predicates;
mod root_causes;

/// Maximum number of verdict reasons retained in the final report.
pub(crate) const MAX_VERDICT_REASONS: usize = 8;
/// Maximum number of top risk drivers retained in the final report.
pub(crate) const MAX_TOP_RISK_DRIVERS: usize = 5;
/// Maximum number of representative rules per root cause group.
pub(crate) const MAX_REPRESENTATIVE_RULES: usize = 5;

use crate::findings::{Finding, FindingSummary, PackageVerdictReport, VerdictReason};
use crate::verdict_calibration::{calibrate_verdict_inputs, VerdictCalibration};

#[must_use]
pub fn derive_package_verdict(
    findings: &[Finding],
    primary_summary: &FindingSummary,
    supporting_summary: &FindingSummary,
    package_summary: &FindingSummary,
) -> PackageVerdictReport {
    let raw_root_cause_groups = root_causes::build_root_cause_groups(findings);
    let calibration = calibrate_verdict_inputs(findings, &raw_root_cause_groups);
    // Destructure calibration so we can move root_cause_groups into merge
    // while retaining the other fields for later use.
    let VerdictCalibration {
        root_cause_groups: calibrated_groups,
        risk_adjustment: calibration_risk_adjustment,
        notes: calibration_notes,
    } = calibration;
    // Calibration may reclassify signal_class (e.g., MaliciousBehavior → ReviewSignal),
    // which can produce groups that now share (scope, category, signal_class). Merge them
    // so downstream consumers see deduplicated groups.
    let root_cause_groups = root_causes::merge_calibrated_groups(calibrated_groups);
    debug_assert!(
        root_cause_groups.len() <= raw_root_cause_groups.len(),
        "Merging calibrated groups must not increase group count"
    );
    let compound_reasons =
        compound::detect_compound_verdict_reasons(findings, &raw_root_cause_groups);
    // Insert compound reasons first so they survive truncation — they drive
    // Malicious verdicts and must remain visible in verdict_reasons.
    let mut verdict_reasons = compound_reasons.clone();
    verdict_reasons.extend(root_cause_groups.iter().map(|group| VerdictReason {
        scope: group.scope,
        category: group.category,
        signal_class: group.signal_class,
        rationale: format!(
            "{} finding(s) in {} with strongest action {}",
            group.finding_count, group.scope, group.strongest_action
        ),
    }));
    verdict_reasons.truncate(MAX_VERDICT_REASONS);

    let predicates = predicates::VerdictPredicates::compute(&predicates::VerdictInputs {
        findings,
        root_cause_groups: &root_cause_groups,
        raw_root_cause_groups: &raw_root_cause_groups,
        compound_reasons: &compound_reasons,
        primary_summary,
        supporting_summary,
    });

    let hygiene_summary = hygiene::build_hygiene_summary(findings);
    let declared_permissions =
        permissions::derive_declared_permissions(findings, supporting_summary);
    let blast_radius_summary =
        blast_radius::build_blast_radius_summary(findings, &declared_permissions);
    let effective_capabilities = capabilities::derive_effective_capabilities(&root_cause_groups);

    // Apply the calibration adjustment to the risk_score used by the
    // verdict decision. Without this, `predicates.verdict()` evaluates
    // `risk_gated_high` against the uncalibrated package score, so packages
    // whose calibration would have brought them below the block threshold
    // are still escalated to Suspicious. The persisted summaries on
    // `ScanResult` keep the raw aggregation view; calibrated scores live in
    // `PackageVerdictReport.calibration_risk_adjustment`.
    let calibrated_primary = primary_summary.with_risk_adjustment(calibration_risk_adjustment);
    let calibrated_package = package_summary.with_risk_adjustment(calibration_risk_adjustment);

    let verdict = predicates.verdict(&calibration_notes, &calibrated_primary, &calibrated_package);
    let package_health = predicates.package_health(&hygiene_summary, verdict);

    let mut top_risk_drivers = package_summary.score_breakdown.clone();
    top_risk_drivers.truncate(MAX_TOP_RISK_DRIVERS);

    PackageVerdictReport {
        verdict,
        package_health,
        hygiene_summary,
        declared_permissions,
        effective_capabilities,
        blast_radius_summary,
        verdict_reasons,
        root_cause_groups,
        top_risk_drivers,
        calibration_notes,
        calibration_risk_adjustment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        Finding, FindingSummary, MatchTarget, PackageHealth, RecommendedAction, Severity,
        ThreatCategory, Verdict,
    };

    #[test]
    fn test_trivial_hygiene_produces_needs_review_not_elevated() {
        // A single Low/Log hygiene finding should produce NeedsReview, not Elevated.
        let finding = Finding::builder("SCOPE_CREEP_GENERIC", ThreatCategory::ScopeCreep)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .matched_on(MatchTarget::Document)
            .match_value("broad scope")
            .reason("Minor scope creep")
            .build();
        let findings = vec![finding];
        let summary = FindingSummary::from_findings(&findings);

        let report = derive_package_verdict(&findings, &summary, &summary, &summary);

        assert_eq!(
            report.package_health,
            PackageHealth::NeedsReview,
            "Trivial hygiene findings should produce NeedsReview, not Elevated"
        );
        assert_eq!(report.verdict, Verdict::Benign);
    }
}
