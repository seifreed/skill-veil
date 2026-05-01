//! Confidence calibration for benchmark findings.
//!
//! Groups labelled findings by `EvidenceKind`, `ThreatCategory`, and
//! the `(evidence_kind, category)` pair, then derives a calibrated
//! `recommended_confidence` per bucket using the Wilson lower bound at
//! 95 %. Empty buckets surface as `NaN` (unambiguous "no data") rather
//! than collapsing to a plausible-looking 0.35.
//!
//! Lives separately from [`super::evaluation`] (which orchestrates the
//! scan and computes precision/recall) and [`super::thresholds`] (grid
//! search for risk-score cutoffs) because calibration is a self-contained
//! statistical sub-problem with its own constants.

use std::collections::BTreeMap;

use super::types::{CalibrationBucket, CalibrationSummary, SampleLabel};
use crate::{EvidenceKind, Finding, ThreatCategory};

/// Confidence floor for a bucket with at least one labelled finding.
/// Picked so that "Wilson lower bound = 0" still yields 0.35 rather than
/// the noisy 0.0 that downstream consumers were collapsing into "unknown".
const CONFIDENCE_FLOOR: f32 = 0.35;
/// Multiplier applied to the Wilson lower bound when blending it into
/// the reported confidence. Empirically tuned so that fully-precise
/// buckets converge near the upper clamp.
const CONFIDENCE_WILSON_SCALE: f32 = 0.6;
/// Lower clamp on the reported confidence: preserves the "we have at
/// least one labelled signal" guarantee.
const CONFIDENCE_LOWER_CLAMP: f32 = 0.1;
/// Upper clamp on the reported confidence: prevents overclaiming on
/// small-N buckets where the Wilson bound is statistically optimistic.
const CONFIDENCE_UPPER_CLAMP: f32 = 0.99;

/// Z-score for a 95 % confidence interval; the assumption matches the
/// reporting copy in `recommend_thresholds`.
const WILSON_Z_SCORE_95: f32 = 1.96;

pub(super) fn calibrate_confidence(findings: &[(SampleLabel, Finding)]) -> CalibrationSummary {
    CalibrationSummary {
        by_evidence_kind: calibration_buckets_by_evidence(findings),
        by_category: calibration_buckets_by_category(findings),
        by_signal_pair: calibration_buckets_by_signal_pair(findings),
    }
}

fn calibration_buckets_by_evidence(findings: &[(SampleLabel, Finding)]) -> Vec<CalibrationBucket> {
    let mut buckets = BTreeMap::<String, Vec<bool>>::new();
    for (label, finding) in findings {
        buckets
            .entry(evidence_key(finding.evidence_kind))
            .or_default()
            .push(*label != SampleLabel::Benign);
    }
    finalize_calibration_buckets(buckets)
}

fn calibration_buckets_by_category(findings: &[(SampleLabel, Finding)]) -> Vec<CalibrationBucket> {
    let mut buckets = BTreeMap::<String, Vec<bool>>::new();
    for (label, finding) in findings {
        buckets
            .entry(category_key(finding.category))
            .or_default()
            .push(*label != SampleLabel::Benign);
    }
    finalize_calibration_buckets(buckets)
}

fn calibration_buckets_by_signal_pair(
    findings: &[(SampleLabel, Finding)],
) -> Vec<CalibrationBucket> {
    let mut buckets = BTreeMap::<String, Vec<bool>>::new();
    for (label, finding) in findings {
        let key = format!(
            "{}+{}",
            evidence_key(finding.evidence_kind),
            category_key(finding.category)
        );
        buckets
            .entry(key)
            .or_default()
            .push(*label != SampleLabel::Benign);
    }
    finalize_calibration_buckets(buckets)
}

fn finalize_calibration_buckets(buckets: BTreeMap<String, Vec<bool>>) -> Vec<CalibrationBucket> {
    buckets
        .into_iter()
        .map(|(key, labels)| {
            let findings = u32::try_from(labels.len()).unwrap_or(u32::MAX);
            let true_positive =
                u32::try_from(labels.iter().filter(|is_positive| **is_positive).count())
                    .unwrap_or(u32::MAX);
            let false_positive = findings.saturating_sub(true_positive);
            let observed_precision = if findings == 0 {
                0.0
            } else {
                true_positive as f32 / findings as f32
            };
            CalibrationBucket {
                key,
                findings,
                true_positive,
                false_positive,
                observed_precision,
                recommended_confidence: calibrate_confidence_value(observed_precision, findings),
            }
        })
        .collect()
}

fn calibrate_confidence_value(observed_precision: f32, findings: u32) -> f32 {
    // An empty bucket (no labelled findings) carries no statistical
    // signal; pre-fix the `findings.max(1)` coercion produced
    // `recommended_confidence = 0.35` which downstream readers cannot
    // distinguish from a real 0.35 calibration. NaN is the right
    // sentinel — `f32::is_nan()` flips clean and serializes to JSON
    // `null` via serde, so consumers can render "no data".
    if findings == 0 {
        return f32::NAN;
    }
    let lower_bound = wilson_lower_bound(observed_precision, findings);
    (CONFIDENCE_FLOOR + (lower_bound * CONFIDENCE_WILSON_SCALE))
        .clamp(CONFIDENCE_LOWER_CLAMP, CONFIDENCE_UPPER_CLAMP)
}

fn wilson_lower_bound(observed_precision: f32, findings: u32) -> f32 {
    debug_assert!(
        findings > 0,
        "wilson_lower_bound: callers must guard `findings == 0` themselves",
    );
    let sample_count = findings.max(1) as f32;
    let z_score_95 = WILSON_Z_SCORE_95;
    let z_score_squared = z_score_95 * z_score_95;
    let center = observed_precision + z_score_squared / (2.0 * sample_count);
    let margin = z_score_95
        * ((observed_precision * (1.0 - observed_precision)
            + z_score_squared / (4.0 * sample_count))
            / sample_count)
            .sqrt();
    let denominator = 1.0 + z_score_squared / sample_count;
    ((center - margin) / denominator).clamp(0.0, 1.0)
}

fn evidence_key(kind: EvidenceKind) -> String {
    kind.to_string()
}

fn category_key(category: ThreatCategory) -> String {
    category.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibrate_confidence_groups_by_evidence() {
        let findings = vec![
            (
                SampleLabel::Malicious,
                Finding::builder("A", ThreatCategory::RemoteExec)
                    .evidence_kind(EvidenceKind::Behavior)
                    .reason("x")
                    .match_value("x")
                    .build(),
            ),
            (
                SampleLabel::Benign,
                Finding::builder("B", ThreatCategory::SocialManipulation)
                    .evidence_kind(EvidenceKind::Intent)
                    .reason("y")
                    .match_value("y")
                    .build(),
            ),
        ];

        let calibration = calibrate_confidence(&findings);
        assert_eq!(calibration.by_evidence_kind.len(), 2);
        assert!(calibration
            .by_evidence_kind
            .iter()
            .any(|bucket| bucket.key == "behavior" && bucket.true_positive == 1));
        assert!(calibration
            .by_signal_pair
            .iter()
            .any(|bucket| bucket.key == "behavior+remote_exec"));
    }

    /// Contract: `calibrate_confidence_value` returns NaN for an empty
    /// bucket. Pre-fix `findings.max(1)` coerced the empty case to 1 and
    /// returned `0.35` — a plausible-looking number that downstream
    /// consumers couldn't distinguish from a real low-precision bucket.
    /// NaN is the unambiguous "no data" sentinel.
    #[test]
    fn calibrate_confidence_value_returns_nan_for_empty_bucket() {
        let result = calibrate_confidence_value(0.0, 0);
        assert!(
            result.is_nan(),
            "empty bucket must produce NaN; got {result}",
        );
    }

    /// Contract: a non-empty bucket produces a finite confidence in
    /// `[0.1, 0.99]`. Positive-case regression guard so the NaN
    /// early-return doesn't accidentally widen.
    #[test]
    fn calibrate_confidence_value_finite_for_non_empty_bucket() {
        let result = calibrate_confidence_value(0.5, 10);
        assert!(result.is_finite(), "non-empty bucket must be finite");
        assert!((0.1..=0.99).contains(&result));
    }
}
