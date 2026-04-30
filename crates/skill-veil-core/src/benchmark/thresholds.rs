//! Threshold-recommendation grid search for the benchmark harness.
//!
//! Sweeps the `(approval_threshold, block_threshold)` plane against the
//! current corpus and selects the operating point that maximises a
//! weighted objective (precision + recall + accuracy − FPR penalty −
//! label-distance regulariser) under a recall-tolerance constraint.
//!
//! Lives separately from [`super::evaluation`] (corpus orchestration)
//! and [`super::calibration`] (Wilson-bound confidence) because the
//! search is a self-contained discrete optimisation with its own
//! tuning knobs.

use super::types::{RegressionMetrics, SampleEvaluation, SampleLabel, ThresholdRecommendation};

/// Lower / upper bound for the approval-threshold sweep used by the
/// `recommend_thresholds` grid search. Anchored well below any
/// real-world block threshold so the search can always cross.
const APPROVAL_THRESHOLD_SEARCH_MIN: u32 = 10;
const APPROVAL_THRESHOLD_SEARCH_MAX: u32 = 50;
/// Lower / upper bound for the block-threshold sweep. Search is bounded
/// below `100` so the recommended block threshold never collapses onto
/// the saturating end of the risk score.
const BLOCK_THRESHOLD_SEARCH_MIN: u32 = 30;
const BLOCK_THRESHOLD_SEARCH_MAX: u32 = 90;
/// Step (in risk-score units) between successive grid points; keeps the
/// double loop at ~21 × 31 = 651 evaluations rather than the dense form.
const THRESHOLD_SEARCH_STEP: usize = 2;

/// Weights of the threshold-selection objective. Precision and recall
/// are equal-weighted, accuracy is a tiebreaker, false-positive rate is
/// a hard penalty, and label-distance is a small monotonic regulariser.
/// Adjust together — the values are jointly tuned against the corpus
/// and changing one in isolation drifts the optimiser.
const OBJ_PRECISION_WEIGHT: f32 = 0.35;
const OBJ_RECALL_WEIGHT: f32 = 0.35;
const OBJ_ACCURACY_WEIGHT: f32 = 0.20;
const OBJ_FALSE_POSITIVE_PENALTY: f32 = 0.55;
const OBJ_LABEL_ERROR_PENALTY: f32 = 0.01;
/// Slack permitted on recall vs the current operating point. A
/// candidate threshold is only adopted if its recall stays within this
/// margin of the baseline; prevents the optimiser from trading away
/// recall for FPR gains.
const OBJ_RECALL_TOLERANCE: f32 = 0.02;

pub(super) fn recommend_thresholds(samples: &[SampleEvaluation]) -> ThresholdRecommendation {
    let current_approval_threshold = crate::findings::RISK_THRESHOLD_APPROVAL;
    let current_block_threshold = crate::findings::RISK_THRESHOLD_BLOCK;
    let expected: Vec<_> = samples.iter().map(|sample| sample.expected).collect();
    let current_actual: Vec<_> = samples
        .iter()
        .map(|sample| {
            classify_with_thresholds(
                sample.risk_score,
                current_approval_threshold,
                current_block_threshold,
            )
        })
        .collect();
    let current_metrics = super::evaluation::compute_metrics(&expected, &current_actual);
    let mut best_score = threshold_objective(&current_metrics, samples, &current_actual);

    let mut best_approval = current_approval_threshold;
    let mut best_block = current_block_threshold;
    let mut best_metrics = current_metrics;

    for approval in (APPROVAL_THRESHOLD_SEARCH_MIN..=APPROVAL_THRESHOLD_SEARCH_MAX)
        .step_by(THRESHOLD_SEARCH_STEP)
    {
        for block in
            (BLOCK_THRESHOLD_SEARCH_MIN..=BLOCK_THRESHOLD_SEARCH_MAX).step_by(THRESHOLD_SEARCH_STEP)
        {
            if block <= approval {
                continue;
            }

            let actual: Vec<_> = samples
                .iter()
                .map(|sample| classify_with_thresholds(sample.risk_score, approval, block))
                .collect();
            let metrics = super::evaluation::compute_metrics(&expected, &actual);
            let score = threshold_objective(&metrics, samples, &actual);
            let acceptable_recall = current_metrics.recall == 0.0
                || metrics.recall + OBJ_RECALL_TOLERANCE >= current_metrics.recall;

            if acceptable_recall && score > best_score {
                best_approval = approval;
                best_block = block;
                best_metrics = metrics;
                best_score = score;
            }
        }
    }

    ThresholdRecommendation {
        current_approval_threshold,
        current_block_threshold,
        recommended_approval_threshold: best_approval,
        recommended_block_threshold: best_block,
        current_metrics,
        recommended_metrics: best_metrics,
        rationale: format!(
            "Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score {:.3}).",
            best_score
        ),
    }
}

fn threshold_objective(
    metrics: &RegressionMetrics,
    samples: &[SampleEvaluation],
    actual: &[SampleLabel],
) -> f32 {
    let label_error_penalty = samples
        .iter()
        .zip(actual.iter())
        .map(|(sample, predicted)| label_distance(sample.expected, *predicted) as f32)
        .sum::<f32>();

    (metrics.precision * OBJ_PRECISION_WEIGHT)
        + (metrics.recall * OBJ_RECALL_WEIGHT)
        + (metrics.accuracy * OBJ_ACCURACY_WEIGHT)
        - (metrics.false_positive_rate * OBJ_FALSE_POSITIVE_PENALTY)
        - (label_error_penalty * OBJ_LABEL_ERROR_PENALTY)
}

fn label_distance(expected: SampleLabel, actual: SampleLabel) -> u32 {
    let rank = |label| match label {
        SampleLabel::Benign => 0_u32,
        SampleLabel::Suspicious => 1_u32,
        SampleLabel::Malicious => 2_u32,
    };
    rank(expected).abs_diff(rank(actual))
}

fn classify_with_thresholds(
    risk_score: u32,
    approval_threshold: u32,
    block_threshold: u32,
) -> SampleLabel {
    if risk_score >= block_threshold {
        SampleLabel::Malicious
    } else if risk_score >= approval_threshold {
        SampleLabel::Suspicious
    } else {
        SampleLabel::Benign
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RecommendedAction, ThreatCategory, Verdict};
    use std::path::PathBuf;

    #[test]
    fn test_recommend_thresholds_can_reduce_false_positive_rate() {
        let samples = vec![
            SampleEvaluation {
                id: "benign-doc".to_string(),
                expected: SampleLabel::Benign,
                actual: SampleLabel::Suspicious,
                verdict: Verdict::Suspicious,
                focus_category: None,
                attack_family: None,
                recommended_action: RecommendedAction::RequireApproval,
                risk_score: 22,
                finding_count: 1,
                primary_finding_count: 1,
                supporting_finding_count: 0,
                duplicates_removed: 0,
                path: PathBuf::from("benign-doc/SKILL.md"),
            },
            SampleEvaluation {
                id: "benign-safe".to_string(),
                expected: SampleLabel::Benign,
                actual: SampleLabel::Benign,
                verdict: Verdict::Benign,
                focus_category: None,
                attack_family: None,
                recommended_action: RecommendedAction::Log,
                risk_score: 10,
                finding_count: 0,
                primary_finding_count: 0,
                supporting_finding_count: 0,
                duplicates_removed: 0,
                path: PathBuf::from("benign-safe/SKILL.md"),
            },
            SampleEvaluation {
                id: "malicious".to_string(),
                expected: SampleLabel::Malicious,
                actual: SampleLabel::Malicious,
                verdict: Verdict::Malicious,
                focus_category: Some(ThreatCategory::RemoteExec),
                attack_family: Some("remote_exec".to_string()),
                recommended_action: RecommendedAction::Block,
                risk_score: 72,
                finding_count: 3,
                primary_finding_count: 2,
                supporting_finding_count: 1,
                duplicates_removed: 0,
                path: PathBuf::from("malicious/SKILL.md"),
            },
        ];

        let recommendation = recommend_thresholds(&samples);
        assert!(
            recommendation.recommended_metrics.false_positive_rate
                <= recommendation.current_metrics.false_positive_rate
        );
        assert!(!recommendation.rationale.is_empty());
    }
}
