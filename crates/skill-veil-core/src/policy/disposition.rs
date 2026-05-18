//! Analyst feedback loop — production triage as training signal.
//!
//! An analyst's real disposition of a finding ("was what we flagged
//! actually malicious?") is the highest-quality label the system ever
//! sees. This module records those dispositions in a project-local
//! overlay (NEVER the signed external rule pack) and derives, per
//! rule, a bounded confidence adjustment and an allowlist promotion.
//!
//! # Safety model — read before touching the math
//!
//! Feedback can only ever REDUCE aggressiveness: the allowlist demotes
//! a rule's findings to `Log`, never manufactures a Block. The
//! confidence delta is Laplace-smoothed and hard-clamped, so neither a
//! handful of records nor a poisoned overlay can swing a rule's
//! confidence to either extreme. A malicious overlay cannot weaponise
//! the scanner — the worst it can do is silence a rule the analyst
//! population already judged noisy.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::types::default_policy_schema_version;

/// Learning rate on the centred TP-rate. Small: a rule needs a clear,
/// sustained signal to move, not a couple of records.
const CONFIDENCE_LEARN_RATE: f32 = 0.30;
/// Hard cap on |delta| regardless of record count — the anti-poisoning
/// bound. No overlay can move a rule's confidence by more than this.
const MAX_CONFIDENCE_DELTA: f32 = 0.15;
/// Adjusted confidence is clamped into `[MIN, MAX]` so feedback can
/// neither zero out nor saturate a rule.
const MIN_LEARNED_CONFIDENCE: f32 = 0.05;
const MAX_LEARNED_CONFIDENCE: f32 = 0.99;
/// Minimum false-positive disposition count before a rule is eligible
/// for allowlist demotion — mirrors the empirical-evidence discipline
/// used for `CONCLUSIVE_SINGLE_RULE_IDS`.
const ALLOWLIST_MIN_FP_SAMPLES: usize = 8;
/// A rule is allowlist-eligible only when its smoothed true-positive
/// rate is below this — i.e. the analyst population overwhelmingly
/// judged it noise.
const ALLOWLIST_MAX_TP_RATE: f32 = 0.15;

/// What the analyst decided the flagged finding actually was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Correctly flagged — a real malicious signal.
    TruePositive,
    /// Incorrectly flagged on a benign artifact.
    FalsePositive,
    /// Benign artifact (treated identically to a false positive for
    /// the rule-confidence math; kept distinct for audit).
    Benign,
}

impl Disposition {
    fn is_true_positive(self) -> bool {
        matches!(self, Disposition::TruePositive)
    }
}

/// One recorded analyst disposition. Append-only; never edited.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispositionRecord {
    pub finding_fingerprint: String,
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub analyst_disposition: Disposition,
    pub recorded_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Project-local disposition overlay. A SEPARATE file from the signed
/// rule pack — that pack and its detached signature are never touched.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispositionOverlay {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub records: Vec<DispositionRecord>,
}

impl Default for DispositionOverlay {
    fn default() -> Self {
        Self {
            schema_version: default_policy_schema_version(),
            records: Vec::new(),
        }
    }
}

/// `(true_positive, non_true_positive)` disposition counts per rule.
/// `Benign` and `FalsePositive` both count as non-TP.
fn per_rule_counts(overlay: &DispositionOverlay) -> BTreeMap<String, (usize, usize)> {
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for r in &overlay.records {
        let entry = counts.entry(r.rule_id.clone()).or_insert((0, 0));
        if r.analyst_disposition.is_true_positive() {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }
    counts
}

/// Laplace-smoothed true-positive rate, centred so 0.5 is "no signal".
fn smoothed_tp_rate(tp: usize, fp: usize) -> f32 {
    (tp as f32 + 1.0) / (tp as f32 + fp as f32 + 2.0)
}

/// Per-rule confidence delta. Signed, monotone in the TP rate, and
/// hard-bounded by `±MAX_CONFIDENCE_DELTA` regardless of record count.
#[must_use]
pub fn learned_confidence_adjustments(overlay: &DispositionOverlay) -> BTreeMap<String, f32> {
    per_rule_counts(overlay)
        .into_iter()
        .map(|(rule, (tp, fp))| {
            let delta = (CONFIDENCE_LEARN_RATE * (smoothed_tp_rate(tp, fp) - 0.5))
                .clamp(-MAX_CONFIDENCE_DELTA, MAX_CONFIDENCE_DELTA);
            (rule, delta)
        })
        .collect()
}

/// Rules the analyst population judged overwhelmingly noisy: enough FP
/// samples AND a smoothed TP rate below the threshold. Membership only
/// ever DEMOTES a rule's findings to `Log` downstream.
#[must_use]
pub fn learned_allowlist(overlay: &DispositionOverlay) -> BTreeSet<String> {
    per_rule_counts(overlay)
        .into_iter()
        .filter(|&(_, (tp, fp))| {
            fp >= ALLOWLIST_MIN_FP_SAMPLES && smoothed_tp_rate(tp, fp) < ALLOWLIST_MAX_TP_RATE
        })
        .map(|(rule, _)| rule)
        .collect()
}

/// Apply a learned delta to a base confidence, hard-clamped into the
/// safe band. Pure.
#[must_use]
pub fn adjust_confidence(base: f32, delta: f32) -> f32 {
    (base + delta).clamp(MIN_LEARNED_CONFIDENCE, MAX_LEARNED_CONFIDENCE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(rule: &str, d: Disposition) -> DispositionRecord {
        DispositionRecord {
            finding_fingerprint: format!("fp-{rule}-{d:?}"),
            rule_id: rule.to_string(),
            sha256: None,
            analyst_disposition: d,
            recorded_at: Utc::now(),
            note: None,
        }
    }

    fn overlay(records: Vec<DispositionRecord>) -> DispositionOverlay {
        DispositionOverlay {
            schema_version: "1".into(),
            records,
        }
    }

    /// Contract: more TP strictly raises the delta, more FP strictly
    /// lowers it (monotone in the TP ratio), both directions.
    #[test]
    fn confidence_delta_is_monotone_in_tp_ratio() {
        let mostly_tp = overlay(vec![
            rec("R", Disposition::TruePositive),
            rec("R", Disposition::TruePositive),
            rec("R", Disposition::TruePositive),
            rec("R", Disposition::FalsePositive),
        ]);
        let mostly_fp = overlay(vec![
            rec("R", Disposition::FalsePositive),
            rec("R", Disposition::FalsePositive),
            rec("R", Disposition::FalsePositive),
            rec("R", Disposition::TruePositive),
        ]);
        let up = learned_confidence_adjustments(&mostly_tp)["R"];
        let down = learned_confidence_adjustments(&mostly_fp)["R"];
        assert!(up > 0.0, "TP-heavy must raise confidence: {up}");
        assert!(down < 0.0, "FP-heavy must lower confidence: {down}");
        assert!(up > down);
    }

    /// Contract: |delta| is hard-bounded no matter how many records —
    /// the anti-poisoning guarantee.
    #[test]
    fn confidence_delta_is_hard_bounded() {
        let flood: Vec<_> = (0..10_000)
            .map(|_| rec("R", Disposition::TruePositive))
            .collect();
        let d = learned_confidence_adjustments(&overlay(flood))["R"];
        assert!(d <= MAX_CONFIDENCE_DELTA, "delta exceeded the cap: {d}");
        assert!(adjust_confidence(0.95, d) <= MAX_LEARNED_CONFIDENCE);
        assert!(adjust_confidence(0.0, -1.0) >= MIN_LEARNED_CONFIDENCE);
    }

    /// Contract: allowlist promotion needs BOTH enough FP samples AND
    /// a low TP rate (both directions).
    #[test]
    fn allowlist_requires_min_samples_and_low_tp_rate() {
        let few_fp = overlay(vec![
            rec("R", Disposition::FalsePositive),
            rec("R", Disposition::FalsePositive),
            rec("R", Disposition::FalsePositive),
        ]);
        assert!(
            !learned_allowlist(&few_fp).contains("R"),
            "3 FP must not allowlist"
        );

        let many_fp = overlay(
            (0..ALLOWLIST_MIN_FP_SAMPLES)
                .map(|_| rec("R", Disposition::FalsePositive))
                .collect(),
        );
        assert!(
            learned_allowlist(&many_fp).contains("R"),
            "{ALLOWLIST_MIN_FP_SAMPLES} FP with ~0 TP rate must allowlist"
        );

        let mut mixed: Vec<_> = (0..ALLOWLIST_MIN_FP_SAMPLES)
            .map(|_| rec("R", Disposition::FalsePositive))
            .collect();
        mixed.extend((0..ALLOWLIST_MIN_FP_SAMPLES).map(|_| rec("R", Disposition::TruePositive)));
        assert!(
            !learned_allowlist(&overlay(mixed)).contains("R"),
            "a high TP rate must keep the rule active even with many FP"
        );
    }

    /// Contract (negative): an empty overlay is the identity — no
    /// adjustments, empty allowlist. Pins the default path unchanged.
    #[test]
    fn empty_overlay_is_identity() {
        let o = overlay(vec![]);
        assert!(learned_confidence_adjustments(&o).is_empty());
        assert!(learned_allowlist(&o).is_empty());
    }

    /// Contract: new schema fields are additive — a minimal overlay
    /// (only records, no schema_version) round-trips.
    #[test]
    fn overlay_deserialises_additively() {
        let json = r#"{"records":[{"finding_fingerprint":"x","rule_id":"R","analyst_disposition":"false_positive","recorded_at":"2026-01-01T00:00:00Z"}]}"#;
        let o: DispositionOverlay = serde_json::from_str(json).unwrap();
        assert_eq!(o.records.len(), 1);
        assert_eq!(o.records[0].analyst_disposition, Disposition::FalsePositive);
        assert!(!o.schema_version.is_empty());
    }
}
