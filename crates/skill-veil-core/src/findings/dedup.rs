use super::{ArtifactKind, ArtifactScope, Finding};
use crate::policy::fingerprint::MIN_RELATIVE_SUFFIX_COMPONENTS;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::Path;

/// Summary of the scanner deduplication pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeduplicationSummary {
    pub original_findings: usize,
    pub unique_findings: usize,
    pub duplicates_removed: usize,
}

/// `Ord`/`PartialOrd` lets `deduplicate_findings` store entries in a
/// `BTreeMap` keyed on this struct. The motivation is defence-in-depth
/// rather than a current bug: Rust's `HashMap` uses `RandomState` by
/// default, randomising bucket layout across processes. Today the final
/// `unique_findings` Vec is fully sorted before return, so the output
/// is already deterministic; switching to `BTreeMap` removes the
/// HashMap dependency on `RandomState` entirely and protects future
/// refactors that might iterate the map before sorting.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct FindingDedupKey {
    rule_id: String,
    category: super::ThreatCategory,
    matched_on: String,
    match_value: String,
    artifact_kind: ArtifactKind,
    artifact_scope: ArtifactScope,
    artifact_path: Option<String>,
}

/// Whether `artifact_path` should be considered to identify the same artifact as
/// `primary` for scope-splitting purposes.
///
/// Contract:
/// - Empty artifact paths never match.
/// - Exact `Path` equality always matches.
/// - One-component bare filenames match when `primary.ends_with(artifact_path)`
///   (single-document scan invariant).
/// - Multi-component relative suffixes match only when the shorter side has
///   `>= MIN_RELATIVE_SUFFIX_COMPONENTS` components. The threshold is shared
///   with `crate::policy::fingerprint::paths_match` (waiver / baseline /
///   override matching) — keep them aligned so scope attribution and waiver
///   suppression agree on what "the same artifact" means.
/// - Other cases (including 2-component relatives, mixed absolute/relative
///   non-equal pairs) do not match.
fn primary_path_matches(primary: &Path, artifact_path: &str) -> bool {
    if artifact_path.is_empty() {
        return false;
    }
    let ap = Path::new(artifact_path);
    if ap == primary {
        return true;
    }
    let ap_components = ap.components().count();
    let primary_components = primary.components().count();
    if ap_components == 1 {
        return primary.ends_with(ap);
    }
    // Mirror `policy::fingerprint::paths_match`: both directions of the suffix
    // relation are valid when the shorter side has ≥ MIN_RELATIVE_SUFFIX_COMPONENTS
    // components. Pre-fix only `primary.ends_with(ap)` was considered, so a
    // primary captured at the relative end (`pkg/src/main.rs`) and an artifact
    // path at the absolute end (`/repo/pkg/src/main.rs`) didn't dedup as the
    // same artifact, even though `paths_match` (used for waiver matching) did
    // treat them as equivalent. The asymmetry let scope-splitting and waiver
    // suppression diverge.
    if ap_components >= MIN_RELATIVE_SUFFIX_COMPONENTS && primary.ends_with(ap) {
        return true;
    }
    if primary_components >= MIN_RELATIVE_SUFFIX_COMPONENTS && ap.ends_with(primary) {
        return true;
    }
    false
}

/// Split findings into primary (entrypoint) and supporting (referenced artifacts) groups.
///
/// A finding is considered primary if it matches the primary path and artifact kind,
/// or if it is a path-less finding whose artifact kind matches the primary kind.
///
/// Path matching is performed by `primary_path_matches`, which compares whole path
/// components and rejects 2-component relative suffixes (which would otherwise
/// silently collide across sibling packages in monorepo or dataset scans). One-
/// component bare filenames are still accepted because the primary path is fixed
/// for the duration of a single-document scan.
pub(crate) fn split_findings_by_scope(
    path: &Path,
    primary_artifact_kind: ArtifactKind,
    findings: &[Finding],
) -> (Vec<Finding>, Vec<Finding>) {
    findings.iter().cloned().partition(|finding| {
        finding.artifact_kind == primary_artifact_kind
            && (finding.artifact_path.is_none()
                || finding
                    .artifact_path
                    .as_deref()
                    .is_some_and(|artifact_path| primary_path_matches(path, artifact_path)))
    })
}

/// Lexicographic descending strength of a finding: `(action, severity, confidence)`.
///
/// `recommended_action` is the dominant axis because the rest of the codebase
/// keys on it for verdict decisions (`select_recommended_action` in
/// `findings/summary.rs`, `recalculate_group_action_excluding` in
/// `verdict_calibration.rs`, and the joint `(action, signal_class)` reads in
/// `verdict/predicates.rs` and `verdict/blast_radius.rs`). `confidence` is f32
/// and uses `partial_cmp().unwrap_or(Equal)` (NaN treated as equal — finding
/// confidences are bounded `[0, 1]` by the builder, so NaN shouldn't occur).
fn cmp_finding_strength(candidate: &Finding, existing: &Finding) -> Ordering {
    candidate
        .recommended_action
        .cmp(&existing.recommended_action)
        .then_with(|| candidate.severity.cmp(&existing.severity))
        .then_with(|| {
            candidate
                .confidence
                .partial_cmp(&existing.confidence)
                .unwrap_or(Ordering::Equal)
        })
}

/// Merge `candidate` into `existing` for two findings sharing the same dedup key.
///
/// Qualitative fields (`recommended_action`, `signal_class`, `evidence_kind`,
/// `reason`, `remediation`, `raw_confidence`, `confidence_rationale`) are taken
/// **as a set** from the strength winner — the finding with the greater
/// `(action, severity, confidence)` tuple. This eliminates the historical
/// incoherence where `recommended_action` came from one finding while
/// `signal_class` came from another, producing pairs like
/// `(action=Block, signal_class=ReviewSignal)` that fool `verdict::predicates`
/// and `verdict::blast_radius` into the wrong tier.
///
/// `severity` and `confidence` remain max-aggregated independently — they are
/// scalar metrics and "worst severity wins" is a meaningful invariant.
///
/// On a total tie of `(action, severity, confidence)`, fall through to the
/// stable "longer text wins" tiebreak for `reason` and `remediation`. The
/// `line_number` field preserves first-non-None: duplicates by definition share
/// `match_value`, so any non-None line number is co-located with the same site.
fn merge_into(existing: &mut Finding, candidate: Finding) {
    let order = cmp_finding_strength(&candidate, existing);
    let candidate_is_stronger = order == Ordering::Greater;

    existing.severity = existing.severity.max(candidate.severity);
    // `confidence` is sanitized in the builder to be finite within `[0, 1]`,
    // but external YAML rule packs could introduce NaN. Handle explicitly:
    // if existing is NaN we always replace; if only candidate is NaN we
    // keep existing; otherwise we take the max.
    if existing.confidence.is_nan()
        || (!candidate.confidence.is_nan() && candidate.confidence > existing.confidence)
    {
        existing.confidence = candidate.confidence;
    }

    if candidate_is_stronger {
        existing.recommended_action = candidate.recommended_action;
        existing.signal_class = candidate.signal_class;
        existing.evidence_kind = candidate.evidence_kind;
        existing.raw_confidence = candidate.raw_confidence;
        existing.confidence_rationale = candidate.confidence_rationale;
        existing.reason = candidate.reason;
        existing.remediation = candidate.remediation;
    } else if order == Ordering::Equal {
        if candidate.reason.len() > existing.reason.len() {
            existing.reason = candidate.reason;
        }
        if candidate.remediation.len() > existing.remediation.len() {
            existing.remediation = candidate.remediation;
        }
    }

    if existing.line_number.is_none() {
        existing.line_number = candidate.line_number;
    }
}

/// Deduplicate findings that match on the same rule, category, match target,
/// artifact kind, and artifact path.
///
/// # Merge Semantics
///
/// - **Severity**: max of the two findings (scalar aggregate).
/// - **Confidence**: max of the two findings (scalar aggregate).
/// - **RecommendedAction, SignalClass, EvidenceKind, Reason, Remediation,
///   RawConfidence, ConfidenceRationale**: all taken from the strength winner —
///   the finding with the greater `(action, severity, confidence)` tuple.
///   Aligning these fields prevents incoherent pairs like
///   `(action=Block, signal_class=ReviewSignal)` that would otherwise mislead
///   `verdict::predicates` and `verdict::blast_radius`.
/// - **Reason / Remediation tie-break**: when the strength tuple ties exactly,
///   the longer text wins (stable preservation of the more informative entry).
/// - **Line number**: first non-None value encountered. Duplicates share
///   `match_value` (it's part of the dedup key), so any non-None line number
///   is co-located with the same evidence site.
///
/// `signal_class` is intentionally NOT part of `FindingDedupKey`. Two findings
/// emitted with the same rule on the same match value but different signal
/// classes are correctly merged here; splitting them would silently inflate
/// finding counts and risk score on emitter quirks.
#[must_use]
pub fn deduplicate_findings(findings: Vec<Finding>) -> (Vec<Finding>, DeduplicationSummary) {
    let original_findings = findings.len();
    // `BTreeMap` (not HashMap) — deterministic iteration order so the
    // post-merge `Finding` for an equal-strength tie no longer depends
    // on HashMap's run-to-run iteration permutation. Tie-break in
    // `merge_into` falls back to "longer text wins" but only the
    // first-encountered finding hits `or_insert`; with BTreeMap the
    // "first encountered" key is deterministic.
    let mut deduped = std::collections::BTreeMap::<FindingDedupKey, Finding>::new();

    for finding in findings {
        let key = FindingDedupKey {
            rule_id: finding.rule_id.clone(),
            category: finding.category,
            // Normalise case so that section-name casing differences
            // (e.g. "Setup" vs "SETUP") don't split findings that are
            // logically the same.  The matching engine is
            // case-insensitive; the dedup key must agree.
            matched_on: finding.matched_on.to_string().to_ascii_lowercase(),
            match_value: finding.match_value.clone(),
            artifact_kind: finding.artifact_kind,
            artifact_scope: finding.artifact_scope,
            artifact_path: finding.artifact_path.clone(),
        };

        deduped
            .entry(key)
            .and_modify(|existing| merge_into(existing, finding.clone()))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `primary_path_matches` mirrors `policy::fingerprint::paths_match`
    /// when the artifact path is a relative suffix (≥3 components) of the
    /// primary. This is the case the pre-fix code already covered.
    #[test]
    fn primary_path_matches_artifact_suffix_of_primary() {
        let primary = Path::new("/repo/pkg/src/main.rs");
        assert!(primary_path_matches(primary, "pkg/src/main.rs"));
    }

    /// Contract: the inverse direction must also match — when the *primary*
    /// is the relative suffix and the *artifact_path* is the longer absolute.
    /// Pre-fix only `primary.ends_with(ap)` was checked, so this case
    /// silently failed even though `policy::fingerprint::paths_match` (used for
    /// waiver matching) treated them as equivalent. The mismatch produced
    /// scope-splitting / waiver-suppression drift.
    #[test]
    fn primary_path_matches_primary_suffix_of_artifact() {
        let primary = Path::new("pkg/src/main.rs");
        assert!(primary_path_matches(primary, "/repo/pkg/src/main.rs"));
    }

    /// Contract: 1-component bare filenames still match by primary suffix
    /// (single-document scan invariant). Negative-case regression guard for
    /// the new inverse branch — it must NOT widen the 1-component rule.
    #[test]
    fn primary_path_matches_one_component_filename_still_matches() {
        let primary = Path::new("/repo/skill.md");
        assert!(primary_path_matches(primary, "skill.md"));
    }

    /// Contract: 2-component relative paths NEITHER direction must match.
    /// Pre-fix this was honoured because of the unidirectional check; the
    /// fix must keep this rejection in both directions to avoid the
    /// monorepo cross-package collision the constant guards against.
    #[test]
    fn primary_path_matches_rejects_two_component_relative_in_either_direction() {
        let primary_long = Path::new("/repo-a/config/skill.md");
        assert!(!primary_path_matches(primary_long, "config/skill.md"));
        let primary_short = Path::new("config/skill.md");
        assert!(!primary_path_matches(
            primary_short,
            "/repo-a/config/skill.md"
        ));
    }

    /// # Contract
    ///
    /// `deduplicate_findings` MUST be deterministic across repeated
    /// invocations on byte-identical input. Pre-fix the implementation
    /// used `std::collections::HashMap` whose bucket layout depends on
    /// `RandomState`; the final sort kept the output Vec stable in
    /// practice, but any future refactor that iterates the map before
    /// the sort would expose the randomness. Switching to `BTreeMap`
    /// makes the iteration order a function of the dedup key only, so
    /// determinism is a property of the data, not of `RandomState`.
    /// This test also pins the longer-text tie-break: regardless of
    /// input order, the merged finding's `reason` is the longer of the
    /// two equal-strength inputs.
    #[test]
    fn deduplicate_findings_is_deterministic_on_equal_strength_ties() {
        use crate::findings::{
            EvidenceKind, MatchTarget, RecommendedAction, Severity, ThreatCategory,
        };

        let make = |reason: &str| {
            Finding::builder("DUP_RULE", ThreatCategory::ToolAbuse)
                .severity(Severity::Medium)
                .confidence(0.5)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .matched_on(MatchTarget::Document)
                .match_value("same-value")
                .reason(reason.to_string())
                .build()
        };
        let short = make("short reason");
        let long = make("a substantially longer reason — chosen by the tie-break");

        let (out_a, _) = deduplicate_findings(vec![short.clone(), long.clone()]);
        let (out_b, _) = deduplicate_findings(vec![long.clone(), short.clone()]);
        let (out_c, _) = deduplicate_findings(vec![short.clone(), long.clone()]);

        assert_eq!(out_a.len(), 1, "duplicates must collapse to one");
        assert_eq!(out_b.len(), 1);
        assert_eq!(
            out_a[0].reason, out_b[0].reason,
            "merged reason MUST be order-independent for equal-strength findings; \
             got {:?} vs {:?}",
            out_a[0].reason, out_b[0].reason
        );
        assert_eq!(
            out_a[0].reason, out_c[0].reason,
            "running deduplicate_findings twice on the same input MUST yield the same merged finding",
        );
        assert!(
            out_a[0].reason.contains("substantially longer"),
            "tie-break MUST pick the longer reason; got {:?}",
            out_a[0].reason
        );
    }
}
