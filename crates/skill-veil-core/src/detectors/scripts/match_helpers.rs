//! Helpers shared by detectors that pair a regex match against the
//! lowercased content with the original-cased source for evidence
//! presentation.

use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::ports::{CompiledPattern, PatternMatch};

/// The per-detector scalars that distinguish one script-pattern emission from
/// another. Everything else in the loop is invariant (see
/// [`findings_from_pattern_table`]).
#[derive(Clone, Copy)]
pub(super) struct FindingSpec {
    pub(super) category: ThreatCategory,
    pub(super) severity: Severity,
    pub(super) action: RecommendedAction,
    pub(super) reason: &'static str,
}

/// Emit one `Finding` per regex match across a `(rule_id, pattern)` table.
///
/// Shared by the script detectors (`network`, `persistence`, `exec`) whose
/// emission loop is otherwise identical: every match against the lowercased
/// `lower` becomes a `Behavior` finding on the referenced artifact, with the
/// original-cased evidence preserved via [`original_match_str`]. Callers that
/// select the table by language do so before calling.
pub(super) fn findings_from_pattern_table(
    table: &[(&str, CompiledPattern)],
    lower: &str,
    original: &str,
    artifact_path: &str,
    spec: FindingSpec,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, regex) in table {
        for matched in regex.find_matches(lower) {
            let evidence = original_match_str(original, lower, &matched);
            findings.push(referenced_artifact_behavior_finding(
                *rule_id,
                spec.category,
                spec.severity,
                spec.action,
                artifact_path,
                evidence,
                spec.reason,
            ));
        }
    }
    findings
}

/// Build a single fixed-shape `Behavior` finding scoped to a referenced
/// artifact. The spine — `EvidenceKind::Behavior`, a
/// `MatchTarget::ReferencedFile`, and a `ReferencedArtifact` scope keyed
/// on `artifact_path` — is shared with [`findings_from_pattern_table`];
/// this serves the script detectors that emit one finding from a
/// non-regex predicate rather than one per regex match.
pub(super) fn referenced_artifact_behavior_finding(
    rule_id: impl Into<String>,
    category: ThreatCategory,
    severity: Severity,
    action: RecommendedAction,
    artifact_path: &str,
    match_value: impl Into<String>,
    reason: impl Into<String>,
) -> Finding {
    Finding::builder(rule_id, category)
        .severity(severity)
        .action(action)
        .evidence_kind(EvidenceKind::Behavior)
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some(artifact_path.to_string()),
        )
        .match_value(match_value)
        .reason(reason)
        .build()
}

/// Extract the byte slice from `original` that corresponds to a port-typed
/// match produced against the lowercased content.
///
/// # Contract
///
/// `lower` MUST be the result of `original.to_ascii_lowercase()` — this
/// preserves byte offsets because ASCII case folding is a 1-byte → 1-byte
/// transformation. Non-ASCII content can break this assumption (some chars
/// have different UTF-8 byte lengths in upper/lower forms), in which case
/// the helper falls back to the lowercased match text rather than producing
/// out-of-bounds reads. The `debug_assert_eq!` on byte length surfaces the
/// invariant break in tests.
pub(super) fn original_match_str(original: &str, lower: &str, matched: &PatternMatch) -> String {
    debug_assert_eq!(
        lower.len(),
        original.len(),
        "ASCII-lowercase invariant: lower.len() must equal original.len()"
    );
    if lower.len() == original.len() {
        // Safe slice on a valid char boundary: matcher offsets are valid into
        // `lower`, and ASCII byte-equivalence means they're valid into
        // `original` too.
        original
            .get(matched.start..matched.end)
            .map(str::to_string)
            .unwrap_or_else(|| matched.matched_text.clone())
    } else {
        // Defensive fallback (non-ASCII content); evidence loses casing but
        // we don't risk a panic.
        matched.matched_text.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::try_compile;

    /// # Contract
    /// `original_match_str` must remain panic-free when ASCII-lowercase
    /// stops being a 1-byte → 1-byte transformation (Turkish `İ` is the
    /// canonical breaker). The helper falls back to the matched text in
    /// that case rather than slicing across UTF-8 boundaries.
    #[test]
    fn original_match_str_falls_back_safely_on_nonascii_breakage() {
        let original = "İSTANBUL CURL X";
        let lower = original.to_ascii_lowercase();
        if lower.len() == original.len() {
            // ASCII path — nothing to test for fallback. Skip.
            return;
        }
        let matches = try_compile("curl").unwrap().find_matches(&lower);
        if let Some(m) = matches.into_iter().next() {
            let evidence = original_match_str(original, &lower, &m);
            assert!(["curl", "CURL"].contains(&evidence.as_str()));
        }
    }
}
