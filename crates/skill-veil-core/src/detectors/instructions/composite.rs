//! Reusable k-of-n composite-family detector framework.
//!
//! Generalises the proven `SKILL_FAKE_DEPENDENCY_DROPPER` 2-of-3
//! detector ([`super::dropper_delivery`]) so a new per-family
//! composite is one data entry in [`composite_families`] — no new
//! code path.
//!
//! # Why composites live in code, not the YAML rule schema
//!
//! Each individual signal of a composite is benign-corpus clean on
//! its own, but the rule schema's single-`when`-regex cannot express
//! "≥k of n independent signals anywhere in the document". The k-of-n
//! conjunction is the precision anchor: any one signal could
//! plausibly appear in a defensive-security skill; the co-occurrence
//! is the unambiguous malware shape.

use std::path::Path;
use std::sync::LazyLock;

use crate::analyzer::SkillDocument;
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, SignalClass,
    ThreatCategory,
};
use crate::ports::CompiledPattern;

/// One independent signal of a composite family. `label` is surfaced
/// in the finding `match_value` so an operator sees exactly which
/// signals co-occurred.
pub(crate) struct CompositeSignal {
    pub(crate) label: &'static str,
    pub(crate) pattern: &'static LazyLock<CompiledPattern>,
}

/// A k-of-n composite-family detector. Fires exactly one
/// document-level [`Finding`] when ≥ `min_signals` distinct signals
/// match. `rule_id` is public API — never rename or remove it.
pub(crate) struct CompositeFamily {
    pub(crate) rule_id: &'static str,
    pub(crate) category: ThreatCategory,
    pub(crate) severity: Severity,
    pub(crate) action: RecommendedAction,
    pub(crate) signal_class: SignalClass,
    pub(crate) min_signals: usize,
    pub(crate) signals: &'static [CompositeSignal],
    pub(crate) match_value_prefix: &'static str,
    pub(crate) reason: &'static str,
}

impl CompositeFamily {
    /// One finding per document when ≥ `min_signals` distinct signals
    /// match. Matched labels are collected in declared signal order
    /// and joined with `" + "` behind `match_value_prefix`; a
    /// document-level shape, so multiple textual hits add no
    /// information.
    pub(crate) fn evaluate(
        &self,
        path: &Path,
        doc: &SkillDocument,
        artifact_kind: ArtifactKind,
    ) -> Vec<Finding> {
        let text = doc.raw_content.as_str();
        let present: Vec<&str> = self
            .signals
            .iter()
            .filter(|s| s.pattern.is_match(text))
            .map(|s| s.label)
            .collect();
        if present.len() < self.min_signals {
            return Vec::new();
        }
        vec![Finding::builder(self.rule_id, self.category)
            .severity(self.severity)
            .action(self.action)
            .evidence_kind(EvidenceKind::Behavior)
            .signal_class(self.signal_class)
            .matched_on(MatchTarget::Document)
            .artifact(artifact_kind, Some(path.display().to_string()))
            .match_value(format!(
                "{}{}",
                self.match_value_prefix,
                present.join(" + ")
            ))
            .reason(self.reason)
            .build()]
    }
}

/// Number of composite families registered. A named constant so the
/// pin-test below fails loudly on an accidental add/remove rather than
/// silently tracking the slice length.
pub(crate) const COMPOSITE_FAMILY_COUNT: usize = 1;

static REGISTRY: [&CompositeFamily; COMPOSITE_FAMILY_COUNT] =
    [&super::dropper_delivery::FAKE_DEPENDENCY_DROPPER];

/// Every composite family in one place. Iterated by
/// `services::artifact_orchestration::instructions` so a new family
/// fires automatically with one registry entry.
pub(crate) fn composite_families() -> &'static [&'static CompositeFamily] {
    &REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: every registered family has a distinct `rule_id`
    /// (mirrors the duplicate-id guard in `get_builtin_rules`; rule
    /// ids are public API).
    #[test]
    fn composite_families_have_unique_rule_ids() {
        let mut ids: Vec<&str> = composite_families().iter().map(|f| f.rule_id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate composite rule_id");
    }

    /// Contract: a composite is k-of-n with `2 ≤ k ≤ n`. A 1-of-n
    /// composite is forbidden by construction — it would be a plain
    /// single-regex rule and lose the precision anchor.
    #[test]
    fn every_family_min_signals_between_two_and_n() {
        for f in composite_families() {
            assert!(
                f.min_signals >= 2,
                "{}: a 1-of-n composite is forbidden",
                f.rule_id
            );
            assert!(
                f.min_signals <= f.signals.len(),
                "{}: min_signals exceeds signal count",
                f.rule_id
            );
        }
    }

    /// Contract: the registry size is pinned to a named constant so an
    /// accidental add/remove is a loud test failure, not a silent
    /// behaviour change.
    #[test]
    fn composite_family_count_is_pinned() {
        assert_eq!(composite_families().len(), COMPOSITE_FAMILY_COUNT);
    }
}
