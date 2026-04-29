use super::{ArtifactTaintRule, ArtifactTaintRuleGroup, TaintSinkKind, TaintSourceKind};
use std::collections::BTreeMap;

/// Build the default taint rules from the embedded YAML literal.
///
/// # Build-time invariant
///
/// The YAML is `include_str!`-loaded at compile time, so a parse
/// failure here is a build-time bug — there is no runtime input that
/// could trigger it. A panic carrying the precise serde-yaml diagnostic
/// is the right escalation: catching the failure in `Result` and
/// surfacing it through the engine API would only allow callers to
/// re-panic on the same invariant. This matches the documented exception
/// for compile-time literals already used by
/// [`crate::adapters::pattern_helpers::compile_patterns`].
///
/// The regression test [`tests::default_rules_yaml_parses_cleanly`]
/// pins the invariant on every CI run, so the panic cannot fire in
/// production unless someone ships a build whose tests were never
/// executed.
pub(super) fn default_rules() -> Vec<ArtifactTaintRule> {
    const YAML: &str = include_str!("../taint_rules.yaml");
    serde_yaml::from_str(YAML)
        .unwrap_or_else(|err| panic!("built-in taint_rules.yaml must parse: {err}"))
}

pub(super) fn group_rules(rules: Vec<ArtifactTaintRule>) -> Vec<ArtifactTaintRuleGroup> {
    let mut groups: BTreeMap<(TaintSourceKind, TaintSinkKind), Vec<ArtifactTaintRule>> =
        BTreeMap::new();
    for rule in rules {
        groups
            .entry((rule.source, rule.sink))
            .or_default()
            .push(rule);
    }

    let mut result: Vec<_> = groups
        .into_iter()
        .map(|((source, sink), rules)| ArtifactTaintRuleGroup {
            source,
            sink,
            rules,
        })
        .collect();

    // Sort by max severity descending so the per-cluster budget is consumed
    // by the highest-severity rules first (not by enum declaration order).
    result.sort_by(|a, b| {
        let max_sev = |group: &ArtifactTaintRuleGroup| group.rules.iter().map(|r| r.severity).max();
        max_sev(b).cmp(&max_sev(a))
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: the embedded `taint_rules.yaml` literal parses cleanly
    /// through `serde_yaml`. Pins the build-time invariant that
    /// `default_rules` relies on. Any future YAML edit that breaks
    /// parsing fails this test before reaching production runtime —
    /// the documented compile-time-invariant exception is only
    /// defensible if a test guarantees the parse never fails.
    #[test]
    fn default_rules_yaml_parses_cleanly() {
        let rules = default_rules();
        assert!(
            !rules.is_empty(),
            "built-in taint_rules.yaml must contribute at least one rule",
        );
    }

    /// Contract: every default rule lands in exactly one
    /// `(source, sink)` group after `group_rules`. Negative-direction
    /// pin so a future schema change that introduces empty groups or
    /// duplicate keys is caught immediately rather than surfacing as
    /// silent rule loss in the engine.
    #[test]
    fn group_rules_preserves_every_default_rule() {
        let rules = default_rules();
        let original_count = rules.len();
        let groups = group_rules(rules);
        let regrouped_count: usize = groups.iter().map(|g| g.rules.len()).sum();
        assert_eq!(
            regrouped_count,
            original_count,
            "group_rules must preserve every input rule (lost {} rules)",
            original_count - regrouped_count,
        );
    }
}
