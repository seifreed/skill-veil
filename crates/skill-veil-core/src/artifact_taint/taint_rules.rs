use super::{ArtifactTaintRule, ArtifactTaintRuleGroup, TaintSinkKind, TaintSourceKind};
use std::collections::BTreeMap;

pub(super) fn default_rules() -> Vec<ArtifactTaintRule> {
    const YAML: &str = include_str!("../taint_rules.yaml");
    serde_yaml::from_str(YAML).expect("built-in taint_rules.yaml is invalid")
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
