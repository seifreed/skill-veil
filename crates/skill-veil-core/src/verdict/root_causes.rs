use std::collections::BTreeMap;

use crate::findings::{ArtifactScope, Finding, RootCauseGroup, SignalClass, ThreatCategory};

pub(super) fn build_root_cause_groups(findings: &[Finding]) -> Vec<RootCauseGroup> {
    let mut groups =
        BTreeMap::<(ArtifactScope, ThreatCategory, SignalClass), RootCauseGroup>::new();

    for finding in findings {
        let key = (
            finding.artifact_scope,
            finding.category,
            finding.signal_class,
        );
        groups
            .entry(key)
            .and_modify(|group| {
                group.finding_count += 1;
                group.strongest_action = group.strongest_action.max(finding.recommended_action);
                if !group.representative_rules.contains(&finding.rule_id) {
                    group.representative_rules.push(finding.rule_id.clone());
                }
            })
            .or_insert_with(|| RootCauseGroup {
                scope: finding.artifact_scope,
                category: finding.category,
                signal_class: finding.signal_class,
                finding_count: 1,
                strongest_action: finding.recommended_action,
                representative_rules: vec![finding.rule_id.clone()],
            });
    }

    let mut groups: Vec<_> = groups.into_values().collect();
    for group in &mut groups {
        group.representative_rules.sort();
        group
            .representative_rules
            .truncate(super::MAX_REPRESENTATIVE_RULES);
    }
    groups.sort_by(|left, right| {
        right
            .strongest_action
            .cmp(&left.strongest_action)
            .then_with(|| right.finding_count.cmp(&left.finding_count))
    });
    groups
}

/// Merge groups that share `(scope, category, signal_class)` after calibration
/// may have reclassified signal_class, creating duplicates.
pub(super) fn merge_calibrated_groups(groups: Vec<RootCauseGroup>) -> Vec<RootCauseGroup> {
    let mut merged =
        BTreeMap::<(ArtifactScope, ThreatCategory, SignalClass), RootCauseGroup>::new();
    for group in groups {
        let key = (group.scope, group.category, group.signal_class);
        merged
            .entry(key)
            .and_modify(|existing| {
                existing.finding_count += group.finding_count;
                existing.strongest_action = existing.strongest_action.max(group.strongest_action);
                for rule in &group.representative_rules {
                    if !existing.representative_rules.contains(rule) {
                        existing.representative_rules.push(rule.clone());
                    }
                }
                existing.representative_rules.sort();
                existing
                    .representative_rules
                    .truncate(super::MAX_REPRESENTATIVE_RULES);
            })
            .or_insert(group);
    }
    let mut result: Vec<_> = merged.into_values().collect();
    result.sort_by(|left, right| {
        right
            .strongest_action
            .cmp(&left.strongest_action)
            .then_with(|| right.finding_count.cmp(&left.finding_count))
    });
    result
}
