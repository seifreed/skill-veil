use super::{DatasetJsonEntry, DatasetPackageVerdictEntry};
use skill_veil_core::{
    ArtifactScope, PackageHealth, RecommendedAction, RootCauseGroup, Severity, SignalClass, Verdict,
};
use std::collections::BTreeMap;

pub(super) fn aggregate_package_verdicts(
    entries: &[DatasetJsonEntry],
) -> Vec<DatasetPackageVerdictEntry> {
    let mut grouped = BTreeMap::<String, Vec<&DatasetJsonEntry>>::new();
    for entry in entries {
        let key = entry
            .package_id
            .clone()
            .unwrap_or_else(|| entry.report.skill_path.clone());
        grouped.entry(key).or_default().push(entry);
    }

    let mut verdicts = Vec::new();
    for (key, group) in grouped {
        let representative = group
            .iter()
            .max_by(|left, right| {
                verdict_priority(&left.report.verdict)
                    .cmp(&verdict_priority(&right.report.verdict))
                    .then_with(|| {
                        left.report
                            .summary
                            .risk_score
                            .cmp(&right.report.summary.risk_score)
                    })
                    .then_with(|| {
                        left.report
                            .heuristic_score
                            .cmp(&right.report.heuristic_score)
                    })
            })
            .expect("group is not empty");

        let final_verdict = group
            .iter()
            .map(|entry| entry.report.verdict)
            .max_by_key(verdict_priority)
            .unwrap_or(Verdict::Benign);
        let package_health = group
            .iter()
            .map(|entry| entry.report.verdict_report.package_health)
            .max_by_key(package_health_priority);
        let strongest_root_cause = strongest_root_cause(&group);
        verdicts.push(DatasetPackageVerdictEntry {
            package_id: Some(key),
            final_verdict,
            package_health,
            blast_radius: Some(
                representative
                    .report
                    .verdict_report
                    .blast_radius_summary
                    .level,
            ),
            declared_permissions: representative
                .report
                .verdict_report
                .declared_permissions
                .clone(),
            strongest_reason: strongest_root_cause
                .map(|group| format!("{}/{}/{}", group.scope, group.category, group.signal_class)),
            top_rule: strongest_finding_rule(&group).or_else(|| {
                strongest_root_cause
                    .and_then(|group| group.representative_rules.first())
                    .cloned()
            }),
            representative_path: representative.report.skill_path.clone(),
            main_summary: summarize_scope(&group, ArtifactScope::AgentEntrypoint),
            supporting_summary: summarize_scope(&group, ArtifactScope::SupportingArtifact),
            package_root_summary: summarize_scope(&group, ArtifactScope::PackageRootArtifact),
        });
    }

    verdicts.sort_by(|left, right| {
        verdict_priority(&right.final_verdict)
            .cmp(&verdict_priority(&left.final_verdict))
            .then_with(|| {
                package_health_priority(&right.package_health.unwrap_or(PackageHealth::Healthy))
                    .cmp(&package_health_priority(
                        &left.package_health.unwrap_or(PackageHealth::Healthy),
                    ))
            })
            .then_with(|| left.package_id.cmp(&right.package_id))
    });
    verdicts
}

pub(super) fn count_aggregated_verdicts(
    entries: &[DatasetPackageVerdictEntry],
) -> (usize, usize, usize) {
    entries.iter().fold((0, 0, 0), |mut acc, entry| {
        match entry.final_verdict {
            Verdict::Benign => acc.0 += 1,
            Verdict::Suspicious => acc.1 += 1,
            Verdict::Malicious => acc.2 += 1,
        }
        acc
    })
}

fn verdict_priority(verdict: &Verdict) -> u8 {
    match verdict {
        Verdict::Malicious => 3,
        Verdict::Suspicious => 2,
        Verdict::Benign => 1,
    }
}

fn signal_class_priority(signal_class: &SignalClass) -> u8 {
    match signal_class {
        SignalClass::MaliciousBehavior => 4,
        SignalClass::SuspiciousPackageBehavior => 3,
        SignalClass::ReviewSignal => 2,
        SignalClass::Hygiene => 1,
    }
}

fn action_priority(action: &RecommendedAction) -> u8 {
    match action {
        RecommendedAction::Log => 1,
        RecommendedAction::RequireApproval => 2,
        RecommendedAction::Block => 3,
    }
}

fn severity_priority(severity: &Severity) -> u8 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn package_health_priority(health: &PackageHealth) -> u8 {
    match health {
        PackageHealth::Healthy => 1,
        PackageHealth::NeedsReview => 2,
        PackageHealth::Elevated => 3,
    }
}

fn strongest_root_cause<'a>(group: &[&'a DatasetJsonEntry]) -> Option<&'a RootCauseGroup> {
    group
        .iter()
        .flat_map(|entry| entry.report.verdict_report.root_cause_groups.iter())
        .max_by(|left, right| {
            action_priority(&left.strongest_action)
                .cmp(&action_priority(&right.strongest_action))
                .then_with(|| {
                    signal_class_priority(&left.signal_class)
                        .cmp(&signal_class_priority(&right.signal_class))
                })
                .then_with(|| left.finding_count.cmp(&right.finding_count))
        })
}

fn strongest_finding_rule(group: &[&DatasetJsonEntry]) -> Option<String> {
    group
        .iter()
        .flat_map(|entry| entry.report.findings.iter())
        .max_by(|left, right| {
            action_priority(&left.recommended_action)
                .cmp(&action_priority(&right.recommended_action))
                .then_with(|| {
                    signal_class_priority(&left.signal_class)
                        .cmp(&signal_class_priority(&right.signal_class))
                })
                .then_with(|| {
                    severity_priority(&left.severity).cmp(&severity_priority(&right.severity))
                })
        })
        .map(|finding| finding.rule_id.clone())
}

fn summarize_scope(entries: &[&DatasetJsonEntry], scope: ArtifactScope) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut seen = BTreeSet::new();
    for entry in entries {
        for group in &entry.report.verdict_report.root_cause_groups {
            if group.scope == scope {
                seen.insert(format!("{}/{}", group.category, group.signal_class));
            }
        }
    }
    seen.into_iter().take(3).collect()
}
