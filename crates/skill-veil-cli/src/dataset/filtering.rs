use super::DatasetMaliciousReason;
use crate::cli_args::DatasetViewArg;
use skill_veil_core::{JsonReport, RecommendedAction, ScanResult, Verdict};

pub(super) fn filter_dataset_results(
    results: &[ScanResult],
    view: DatasetViewArg,
) -> Vec<ScanResult> {
    results
        .iter()
        .filter(|result| match view {
            DatasetViewArg::Full => true,
            DatasetViewArg::Entrypoints => {
                result.metadata.classification
                    != skill_veil_core::ArtifactClassification::GenericMarkdown
            }
            DatasetViewArg::PackageRisk => {
                result.metadata.classification
                    != skill_veil_core::ArtifactClassification::GenericMarkdown
                    && !result.supporting_findings.is_empty()
            }
            DatasetViewArg::Verdicts => result.verdict != Verdict::Benign,
        })
        .cloned()
        .collect()
}

pub(super) fn count_verdicts(reports: &[JsonReport]) -> (usize, usize, usize) {
    reports.iter().fold((0, 0, 0), |mut acc, report| {
        match report.verdict {
            Verdict::Benign => acc.0 += 1,
            Verdict::Suspicious => acc.1 += 1,
            Verdict::Malicious => acc.2 += 1,
        }
        acc
    })
}

pub(super) fn count_warning_rule(reports: &[JsonReport], rule_id: &str) -> usize {
    reports
        .iter()
        .filter(|report| {
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule_id)
        })
        .count()
}

pub(super) fn extract_package_id_from_skill_path(skill_path: &str) -> Option<String> {
    skill_path
        .split('/')
        .find(|segment| segment.len() == 64 && segment.chars().all(|c| c.is_ascii_hexdigit()))
        .map(ToOwned::to_owned)
}

pub(super) fn top_malicious_reasons(reports: &[JsonReport]) -> Vec<DatasetMaliciousReason> {
    let mut reasons: Vec<_> = reports
        .iter()
        .filter(|report| report.verdict == Verdict::Malicious)
        .flat_map(|report| {
            report
                .verdict_report
                .root_cause_groups
                .iter()
                .filter(|group| group.strongest_action == RecommendedAction::Block)
                .map(|group| DatasetMaliciousReason {
                    package_id: report
                        .package_id
                        .clone()
                        .or_else(|| extract_package_id_from_skill_path(&report.skill_path)),
                    skill_path: report.skill_path.clone(),
                    scope: group.scope.to_string(),
                    representative_rules: group.representative_rules.clone(),
                    category: group.category.to_string(),
                    signal_class: group.signal_class.to_string(),
                    strongest_action: group.strongest_action.to_string(),
                })
        })
        .collect();
    reasons.sort_by(|left, right| {
        left.package_id
            .cmp(&right.package_id)
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| left.category.cmp(&right.category))
    });
    reasons
}
