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
    super::count_verdicts_by(reports, |report| report.verdict)
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
    // Split on both `/` and `\` so the SHA-256 segment is recovered on
    // Windows (paths produced by `Path::display()` use `\`) and on tools
    // that emit mixed separators. Mirrors the platform-aware ancestor
    // walk in `crate::scanner_graph::derive_package_id`.
    skill_path
        .split(['/', '\\'])
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a Unix-style path with a 64-hex segment yields the SHA.
    /// Pins the no-op case so the cross-platform fix doesn't accidentally
    /// regress Unix behavior.
    #[test]
    fn extract_package_id_handles_unix_path() {
        let sha = "a".repeat(64);
        let path = format!("/data/{sha}/SKILL.md");
        assert_eq!(extract_package_id_from_skill_path(&path), Some(sha));
    }

    /// Contract: a Windows-style path (backslash separators) yields the
    /// SHA. The pre-fix `split('/')` returned `None` on Windows because
    /// the entire path was treated as a single segment.
    #[test]
    fn extract_package_id_handles_windows_path() {
        let sha = "b".repeat(64);
        let path = format!("C:\\data\\{sha}\\SKILL.md");
        assert_eq!(extract_package_id_from_skill_path(&path), Some(sha));
    }

    /// Contract: paths that mix `/` and `\` are tolerated. Real-world
    /// tools (e.g. some IDEs, log aggregators) emit mixed separators.
    #[test]
    fn extract_package_id_handles_mixed_separators() {
        let sha = "c".repeat(64);
        let path = format!("C:/data\\{sha}/SKILL.md");
        assert_eq!(extract_package_id_from_skill_path(&path), Some(sha));
    }

    /// Contract: a path with no 64-hex segment returns `None`.
    #[test]
    fn extract_package_id_returns_none_when_no_hex_segment() {
        let path = "/data/skills/my-pkg/SKILL.md";
        assert_eq!(extract_package_id_from_skill_path(path), None);
    }

    /// Contract: a 63-char or non-hex 64-char segment is rejected.
    /// Keeps the SHA-256 specificity contract intact under the
    /// cross-platform fix.
    #[test]
    fn extract_package_id_rejects_short_or_non_hex_segments() {
        let short = "a".repeat(63);
        let non_hex = "g".repeat(64);
        let unix_short = format!("/data/{short}/SKILL.md");
        let unix_non_hex = format!("/data/{non_hex}/SKILL.md");
        let win_short = format!("C:\\data\\{short}\\SKILL.md");
        let win_non_hex = format!("C:\\data\\{non_hex}\\SKILL.md");
        assert_eq!(extract_package_id_from_skill_path(&unix_short), None);
        assert_eq!(extract_package_id_from_skill_path(&unix_non_hex), None);
        assert_eq!(extract_package_id_from_skill_path(&win_short), None);
        assert_eq!(extract_package_id_from_skill_path(&win_non_hex), None);
    }
}
