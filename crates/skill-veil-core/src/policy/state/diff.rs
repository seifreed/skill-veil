//! Report-to-report diff: compare two scan results, classifying findings
//! into new / resolved / waived / baselined / unchanged.

use crate::findings::ThreatCategory;
use crate::policy::baseline::{BaselineFile, WaiverFile};
use crate::policy::fingerprint::{
    baseline_matches_finding, finding_fingerprint, finding_to_diff_entry, paths_match,
};
use crate::policy::reports::JsonReport;
use crate::policy::types::{DiffEntry, DiffReport};
use chrono::Utc;
use std::collections::HashMap;

use super::matchers::waiver_matches_finding;

#[must_use]
pub fn diff_reports(previous: &[JsonReport], current: &[JsonReport]) -> DiffReport {
    diff_reports_with_policy_state(previous, current, None, None)
}

#[must_use]
pub fn diff_reports_with_policy_state(
    previous: &[JsonReport],
    current: &[JsonReport],
    baseline: Option<&BaselineFile>,
    waivers: Option<&WaiverFile>,
) -> DiffReport {
    let now = Utc::now();
    let previous_map: HashMap<_, _> = previous
        .iter()
        .flat_map(|report| report.findings.iter())
        .map(|finding| (finding_fingerprint(finding), finding_to_diff_entry(finding)))
        .collect();

    let mut active_current = HashMap::new();
    let mut waived_findings = Vec::new();
    let mut baselined_findings = Vec::new();

    for finding in current.iter().flat_map(|report| report.findings.iter()) {
        let fingerprint = finding_fingerprint(finding);
        // Check waivers first, then baseline — matches scan_filter.rs ordering
        if waivers.is_some_and(|waiver_file| {
            waiver_file
                .waivers
                .iter()
                .any(|waiver| waiver_matches_finding(waiver, finding, now))
        }) {
            waived_findings.push(finding_to_diff_entry(finding));
            continue;
        }

        if baseline.is_some_and(|baseline_file| {
            baseline_file
                .entries
                .iter()
                .any(|entry| baseline_matches_finding(entry, finding))
        }) {
            baselined_findings.push(finding_to_diff_entry(finding));
            continue;
        }

        active_current.insert(fingerprint, finding_to_diff_entry(finding));
    }

    let new_findings = active_current
        .iter()
        .filter(|(fingerprint, _)| !previous_map.contains_key(*fingerprint))
        .map(|(_, entry)| entry.clone())
        .collect();

    // Build logical IDs from current active findings to detect "text-changed"
    // findings that are still logically present under a new fingerprint.
    let current_logical_ids =
        build_logical_ids(&active_current.values().cloned().collect::<Vec<_>>());

    // Logical IDs of findings suppressed by waivers or baselines.
    let suppressed_entries: Vec<DiffEntry> = waived_findings
        .iter()
        .chain(baselined_findings.iter())
        .cloned()
        .collect();
    let suppressed_logical_ids = build_logical_ids(&suppressed_entries);

    // A previous finding is "resolved" only if:
    // 1. Its exact fingerprint is NOT in current active (didn't survive unchanged)
    // 2. Its logical ID is NOT in current active (not still present with changed text)
    // 3. Its logical ID is NOT suppressed (not waived/baselined)
    let resolved_findings = previous_map
        .iter()
        .filter(|(fingerprint, _)| !active_current.contains_key(*fingerprint))
        .filter(|(_, entry)| !logical_id_matches(&current_logical_ids, entry))
        .filter(|(_, entry)| !logical_id_matches(&suppressed_logical_ids, entry))
        .map(|(_, entry)| entry.clone())
        .collect();
    let unchanged_findings = active_current
        .keys()
        .filter(|fingerprint| previous_map.contains_key(*fingerprint))
        .count();

    DiffReport {
        new_findings,
        resolved_findings,
        waived_findings,
        baselined_findings,
        unchanged_findings,
    }
}

/// Extracts logical identities (rule_id, artifact_path, category) from a slice of diff entries.
fn build_logical_ids(entries: &[DiffEntry]) -> Vec<(String, Option<String>, ThreatCategory)> {
    entries
        .iter()
        .map(|entry| {
            (
                entry.rule_id.clone(),
                entry.artifact_path.clone(),
                entry.category,
            )
        })
        .collect()
}

/// Checks whether a `DiffEntry`'s logical identity matches any entry in `ids`.
/// Uses suffix-based `paths_match` for consistency with waiver/baseline path matching.
fn logical_id_matches(ids: &[(String, Option<String>, ThreatCategory)], entry: &DiffEntry) -> bool {
    ids.iter().any(|id| {
        id.0 == entry.rule_id
            && id.2 == entry.category
            && match (&id.1, &entry.artifact_path) {
                (Some(pa), Some(pb)) => paths_match(pa, pb),
                (None, None) => true,
                _ => false,
            }
    })
}
