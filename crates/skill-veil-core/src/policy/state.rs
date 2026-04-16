use super::{
    AppliedPolicyOverride, BaselineEntry, BaselineFile, DiffEntry, DiffReport, JsonReport,
    PolicyFile, PolicyOverride, WaiverEntry, WaiverFile, POLICY_SCHEMA_VERSION,
};
use crate::findings::{default_operational_contexts, Finding, OperationalContext, ThreatCategory};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

pub fn finding_fingerprint(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(finding.reason.as_bytes());
    hasher.update(b"\0");
    hasher.update(
        finding
            .artifact_path
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update(b"\0");
    hasher.update(finding.match_value.as_bytes());
    hasher.update(b"\0");
    hasher.update(finding.matched_on.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

#[must_use]
pub fn baseline_from_reports(reports: &[JsonReport]) -> BaselineFile {
    let entries = reports
        .iter()
        .flat_map(|report| report.findings.iter())
        .map(|finding| BaselineEntry {
            fingerprint: finding_fingerprint(finding),
            rule_id: finding.rule_id.clone(),
            artifact_path: finding.artifact_path.clone(),
            reason: finding.reason.clone(),
        })
        .collect();

    BaselineFile {
        schema_version: default_policy_schema_version(),
        entries,
    }
}

#[must_use]
pub fn apply_baseline(findings: Vec<Finding>, baseline: Option<&BaselineFile>) -> Vec<Finding> {
    let Some(baseline) = baseline else {
        return findings;
    };

    findings
        .into_iter()
        .filter(|finding| !finding_in_baseline(finding, baseline))
        .collect()
}

/// Count how many findings in the slice match a baseline entry.
/// Used to compute accurate suppression counts independently of application order.
///
/// NOTE: This assumes `apply_baseline` performs simple removal of matched findings.
/// If `apply_baseline` semantics change (e.g., to downgrade actions instead of removing),
/// this function must be updated to match.
#[must_use]
pub fn count_baseline_matches(findings: &[Finding], baseline: Option<&BaselineFile>) -> usize {
    let Some(baseline) = baseline else {
        return 0;
    };
    findings
        .iter()
        .filter(|finding| finding_in_baseline(finding, baseline))
        .count()
}

fn finding_in_baseline(finding: &Finding, baseline: &BaselineFile) -> bool {
    let fingerprint = finding_fingerprint(finding);
    baseline
        .entries
        .iter()
        .any(|entry| entry.fingerprint == fingerprint)
}

#[must_use]
pub fn apply_waivers(findings: Vec<Finding>, waivers: Option<&WaiverFile>) -> Vec<Finding> {
    let Some(waivers) = waivers else {
        return findings;
    };

    let now = Utc::now();
    findings
        .into_iter()
        .filter(|finding| {
            !waivers
                .waivers
                .iter()
                .any(|waiver| waiver_matches_finding(waiver, finding, now))
        })
        .collect()
}

#[must_use]
pub fn apply_policy_overrides(findings: Vec<Finding>, policy: Option<&PolicyFile>) -> Vec<Finding> {
    apply_policy_overrides_with_audit(findings, policy).0
}

#[must_use]
pub fn apply_policy_overrides_with_audit(
    findings: Vec<Finding>,
    policy: Option<&PolicyFile>,
) -> (Vec<Finding>, Vec<AppliedPolicyOverride>) {
    let Some(policy) = policy else {
        return (findings, Vec::new());
    };

    let now = Utc::now();
    let mut audit = Vec::new();
    let findings = findings
        .into_iter()
        .map(|mut finding| {
            let selected = policy
                .overrides
                .iter()
                .enumerate()
                .filter(|(_, policy_override)| {
                    policy_override_matches(policy_override, &finding, now)
                })
                .max_by_key(|(index, policy_override)| {
                    (policy_override_specificity(policy_override), *index)
                })
                .map(|(_, policy_override)| policy_override);

            if let Some(policy_override) = selected {
                let original_action = finding.recommended_action;
                let fingerprint = finding_fingerprint(&finding);
                // Policy overrides unconditionally replace the action, including
                // escalation (e.g., Log → Block). This is intentional for enterprise
                // use cases. The audit trail (AppliedPolicyOverride) records both
                // original_action and effective_action for full visibility.
                finding.recommended_action = policy_override.action;
                audit.push(AppliedPolicyOverride {
                    finding_fingerprint: fingerprint,
                    rule_id: finding.rule_id.clone(),
                    artifact_path: finding.artifact_path.clone(),
                    override_id: policy_override.id.clone(),
                    original_action,
                    effective_action: policy_override.action,
                    specificity: policy_override_specificity(policy_override),
                    reason: policy_override.reason.clone(),
                    matched_contexts: finding_contexts(&finding),
                });
            }

            finding
        })
        .collect();
    (findings, audit)
}

pub fn load_baseline(path: &Path) -> Result<BaselineFile, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

pub fn load_waivers(path: &Path) -> Result<WaiverFile, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

pub fn load_policy(path: &Path) -> Result<PolicyFile, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let policy = serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    validate_policy(&policy)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(policy)
}

pub fn validate_policy(policy: &PolicyFile) -> Result<(), String> {
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(format!(
            "Unsupported policy schema_version '{}', expected '{}'",
            policy.schema_version, POLICY_SCHEMA_VERSION
        ));
    }

    let mut seen = std::collections::HashSet::new();
    for policy_override in &policy.overrides {
        if policy_override.rule_id.is_none()
            && policy_override.artifact_path.is_none()
            && policy_override.context.is_none()
        {
            return Err(
                "Each policy override must define at least one selector: rule_id, artifact_path, or context"
                    .to_string(),
            );
        }
        if policy_override.reason.trim().is_empty() {
            return Err("Policy overrides must define a non-empty reason".to_string());
        }
        let key = format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            policy_override.id,
            policy_override.rule_id,
            policy_override.artifact_path,
            policy_override.context,
            policy_override.expires_at,
            policy_override.action
        );
        if !seen.insert(key) {
            return Err("Duplicate policy override entries detected".to_string());
        }
    }

    Ok(())
}

pub fn validate_waivers(waivers: &WaiverFile) -> Result<(), String> {
    if waivers.schema_version != POLICY_SCHEMA_VERSION {
        return Err(format!(
            "Unsupported waiver schema_version '{}', expected '{}'",
            waivers.schema_version, POLICY_SCHEMA_VERSION
        ));
    }

    let mut seen = std::collections::HashSet::new();
    for waiver in &waivers.waivers {
        if waiver.rule_id.is_none() && waiver.artifact_path.is_none() && waiver.context.is_none() {
            return Err(
                "Each waiver must define at least one selector: rule_id, artifact_path, or context"
                    .to_string(),
            );
        }
        let key = format!(
            "{:?}|{:?}|{:?}|{:?}",
            waiver.rule_id, waiver.artifact_path, waiver.context, waiver.expires_at
        );
        if !seen.insert(key) {
            return Err("Duplicate waiver entries detected".to_string());
        }
    }

    Ok(())
}

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

    // Helper: check if a DiffEntry's logical identity (rule_id + category + artifact_path)
    // matches any entry in a list. Uses suffix-based paths_match for consistency with
    // waiver/baseline path matching.
    let logical_id_matches =
        |ids: &[(String, Option<String>, ThreatCategory)], entry: &DiffEntry| -> bool {
            ids.iter().any(|id| {
                id.0 == entry.rule_id
                    && id.2 == entry.category
                    && match (&id.1, &entry.artifact_path) {
                        (Some(pa), Some(pb)) => paths_match(pa, pb),
                        (None, None) => true,
                        _ => false,
                    }
            })
        };

    // Build logical IDs from current active findings to detect "text-changed"
    // findings that are still logically present under a new fingerprint.
    let current_logical_ids: Vec<(String, Option<String>, ThreatCategory)> = active_current
        .values()
        .map(|entry| {
            (
                entry.rule_id.clone(),
                entry.artifact_path.clone(),
                entry.category,
            )
        })
        .collect();

    // Logical IDs of findings suppressed by waivers or baselines.
    let suppressed_logical_ids: Vec<(String, Option<String>, ThreatCategory)> = waived_findings
        .iter()
        .chain(baselined_findings.iter())
        .map(|entry| {
            (
                entry.rule_id.clone(),
                entry.artifact_path.clone(),
                entry.category,
            )
        })
        .collect();

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

pub(crate) fn default_policy_schema_version() -> String {
    POLICY_SCHEMA_VERSION.to_string()
}

/// Compare two artifact paths for logical equality.
///
/// Supports suffix matching when the shorter path has >1 component, so
/// `"scripts/install.sh"` matches `"/repo/scripts/install.sh"`. A bare
/// filename like `"package.json"` will NOT match across directories.
///
/// **Trade-off**: a 2-component waiver path like `"src/main.rs"` will match
/// any directory ending in `src/main.rs`. This is intentional for ergonomic
/// waiver/baseline definitions, but users should use longer paths when
/// disambiguation is needed.
pub(crate) fn paths_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let pa = std::path::Path::new(a);
    let pb = std::path::Path::new(b);
    // Only allow suffix matching when the shorter path has >1 component
    // to prevent bare filenames (e.g. "package.json") from matching
    // across unrelated directories.
    let a_components = pa.components().count();
    let b_components = pb.components().count();
    (b_components > 1 && pa.ends_with(pb)) || (a_components > 1 && pb.ends_with(pa))
}

pub(crate) fn waiver_matches_finding(
    waiver: &WaiverEntry,
    finding: &Finding,
    now: DateTime<Utc>,
) -> bool {
    if waiver.expires_at.is_some_and(|expires_at| expires_at < now) {
        return false;
    }

    let rule_matches = waiver
        .rule_id
        .as_ref()
        .is_none_or(|rule_id| rule_id == &finding.rule_id);
    let path_matches = waiver.artifact_path.as_ref().is_none_or(|path| {
        finding
            .artifact_path
            .as_ref()
            .is_some_and(|artifact_path| paths_match(artifact_path, path))
    });
    let context_matches = waiver
        .context
        .is_none_or(|context| finding_contexts(finding).contains(&context));

    rule_matches && path_matches && context_matches
}

pub(crate) fn baseline_matches_finding(entry: &BaselineEntry, finding: &Finding) -> bool {
    entry.fingerprint == finding_fingerprint(finding)
}

pub(crate) fn finding_to_diff_entry(finding: &Finding) -> DiffEntry {
    DiffEntry {
        fingerprint: finding_fingerprint(finding),
        rule_id: finding.rule_id.clone(),
        category: finding.category,
        artifact_path: finding.artifact_path.clone(),
        reason: finding.reason.clone(),
    }
}

pub(crate) fn policy_override_matches(
    policy_override: &PolicyOverride,
    finding: &Finding,
    now: DateTime<Utc>,
) -> bool {
    if policy_override
        .expires_at
        .is_some_and(|expires_at| expires_at < now)
    {
        return false;
    }

    let rule_matches = policy_override
        .rule_id
        .as_ref()
        .is_none_or(|rule_id| rule_id == &finding.rule_id);
    let path_matches = policy_override.artifact_path.as_ref().is_none_or(|path| {
        finding
            .artifact_path
            .as_ref()
            .is_some_and(|artifact_path| paths_match(artifact_path, path))
    });
    let context_matches = policy_override
        .context
        .is_none_or(|context| finding_contexts(finding).contains(&context));

    rule_matches && path_matches && context_matches
}

pub(crate) fn policy_override_specificity(policy_override: &PolicyOverride) -> usize {
    let mut specificity = 0_usize;
    if policy_override.rule_id.is_some() {
        specificity += 4;
    }
    if policy_override.artifact_path.is_some() {
        specificity += 2;
    }
    if policy_override.context.is_some() {
        specificity += 1;
    }
    specificity
}

pub(crate) fn finding_contexts(finding: &Finding) -> Vec<OperationalContext> {
    if finding.operational_contexts.is_empty() {
        default_operational_contexts(finding.category, finding.artifact_kind)
    } else {
        finding.operational_contexts.clone()
    }
}
