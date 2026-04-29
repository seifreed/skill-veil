//! Functions that apply baseline / waiver / policy state against a slice
//! of `Finding`s. These are the runtime effects of the YAML files loaded
//! by `loaders.rs`.

use crate::findings::{Finding, RecommendedAction};
use crate::policy::baseline::{BaselineEntry, BaselineFile, WaiverFile};
use crate::policy::fingerprint::finding_fingerprint;
use crate::policy::reports::JsonReport;
use crate::policy::types::{
    default_policy_schema_version, AppliedPolicyOverride, PolicyFile, PolicyOverride,
};
use chrono::{DateTime, Utc};

use super::matchers::{
    finding_contexts, policy_override_matches, policy_override_specificity, waiver_matches_finding,
};

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

fn match_override<'p>(
    finding: &Finding,
    overrides: &'p [PolicyOverride],
    now: DateTime<Utc>,
) -> Option<&'p PolicyOverride> {
    overrides
        .iter()
        .enumerate()
        .filter(|(_, po)| policy_override_matches(po, finding, now))
        .max_by_key(|(index, po)| (policy_override_specificity(po), *index))
        .map(|(_, po)| po)
}

fn build_audit_entry(
    finding: &Finding,
    po: &PolicyOverride,
    original_action: RecommendedAction,
) -> AppliedPolicyOverride {
    AppliedPolicyOverride {
        finding_fingerprint: finding_fingerprint(finding),
        rule_id: finding.rule_id.clone(),
        artifact_path: finding.artifact_path.clone(),
        override_id: po.id.clone(),
        original_action,
        effective_action: po.action,
        specificity: policy_override_specificity(po),
        reason: po.reason.clone(),
        matched_contexts: finding_contexts(finding),
    }
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
            if let Some(po) = match_override(&finding, &policy.overrides, now) {
                let original_action = finding.recommended_action;
                // Policy overrides unconditionally replace the action, including
                // escalation (e.g., Log → Block). This is intentional for enterprise
                // use cases. The audit trail records both actions for full visibility.
                finding.recommended_action = po.action;
                audit.push(build_audit_entry(&finding, po, original_action));
            }
            finding
        })
        .collect();
    (findings, audit)
}
