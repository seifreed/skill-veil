//! Matching predicates shared across waivers, policy overrides, and the diff
//! engine. Pure functions only — no I/O, no mutation.

use crate::findings::{default_operational_contexts, Finding, OperationalContext};
use crate::policy::baseline::WaiverEntry;
use crate::policy::fingerprint::paths_match;
use crate::policy::types::PolicyOverride;
use chrono::{DateTime, Utc};

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

#[must_use]
pub(crate) fn finding_contexts(finding: &Finding) -> Vec<OperationalContext> {
    if finding.operational_contexts.is_empty() {
        default_operational_contexts(finding.category, finding.artifact_kind)
    } else {
        finding.operational_contexts.clone()
    }
}
