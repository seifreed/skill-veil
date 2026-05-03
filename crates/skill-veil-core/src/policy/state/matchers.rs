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
        .is_none_or(|rule_id| rule_id.eq_ignore_ascii_case(&finding.rule_id));
    let path_matches = waiver.artifact_path.as_ref().is_none_or(|path| {
        // When the finding has no artifact_path (e.g. graph-derived taint
        // findings), the waiver's path selector cannot be confirmed or
        // denied. Allow the match so that intentional waivers are not
        // bypassed by findings that lack a concrete path.
        finding
            .artifact_path
            .as_ref()
            .is_none_or(|artifact_path| paths_match(artifact_path, path))
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
        .is_none_or(|rule_id| rule_id.eq_ignore_ascii_case(&finding.rule_id));
    let path_matches = policy_override.artifact_path.as_ref().is_none_or(|path| {
        finding
            .artifact_path
            .as_ref()
            .is_none_or(|artifact_path| paths_match(artifact_path, path))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        ArtifactKind, ArtifactScope, EvidenceKind, Finding, MatchTarget, RecommendedAction,
        Severity, SignalClass, ThreatCategory,
    };
    use chrono::Utc;

    fn make_finding(rule_id: &str) -> Finding {
        Finding::builder(rule_id, ThreatCategory::RemoteExec)
            .severity(Severity::High)
            .confidence(0.9)
            .matched_on(MatchTarget::Document)
            .match_value("test")
            .reason("test")
            .remediation("test")
            .action(RecommendedAction::Block)
            .evidence_kind(EvidenceKind::Behavior)
            .artifact(ArtifactKind::SkillDocument, None)
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .signal_class(SignalClass::MaliciousBehavior)
            .build()
    }

    /// # Contract
    ///
    /// Waiver rule_id matching MUST be case-insensitive, consistent with
    /// inline suppressions (`eq_ignore_ascii_case`). A waiver written as
    /// `skill_remote_exec` must match a finding with rule ID
    /// `SKILL_REMOTE_EXEC`.
    #[test]
    fn waiver_rule_id_matches_case_insensitively() {
        let now = Utc::now();
        let finding = make_finding("SKILL_REMOTE_EXEC");

        let waiver_lower = WaiverEntry {
            rule_id: Some("skill_remote_exec".to_string()),
            artifact_path: None,
            context: None,
            reason: "test".to_string(),
            expires_at: None,
        };
        let waiver_upper = WaiverEntry {
            rule_id: Some("SKILL_REMOTE_EXEC".to_string()),
            artifact_path: None,
            context: None,
            reason: "test".to_string(),
            expires_at: None,
        };
        let waiver_mixed = WaiverEntry {
            rule_id: Some("Skill_Remote_Exec".to_string()),
            artifact_path: None,
            context: None,
            reason: "test".to_string(),
            expires_at: None,
        };

        assert!(
            waiver_matches_finding(&waiver_lower, &finding, now),
            "lowercase waiver must match uppercase finding rule_id"
        );
        assert!(
            waiver_matches_finding(&waiver_upper, &finding, now),
            "same-case waiver must match"
        );
        assert!(
            waiver_matches_finding(&waiver_mixed, &finding, now),
            "mixed-case waiver must match"
        );
    }

    /// # Contract
    ///
    /// Waiver with `rule_id: None` acts as a wildcard and matches any
    /// finding regardless of the finding's rule_id.
    #[test]
    fn waiver_none_rule_id_matches_any_finding() {
        let now = Utc::now();
        let finding = make_finding("SKILL_REMOTE_EXEC");

        let waiver = WaiverEntry {
            rule_id: None,
            artifact_path: None,
            context: None,
            reason: "test".to_string(),
            expires_at: None,
        };

        assert!(
            waiver_matches_finding(&waiver, &finding, now),
            "waiver with no rule_id must match any finding"
        );
    }

    /// # Contract
    ///
    /// Waiver rule_id must NOT match a different rule regardless of case.
    #[test]
    fn waiver_rule_id_does_not_match_different_rule() {
        let now = Utc::now();
        let finding = make_finding("SKILL_REMOTE_EXEC");

        let waiver = WaiverEntry {
            rule_id: Some("skill_credential_theft".to_string()),
            artifact_path: None,
            context: None,
            reason: "test".to_string(),
            expires_at: None,
        };

        assert!(
            !waiver_matches_finding(&waiver, &finding, now),
            "waiver must not match a different rule_id"
        );
    }

    /// # Contract
    ///
    /// Expired waivers must never match, regardless of rule_id.
    #[test]
    fn expired_waiver_never_matches() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        let finding = make_finding("SKILL_REMOTE_EXEC");

        let waiver = WaiverEntry {
            rule_id: Some("SKILL_REMOTE_EXEC".to_string()),
            artifact_path: None,
            context: None,
            reason: "test".to_string(),
            expires_at: Some(past),
        };

        assert!(
            !waiver_matches_finding(&waiver, &finding, now),
            "expired waiver must not match"
        );
    }

    /// # Contract
    ///
    /// Policy override rule_id matching MUST be case-insensitive,
    /// consistent with inline suppressions.
    #[test]
    fn policy_override_rule_id_matches_case_insensitively() {
        let now = Utc::now();
        let finding = make_finding("SKILL_REMOTE_EXEC");

        let po_lower = PolicyOverride {
            id: None,
            rule_id: Some("skill_remote_exec".to_string()),
            artifact_path: None,
            context: None,
            action: RecommendedAction::Log,
            reason: "test".to_string(),
            expires_at: None,
        };
        let po_mixed = PolicyOverride {
            id: None,
            rule_id: Some("Skill_Remote_Exec".to_string()),
            artifact_path: None,
            context: None,
            action: RecommendedAction::Log,
            reason: "test".to_string(),
            expires_at: None,
        };

        assert!(
            policy_override_matches(&po_lower, &finding, now),
            "lowercase override must match uppercase finding rule_id"
        );
        assert!(
            policy_override_matches(&po_mixed, &finding, now),
            "mixed-case override must match"
        );
    }

    /// # Contract
    ///
    /// Policy override with `rule_id: None` matches any finding.
    #[test]
    fn policy_override_none_rule_id_matches_any_finding() {
        let now = Utc::now();
        let finding = make_finding("SKILL_REMOTE_EXEC");

        let po = PolicyOverride {
            id: None,
            rule_id: None,
            artifact_path: None,
            context: None,
            action: RecommendedAction::Log,
            reason: "test".to_string(),
            expires_at: None,
        };

        assert!(
            policy_override_matches(&po, &finding, now),
            "override with no rule_id must match any finding"
        );
    }

    /// # Contract
    ///
    /// Expired policy overrides must never match, regardless of rule_id.
    #[test]
    fn expired_policy_override_never_matches() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        let finding = make_finding("SKILL_REMOTE_EXEC");

        let po = PolicyOverride {
            id: None,
            rule_id: Some("SKILL_REMOTE_EXEC".to_string()),
            artifact_path: None,
            context: None,
            action: RecommendedAction::Log,
            reason: "test".to_string(),
            expires_at: Some(past),
        };

        assert!(
            !policy_override_matches(&po, &finding, now),
            "expired override must not match"
        );
    }
}
