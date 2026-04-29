//! Validators for policy, waiver, and baseline files. Each validator
//! captures invariants that the matching pipeline relies on (no
//! catch-all selectors, no duplicate overrides, no empty fingerprints).
//! These are surfaced at load time so suppression bugs cannot reach the
//! filtering stage.

use crate::policy::baseline::{BaselineFile, WaiverFile};
use crate::policy::types::PolicyFile;
use crate::policy::POLICY_SCHEMA_VERSION;

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
        // Dedup key intentionally EXCLUDES `id`: that field is human
        // bookkeeping, not a semantic selector. Two overrides with the same
        // selectors + action but different ids are functionally duplicate;
        // `match_override`'s `max_by_key` would pick one arbitrarily, masking
        // the policy conflict. Keep `expires_at` in the key — different
        // expirations represent intentional time-bounded overrides.
        let key = format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}",
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

pub fn validate_baseline(baseline: &BaselineFile) -> Result<(), String> {
    if baseline.schema_version != POLICY_SCHEMA_VERSION {
        return Err(format!(
            "Unsupported baseline schema_version '{}', expected '{}'",
            baseline.schema_version, POLICY_SCHEMA_VERSION
        ));
    }

    for entry in &baseline.entries {
        if entry.fingerprint.trim().is_empty() {
            return Err("Baseline entries must define a non-empty fingerprint".to_string());
        }
        if entry.rule_id.trim().is_empty() {
            return Err("Baseline entries must define a non-empty rule_id".to_string());
        }
        if entry.reason.trim().is_empty() {
            return Err("Baseline entries must define a non-empty reason".to_string());
        }
    }

    Ok(())
}

#[cfg(test)]
mod validate_policy_tests {
    use super::*;
    use crate::findings::RecommendedAction;
    use crate::policy::types::PolicyOverride;
    use crate::policy::POLICY_SCHEMA_VERSION;

    fn ov(id: Option<&str>, rule_id: Option<&str>, action: RecommendedAction) -> PolicyOverride {
        PolicyOverride {
            id: id.map(ToOwned::to_owned),
            rule_id: rule_id.map(ToOwned::to_owned),
            artifact_path: None,
            context: None,
            action,
            expires_at: None,
            reason: "test reason".to_string(),
        }
    }

    fn empty_policy() -> PolicyFile {
        PolicyFile {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            overrides: Vec::new(),
            profiles: Default::default(),
        }
    }

    /// Contract: two overrides with the same SELECTORS but different `id`
    /// are duplicates. Including `id` in the dedup key let conflicting
    /// overrides slip past validation; `match_override`'s `max_by_key`
    /// would then pick one arbitrarily, hiding the conflict from the user.
    #[test]
    fn validate_policy_detects_duplicate_overrides_with_different_ids() {
        let mut policy = empty_policy();
        policy.overrides = vec![
            ov(Some("foo"), Some("RULE_A"), RecommendedAction::Block),
            ov(Some("bar"), Some("RULE_A"), RecommendedAction::Block),
        ];
        let result = validate_policy(&policy);
        assert!(
            result.is_err(),
            "Two overrides with identical selectors+action but different ids \
             MUST be flagged as duplicates"
        );
    }

    /// Different actions for the same selectors are NOT duplicates
    /// (intentional: a policy could differentiate `Log` vs `Block` by
    /// expiration window).
    #[test]
    fn validate_policy_accepts_different_actions_for_same_selectors() {
        let mut policy = empty_policy();
        policy.overrides = vec![
            ov(Some("a"), Some("RULE_A"), RecommendedAction::Block),
            ov(Some("b"), Some("RULE_A"), RecommendedAction::Log),
        ];
        assert!(validate_policy(&policy).is_ok());
    }
}

#[cfg(test)]
mod baseline_matches_tests {
    use crate::findings::{ArtifactKind, Finding, ThreatCategory};
    use crate::policy::baseline::BaselineEntry;
    use crate::policy::fingerprint::{baseline_matches_finding, finding_fingerprint};

    fn finding_for(rule_id: &str, artifact_path: Option<&str>) -> Finding {
        Finding::builder(rule_id, ThreatCategory::Generic)
            .match_value("payload")
            .reason("test")
            .artifact(
                ArtifactKind::SkillDocument,
                artifact_path.map(ToOwned::to_owned),
            )
            .build()
    }

    /// Contract: a baseline entry matches a finding ONLY when their
    /// fingerprints (rule_id + artifact_path + match_value + matched_on)
    /// are byte-equal. Pins the documented "fingerprint-exact" identity
    /// contract on `baseline_matches_finding` so any future refactor that
    /// loosens the comparison (e.g. switching to `paths_match` like
    /// waivers) regresses this test instead of silently widening
    /// suppression scope.
    #[test]
    fn baseline_matches_finding_requires_fingerprint_equality() {
        let finding = finding_for("RULE_A", Some("pkg/src/main.rs"));
        let entry = BaselineEntry {
            fingerprint: finding_fingerprint(&finding),
            rule_id: finding.rule_id.clone(),
            artifact_path: finding.artifact_path.clone(),
            reason: finding.reason.clone(),
        };
        assert!(
            baseline_matches_finding(&entry, &finding),
            "fingerprint-equal entry MUST match"
        );
    }

    /// Contract (negative): a baseline entry whose `artifact_path` is a
    /// path-suffix of the finding's `artifact_path` MUST NOT match. This
    /// guards the asymmetry with `waiver_matches_finding` /
    /// `policy_override_matches`, which DO use `paths_match` suffix
    /// semantics. Auto-generated baselines must remain a pinned snapshot,
    /// not a fuzzy filter — see the `# Identity contract` doc-comment on
    /// `baseline_matches_finding`.
    #[test]
    fn baseline_matches_finding_does_not_apply_paths_match_suffix() {
        let finding = finding_for("RULE_A", Some("/abs/repo/pkg/src/main.rs"));
        let suffix_finding = finding_for("RULE_A", Some("pkg/src/main.rs"));
        let entry = BaselineEntry {
            fingerprint: finding_fingerprint(&suffix_finding),
            rule_id: suffix_finding.rule_id.clone(),
            artifact_path: suffix_finding.artifact_path.clone(),
            reason: suffix_finding.reason.clone(),
        };
        assert!(
            !baseline_matches_finding(&entry, &finding),
            "suffix-equivalent paths must NOT match — baselines are fingerprint-exact"
        );
    }

    /// Contract: a finding with a different `rule_id` cannot match an
    /// entry, even when every other field (path, match_value, matched_on)
    /// is identical. Confirms `rule_id` is part of the fingerprint.
    #[test]
    fn baseline_matches_finding_rejects_different_rule_id() {
        let finding_a = finding_for("RULE_A", Some("pkg/src/main.rs"));
        let finding_b = finding_for("RULE_B", Some("pkg/src/main.rs"));
        let entry = BaselineEntry {
            fingerprint: finding_fingerprint(&finding_a),
            rule_id: finding_a.rule_id.clone(),
            artifact_path: finding_a.artifact_path.clone(),
            reason: finding_a.reason.clone(),
        };
        assert!(!baseline_matches_finding(&entry, &finding_b));
    }
}
