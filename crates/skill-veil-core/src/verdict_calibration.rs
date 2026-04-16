//! Verdict calibration logic for adjusting root cause groups.
//!
//! This module implements the calibration step that runs after root cause groups
//! are derived from findings. Calibration adjusts verdicts to prevent false positives
//! from isolated weak signals.
//!
//! # Calibration Ordering
//!
//! Calibration rules are applied **sequentially** in the order they appear in the
//! `for group in &mut groups` loop. Each rule may modify `group.strongest_action`
//! and `group.signal_class`. Rules check **snapshotted** pre-mutation state to
//! ensure independence.
//!
//! This ordering is intentional and documented:
//!
//! 1. **DECLARED_PERMISSION_NETWORK_ACCESS** - Downgrades to `Log` if no stronger
//!    behavior exists. This prevents network access declarations from escalating
//!    verdicts on their own.
//!
//! 2. **CAPABILITY_PERMISSION_MISMATCH** - Downgrades to `Log` if no stronger
//!    behavior exists. Capability mismatches are retained for explainability
//!    but don't escalate without corroboration.
//!
//! 3. **INTERNAL_NETWORK_ACCESS** - Downgrades to `Log` if no network chain
//!    evidence exists. Internal network access alone is not actionable.
//!
//! 4. **MCP_NO_AUTH_MODEL** - Downgrades to `Log` if no remote execution surface
//!    is present. MCP servers without auth are a concern only when combined with
//!    other risky capabilities.
//!
//! # Rule Independence
//!
//! Each calibration rule's **firing condition** checks the group's original state
//! (via snapshotted `original_signal_class`), so earlier downgrades cannot prevent
//! a later rule from firing on the same group. However, the **effect measurement**
//! (`changed_from_previous`) compares against the action before *that specific rule*
//! (not the original), which is intentional to avoid double-counting risk adjustments
//! when multiple rules apply to the same group.

use crate::findings::{
    Finding, RecommendedAction, RootCauseGroup, SignalClass, ThreatCategory, VerdictCalibrationNote,
};

/// Rule IDs that verdict calibration may downgrade or reclassify.
///
/// This is the single source of truth used by both calibration logic and the
/// compound verdict detector in `verdict.rs` to guard against accidentally
/// checking a calibrated rule's raw finding action.
pub(crate) const CALIBRATED_RULE_IDS: &[&str] = &[
    "DECLARED_PERMISSION_NETWORK_ACCESS",
    "CAPABILITY_PERMISSION_MISMATCH",
    "INTERNAL_NETWORK_ACCESS",
    "MCP_NO_AUTH_MODEL",
    "OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT",
];

#[derive(Debug, Clone)]
pub(crate) struct VerdictCalibration {
    pub(crate) root_cause_groups: Vec<RootCauseGroup>,
    pub(crate) risk_adjustment: i32,
    pub(crate) notes: Vec<VerdictCalibrationNote>,
}

pub(crate) fn calibrate_verdict_inputs(
    findings: &[Finding],
    root_cause_groups: &[RootCauseGroup],
) -> VerdictCalibration {
    let mut groups = root_cause_groups.to_vec();
    let mut notes = Vec::new();
    let mut risk_adjustment = 0_i32;

    let has_stronger_behavior = findings.iter().any(|finding| {
        finding.recommended_action != RecommendedAction::Log
            && !is_permission_model_rule(&finding.rule_id)
            && finding.rule_id != "INTERNAL_NETWORK_ACCESS"
            && !is_mcp_no_auth_rule(&finding.rule_id)
            && matches!(
                finding.signal_class,
                SignalClass::SuspiciousPackageBehavior | SignalClass::MaliciousBehavior
            )
    });
    let has_network_chain = findings.iter().any(|finding| {
        let is_known_chain_rule = matches!(
            finding.rule_id.as_str(),
            "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK"
                | "ARTIFACT_TAINT_DOWNLOAD_TO_EXECUTION"
                | "SSRF_LIKE_FETCH"
                | "SKILL_REMOTE_EXEC_CURL_BASH"
                | "SKILL_REMOTE_EXEC_POWERSHELL_IEX"
                | "OFFICIAL_REMOTE_FETCH_EXEC_POLYGLOT"
                | "OFFICIAL_SECRET_EXFIL_WEBHOOK"
        );
        let is_actionable_chain_category = matches!(
            finding.category,
            ThreatCategory::RemoteExec
                | ThreatCategory::DataExfiltration
                | ThreatCategory::CredentialExposure
        ) && finding.recommended_action
            != RecommendedAction::Log;
        is_known_chain_rule || is_actionable_chain_category
    });
    let has_remote_mcp_exec_pair = findings.iter().any(|finding| {
        matches!(
            finding.rule_id.as_str(),
            "MCP_REMOTE_EXEC_SURFACE"
                | "MCP_TOOLING_TRANSPORT_DECLARED"
                | "OFFICIAL_MCP_REMOTE_TUNNEL_WITH_EXEC"
                | "OFFICIAL_MCP_REMOTE_BRIDGE_WITH_COMMAND"
        )
    });

    // Snapshot original actions and signal classes so each calibration rule checks pre-mutation state.
    // This makes rules independent: earlier downgrades don't prevent later rules from firing.
    let original_snapshots: Vec<(RecommendedAction, SignalClass)> = groups
        .iter()
        .map(|group| (group.strongest_action, group.signal_class))
        .collect();

    // Check findings directly instead of representative_rules (which is truncated to
    // MAX_REPRESENTATIVE_RULES entries and could exclude calibration-relevant rules).
    let group_has_rule =
        |group: &RootCauseGroup, original_signal_class: SignalClass, rule_id: &str| -> bool {
            findings.iter().any(|f| {
                f.artifact_scope == group.scope
                    && f.category == group.category
                    && f.signal_class == original_signal_class
                    && f.rule_id == rule_id
            })
        };
    let group_has_mcp_no_auth_rule =
        |group: &RootCauseGroup, original_signal_class: SignalClass| -> bool {
            findings.iter().any(|f| {
                f.artifact_scope == group.scope
                    && f.category == group.category
                    && f.signal_class == original_signal_class
                    && is_mcp_no_auth_rule(&f.rule_id)
            })
        };

    // Accumulate excluded rule IDs per group so successive calibration rules don't
    // re-include findings that a previous rule already calibrated away.
    let mut accumulated_exclusions: Vec<Vec<&str>> = vec![Vec::new(); groups.len()];
    // Track the action before each calibration rule fires, so effect strings
    // and risk_adjustment reflect what THIS rule actually changed (not cumulative
    // delta from original).
    let mut pre_rule_actions: Vec<RecommendedAction> =
        groups.iter().map(|g| g.strongest_action).collect();

    for (i, group) in groups.iter_mut().enumerate() {
        let original_signal_class = original_snapshots[i].1;

        if group_has_rule(
            group,
            original_signal_class,
            "DECLARED_PERMISSION_NETWORK_ACCESS",
        ) && !has_stronger_behavior
        {
            accumulated_exclusions[i].push("DECLARED_PERMISSION_NETWORK_ACCESS");
            let (new_action, remaining_count) = recalculate_group_action_excluding(
                findings,
                group,
                original_signal_class,
                &accumulated_exclusions[i],
            );
            group.strongest_action = new_action;
            group.finding_count = remaining_count;
            let changed_from_previous = group.strongest_action < pre_rule_actions[i];
            if changed_from_previous {
                risk_adjustment -= 10;
            }
            pre_rule_actions[i] = group.strongest_action;
            notes.push(VerdictCalibrationNote {
                rule_id: "DECLARED_PERMISSION_NETWORK_ACCESS".to_string(),
                effect: if changed_from_previous {
                    "downgraded_to_context".to_string()
                } else {
                    "remains_context_only".to_string()
                },
                rationale: "Declared network access remains useful for blast-radius reporting, but it no longer drives package escalation without corroborating behavior.".to_string(),
            });
        }

        if group_has_rule(
            group,
            original_signal_class,
            "CAPABILITY_PERMISSION_MISMATCH",
        ) && !has_stronger_behavior
        {
            accumulated_exclusions[i].push("CAPABILITY_PERMISSION_MISMATCH");
            let (new_action, remaining_count) = recalculate_group_action_excluding(
                findings,
                group,
                original_signal_class,
                &accumulated_exclusions[i],
            );
            group.strongest_action = new_action;
            group.finding_count = remaining_count;
            let changed_from_previous = group.strongest_action < pre_rule_actions[i];
            if changed_from_previous {
                risk_adjustment -= 8;
            }
            pre_rule_actions[i] = group.strongest_action;
            notes.push(VerdictCalibrationNote {
                rule_id: "CAPABILITY_PERMISSION_MISMATCH".to_string(),
                effect: if changed_from_previous {
                    "downgraded_to_context".to_string()
                } else {
                    "remains_context_only".to_string()
                },
                rationale: "Capability mismatch is retained as an explainability signal, but it no longer escalates verdicts without stronger intent or behavioral evidence.".to_string(),
            });
        }

        if group_has_rule(group, original_signal_class, "INTERNAL_NETWORK_ACCESS")
            && !has_network_chain
        {
            accumulated_exclusions[i].push("INTERNAL_NETWORK_ACCESS");
            let (new_action, remaining_count) = recalculate_group_action_excluding(
                findings,
                group,
                original_signal_class,
                &accumulated_exclusions[i],
            );
            group.strongest_action = new_action;
            group.finding_count = remaining_count;
            let changed_from_previous = group.strongest_action < pre_rule_actions[i];
            if changed_from_previous {
                risk_adjustment -= 12;
            }
            // Reclassify to ReviewSignal so that verdict.rs does not treat an
            // isolated internal-network finding as MaliciousBehavior or
            // SuspiciousPackageBehavior. This is safe because the calibration
            // condition already confirmed no network-chain evidence exists —
            // true positives always have corroborating chain rules.
            if changed_from_previous || group.strongest_action == RecommendedAction::Log {
                group.signal_class = SignalClass::ReviewSignal;
            }
            pre_rule_actions[i] = group.strongest_action;
            notes.push(VerdictCalibrationNote {
                rule_id: "INTERNAL_NETWORK_ACCESS".to_string(),
                effect: if changed_from_previous {
                    "downgraded_to_review_only".to_string()
                } else {
                    "remains_review_only".to_string()
                },
                rationale: "Internal or loopback network targets are treated as review-only unless paired with fetch, execution, exfiltration, or metadata-service behavior.".to_string(),
            });
        }

        if group_has_mcp_no_auth_rule(group, original_signal_class) && !has_remote_mcp_exec_pair {
            accumulated_exclusions[i]
                .extend_from_slice(&["MCP_NO_AUTH_MODEL", "OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT"]);
            let (new_action, remaining_count) = recalculate_group_action_excluding(
                findings,
                group,
                original_signal_class,
                &accumulated_exclusions[i],
            );
            group.strongest_action = new_action;
            group.finding_count = remaining_count;
            let changed_from_previous = group.strongest_action < pre_rule_actions[i];
            if changed_from_previous {
                risk_adjustment -= 6;
            }
            if changed_from_previous || group.strongest_action == RecommendedAction::Log {
                group.signal_class = SignalClass::ReviewSignal;
            }
            pre_rule_actions[i] = group.strongest_action;
            notes.push(VerdictCalibrationNote {
                rule_id: "MCP_NO_AUTH_MODEL".to_string(),
                effect: if changed_from_previous {
                    "downgraded_to_context".to_string()
                } else {
                    "remains_context_only".to_string()
                },
                rationale: "Remote MCP without auth is still risky, but it is not treated as standalone malicious behavior unless it widens into command or transport execution semantics.".to_string(),
            });
        }
    }

    // Remove groups that lost all their findings during calibration.
    // These phantom groups would otherwise inflate root_cause_groups counts
    // and produce confusing "0 finding(s)" entries in verdict reasons.
    groups.retain(|g| g.finding_count > 0);

    dedup_notes(&mut notes);

    VerdictCalibration {
        root_cause_groups: groups,
        risk_adjustment,
        notes,
    }
}

fn is_permission_model_rule(rule_id: &str) -> bool {
    crate::findings::is_declared_permission_rule(rule_id)
        || rule_id == "CAPABILITY_PERMISSION_MISMATCH"
}

fn is_mcp_no_auth_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "MCP_NO_AUTH_MODEL" | "OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT"
    )
}

/// Recalculate a group's strongest action and remaining finding count from findings
/// that are NOT in the excluded set.
/// This prevents calibration of one rule from silencing other legitimate rules in the same group.
fn recalculate_group_action_excluding(
    findings: &[Finding],
    group: &RootCauseGroup,
    original_signal_class: SignalClass,
    excluded_rule_ids: &[&str],
) -> (RecommendedAction, usize) {
    let remaining: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.artifact_scope == group.scope
                && f.category == group.category
                && f.signal_class == original_signal_class
                && !excluded_rule_ids.contains(&f.rule_id.as_str())
        })
        .collect();
    let action = remaining.iter().fold(RecommendedAction::Log, |acc, f| {
        acc.max(f.recommended_action)
    });
    (action, remaining.len())
}

fn dedup_notes(notes: &mut Vec<VerdictCalibrationNote>) {
    notes.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then_with(|| a.effect.cmp(&b.effect))
            .then_with(|| a.rationale.cmp(&b.rationale))
    });
    // The comparison is symmetric (field equality), so dedup_by parameter order is irrelevant.
    notes.dedup_by(|a, b| {
        a.rule_id == b.rule_id && a.effect == b.effect && a.rationale == b.rationale
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensure CALIBRATED_RULE_IDS stays in sync with the rules that
    /// calibration actually checks. Every rule referenced by
    /// `is_permission_model_rule` that has its own calibration branch,
    /// `is_mcp_no_auth_rule`, and directly named rules must appear.
    #[test]
    fn calibrated_rule_ids_covers_all_calibration_targets() {
        // Rules that have explicit calibration branches in calibrate_verdict_inputs
        let expected: &[&str] = &[
            "DECLARED_PERMISSION_NETWORK_ACCESS",
            "CAPABILITY_PERMISSION_MISMATCH",
            "INTERNAL_NETWORK_ACCESS",
            "MCP_NO_AUTH_MODEL",
            "OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT",
        ];

        for rule_id in expected {
            assert!(
                CALIBRATED_RULE_IDS.contains(rule_id),
                "Calibration target rule '{rule_id}' is missing from CALIBRATED_RULE_IDS. \
                 Add it to the constant in verdict_calibration.rs."
            );
        }

        for rule_id in CALIBRATED_RULE_IDS {
            assert!(
                expected.contains(rule_id),
                "CALIBRATED_RULE_IDS contains '{rule_id}' which is not a known calibration target. \
                 Either add a calibration branch or remove it from the constant."
            );
        }
    }

    #[test]
    fn calibration_updates_finding_count_when_excluding_rules() {
        use crate::findings::{
            ArtifactScope, Finding, MatchTarget, RootCauseGroup, Severity, ThreatCategory,
        };

        // Two findings in the same group, both DECLARED_PERMISSION_NETWORK_ACCESS
        let findings = vec![
            Finding::builder(
                "DECLARED_PERMISSION_NETWORK_ACCESS",
                ThreatCategory::DataExfiltration,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .signal_class(SignalClass::SuspiciousPackageBehavior)
            .matched_on(MatchTarget::Document)
            .match_value("network access")
            .reason("declared network")
            .build(),
            Finding::builder(
                "DECLARED_PERMISSION_NETWORK_ACCESS",
                ThreatCategory::DataExfiltration,
            )
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .signal_class(SignalClass::SuspiciousPackageBehavior)
            .matched_on(MatchTarget::Document)
            .match_value("another network ref")
            .reason("declared network 2")
            .build(),
        ];

        let root_cause_groups = vec![RootCauseGroup {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::DataExfiltration,
            signal_class: SignalClass::SuspiciousPackageBehavior,
            finding_count: 2,
            strongest_action: RecommendedAction::RequireApproval,
            representative_rules: vec!["DECLARED_PERMISSION_NETWORK_ACCESS".to_string()],
        }];

        let result = calibrate_verdict_inputs(&findings, &root_cause_groups);

        // Both findings were excluded by the DECLARED_PERMISSION_NETWORK_ACCESS rule,
        // so the group is removed entirely (phantom groups with 0 findings are pruned).
        assert!(
            result.root_cause_groups.is_empty(),
            "Groups with 0 remaining findings should be pruned"
        );
    }
}
