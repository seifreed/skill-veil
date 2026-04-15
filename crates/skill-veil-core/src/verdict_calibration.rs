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
//! Each calibration rule checks the group's **original** `strongest_action` (before
//! any calibration modifications). This ensures rules are independent: an earlier
//! downgrade cannot prevent a later rule from firing on the same group.

use crate::findings::{
    Finding, RecommendedAction, RootCauseGroup, SignalClass, ThreatCategory, VerdictCalibrationNote,
};

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

    // Check findings directly instead of representative_rules (which is truncated to 5
    // entries and could exclude calibration-relevant rules).
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
        let (original_action, original_signal_class) = original_snapshots[i];
        pre_rule_actions[i] = original_action;

        if group_has_rule(
            group,
            original_signal_class,
            "DECLARED_PERMISSION_NETWORK_ACCESS",
        ) && !has_stronger_behavior
        {
            accumulated_exclusions[i].push("DECLARED_PERMISSION_NETWORK_ACCESS");
            group.strongest_action = recalculate_group_action_excluding(
                findings,
                group,
                original_signal_class,
                &accumulated_exclusions[i],
            );
            let changed_from_previous =
                group.strongest_action.priority() < pre_rule_actions[i].priority();
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
            group.strongest_action = recalculate_group_action_excluding(
                findings,
                group,
                original_signal_class,
                &accumulated_exclusions[i],
            );
            let changed_from_previous =
                group.strongest_action.priority() < pre_rule_actions[i].priority();
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
            group.strongest_action = recalculate_group_action_excluding(
                findings,
                group,
                original_signal_class,
                &accumulated_exclusions[i],
            );
            let changed_from_previous =
                group.strongest_action.priority() < pre_rule_actions[i].priority();
            if changed_from_previous {
                risk_adjustment -= 12;
            }
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
            group.strongest_action = recalculate_group_action_excluding(
                findings,
                group,
                original_signal_class,
                &accumulated_exclusions[i],
            );
            let changed_from_previous =
                group.strongest_action.priority() < pre_rule_actions[i].priority();
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

    dedup_notes(&mut notes);

    VerdictCalibration {
        root_cause_groups: groups,
        risk_adjustment,
        notes,
    }
}

fn is_permission_model_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "DECLARED_PERMISSION_NETWORK_ACCESS"
            | "DECLARED_PERMISSION_BROWSER_FULL"
            | "DECLARED_PERMISSION_FILE_WRITE"
            | "DECLARED_PERMISSION_SHELL_EXEC"
            | "DECLARED_PERMISSION_SECRETS_ACCESS"
            | "DECLARED_PERMISSION_OAUTH_SCOPES"
            | "CAPABILITY_PERMISSION_MISMATCH"
    )
}

fn is_mcp_no_auth_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "MCP_NO_AUTH_MODEL" | "OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT"
    )
}

/// Recalculate a group's strongest action from findings that are NOT in the excluded set.
/// This prevents calibration of one rule from silencing other legitimate rules in the same group.
fn recalculate_group_action_excluding(
    findings: &[Finding],
    group: &RootCauseGroup,
    original_signal_class: SignalClass,
    excluded_rule_ids: &[&str],
) -> RecommendedAction {
    findings
        .iter()
        .filter(|f| {
            f.artifact_scope == group.scope
                && f.category == group.category
                && f.signal_class == original_signal_class
                && !excluded_rule_ids.contains(&f.rule_id.as_str())
        })
        .fold(RecommendedAction::Log, |acc, f| {
            RecommendedAction::max(acc, f.recommended_action)
        })
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
