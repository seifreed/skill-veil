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
fn stronger_behavior_prevents_network_downgrade() {
    use crate::findings::{
        ArtifactScope, Finding, MatchTarget, RootCauseGroup, Severity, ThreatCategory,
    };

    // The "stronger behavior" finding prevents the gate from opening for
    // DECLARED_PERMISSION_NETWORK_ACCESS calibration.
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
        // This finding qualifies as "stronger behavior": RequireApproval,
        // SuspiciousPackageBehavior, not a permission-model or calibration rule.
        Finding::builder("SKILL_REMOTE_EXEC_CURL_BASH", ThreatCategory::RemoteExec)
            .severity(Severity::Critical)
            .action(RecommendedAction::RequireApproval)
            .signal_class(SignalClass::SuspiciousPackageBehavior)
            .matched_on(MatchTarget::Document)
            .match_value("curl | bash")
            .reason("remote exec")
            .build(),
    ];

    let root_cause_groups = vec![RootCauseGroup {
        scope: ArtifactScope::AgentEntrypoint,
        category: ThreatCategory::DataExfiltration,
        signal_class: SignalClass::SuspiciousPackageBehavior,
        finding_count: 1,
        strongest_action: RecommendedAction::RequireApproval,
        representative_rules: vec!["DECLARED_PERMISSION_NETWORK_ACCESS".to_string()],
    }];

    let result = calibrate_verdict_inputs(&findings, &root_cause_groups);

    assert_eq!(
        result.root_cause_groups.len(),
        1,
        "group must not be pruned when stronger behavior prevents downgrade"
    );
    assert_eq!(
        result.root_cause_groups[0].strongest_action,
        RecommendedAction::RequireApproval,
        "action must remain RequireApproval when gate is blocked by stronger behavior"
    );
    assert!(
        result.notes.is_empty(),
        "no calibration note should be emitted when the gate does not open"
    );
}

#[test]
fn internal_network_reclassifies_to_review_signal() {
    use crate::findings::{
        ArtifactScope, Finding, MatchTarget, RootCauseGroup, Severity, ThreatCategory,
    };

    // ToolAbuse is used intentionally: DataExfiltration + RequireApproval would
    // satisfy `has_network_chain` (the gate condition), preventing calibration
    // from firing. ToolAbuse is outside the chain-category check.
    let findings = vec![
        Finding::builder("INTERNAL_NETWORK_ACCESS", ThreatCategory::ToolAbuse)
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .signal_class(SignalClass::SuspiciousPackageBehavior)
            .matched_on(MatchTarget::Document)
            .match_value("localhost")
            .reason("internal network")
            .build(),
        // A low-severity co-resident finding that will survive exclusion and
        // keep the group alive so we can inspect its signal_class.
        Finding::builder("SOME_REVIEW_SIGNAL", ThreatCategory::ToolAbuse)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .signal_class(SignalClass::SuspiciousPackageBehavior)
            .matched_on(MatchTarget::Document)
            .match_value("benign")
            .reason("low risk")
            .build(),
    ];

    let root_cause_groups = vec![RootCauseGroup {
        scope: ArtifactScope::AgentEntrypoint,
        category: ThreatCategory::ToolAbuse,
        signal_class: SignalClass::SuspiciousPackageBehavior,
        finding_count: 2,
        strongest_action: RecommendedAction::RequireApproval,
        representative_rules: vec!["INTERNAL_NETWORK_ACCESS".to_string()],
    }];

    let result = calibrate_verdict_inputs(&findings, &root_cause_groups);

    assert_eq!(
        result.root_cause_groups.len(),
        1,
        "group should survive because one non-calibrated finding remains"
    );
    assert_eq!(
        result.root_cause_groups[0].signal_class,
        SignalClass::ReviewSignal,
        "INTERNAL_NETWORK_ACCESS calibration must reclassify group to ReviewSignal"
    );
}

#[test]
fn note_deduplication_collapses_identical_notes() {
    use crate::findings::{
        ArtifactScope, Finding, MatchTarget, RootCauseGroup, Severity, ThreatCategory,
    };

    // Two separate groups (different categories) both matching
    // DECLARED_PERMISSION_NETWORK_ACCESS produce identical notes; dedup_notes
    // must collapse them to one.
    let findings = vec![
        Finding::builder(
            "DECLARED_PERMISSION_NETWORK_ACCESS",
            ThreatCategory::DataExfiltration,
        )
        .severity(Severity::Medium)
        .action(RecommendedAction::RequireApproval)
        .signal_class(SignalClass::SuspiciousPackageBehavior)
        .matched_on(MatchTarget::Document)
        .match_value("network exfil")
        .reason("group a")
        .build(),
        Finding::builder(
            "DECLARED_PERMISSION_NETWORK_ACCESS",
            ThreatCategory::SupplyChain,
        )
        .severity(Severity::Medium)
        .action(RecommendedAction::RequireApproval)
        .signal_class(SignalClass::SuspiciousPackageBehavior)
        .matched_on(MatchTarget::Document)
        .match_value("network supply")
        .reason("group b")
        .build(),
    ];

    let root_cause_groups = vec![
        RootCauseGroup {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::DataExfiltration,
            signal_class: SignalClass::SuspiciousPackageBehavior,
            finding_count: 1,
            strongest_action: RecommendedAction::RequireApproval,
            representative_rules: vec!["DECLARED_PERMISSION_NETWORK_ACCESS".to_string()],
        },
        RootCauseGroup {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::SupplyChain,
            signal_class: SignalClass::SuspiciousPackageBehavior,
            finding_count: 1,
            strongest_action: RecommendedAction::RequireApproval,
            representative_rules: vec!["DECLARED_PERMISSION_NETWORK_ACCESS".to_string()],
        },
    ];

    let result = calibrate_verdict_inputs(&findings, &root_cause_groups);

    assert_eq!(
        result.notes.len(),
        1,
        "duplicate calibration notes must be collapsed to one by dedup_notes"
    );
}

#[test]
fn effect_unchanged_when_action_already_at_minimum() {
    use crate::findings::{
        ArtifactScope, Finding, MatchTarget, RootCauseGroup, Severity, ThreatCategory,
    };

    // Finding with Log action: after excluding DECLARED_PERMISSION the group
    // ends up at Log regardless — no downgrade occurred, so effect_unchanged fires.
    let findings = vec![Finding::builder(
        "DECLARED_PERMISSION_NETWORK_ACCESS",
        ThreatCategory::DataExfiltration,
    )
    .severity(Severity::Low)
    .action(RecommendedAction::Log)
    .signal_class(SignalClass::SuspiciousPackageBehavior)
    .matched_on(MatchTarget::Document)
    .match_value("network")
    .reason("declared network log-level")
    .build()];

    let root_cause_groups = vec![RootCauseGroup {
        scope: ArtifactScope::AgentEntrypoint,
        category: ThreatCategory::DataExfiltration,
        signal_class: SignalClass::SuspiciousPackageBehavior,
        finding_count: 1,
        strongest_action: RecommendedAction::Log,
        representative_rules: vec!["DECLARED_PERMISSION_NETWORK_ACCESS".to_string()],
    }];

    let result = calibrate_verdict_inputs(&findings, &root_cause_groups);

    assert_eq!(
        result.notes.len(),
        1,
        "one calibration note must be emitted"
    );
    assert_eq!(
        result.notes[0].effect, "remains_context_only",
        "effect must be 'remains_context_only' when action was already at Log"
    );
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
