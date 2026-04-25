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

/// Contract: dedup_notes collapses notes that match on the FULL identity
/// tuple `(scope, category, rule_id, effect, rationale)`. Two groups that
/// differ only in `category` produce DIFFERENT notes and MUST survive
/// independently — the verdict predicate filters by `(scope, category)`
/// to decide isolated-weak Benign downgrades, so collapsing them would
/// silently widen the downgrade.
#[test]
fn note_deduplication_keeps_per_group_notes() {
    use crate::findings::{
        ArtifactScope, Finding, MatchTarget, RootCauseGroup, Severity, ThreatCategory,
    };

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

    // Two distinct (scope, category) pairs MUST surface two notes so
    // verdict::predicates can filter per-group.
    assert_eq!(
        result.notes.len(),
        2,
        "Notes for groups with different (scope, category) MUST NOT collapse; \
         the verdict predicate keys on those fields to decide Benign downgrades"
    );
    let categories: std::collections::HashSet<_> =
        result.notes.iter().map(|n| n.category).collect();
    assert!(categories.contains(&ThreatCategory::DataExfiltration));
    assert!(categories.contains(&ThreatCategory::SupplyChain));
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

/// Contract: `dedup_notes` must keep notes with the same `(rule_id, effect, rationale)`
/// when their `(scope, category)` differ. Downstream verdict predicates filter notes
/// by `(scope, category)` to decide isolated-weak Benign downgrades; collapsing them
/// would let one group's `downgraded_*` note vacuously satisfy another group's
/// predicate, silently turning `Suspicious` into `Benign`.
///
/// This test guards against re-introducing the round-1 `dedup_notes` regression.
#[test]
fn dedup_notes_preserves_per_group_distinctions() {
    use crate::findings::{ArtifactScope, ThreatCategory, VerdictCalibrationNote};

    let mut notes = vec![
        VerdictCalibrationNote {
            rule_id: "DECLARED_PERMISSION_NETWORK_ACCESS".to_string(),
            effect: "remains_context_only".to_string(),
            rationale: "shared rationale".to_string(),
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::ScopeCreep,
        },
        VerdictCalibrationNote {
            rule_id: "DECLARED_PERMISSION_NETWORK_ACCESS".to_string(),
            effect: "remains_context_only".to_string(),
            rationale: "shared rationale".to_string(),
            scope: ArtifactScope::PackageRootArtifact,
            category: ThreatCategory::ScopeCreep,
        },
        // Exact duplicate of the first — must collapse.
        VerdictCalibrationNote {
            rule_id: "DECLARED_PERMISSION_NETWORK_ACCESS".to_string(),
            effect: "remains_context_only".to_string(),
            rationale: "shared rationale".to_string(),
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::ScopeCreep,
        },
    ];

    dedup_notes(&mut notes);

    assert_eq!(
        notes.len(),
        2,
        "Notes differing only in scope/category MUST survive dedup; \
         exact duplicates MUST collapse"
    );
    let scopes: Vec<_> = notes.iter().map(|n| n.scope).collect();
    assert!(scopes.contains(&ArtifactScope::AgentEntrypoint));
    assert!(scopes.contains(&ArtifactScope::PackageRootArtifact));
}

#[test]
fn dedup_notes_collapses_per_group_duplicates_within_same_group() {
    use crate::findings::{ArtifactScope, ThreatCategory, VerdictCalibrationNote};

    let mut notes = vec![
        VerdictCalibrationNote {
            rule_id: "RULE_A".to_string(),
            effect: "remains_context_only".to_string(),
            rationale: "x".to_string(),
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::ScopeCreep,
        },
        VerdictCalibrationNote {
            rule_id: "RULE_A".to_string(),
            effect: "remains_context_only".to_string(),
            rationale: "x".to_string(),
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::ScopeCreep,
        },
    ];
    dedup_notes(&mut notes);
    assert_eq!(notes.len(), 1);
}
