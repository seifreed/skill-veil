use crate::findings::{
    ArtifactScope, Finding, RecommendedAction, RootCauseGroup, SignalClass, ThreatCategory,
    VerdictReason,
};

pub(super) fn detect_compound_verdict_reasons(
    findings: &[Finding],
    raw_root_cause_groups: &[RootCauseGroup],
) -> Vec<VerdictReason> {
    [
        detect_prompt_tampering_with_exec(findings, raw_root_cause_groups),
        detect_credential_exfil_chain(findings, raw_root_cause_groups),
        detect_install_hook_with_exec_surface(findings, raw_root_cause_groups),
        detect_broad_permissions_with_autonomy(findings, raw_root_cause_groups),
        detect_mcp_remote_endpoint_with_exec(findings, raw_root_cause_groups),
        detect_heartbeat_poll_with_credential_read(findings, raw_root_cause_groups),
    ]
    .into_iter()
    .flatten()
    .collect()
}

// Use pre-calibration groups so calibration of individual rules cannot silently disable
// compound verdict detection. Compound patterns represent architectural risk that should
// be evaluated independently of calibration.
fn compound_has_category(
    raw_root_cause_groups: &[RootCauseGroup],
    category: ThreatCategory,
) -> bool {
    raw_root_cause_groups
        .iter()
        .any(|group| group.category == category && group.strongest_action != RecommendedAction::Log)
}

/// Find the most actionable scope for attribution where any actionable
/// group matching `category` appears.
///
/// `ArtifactScope`'s derived `Ord` ranks `AgentEntrypoint <
/// PackageRootArtifact < SupportingArtifact`. We want the entrypoint
/// scope when it's available because the entrypoint is the most
/// user-visible attribution surface (and the most actionable for
/// reviewers), so `.min()` is correct. The phrase "most specific" in
/// older comments was misleading — `AgentEntrypoint` is structurally
/// the broadest classification but the most actionable for compound
/// verdict attribution. Returns `None` if no actionable group matches.
fn most_specific_scope_for_category(
    raw_root_cause_groups: &[RootCauseGroup],
    category: ThreatCategory,
) -> Option<ArtifactScope> {
    raw_root_cause_groups
        .iter()
        .filter(|g| g.category == category && g.strongest_action != RecommendedAction::Log)
        .map(|g| g.scope)
        .min()
}

// Checks the *pre-calibration* finding action — calibration only modifies
// root_cause_groups, not individual findings. Use compound_has_category for
// calibrated rule ids.
fn compound_has_rule(findings: &[Finding], rule_id: &str) -> bool {
    debug_assert!(
        !crate::verdict_calibration::CALIBRATED_RULE_IDS.contains(&rule_id),
        "compound_has_rule checks pre-calibration actions; use compound_has_category for calibrated rule {rule_id}"
    );
    findings
        .iter()
        .any(|f| f.rule_id == rule_id && f.recommended_action != RecommendedAction::Log)
}

// Like compound_has_rule but also requires a specific artifact scope to avoid cross-scope false positives.
fn compound_has_rule_in_scope(findings: &[Finding], rule_id: &str, scope: ArtifactScope) -> bool {
    debug_assert!(
        !crate::verdict_calibration::CALIBRATED_RULE_IDS.contains(&rule_id),
        "compound_has_rule_in_scope checks pre-calibration actions; use compound_has_category for calibrated rule {rule_id}"
    );
    findings.iter().any(|f| {
        f.rule_id == rule_id
            && f.recommended_action != RecommendedAction::Log
            && f.artifact_scope == scope
    })
}

// Declared permissions contribute to compound verdicts by their mere presence, regardless of
// action level — compound patterns represent architectural risk that cannot be waived rule-by-rule.
fn compound_has_declared_permission_rule(findings: &[Finding], rule_id: &str) -> bool {
    findings
        .iter()
        .any(|f| f.rule_id == rule_id && f.artifact_scope == ArtifactScope::AgentEntrypoint)
}

fn compound_has_high_risk_autonomy(
    findings: &[Finding],
    raw_root_cause_groups: &[RootCauseGroup],
) -> bool {
    raw_root_cause_groups.iter().any(|group| {
        group.category == ThreatCategory::AutonomyEscalation
            && group.scope == ArtifactScope::AgentEntrypoint
            && (group.strongest_action == RecommendedAction::Block
                || group.signal_class == SignalClass::MaliciousBehavior)
    }) || compound_has_rule(findings, "OFFICIAL_APPROVAL_BYPASS_WITH_EXECUTION")
        || compound_has_rule(findings, "OFFICIAL_APPROVAL_BYPASS_DELETE_OR_MODIFY")
        || compound_has_rule(findings, "OFFICIAL_PROMPT_OVERRIDE_WITH_PERSISTENCE")
        || compound_has_rule(findings, "OFFICIAL_FORCED_APPROVAL_BYPASS")
}

fn detect_prompt_tampering_with_exec(
    _findings: &[Finding],
    raw_root_cause_groups: &[RootCauseGroup],
) -> Option<VerdictReason> {
    if compound_has_category(
        raw_root_cause_groups,
        ThreatCategory::PersistentPromptTampering,
    ) && compound_has_category(raw_root_cause_groups, ThreatCategory::RemoteExec)
    {
        Some(VerdictReason {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::RemoteExec,
            signal_class: SignalClass::MaliciousBehavior,
            rationale: "Compound verdict: prompt override is paired with execution behavior"
                .to_string(),
        })
    } else {
        None
    }
}

fn detect_credential_exfil_chain(
    _findings: &[Finding],
    raw_root_cause_groups: &[RootCauseGroup],
) -> Option<VerdictReason> {
    let cred_scope = most_specific_scope_for_category(
        raw_root_cause_groups,
        ThreatCategory::CredentialExposure,
    )?;
    let exfil_scope =
        most_specific_scope_for_category(raw_root_cause_groups, ThreatCategory::DataExfiltration)?;
    // Attribute the compound finding to the more specific (most actionable)
    // of the two contributing scopes. Without this, evidence sitting in the
    // primary entrypoint was previously labelled `SupportingArtifact`,
    // confusing audit trails and scope-keyed suppressions.
    let scope = cred_scope.min(exfil_scope);
    Some(VerdictReason {
        scope,
        category: ThreatCategory::DataExfiltration,
        signal_class: SignalClass::MaliciousBehavior,
        rationale: "Compound verdict: token or session access is paired with outbound transmission"
            .to_string(),
    })
}

fn detect_install_hook_with_exec_surface(
    findings: &[Finding],
    raw_root_cause_groups: &[RootCauseGroup],
) -> Option<VerdictReason> {
    if compound_has_rule_in_scope(
        findings,
        "MANIFEST_PACKAGE_JSON_INSTALL_HOOK",
        ArtifactScope::PackageRootArtifact,
    ) && (compound_has_category(raw_root_cause_groups, ThreatCategory::RemoteExec)
        || compound_has_rule(findings, "OFFICIAL_REMOTE_FETCH_EXEC_POLYGLOT"))
    {
        Some(VerdictReason {
            scope: ArtifactScope::PackageRootArtifact,
            category: ThreatCategory::SupplyChain,
            signal_class: SignalClass::MaliciousBehavior,
            rationale: "Compound verdict: install hook is paired with remote fetch or execution"
                .to_string(),
        })
    } else {
        None
    }
}

fn detect_broad_permissions_with_autonomy(
    findings: &[Finding],
    raw_root_cause_groups: &[RootCauseGroup],
) -> Option<VerdictReason> {
    let has_broad_permission_combo =
        compound_has_declared_permission_rule(findings, "DECLARED_PERMISSION_BROWSER_FULL")
            || compound_has_declared_permission_rule(findings, "DECLARED_PERMISSION_SHELL_EXEC")
            || (compound_has_declared_permission_rule(
                findings,
                "DECLARED_PERMISSION_OAUTH_SCOPES",
            ) && compound_has_declared_permission_rule(
                findings,
                "DECLARED_PERMISSION_SECRETS_ACCESS",
            ));

    if has_broad_permission_combo
        && compound_has_high_risk_autonomy(findings, raw_root_cause_groups)
    {
        Some(VerdictReason {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::AutonomyEscalation,
            signal_class: SignalClass::MaliciousBehavior,
            rationale:
                "Compound verdict: broad permissions are paired with autonomous execution semantics"
                    .to_string(),
        })
    } else {
        None
    }
}

fn detect_heartbeat_poll_with_credential_read(
    findings: &[Finding],
    raw_root_cause_groups: &[RootCauseGroup],
) -> Option<VerdictReason> {
    // Long-poll / heartbeat fetch paired with any credential-read behaviour is
    // classic agent-C2 architecture: the skill pulls instructions at a fixed
    // cadence while already holding a token, giving the operator remote
    // command-and-control without the skill ever matching an exec rule alone.
    if compound_has_rule(findings, "SKILL_HEARTBEAT_REMOTE_POLL")
        && compound_has_category(raw_root_cause_groups, ThreatCategory::CredentialExposure)
    {
        Some(VerdictReason {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::AutonomyEscalation,
            signal_class: SignalClass::MaliciousBehavior,
            rationale:
                "Compound verdict: heartbeat polling is paired with credential or token access"
                    .to_string(),
        })
    } else {
        None
    }
}

fn detect_mcp_remote_endpoint_with_exec(
    findings: &[Finding],
    _raw_root_cause_groups: &[RootCauseGroup],
) -> Option<VerdictReason> {
    if compound_has_rule_in_scope(
        findings,
        "MCP_REMOTE_SERVER_ENDPOINT",
        ArtifactScope::PackageRootArtifact,
    ) && (compound_has_rule(findings, "MCP_REMOTE_EXEC_SURFACE")
        || compound_has_rule(findings, "MCP_TOOLING_TRANSPORT_DECLARED"))
    {
        Some(VerdictReason {
            scope: ArtifactScope::PackageRootArtifact,
            category: ThreatCategory::RemoteExec,
            signal_class: SignalClass::MaliciousBehavior,
            rationale: "Compound verdict: MCP remote endpoint is paired with command or stdio execution semantics"
                .to_string(),
        })
    } else {
        None
    }
}
