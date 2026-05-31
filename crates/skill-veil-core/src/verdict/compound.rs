use crate::findings::{
    ArtifactScope, Finding, RecommendedAction, RootCauseGroup, SignalClass, ThreatCategory,
    VerdictReason,
};

/// Rule IDs that emit `DataExfiltration` evidence and participate in
/// the trusted-API-host downgrade. When EVERY data-exfiltration
/// finding in the relevant scope is one of these rules AND every
/// such finding is annotated with `sinks_trusted=true` in its
/// `match_value`, the compound exfil chain downgrades from
/// `MaliciousBehavior` to `ReviewSignal` — the per-finding downgrade
/// would otherwise be silently re-escalated by the compound layer.
///
/// Limited to the SECRET / IDENTITY taint rules that opt into the
/// downgrade in `artifact_taint::analysis::TRUSTED_HOST_DOWNGRADE_RULE_IDS`.
const TRUSTED_HOST_DOWNGRADE_TAINT_RULES: &[&str] = &[
    "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
    "ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK",
];

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
    findings: &[Finding],
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

    // Trusted-host downgrade respect: when every actionable
    // DataExfiltration finding in `scope` is a trust-downgraded
    // taint match (sinks_trusted=true), the per-finding emission was
    // already moved to ReviewSignal — re-escalating to
    // MaliciousBehavior here defeats that downgrade. Drop to
    // ReviewSignal so the compound chain still surfaces the chain
    // shape but no longer auto-blocks. A SINGLE non-trust-downgraded
    // exfil finding defeats the downgrade and the compound stays at
    // MaliciousBehavior.
    let exfil_findings_in_scope: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            f.category == ThreatCategory::DataExfiltration
                && f.artifact_scope == scope
                && f.recommended_action != RecommendedAction::Log
        })
        .collect();
    let signal_class = if !exfil_findings_in_scope.is_empty()
        && exfil_findings_in_scope
            .iter()
            .all(|f| is_trust_downgraded_taint(f))
    {
        SignalClass::ReviewSignal
    } else {
        SignalClass::MaliciousBehavior
    };

    Some(VerdictReason {
        scope,
        category: ThreatCategory::DataExfiltration,
        signal_class,
        rationale: "Compound verdict: token or session access is paired with outbound transmission"
            .to_string(),
    })
}

/// `true` when `finding` is one of the trust-opt-in taint rules AND
/// its `match_value` carries the `sinks_trusted=true` annotation
/// emitted by `artifact_taint::analysis::build_taint_finding` when
/// every external sink resolved to the API allowlist.
fn is_trust_downgraded_taint(finding: &Finding) -> bool {
    if !TRUSTED_HOST_DOWNGRADE_TAINT_RULES.contains(&finding.rule_id.as_str()) {
        return false;
    }
    finding.match_value.contains("sinks_trusted=true")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Finding;

    fn taint_finding(rule_id: &str, sinks_trusted: bool) -> Finding {
        let suffix = if sinks_trusted {
            " sinks_trusted=true"
        } else {
            ""
        };
        Finding {
            rule_id: rule_id.to_string(),
            category: ThreatCategory::DataExfiltration,
            severity: crate::findings::Severity::Critical,
            confidence: 0.9,
            raw_confidence: 0.9,
            confidence_rationale: String::new(),
            matched_on: crate::findings::MatchTarget::ReferencedFile {
                path: "SKILL.md".to_string(),
            },
            match_value: format!(
                "family=exfil source=secret_access sink=https://api.openai.com/v1{suffix}"
            ),
            reason: String::new(),
            remediation: String::new(),
            recommended_action: if sinks_trusted {
                RecommendedAction::RequireApproval
            } else {
                RecommendedAction::Block
            },
            evidence_kind: crate::findings::EvidenceKind::Behavior,
            artifact_kind: crate::findings::ArtifactKind::SkillDocument,
            artifact_scope: ArtifactScope::AgentEntrypoint,
            signal_class: if sinks_trusted {
                SignalClass::ReviewSignal
            } else {
                SignalClass::MaliciousBehavior
            },
            artifact_path: Some("SKILL.md".to_string()),
            operational_contexts: Vec::new(),
            taxonomy_tags: Vec::new(),
            user_taxonomy: Vec::new(),
            line_number: None,
            suppression: None,
        }
    }

    fn cred_group() -> RootCauseGroup {
        RootCauseGroup {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::CredentialExposure,
            signal_class: SignalClass::ReviewSignal,
            finding_count: 1,
            strongest_action: RecommendedAction::RequireApproval,
            representative_rules: vec!["SKILL_SECRETS_DIR_WRITE".to_string()],
        }
    }

    fn exfil_group() -> RootCauseGroup {
        RootCauseGroup {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::DataExfiltration,
            signal_class: SignalClass::ReviewSignal,
            finding_count: 1,
            strongest_action: RecommendedAction::RequireApproval,
            representative_rules: vec!["ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK".to_string()],
        }
    }

    /// Contract: when EVERY DataExfiltration finding in scope is a
    /// trust-downgraded taint (`sinks_trusted=true`), the compound
    /// credential-exfil chain emits ReviewSignal — NOT
    /// MaliciousBehavior. Pre-fix the per-finding trust downgrade
    /// was silently re-escalated by the compound chain because the
    /// chain only consulted raw_root_cause_groups; an Atlassian /
    /// OpenAI / GitHub-only skill therefore stayed `malicious` at
    /// the verdict layer.
    #[test]
    fn credential_exfil_chain_respects_trust_downgrade() {
        let findings = vec![taint_finding(
            "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
            true,
        )];
        let groups = vec![cred_group(), exfil_group()];
        let reason = detect_credential_exfil_chain(&findings, &groups)
            .expect("chain should still emit a verdict reason");
        assert_eq!(
            reason.signal_class,
            SignalClass::ReviewSignal,
            "trust-downgraded taint must downgrade compound chain to ReviewSignal"
        );
    }

    /// Contract (negative): a single non-trust-downgraded taint
    /// finding defeats the trust downgrade — the compound chain
    /// stays at MaliciousBehavior so a real exfil signal cannot be
    /// laundered by mixing it with one trusted-host call.
    #[test]
    fn credential_exfil_chain_one_untrusted_defeats_downgrade() {
        let findings = vec![
            taint_finding("ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK", true),
            taint_finding("ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK", false),
        ];
        let groups = vec![cred_group(), exfil_group()];
        let reason = detect_credential_exfil_chain(&findings, &groups)
            .expect("chain should still emit a verdict reason");
        assert_eq!(
            reason.signal_class,
            SignalClass::MaliciousBehavior,
            "one untrusted taint sink must keep compound chain at MaliciousBehavior"
        );
    }

    /// Contract: when there is no DataExfiltration finding at all
    /// in the scope under consideration (e.g. the exfil evidence is
    /// in a different scope / artifact), the compound chain MUST
    /// still emit MaliciousBehavior — the trust downgrade only
    /// applies when actual taint findings are present and ALL
    /// trust-downgraded.
    #[test]
    fn credential_exfil_chain_no_in_scope_findings_stays_malicious() {
        let findings: Vec<Finding> = Vec::new();
        let groups = vec![cred_group(), exfil_group()];
        let reason = detect_credential_exfil_chain(&findings, &groups)
            .expect("chain should still emit a verdict reason");
        assert_eq!(
            reason.signal_class,
            SignalClass::MaliciousBehavior,
            "no in-scope exfil findings must keep chain at MaliciousBehavior"
        );
    }
}
