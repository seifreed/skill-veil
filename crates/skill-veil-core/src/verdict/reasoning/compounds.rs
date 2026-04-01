use crate::findings::{
    ArtifactScope, Finding, RecommendedAction, RootCauseGroup, SignalClass, ThreatCategory,
    VerdictReason,
};

pub(crate) fn detect_compound_verdict_reasons(
    findings: &[Finding],
    root_cause_groups: &[RootCauseGroup],
) -> Vec<VerdictReason> {
    let mut reasons = Vec::new();

    let has_category = |category: ThreatCategory| {
        root_cause_groups.iter().any(|group| {
            group.category == category && group.strongest_action != RecommendedAction::Log
        })
    };
    let has_rule = |rule_id: &str| findings.iter().any(|finding| finding.rule_id == rule_id);
    let has_declared_permission_rule = |rule_id: &str| {
        findings.iter().any(|finding| {
            finding.rule_id == rule_id && finding.artifact_scope == ArtifactScope::AgentEntrypoint
        })
    };
    let has_high_risk_autonomy = || {
        root_cause_groups.iter().any(|group| {
            group.category == ThreatCategory::AutonomyEscalation
                && group.scope == ArtifactScope::AgentEntrypoint
                && (group.strongest_action == RecommendedAction::Block
                    || group.signal_class == SignalClass::MaliciousBehavior)
        }) || has_rule("OFFICIAL_APPROVAL_BYPASS_WITH_EXECUTION")
            || has_rule("OFFICIAL_APPROVAL_BYPASS_DELETE_OR_MODIFY")
            || has_rule("OFFICIAL_PROMPT_OVERRIDE_WITH_PERSISTENCE")
            || has_rule("OFFICIAL_FORCED_APPROVAL_BYPASS")
    };

    if has_category(ThreatCategory::PersistentPromptTampering)
        && has_category(ThreatCategory::RemoteExec)
    {
        reasons.push(VerdictReason {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::RemoteExec,
            signal_class: SignalClass::MaliciousBehavior,
            rationale: "Compound verdict: prompt override is paired with execution behavior"
                .to_string(),
        });
    }

    if has_category(ThreatCategory::CredentialExposure)
        && has_category(ThreatCategory::DataExfiltration)
    {
        reasons.push(VerdictReason {
            scope: ArtifactScope::SupportingArtifact,
            category: ThreatCategory::DataExfiltration,
            signal_class: SignalClass::MaliciousBehavior,
            rationale:
                "Compound verdict: token or session access is paired with outbound transmission"
                    .to_string(),
        });
    }

    if has_rule("MANIFEST_PACKAGE_JSON_INSTALL_HOOK")
        && (has_category(ThreatCategory::RemoteExec)
            || has_rule("OFFICIAL_REMOTE_FETCH_EXEC_POLYGLOT"))
    {
        reasons.push(VerdictReason {
            scope: ArtifactScope::PackageRootArtifact,
            category: ThreatCategory::SupplyChain,
            signal_class: SignalClass::MaliciousBehavior,
            rationale: "Compound verdict: install hook is paired with remote fetch or execution"
                .to_string(),
        });
    }

    let has_broad_permission_combo =
        has_declared_permission_rule("DECLARED_PERMISSION_BROWSER_FULL")
            || has_declared_permission_rule("DECLARED_PERMISSION_SHELL_EXEC")
            || (has_declared_permission_rule("DECLARED_PERMISSION_OAUTH_SCOPES")
                && has_declared_permission_rule("DECLARED_PERMISSION_SECRETS_ACCESS"));

    if has_broad_permission_combo && has_high_risk_autonomy() {
        reasons.push(VerdictReason {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::AutonomyEscalation,
            signal_class: SignalClass::MaliciousBehavior,
            rationale:
                "Compound verdict: broad permissions are paired with autonomous execution semantics"
                    .to_string(),
        });
    }

    if has_rule("MCP_REMOTE_SERVER_ENDPOINT")
        && (has_rule("MCP_REMOTE_EXEC_SURFACE") || has_rule("MCP_TOOLING_TRANSPORT_DECLARED"))
    {
        reasons.push(VerdictReason {
            scope: ArtifactScope::PackageRootArtifact,
            category: ThreatCategory::RemoteExec,
            signal_class: SignalClass::MaliciousBehavior,
            rationale:
                "Compound verdict: MCP remote endpoint is paired with command or stdio execution semantics"
                    .to_string(),
        });
    }

    if has_rule("MCP_NO_AUTH_MODEL") && has_rule("MCP_REMOTE_EXEC_SURFACE") {
        reasons.push(VerdictReason {
            scope: ArtifactScope::PackageRootArtifact,
            category: ThreatCategory::RemoteExec,
            signal_class: SignalClass::MaliciousBehavior,
            rationale:
                "Compound verdict: remote MCP execution surface is exposed without authentication"
                    .to_string(),
        });
    }

    reasons
}

pub(crate) fn is_isolated_weak_package_root_signal(root_cause_groups: &[RootCauseGroup]) -> bool {
    let actionable_groups: Vec<_> = root_cause_groups
        .iter()
        .filter(|group| group.strongest_action != RecommendedAction::Log)
        .collect();

    actionable_groups.len() == 1
        && actionable_groups[0].scope == ArtifactScope::PackageRootArtifact
        && actionable_groups[0].strongest_action == RecommendedAction::RequireApproval
        && matches!(
            actionable_groups[0].signal_class,
            SignalClass::ReviewSignal | SignalClass::SuspiciousPackageBehavior
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{ArtifactKind, MatchTarget, Severity};

    fn finding(rule_id: &str, category: ThreatCategory, scope: ArtifactScope) -> Finding {
        Finding::builder(rule_id, category)
            .severity(Severity::High)
            .matched_on(MatchTarget::Document)
            .match_value("x")
            .reason("x")
            .remediation("x")
            .action(RecommendedAction::Block)
            .artifact(ArtifactKind::GenericArtifact, None)
            .artifact_scope(scope)
            .build()
    }

    fn group(category: ThreatCategory, scope: ArtifactScope) -> RootCauseGroup {
        RootCauseGroup {
            scope,
            category,
            signal_class: SignalClass::MaliciousBehavior,
            finding_count: 1,
            strongest_action: RecommendedAction::Block,
            representative_rules: vec!["RULE".to_string()],
        }
    }

    #[test]
    fn compound_reasons_detect_broad_permission_plus_autonomy() {
        let reasons = detect_compound_verdict_reasons(
            &[
                finding(
                    "DECLARED_PERMISSION_BROWSER_FULL",
                    ThreatCategory::AutonomyEscalation,
                    ArtifactScope::AgentEntrypoint,
                ),
                finding(
                    "OFFICIAL_FORCED_APPROVAL_BYPASS",
                    ThreatCategory::AutonomyEscalation,
                    ArtifactScope::AgentEntrypoint,
                ),
            ],
            &[group(
                ThreatCategory::AutonomyEscalation,
                ArtifactScope::AgentEntrypoint,
            )],
        );
        assert!(reasons.iter().any(|reason| {
            reason.category == ThreatCategory::AutonomyEscalation
                && reason.rationale.contains("broad permissions")
        }));
    }
}
