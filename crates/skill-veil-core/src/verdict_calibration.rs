use crate::findings::{
    ArtifactScope, Finding, RecommendedAction, RootCauseGroup, SignalClass, ThreatCategory,
    VerdictCalibrationNote,
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
        ) && finding.recommended_action != RecommendedAction::Log;
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

    for group in &mut groups {
        if group
            .representative_rules
            .iter()
            .any(|rule_id| rule_id == "DECLARED_PERMISSION_NETWORK_ACCESS")
            && !has_stronger_behavior
        {
            if group.strongest_action != RecommendedAction::Log {
                group.strongest_action = RecommendedAction::Log;
                risk_adjustment -= 10;
            }
            notes.push(VerdictCalibrationNote {
                rule_id: "DECLARED_PERMISSION_NETWORK_ACCESS".to_string(),
                effect: "downgraded_to_context".to_string(),
                rationale: "Declared network access remains useful for blast-radius reporting, but it no longer drives package escalation without corroborating behavior.".to_string(),
            });
        }

        if group
            .representative_rules
            .iter()
            .any(|rule_id| rule_id == "CAPABILITY_PERMISSION_MISMATCH")
            && !has_stronger_behavior
        {
            if group.strongest_action != RecommendedAction::Log {
                group.strongest_action = RecommendedAction::Log;
                risk_adjustment -= 8;
            }
            notes.push(VerdictCalibrationNote {
                rule_id: "CAPABILITY_PERMISSION_MISMATCH".to_string(),
                effect: "requires_corroboration".to_string(),
                rationale: "Capability mismatch is retained as an explainability signal, but it no longer escalates verdicts without stronger intent or behavioral evidence.".to_string(),
            });
        }

        if group
            .representative_rules
            .iter()
            .any(|rule_id| rule_id == "INTERNAL_NETWORK_ACCESS")
            && !has_network_chain
        {
            if group.strongest_action != RecommendedAction::Log {
                group.strongest_action = RecommendedAction::Log;
                risk_adjustment -= 12;
            }
            group.signal_class = SignalClass::ReviewSignal;
            notes.push(VerdictCalibrationNote {
                rule_id: "INTERNAL_NETWORK_ACCESS".to_string(),
                effect: "review_only_without_chain".to_string(),
                rationale: "Internal or loopback network targets are treated as review-only unless paired with fetch, execution, exfiltration, or metadata-service behavior.".to_string(),
            });
        }

        if group
            .representative_rules
            .iter()
            .any(|rule_id| is_mcp_no_auth_rule(rule_id))
            && !has_remote_mcp_exec_pair
        {
            if group.strongest_action == RecommendedAction::Block {
                group.strongest_action = RecommendedAction::RequireApproval;
                risk_adjustment -= 6;
            }
            if group.scope == ArtifactScope::PackageRootArtifact {
                group.signal_class = SignalClass::SuspiciousPackageBehavior;
            }
            notes.push(VerdictCalibrationNote {
                rule_id: "MCP_NO_AUTH_MODEL".to_string(),
                effect: "approval_without_exec_pair".to_string(),
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

fn dedup_notes(notes: &mut Vec<VerdictCalibrationNote>) {
    notes.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    notes.dedup_by(|left, right| left.rule_id == right.rule_id && left.effect == right.effect);
}
