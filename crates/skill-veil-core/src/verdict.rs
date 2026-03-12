use std::collections::BTreeMap;

use crate::findings::{
    ArtifactScope, BlastRadiusLevel, BlastRadiusSummary, DeclaredPermission, Finding,
    FindingSummary, HygieneSummary, PackageHealth, PackageVerdictReport, RecommendedAction,
    RootCauseGroup, SignalClass, ThreatCategory, Verdict, VerdictReason,
};

#[must_use]
pub fn derive_package_verdict(
    findings: &[Finding],
    primary_summary: &FindingSummary,
    supporting_summary: &FindingSummary,
    package_summary: &FindingSummary,
) -> PackageVerdictReport {
    let root_cause_groups = build_root_cause_groups(findings);
    let has_conclusive_supporting_malicious = findings.iter().any(is_conclusive_supporting_malicious);
    let compound_reasons = detect_compound_verdict_reasons(findings, &root_cause_groups);
    let mut verdict_reasons = root_cause_groups
        .iter()
        .take(6)
        .map(|group| VerdictReason {
            scope: group.scope,
            category: group.category,
            signal_class: group.signal_class,
            rationale: format!(
                "{} finding(s) in {} with strongest action {}",
                group.finding_count, group.scope, group.strongest_action
            ),
        })
        .collect::<Vec<_>>();
    verdict_reasons.extend(compound_reasons.clone());

    let has_malicious_behavior = root_cause_groups.iter().any(|group| {
        group.signal_class == SignalClass::MaliciousBehavior
            && group.strongest_action == RecommendedAction::Block
    });
    let has_compound_malicious = compound_reasons
        .iter()
        .any(|reason| reason.signal_class == SignalClass::MaliciousBehavior);
    let has_supporting_block = supporting_summary.recommended_action == RecommendedAction::Block;
    let has_non_hygiene_signal = root_cause_groups.iter().any(|group| {
        matches!(
            group.signal_class,
            SignalClass::MaliciousBehavior
                | SignalClass::SuspiciousPackageBehavior
                | SignalClass::ReviewSignal
        ) && group.strongest_action != RecommendedAction::Log
    });
    let has_actionable_non_package_root = root_cause_groups.iter().any(|group| {
        group.scope != ArtifactScope::PackageRootArtifact
            && group.strongest_action != RecommendedAction::Log
            && group.signal_class != SignalClass::Hygiene
    });
    let severe_hygiene_only = !has_non_hygiene_signal
        && primary_summary.recommended_action == RecommendedAction::Log
        && supporting_summary.recommended_action == RecommendedAction::Log
        && root_cause_groups.iter().any(|group| {
            group.signal_class == SignalClass::Hygiene
                && (group.strongest_action == RecommendedAction::Block
                    || group.finding_count >= 4)
        });
    let hygiene_summary = build_hygiene_summary(findings);
    let declared_permissions =
        derive_declared_permissions(findings, primary_summary, supporting_summary);
    let blast_radius_summary = build_blast_radius_summary(findings, &declared_permissions);
    let effective_capabilities = derive_effective_capabilities(findings);
    let package_health =
        if hygiene_summary.package_root_findings == 0 && hygiene_summary.supporting_findings == 0 {
            PackageHealth::Healthy
        } else if severe_hygiene_only {
            PackageHealth::Elevated
        } else {
            PackageHealth::NeedsReview
        };
    let isolated_weak_package_root_signal = is_isolated_weak_package_root_signal(&root_cause_groups);
    let verdict = if has_malicious_behavior
        || has_compound_malicious
        || (has_supporting_block && has_conclusive_supporting_malicious)
    {
        Verdict::Malicious
    } else if isolated_weak_package_root_signal {
        Verdict::Benign
    } else if has_non_hygiene_signal || has_actionable_non_package_root {
        Verdict::Suspicious
    } else {
        Verdict::Benign
    };

    let mut top_risk_drivers = package_summary.score_breakdown.clone();
    top_risk_drivers.truncate(5);

    PackageVerdictReport {
        verdict,
        package_health,
        hygiene_summary,
        declared_permissions,
        effective_capabilities,
        blast_radius_summary,
        verdict_reasons,
        root_cause_groups,
        top_risk_drivers,
    }
}

fn detect_compound_verdict_reasons(
    findings: &[Finding],
    root_cause_groups: &[RootCauseGroup],
) -> Vec<VerdictReason> {
    let mut reasons = Vec::new();

    let has_category = |category: ThreatCategory| {
        root_cause_groups
            .iter()
            .any(|group| group.category == category && group.strongest_action != RecommendedAction::Log)
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
            rationale: "Compound verdict: prompt override is paired with execution behavior".to_string(),
        });
    }

    if has_category(ThreatCategory::CredentialExposure)
        && has_category(ThreatCategory::DataExfiltration)
    {
        reasons.push(VerdictReason {
            scope: ArtifactScope::SupportingArtifact,
            category: ThreatCategory::DataExfiltration,
            signal_class: SignalClass::MaliciousBehavior,
            rationale: "Compound verdict: token or session access is paired with outbound transmission".to_string(),
        });
    }

    if has_rule("MANIFEST_PACKAGE_JSON_INSTALL_HOOK")
        && (has_category(ThreatCategory::RemoteExec) || has_rule("OFFICIAL_REMOTE_FETCH_EXEC_POLYGLOT"))
    {
        reasons.push(VerdictReason {
            scope: ArtifactScope::PackageRootArtifact,
            category: ThreatCategory::SupplyChain,
            signal_class: SignalClass::MaliciousBehavior,
            rationale: "Compound verdict: install hook is paired with remote fetch or execution".to_string(),
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

    reasons
}

fn is_isolated_weak_package_root_signal(root_cause_groups: &[RootCauseGroup]) -> bool {
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

fn derive_declared_permissions(
    findings: &[Finding],
    _primary_summary: &FindingSummary,
    supporting_summary: &FindingSummary,
) -> Vec<DeclaredPermission> {
    let mut permissions = Vec::new();

    for finding in findings
        .iter()
        .filter(|finding| finding.artifact_scope == ArtifactScope::AgentEntrypoint)
    {
        let permission = match finding.rule_id.as_str() {
            "DECLARED_PERMISSION_BROWSER_FULL" => Some(DeclaredPermission::BrowserFull),
            "DECLARED_PERMISSION_FILE_WRITE" => Some(DeclaredPermission::FileWrite),
            "DECLARED_PERMISSION_SHELL_EXEC" => Some(DeclaredPermission::ShellExec),
            "DECLARED_PERMISSION_NETWORK_ACCESS" => Some(DeclaredPermission::NetworkAccess),
            "DECLARED_PERMISSION_SECRETS_ACCESS" => Some(DeclaredPermission::SecretsAccess),
            "DECLARED_PERMISSION_OAUTH_SCOPES" => Some(DeclaredPermission::OAuthScopes),
            _ => None,
        };

        if let Some(permission) = permission {
            if !permissions.contains(&permission) {
                permissions.push(permission);
            }
        }
    }

    let values = findings
        .iter()
        .filter(|finding| finding.artifact_scope == ArtifactScope::AgentEntrypoint)
        .map(|finding| {
            format!(
                "{} {} {}",
                finding.rule_id.to_ascii_lowercase(),
                finding.reason.to_ascii_lowercase(),
                finding.match_value.to_ascii_lowercase()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let add_if = |permissions: &mut Vec<DeclaredPermission>, cond: bool, permission| {
        if cond && !permissions.contains(&permission) {
            permissions.push(permission);
        }
    };

    add_if(
        &mut permissions,
        values.contains("browser")
            || values.contains("navigation")
            || values.contains("click any element")
            || values.contains("full autonomous browser")
            || values.contains("allow-all"),
        DeclaredPermission::BrowserFull,
    );
    add_if(
        &mut permissions,
        values.contains("write file")
            || values.contains("delete work")
            || values.contains("modify"),
        DeclaredPermission::FileWrite,
    );
    add_if(
        &mut permissions,
        values.contains("shell")
            || values.contains("command")
            || values.contains("stdio")
            || supporting_summary
                .score_breakdown
                .iter()
                .any(|factor| factor.factor.contains("process_execution")),
        DeclaredPermission::ShellExec,
    );
    add_if(
        &mut permissions,
        values.contains("http://")
            || values.contains("https://")
            || values.contains("webhook")
            || values.contains("network")
            || values.contains("api"),
        DeclaredPermission::NetworkAccess,
    );
    add_if(
        &mut permissions,
        values.contains("token")
            || values.contains("secret")
            || values.contains("password")
            || values.contains("credential")
            || values.contains("cookie"),
        DeclaredPermission::SecretsAccess,
    );
    add_if(
        &mut permissions,
        values.contains("oauth")
            || values.contains("scope")
            || values.contains("read/write")
            || values.contains("admin scope")
            || values.contains("calendar")
            || values.contains("drive")
            || values.contains("slack"),
        DeclaredPermission::OAuthScopes,
    );

    permissions.sort();
    permissions
}

fn derive_effective_capabilities(findings: &[Finding]) -> Vec<String> {
    let mut capabilities = BTreeMap::<String, usize>::new();
    for finding in findings {
        let key = match finding.category {
            ThreatCategory::RemoteExec => "process_execution",
            ThreatCategory::CredentialExposure => "secret_access",
            ThreatCategory::DataExfiltration => "network_exfiltration",
            ThreatCategory::PersistentPromptTampering => "persistence_surface",
            ThreatCategory::SupplyChain => "supply_chain_installation",
            ThreatCategory::ToolAbuse => "tool_abuse",
            ThreatCategory::AutonomyEscalation => "autonomous_actions",
            ThreatCategory::PrivilegeEscalation => "filesystem_or_runtime_escalation",
            ThreatCategory::ScopeCreep => "scope_creep",
            ThreatCategory::SocialManipulation | ThreatCategory::PersuasiveLanguage => "trust_bypass",
            ThreatCategory::Obfuscation => "obfuscation",
            ThreatCategory::UnsafeBinary => "unsafe_binary",
            ThreatCategory::Generic => "generic_review",
        };
        *capabilities.entry(key.to_string()).or_insert(0) += 1;
    }
    capabilities.into_keys().collect()
}

fn build_blast_radius_summary(
    findings: &[Finding],
    declared_permissions: &[DeclaredPermission],
) -> BlastRadiusSummary {
    let mut factors = Vec::new();
    let mut network_targets = Vec::new();
    let mut severe_count = 0_u32;

    for finding in findings {
        if finding.recommended_action != RecommendedAction::Log {
            severe_count += 1;
        }

        let value = finding.match_value.to_ascii_lowercase();
        if [
            "http://",
            "https://",
            "localhost",
            "127.0.0.1",
            "169.254.169.254",
            ".internal",
            ".local",
        ]
        .iter()
        .any(|needle| value.contains(needle))
        {
            network_targets.push(finding.match_value.clone());
        }

        let factor = match finding.category {
            ThreatCategory::RemoteExec => "remote execution",
            ThreatCategory::DataExfiltration => "data exfiltration",
            ThreatCategory::CredentialExposure => "secret access",
            ThreatCategory::PrivilegeEscalation => "privilege or filesystem impact",
            ThreatCategory::PersistentPromptTampering => "persistent behavior changes",
            ThreatCategory::ToolAbuse => "tool overreach",
            ThreatCategory::AutonomyEscalation => "autonomous high-impact actions",
            ThreatCategory::SupplyChain => "supply chain changes",
            _ => continue,
        };
        if !factors.iter().any(|existing| existing == factor) {
            factors.push(factor.to_string());
        }
    }

    network_targets.sort();
    network_targets.dedup();

    let level = if severe_count >= 3
        || factors
            .iter()
            .any(|factor| factor == "remote execution" || factor == "data exfiltration")
    {
        Some(BlastRadiusLevel::High)
    } else if severe_count >= 1 || !declared_permissions.is_empty() || !factors.is_empty() {
        Some(BlastRadiusLevel::Medium)
    } else {
        Some(BlastRadiusLevel::Low)
    };

    BlastRadiusSummary {
        level,
        factors,
        network_targets,
        declared_permissions: declared_permissions.to_vec(),
    }
}

fn is_conclusive_supporting_malicious(finding: &Finding) -> bool {
    if finding.artifact_scope != ArtifactScope::SupportingArtifact
        || finding.signal_class != SignalClass::MaliciousBehavior
        || finding.recommended_action != RecommendedAction::Block
    {
        return false;
    }

    let value = finding.match_value.to_ascii_lowercase();
    let has_remote_indicator = [
        "http://",
        "https://",
        "curl ",
        "wget ",
        "fetch(",
        "requests.get",
        "urllib.request.urlopen",
        "invoke-webrequest",
        "iwr ",
    ]
    .iter()
    .any(|needle| value.contains(needle));
    let has_sensitive_payload = ["cookie", "token", "secret", "session"]
        .iter()
        .any(|needle| value.contains(needle));
    let has_transmit_verb = ["send", "post", "upload", "forward", "exfiltrate"]
        .iter()
        .any(|needle| value.contains(needle));
    let has_exfil_channel = [
        "discord.com/api/webhooks",
        "api.telegram.org/bot",
        "smtp.",
        "sendgrid",
        "mailgun",
    ]
    .iter()
    .any(|needle| value.contains(needle));

    match finding.category {
        ThreatCategory::RemoteExec => has_remote_indicator,
        ThreatCategory::DataExfiltration => {
            has_sensitive_payload && has_transmit_verb && has_exfil_channel
        }
        ThreatCategory::PersistentPromptTampering => true,
        _ => false,
    }
}

fn build_root_cause_groups(findings: &[Finding]) -> Vec<RootCauseGroup> {
    let mut groups =
        BTreeMap::<(ArtifactScope, ThreatCategory, SignalClass), RootCauseGroup>::new();

    for finding in findings {
        let key = (finding.artifact_scope, finding.category, finding.signal_class);
        groups
            .entry(key)
            .and_modify(|group| {
                group.finding_count += 1;
                group.strongest_action =
                    RecommendedAction::max(group.strongest_action, finding.recommended_action);
                if !group.representative_rules.contains(&finding.rule_id) {
                    group.representative_rules.push(finding.rule_id.clone());
                    group.representative_rules.sort();
                    group.representative_rules.truncate(5);
                }
            })
            .or_insert_with(|| RootCauseGroup {
                scope: finding.artifact_scope,
                category: finding.category,
                signal_class: finding.signal_class,
                finding_count: 1,
                strongest_action: finding.recommended_action,
                representative_rules: vec![finding.rule_id.clone()],
            });
    }

    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by(|left, right| {
        right
            .strongest_action
            .priority()
            .cmp(&left.strongest_action.priority())
            .then_with(|| right.finding_count.cmp(&left.finding_count))
    });
    groups
}

fn build_hygiene_summary(findings: &[Finding]) -> HygieneSummary {
    let mut top_rules = BTreeMap::<String, usize>::new();
    let mut package_root_findings = 0_usize;
    let mut supporting_findings = 0_usize;

    for finding in findings {
        if finding.signal_class != SignalClass::Hygiene {
            continue;
        }

        match finding.artifact_scope {
            ArtifactScope::PackageRootArtifact => package_root_findings += 1,
            ArtifactScope::SupportingArtifact => supporting_findings += 1,
            ArtifactScope::AgentEntrypoint => {}
        }
        *top_rules.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }

    let mut top_rules: Vec<_> = top_rules.into_iter().collect();
    top_rules.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    HygieneSummary {
        package_root_findings,
        supporting_findings,
        top_rules: top_rules.into_iter().map(|(rule, _)| rule).take(5).collect(),
    }
}
