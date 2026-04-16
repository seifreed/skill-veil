use std::collections::{BTreeMap, BTreeSet};

/// Maximum number of verdict reasons retained in the final report.
pub(crate) const MAX_VERDICT_REASONS: usize = 8;
/// Maximum number of top risk drivers retained in the final report.
pub(crate) const MAX_TOP_RISK_DRIVERS: usize = 5;
/// Maximum number of representative rules per root cause group.
pub(crate) const MAX_REPRESENTATIVE_RULES: usize = 5;

use crate::findings::{
    ArtifactScope, BlastRadiusLevel, BlastRadiusSummary, DeclaredPermission, Finding,
    FindingSummary, HygieneSummary, PackageHealth, PackageVerdictReport, RecommendedAction,
    RootCauseGroup, SignalClass, ThreatCategory, Verdict, VerdictReason, RISK_THRESHOLD_APPROVAL,
};
use crate::verdict_calibration::{calibrate_verdict_inputs, VerdictCalibration};

/// Collected boolean predicates used for verdict and package health decisions.
///
/// Extracted to make the decision logic in `derive_package_verdict` explicit
/// and independently testable.
struct VerdictPredicates {
    has_malicious_behavior: bool,
    has_compound_malicious: bool,
    has_primary_block: bool,
    has_supporting_block: bool,
    has_non_hygiene_signal: bool,
    calibration_weakened_non_hygiene: bool,
    has_actionable_non_package_root: bool,
    severe_hygiene_only: bool,
    has_conclusive_supporting_malicious: bool,
    isolated_weak_package_root_signal: bool,
}

impl VerdictPredicates {
    #[allow(clippy::too_many_arguments)]
    fn compute(
        findings: &[Finding],
        root_cause_groups: &[RootCauseGroup],
        raw_root_cause_groups: &[RootCauseGroup],
        compound_reasons: &[VerdictReason],
        primary_summary: &FindingSummary,
        supporting_summary: &FindingSummary,
    ) -> Self {
        let has_malicious_behavior = root_cause_groups.iter().any(|group| {
            group.signal_class == SignalClass::MaliciousBehavior
                && group.strongest_action == RecommendedAction::Block
        });
        // All compound reasons are emitted with MaliciousBehavior signal_class,
        // so presence of any compound reason implies malicious compound behavior.
        let has_compound_malicious = !compound_reasons.is_empty();
        let has_primary_block = primary_summary.recommended_action == RecommendedAction::Block;
        let has_supporting_block =
            supporting_summary.recommended_action == RecommendedAction::Block;
        let has_non_hygiene_signal = root_cause_groups.iter().any(|group| {
            matches!(
                group.signal_class,
                SignalClass::MaliciousBehavior
                    | SignalClass::SuspiciousPackageBehavior
                    | SignalClass::ReviewSignal
            ) && group.strongest_action != RecommendedAction::Log
        });
        // Check pre-calibration groups too: if calibration downgraded any non-hygiene signal,
        // we should not treat the package as "hygiene-only" or "isolated weak signal".
        // After merge_calibrated_groups the calibrated vec may be shorter or reordered,
        // so we match by (scope, category) instead of relying on index alignment.
        let calibration_weakened_non_hygiene = raw_root_cause_groups.iter().any(|raw_group| {
            let is_non_hygiene = matches!(
                raw_group.signal_class,
                SignalClass::MaliciousBehavior
                    | SignalClass::SuspiciousPackageBehavior
                    | SignalClass::ReviewSignal
            ) && raw_group.strongest_action != RecommendedAction::Log;
            if !is_non_hygiene {
                return false;
            }
            // Find the corresponding calibrated group. First try an exact match on
            // (scope, category, signal_class) to avoid picking up a different group
            // that shares (scope, category) but was merged from a different signal_class.
            // Fall back to (scope, category) only if no exact match exists — absence
            // of the original signal_class itself counts as weakening.
            let calibrated = root_cause_groups
                .iter()
                .find(|cal| {
                    cal.scope == raw_group.scope
                        && cal.category == raw_group.category
                        && cal.signal_class == raw_group.signal_class
                })
                .or_else(|| {
                    root_cause_groups.iter().find(|cal| {
                        cal.scope == raw_group.scope && cal.category == raw_group.category
                    })
                });
            let Some(calibrated) = calibrated else {
                return true;
            };
            calibrated.strongest_action < raw_group.strongest_action
                || calibrated.signal_class != raw_group.signal_class
        });
        let has_actionable_non_package_root = root_cause_groups.iter().any(|group| {
            group.scope != ArtifactScope::PackageRootArtifact
                && group.strongest_action != RecommendedAction::Log
                && group.signal_class != SignalClass::Hygiene
        });
        let severe_hygiene_only = !has_non_hygiene_signal
            && !calibration_weakened_non_hygiene
            && root_cause_groups.iter().any(|group| {
                group.signal_class == SignalClass::Hygiene
                    && group.strongest_action == RecommendedAction::Block
            });
        let has_conclusive_supporting_malicious = findings
            .iter()
            .any(Finding::is_conclusive_malicious_evidence);
        let isolated_weak_package_root_signal =
            is_isolated_weak_package_root_signal(root_cause_groups);

        Self {
            has_malicious_behavior,
            has_compound_malicious,
            has_primary_block,
            has_supporting_block,
            has_non_hygiene_signal,
            calibration_weakened_non_hygiene,
            has_actionable_non_package_root,
            severe_hygiene_only,
            has_conclusive_supporting_malicious,
            isolated_weak_package_root_signal,
        }
    }

    fn verdict(
        &self,
        calibration_notes: &[crate::findings::VerdictCalibrationNote],
        primary_summary: &FindingSummary,
        package_summary: &FindingSummary,
    ) -> Verdict {
        if self.has_malicious_behavior
            || self.has_compound_malicious
            || (self.has_supporting_block && self.has_conclusive_supporting_malicious)
        {
            Verdict::Malicious
        } else if self.isolated_weak_package_root_signal
            && !self.has_actionable_non_package_root
            && !self.has_primary_block
            && !self.calibration_weakened_non_hygiene
            && !calibration_notes
                .iter()
                .any(|n| !n.effect.starts_with("remains_"))
            && package_summary.risk_score < RISK_THRESHOLD_APPROVAL
            && primary_summary.risk_score < RISK_THRESHOLD_APPROVAL
        {
            // Isolated weak package root signals are downgraded to Benign,
            // but ONLY if there are no actionable signals in other artifacts
            // and calibration did not actually change any actions. Notes with
            // "remains_context_only" or "remains_review_only" indicate calibration
            // matched but did not modify anything, so they do not block downgrade.
            Verdict::Benign
        } else if self.has_non_hygiene_signal
            || self.has_actionable_non_package_root
            || self.severe_hygiene_only
            || self.calibration_weakened_non_hygiene
        {
            Verdict::Suspicious
        } else {
            Verdict::Benign
        }
    }

    fn package_health(&self, hygiene_summary: &HygieneSummary, verdict: Verdict) -> PackageHealth {
        let base_health = if hygiene_summary.package_root_findings == 0
            && hygiene_summary.entrypoint_findings == 0
            && hygiene_summary.supporting_findings == 0
        {
            PackageHealth::Healthy
        } else if self.severe_hygiene_only {
            PackageHealth::NeedsReview
        } else if self.has_non_hygiene_signal || self.calibration_weakened_non_hygiene {
            PackageHealth::Elevated
        } else {
            // Only hygiene findings exist, but none severe enough for Block —
            // NeedsReview is more appropriate than Elevated.
            PackageHealth::NeedsReview
        };

        // A Benign verdict with Elevated health is contradictory — downgrade to NeedsReview.
        if verdict == Verdict::Benign && base_health == PackageHealth::Elevated {
            PackageHealth::NeedsReview
        } else {
            base_health
        }
    }
}

#[must_use]
pub fn derive_package_verdict(
    findings: &[Finding],
    primary_summary: &FindingSummary,
    supporting_summary: &FindingSummary,
    package_summary: &FindingSummary,
) -> PackageVerdictReport {
    let raw_root_cause_groups = build_root_cause_groups(findings);
    let calibration = calibrate_verdict_inputs(findings, &raw_root_cause_groups);
    // Destructure calibration so we can move root_cause_groups into merge
    // while retaining the other fields for later use.
    let VerdictCalibration {
        root_cause_groups: calibrated_groups,
        risk_adjustment: calibration_risk_adjustment,
        notes: calibration_notes,
    } = calibration;
    // Calibration may reclassify signal_class (e.g., MaliciousBehavior → ReviewSignal),
    // which can produce groups that now share (scope, category, signal_class). Merge them
    // so downstream consumers see deduplicated groups.
    let root_cause_groups = merge_calibrated_groups(calibrated_groups);
    debug_assert!(
        root_cause_groups.len() <= raw_root_cause_groups.len(),
        "Merging calibrated groups must not increase group count"
    );
    let compound_reasons = detect_compound_verdict_reasons(findings, &raw_root_cause_groups);
    // Insert compound reasons first so they survive truncation — they drive
    // Malicious verdicts and must remain visible in verdict_reasons.
    let mut verdict_reasons = compound_reasons.clone();
    verdict_reasons.extend(root_cause_groups.iter().map(|group| VerdictReason {
        scope: group.scope,
        category: group.category,
        signal_class: group.signal_class,
        rationale: format!(
            "{} finding(s) in {} with strongest action {}",
            group.finding_count, group.scope, group.strongest_action
        ),
    }));
    verdict_reasons.truncate(MAX_VERDICT_REASONS);

    let predicates = VerdictPredicates::compute(
        findings,
        &root_cause_groups,
        &raw_root_cause_groups,
        &compound_reasons,
        primary_summary,
        supporting_summary,
    );

    let hygiene_summary = build_hygiene_summary(findings);
    let declared_permissions = derive_declared_permissions(findings, supporting_summary);
    let blast_radius_summary = build_blast_radius_summary(findings, &declared_permissions);
    let effective_capabilities = derive_effective_capabilities(&root_cause_groups);

    let verdict = predicates.verdict(&calibration_notes, primary_summary, package_summary);
    let package_health = predicates.package_health(&hygiene_summary, verdict);

    let mut top_risk_drivers = package_summary.score_breakdown.clone();
    top_risk_drivers.truncate(MAX_TOP_RISK_DRIVERS);

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
        calibration_notes,
        calibration_risk_adjustment,
    }
}

fn detect_compound_verdict_reasons(
    findings: &[Finding],
    raw_root_cause_groups: &[RootCauseGroup],
) -> Vec<VerdictReason> {
    [
        detect_prompt_tampering_with_exec(findings, raw_root_cause_groups),
        detect_credential_exfil_chain(findings, raw_root_cause_groups),
        detect_install_hook_with_exec_surface(findings, raw_root_cause_groups),
        detect_broad_permissions_with_autonomy(findings, raw_root_cause_groups),
        detect_mcp_remote_endpoint_with_exec(findings, raw_root_cause_groups),
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

// Checks if a rule fired with an actionable recommendation (not Log).
// NOTE: This checks the original finding action, NOT calibrated state.
// Calibration only modifies root_cause_groups, not individual findings.
// The debug_assert below guards against accidentally using a calibrated
// rule here — use compound_has_category for rules subject to verdict calibration.
fn compound_has_rule(findings: &[Finding], rule_id: &str) -> bool {
    debug_assert!(
        !crate::verdict_calibration::CALIBRATED_RULE_IDS.contains(&rule_id),
        "compound_has_rule checks pre-calibration actions; use compound_has_category for calibrated rule {rule_id}"
    );
    findings
        .iter()
        .any(|f| f.rule_id == rule_id && f.recommended_action != RecommendedAction::Log)
}

// Like compound_has_rule but also requires the finding to belong to a specific artifact scope.
// Use this for manifest/package rules where the scope matters to avoid cross-scope false positives.
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
// action level. Policy overrides can downgrade individual permission findings to Log, but compound
// patterns represent an architectural risk that cannot be waived rule-by-rule.
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
    if compound_has_category(raw_root_cause_groups, ThreatCategory::CredentialExposure)
        && compound_has_category(raw_root_cause_groups, ThreatCategory::DataExfiltration)
    {
        Some(VerdictReason {
            scope: ArtifactScope::SupportingArtifact,
            category: ThreatCategory::DataExfiltration,
            signal_class: SignalClass::MaliciousBehavior,
            rationale:
                "Compound verdict: token or session access is paired with outbound transmission"
                    .to_string(),
        })
    } else {
        None
    }
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

fn detect_mcp_remote_endpoint_with_exec(
    findings: &[Finding],
    raw_root_cause_groups: &[RootCauseGroup],
) -> Option<VerdictReason> {
    let _ = raw_root_cause_groups;
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
    supporting_summary: &FindingSummary,
) -> Vec<DeclaredPermission> {
    let mut permissions = Vec::new();

    for finding in findings
        .iter()
        .filter(|finding| finding.artifact_scope == ArtifactScope::AgentEntrypoint)
    {
        if let Some(permission) = crate::findings::declared_permission_for_rule(&finding.rule_id) {
            if !permissions.contains(&permission) {
                permissions.push(permission);
            }
        }
    }

    let entrypoint_findings: Vec<_> = findings
        .iter()
        .filter(|finding| finding.artifact_scope == ArtifactScope::AgentEntrypoint)
        .collect();

    // Only infer keyword-based permissions from findings that belong to
    // declared-permission, capability, or official rules.  This prevents
    // generic rule matches (e.g. ScopeCreep, Generic) from inflating the
    // declared-permissions list with false positives from broad substrings.
    let permission_relevant_findings: Vec<_> = entrypoint_findings
        .iter()
        .filter(|finding| {
            finding.rule_id.starts_with("DECLARED_PERMISSION_")
                || finding.rule_id.starts_with("CAPABILITY_")
                || finding.rule_id.starts_with("OFFICIAL_")
        })
        .collect();

    // Match keywords against match_value only (not rule_id or reason) to avoid
    // false positives from metadata containing generic substrings like "api" or "token".
    let any_finding_matches = |keywords: &[&str]| -> bool {
        permission_relevant_findings.iter().any(|finding| {
            let text = finding.match_value.to_ascii_lowercase();
            keywords.iter().any(|kw| text.contains(kw))
        })
    };

    let add_if = |permissions: &mut Vec<DeclaredPermission>, cond: bool, permission| {
        if cond && !permissions.contains(&permission) {
            permissions.push(permission);
        }
    };

    add_if(
        &mut permissions,
        any_finding_matches(&[
            "browser",
            "navigation",
            "click any element",
            "full autonomous browser",
            "allow-all",
        ]),
        DeclaredPermission::BrowserFull,
    );
    add_if(
        &mut permissions,
        any_finding_matches(&[
            "write file",
            "delete work",
            "modify file",
            "modify disk",
            "modify local",
        ]),
        DeclaredPermission::FileWrite,
    );
    add_if(
        &mut permissions,
        any_finding_matches(&[
            "shell",
            "command",
            "run command",
            "execute command",
            "shell command",
            "stdio",
        ]) || supporting_summary
            .score_breakdown
            .iter()
            .any(|factor| factor.factor.contains("process_execution")),
        DeclaredPermission::ShellExec,
    );
    add_if(
        &mut permissions,
        any_finding_matches(&[
            "http://",
            "https://",
            "webhook",
            "network",
            "api endpoint",
            "api access",
            "external api",
            "api_key",
        ]) || supporting_summary
            .score_breakdown
            .iter()
            .any(|factor| factor.factor.contains("network_access")),
        DeclaredPermission::NetworkAccess,
    );
    add_if(
        &mut permissions,
        any_finding_matches(&[
            "token",
            "access_token",
            "api_token",
            "auth token",
            "bearer token",
            "secret",
            "password",
            "credential",
            "cookie",
        ]) || supporting_summary
            .score_breakdown
            .iter()
            .any(|factor| factor.factor.contains("secret_access")),
        DeclaredPermission::SecretsAccess,
    );
    add_if(
        &mut permissions,
        any_finding_matches(&[
            "oauth",
            "oauth scope",
            "api scope",
            "drive.scope",
            "calendar.scope",
            "read/write",
            "admin scope",
            "google calendar",
            "calendar.events",
            "google drive",
            "drive.file",
            "slack.com",
            "slack api",
            "slack scope",
        ]),
        DeclaredPermission::OAuthScopes,
    );

    permissions.sort();
    permissions
}

fn derive_effective_capabilities(root_cause_groups: &[RootCauseGroup]) -> Vec<String> {
    let mut capabilities = BTreeSet::<String>::new();
    for group in root_cause_groups
        .iter()
        .filter(|g| g.strongest_action != RecommendedAction::Log)
    {
        let key = match group.category {
            ThreatCategory::RemoteExec => "process_execution",
            ThreatCategory::CredentialExposure => "secret_access",
            ThreatCategory::DataExfiltration => "data_exfiltration",
            ThreatCategory::PersistentPromptTampering => "persistence_surface",
            ThreatCategory::SupplyChain => "supply_chain_installation",
            ThreatCategory::ToolAbuse => "tool_abuse",
            ThreatCategory::AutonomyEscalation => "autonomous_actions",
            ThreatCategory::PrivilegeEscalation => "filesystem_or_runtime_escalation",
            ThreatCategory::ScopeCreep => "scope_creep",
            ThreatCategory::SocialManipulation | ThreatCategory::PersuasiveLanguage => {
                "trust_bypass"
            }
            ThreatCategory::Obfuscation => "obfuscation",
            ThreatCategory::UnsafeBinary => "unsafe_binary",
            ThreatCategory::Generic => "generic_review",
        };
        capabilities.insert(key.to_string());
    }
    capabilities.into_iter().collect()
}

fn build_blast_radius_summary(
    findings: &[Finding],
    declared_permissions: &[DeclaredPermission],
) -> BlastRadiusSummary {
    let mut factors = Vec::new();
    let mut severe_factors = Vec::new();
    let mut network_targets = Vec::new();
    let mut severe_count = 0_u32;

    let is_local_only_target = |value: &str| -> bool {
        let local_indicators = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "[::1]",
            ".local",
            ".internal",
        ];
        let has_local = local_indicators.iter().any(|ind| value.contains(ind));
        if !has_local {
            return false;
        }
        // Check tokens individually so a mixed value like
        // "fetches from http://localhost then sends to https://evil.com"
        // is NOT treated as local-only.
        let external_indicators = ["http://", "https://", "169.254.169.254"];
        let has_non_local_external = value.split_whitespace().any(|token| {
            let is_local = local_indicators.iter().any(|ind| token.contains(ind));
            let is_external = external_indicators.iter().any(|ind| token.contains(ind))
                || (token.contains("://") && !is_local);
            // A token like "http://localhost/redirect?to=https://evil.com" is local
            // by hostname but embeds an external URL in query params or path.
            // Check for embedded external URLs after the local indicator match.
            let has_embedded_external = is_local && {
                let lower = token.to_ascii_lowercase();
                // Find the furthest local indicator match, then check if any
                // external URL appears after it pointing to a non-local host.
                let after_local = local_indicators
                    .iter()
                    .filter_map(|ind| lower.find(ind).map(|pos| pos + ind.len()))
                    .max()
                    .unwrap_or(0);
                let remainder = &lower[after_local..];
                ["http://", "https://"].iter().any(|proto| {
                    remainder.find(proto).is_some_and(|proto_pos| {
                        let embedded = &remainder[proto_pos..];
                        !local_indicators.iter().any(|li| embedded.contains(li))
                    })
                })
            };
            (is_external && !is_local) || has_embedded_external
        });
        !has_non_local_external
    };

    for finding in findings {
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
        if finding.recommended_action != RecommendedAction::Log
            && finding.signal_class != SignalClass::Hygiene
            && !is_local_only_target(&value)
        {
            severe_count += 1;
            if !severe_factors.iter().any(|existing| existing == factor) {
                severe_factors.push(factor.to_string());
            }
        }
        if !factors.iter().any(|existing| existing == factor) {
            factors.push(factor.to_string());
        }
    }

    network_targets.sort();
    network_targets.dedup();

    let level = if severe_count >= 3
        || (severe_count >= 2
            && severe_factors
                .iter()
                .any(|factor| factor == "remote execution" || factor == "data exfiltration"))
    {
        BlastRadiusLevel::High
    } else if severe_count >= 1
        || !declared_permissions.is_empty()
        || findings.iter().any(|f| {
            f.signal_class != SignalClass::Hygiene && f.recommended_action != RecommendedAction::Log
        })
    {
        BlastRadiusLevel::Medium
    } else {
        BlastRadiusLevel::Low
    };

    BlastRadiusSummary {
        level,
        factors,
        network_targets,
        declared_permissions: declared_permissions.to_vec(),
    }
}

/// Merge groups that share `(scope, category, signal_class)` after calibration
/// may have reclassified signal_class, creating duplicates.
fn merge_calibrated_groups(groups: Vec<RootCauseGroup>) -> Vec<RootCauseGroup> {
    let mut merged =
        BTreeMap::<(ArtifactScope, ThreatCategory, SignalClass), RootCauseGroup>::new();
    for group in groups {
        let key = (group.scope, group.category, group.signal_class);
        merged
            .entry(key)
            .and_modify(|existing| {
                existing.finding_count += group.finding_count;
                existing.strongest_action = existing.strongest_action.max(group.strongest_action);
                for rule in &group.representative_rules {
                    if !existing.representative_rules.contains(rule) {
                        existing.representative_rules.push(rule.clone());
                    }
                }
                existing.representative_rules.sort();
                existing
                    .representative_rules
                    .truncate(MAX_REPRESENTATIVE_RULES);
            })
            .or_insert(group);
    }
    let mut result: Vec<_> = merged.into_values().collect();
    result.sort_by(|left, right| {
        right
            .strongest_action
            .cmp(&left.strongest_action)
            .then_with(|| right.finding_count.cmp(&left.finding_count))
    });
    result
}

fn build_root_cause_groups(findings: &[Finding]) -> Vec<RootCauseGroup> {
    let mut groups =
        BTreeMap::<(ArtifactScope, ThreatCategory, SignalClass), RootCauseGroup>::new();

    for finding in findings {
        let key = (
            finding.artifact_scope,
            finding.category,
            finding.signal_class,
        );
        groups
            .entry(key)
            .and_modify(|group| {
                group.finding_count += 1;
                group.strongest_action = group.strongest_action.max(finding.recommended_action);
                if !group.representative_rules.contains(&finding.rule_id) {
                    group.representative_rules.push(finding.rule_id.clone());
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
    for group in &mut groups {
        group.representative_rules.sort();
        group
            .representative_rules
            .truncate(MAX_REPRESENTATIVE_RULES);
    }
    groups.sort_by(|left, right| {
        right
            .strongest_action
            .cmp(&left.strongest_action)
            .then_with(|| right.finding_count.cmp(&left.finding_count))
    });
    groups
}

fn build_hygiene_summary(findings: &[Finding]) -> HygieneSummary {
    let mut top_rules = BTreeMap::<String, usize>::new();
    let mut package_root_findings = 0_usize;
    let mut entrypoint_findings = 0_usize;
    let mut supporting_findings = 0_usize;

    for finding in findings {
        if finding.signal_class != SignalClass::Hygiene {
            continue;
        }

        match finding.artifact_scope {
            ArtifactScope::PackageRootArtifact => package_root_findings += 1,
            ArtifactScope::SupportingArtifact => supporting_findings += 1,
            ArtifactScope::AgentEntrypoint => entrypoint_findings += 1,
        }
        *top_rules.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }

    let mut top_rules: Vec<_> = top_rules.into_iter().collect();
    top_rules.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    HygieneSummary {
        package_root_findings,
        entrypoint_findings,
        supporting_findings,
        top_rules: top_rules
            .into_iter()
            .map(|(rule, _)| rule)
            .take(5)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, FindingSummary, MatchTarget, Severity, ThreatCategory};

    #[test]
    fn test_trivial_hygiene_produces_needs_review_not_elevated() {
        // A single Low/Log hygiene finding should produce NeedsReview, not Elevated.
        let finding = Finding::builder("SCOPE_CREEP_GENERIC", ThreatCategory::ScopeCreep)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .matched_on(MatchTarget::Document)
            .match_value("broad scope")
            .reason("Minor scope creep")
            .build();
        let findings = vec![finding];
        let summary = FindingSummary::from_findings(&findings);

        let report = derive_package_verdict(&findings, &summary, &summary, &summary);

        assert_eq!(
            report.package_health,
            PackageHealth::NeedsReview,
            "Trivial hygiene findings should produce NeedsReview, not Elevated"
        );
        assert_eq!(report.verdict, Verdict::Benign);
    }
}
