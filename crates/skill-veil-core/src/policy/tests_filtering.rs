use super::*;
use crate::analyzer::{
    AgentExtensionKind, ArtifactClassification, ArtifactIdentitySource, StructuralValidity,
};
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{
    ArtifactKind, Finding, FindingSummary, MatchTarget, PackageVerdictReport, ThreatCategory,
    Verdict,
};
use chrono::Utc;

/// Contract: `apply_baseline` MUST drop every finding whose fingerprint
/// matches a `BaselineEntry`, leaving callers with only findings the
/// policy author has not yet acknowledged.
#[test]
fn test_apply_baseline_filters_known_findings() {
    let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .build();
    let baseline = BaselineFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        entries: vec![BaselineEntry {
            fingerprint: finding_fingerprint(&finding),
            rule_id: finding.rule_id.clone(),
            artifact_path: finding.artifact_path.clone(),
            reason: finding.reason.clone(),
        }],
    };

    let filtered = apply_baseline(vec![finding], Some(&baseline));
    assert!(filtered.is_empty());
}

/// Contract: `apply_waivers` MUST drop a finding whose `rule_id` and
/// `artifact_path` both match a `WaiverEntry`; the waiver is the
/// caller's explicit acceptance of that signal at that location.
#[test]
fn test_apply_waivers_filters_matching_findings() {
    let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
        .artifact(
            crate::findings::ArtifactKind::ReferencedArtifact,
            Some("scripts/install.sh".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .build();
    let waivers = WaiverFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        waivers: vec![WaiverEntry {
            rule_id: Some("TEST_RULE".to_string()),
            artifact_path: Some("scripts/install.sh".to_string()),
            context: None,
            reason: "accepted".to_string(),
            expires_at: None,
        }],
    };

    let filtered = apply_waivers(vec![finding], Some(&waivers));
    assert!(filtered.is_empty());
}

/// Contract: `apply_waivers` MUST also accept `OperationalContext` as a
/// matching dimension — a waiver can wave findings of a given rule_id
/// across all artifact paths whenever they fire under the declared
/// context (e.g., `Secrets`).
#[test]
fn test_apply_waivers_filters_matching_context() {
    let finding = Finding::builder("TEST_SECRET", ThreatCategory::CredentialExposure)
        .matched_on(MatchTarget::Document)
        .match_value("token")
        .reason("secret")
        .build();
    let waivers = WaiverFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        waivers: vec![WaiverEntry {
            rule_id: Some("TEST_SECRET".to_string()),
            artifact_path: None,
            context: Some(OperationalContext::Secrets),
            reason: "accepted".to_string(),
            expires_at: None,
        }],
    };

    let filtered = apply_waivers(vec![finding], Some(&waivers));
    assert!(filtered.is_empty());
}

/// Contract: when multiple `PolicyOverride`s match the same finding,
/// `apply_policy_overrides` MUST pick the most specific one
/// (rule_id + artifact_path + context wins over rule_id alone). This
/// stops a broad org-wide override from silently masking a precise,
/// per-artifact decision.
#[test]
fn test_apply_policy_overrides_uses_most_specific_match() {
    let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some("scripts/install.sh".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .action(RecommendedAction::Block)
        .build();
    let policy = PolicyFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        profiles: PolicyProfiles::default(),
        overrides: vec![
            PolicyOverride {
                id: None,
                rule_id: Some("TEST_RULE".to_string()),
                artifact_path: None,
                context: None,
                action: RecommendedAction::RequireApproval,
                reason: "broad override".to_string(),
                expires_at: None,
            },
            PolicyOverride {
                id: None,
                rule_id: Some("TEST_RULE".to_string()),
                artifact_path: Some("scripts/install.sh".to_string()),
                context: Some(OperationalContext::Install),
                action: RecommendedAction::Log,
                reason: "specific override".to_string(),
                expires_at: None,
            },
        ],
    };

    let overridden = apply_policy_overrides(vec![finding], Some(&policy));
    assert_eq!(overridden[0].recommended_action, RecommendedAction::Log);
}

/// Contract: `apply_policy_overrides_with_audit` MUST emit an
/// `OverrideAuditEntry` for every override it applies, carrying the
/// override's `id` so reviewers can trace why a given finding was
/// downgraded back to the policy file that authorized it.
#[test]
fn test_apply_policy_overrides_with_audit_records_override() {
    let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some("scripts/install.sh".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .action(RecommendedAction::Block)
        .build();
    let policy = PolicyFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        profiles: PolicyProfiles::default(),
        overrides: vec![PolicyOverride {
            id: Some("override-1".to_string()),
            rule_id: Some("TEST_RULE".to_string()),
            artifact_path: Some("scripts/install.sh".to_string()),
            context: Some(OperationalContext::Install),
            action: RecommendedAction::Log,
            reason: "specific override".to_string(),
            expires_at: None,
        }],
    };

    let (overridden, audit) = apply_policy_overrides_with_audit(vec![finding], Some(&policy));
    assert_eq!(overridden[0].recommended_action, RecommendedAction::Log);
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].override_id.as_deref(), Some("override-1"));
}

/// Contract: a `ConfiguredProfile` declared in `PolicyFile.profiles`
/// MUST be honored by `resolve_fail_on` and `resolve_context_action`,
/// so org-level guardrails (per-team `fail_on`, per-context Block)
/// take effect without each finding needing its own override.
#[test]
fn test_policy_file_can_override_profile_context_action() {
    let policy = PolicyFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        profiles: PolicyProfiles {
            team: Some(ConfiguredProfile {
                fail_on: Some(Severity::Medium),
                context_actions: vec![ContextActionOverride {
                    context: OperationalContext::Network,
                    action: RecommendedAction::Block,
                }],
            }),
            ..PolicyProfiles::default()
        },
        overrides: Vec::new(),
    };

    assert_eq!(
        policy.resolve_fail_on(PolicyProfile::Team),
        Some(Severity::Medium)
    );
    assert_eq!(
        policy.resolve_context_action(PolicyProfile::Team, OperationalContext::Network),
        RecommendedAction::Block
    );
}

/// Contract (negative): `validate_policy` MUST reject a `PolicyOverride`
/// that defines no selectors at all (rule_id, artifact_path, context all
/// `None`). A selectorless override would silently match every finding
/// and effectively disable the rule engine; failing fast at policy load
/// is the only safe outcome.
#[test]
fn test_validate_policy_rejects_selectorless_override() {
    let policy = PolicyFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        profiles: PolicyProfiles::default(),
        overrides: vec![PolicyOverride {
            id: None,
            rule_id: None,
            artifact_path: None,
            context: None,
            action: RecommendedAction::Log,
            reason: "invalid".to_string(),
            expires_at: None,
        }],
    };

    assert!(validate_policy(&policy).is_err());
}

/// Contract (positive): `validate_policy` MUST accept an override that
/// declares at least one selector (here `rule_id`). Pairs with
/// [`test_validate_policy_rejects_selectorless_override`] so both
/// directions of the selector-presence rule are pinned, per the
/// CLAUDE.md mandate to cover positive AND negative cases.
#[test]
fn test_validate_policy_accepts_override_with_rule_id_selector() {
    let policy = PolicyFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        profiles: PolicyProfiles::default(),
        overrides: vec![PolicyOverride {
            id: None,
            rule_id: Some("TEST_RULE".to_string()),
            artifact_path: None,
            context: None,
            action: RecommendedAction::Log,
            reason: "valid override".to_string(),
            expires_at: None,
        }],
    };

    assert!(validate_policy(&policy).is_ok());
}

fn make_report(skill: &str, findings: Vec<Finding>, verdict: Verdict) -> JsonReport {
    JsonReport {
        skill_name: skill.to_string(),
        skill_path: skill.to_string(),
        timestamp: Utc::now(),
        extension_kind: AgentExtensionKind::Skill,
        classification: ArtifactClassification::ConfirmedSkill,
        package_id: None,
        identity_source: ArtifactIdentitySource::ExplicitName,
        structural_validity: StructuralValidity::Confirmed,
        heuristic_score: 0,
        findings,
        primary_findings: Vec::new(),
        supporting_findings: Vec::new(),
        summary: FindingSummary::from_findings(&[]),
        primary_summary: FindingSummary::from_findings(&[]),
        supporting_summary: FindingSummary::from_findings(&[]),
        artifact_graph: ArtifactGraph::new(),
        policies: Vec::new(),
        context_policies: Vec::new(),
        profile: None,
        suppression_summary: SuppressionSummary::default(),
        policy_audit: PolicyAudit::default(),
        verdict,
        verdict_report: PackageVerdictReport {
            verdict,
            package_health: crate::findings::PackageHealth::Healthy,
            hygiene_summary: crate::findings::HygieneSummary::default(),
            declared_permissions: Vec::new(),
            effective_capabilities: Vec::new(),
            blast_radius_summary: crate::findings::BlastRadiusSummary::default(),
            verdict_reasons: Vec::new(),
            root_cause_groups: Vec::new(),
            top_risk_drivers: Vec::new(),
            calibration_notes: Vec::new(),
            calibration_risk_adjustment: 0,
        },
    }
}

/// Contract: `diff_reports` MUST classify findings present only in the
/// current scan as `new_findings` and findings present only in the
/// previous scan as `resolved_findings`, so reviewers can see what
/// changed across runs without re-deriving fingerprints by hand.
#[test]
fn test_diff_reports_detects_new_and_resolved_findings() {
    let previous = make_report(
        "a",
        vec![Finding::builder("OLD_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("old")
            .reason("old")
            .build()],
        Verdict::Benign,
    );
    let current = make_report(
        "a",
        vec![Finding::builder("NEW_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("new")
            .reason("new")
            .build()],
        Verdict::Benign,
    );

    let diff = diff_reports(&[previous], &[current]);
    assert_eq!(diff.new_findings.len(), 1);
    assert_eq!(diff.resolved_findings.len(), 1);
    assert_eq!(diff.waived_findings.len(), 0);
    assert_eq!(diff.baselined_findings.len(), 0);
    assert_eq!(diff.unchanged_findings, 0);
}

/// Contract: when a baseline and waiver file are passed to
/// `diff_reports_with_policy_state`, findings matching them MUST be
/// surfaced as `baselined_findings` and `waived_findings` respectively
/// rather than masquerading as `new_findings` — otherwise CI would
/// fail-loud on signals the policy already accepted.
#[test]
fn test_diff_reports_classifies_waived_and_baselined_findings() {
    let current_finding = Finding::builder("CUR_RULE", ThreatCategory::CredentialExposure)
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some("scripts/install.sh".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("token")
        .reason("current")
        .build();
    let current_report = make_report("a", vec![current_finding.clone()], Verdict::Suspicious);
    let baseline = BaselineFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        entries: vec![BaselineEntry {
            fingerprint: finding_fingerprint(&current_finding),
            rule_id: current_finding.rule_id.clone(),
            artifact_path: current_finding.artifact_path.clone(),
            reason: current_finding.reason.clone(),
        }],
    };
    let waived_finding = Finding::builder("WAIVE_RULE", ThreatCategory::CredentialExposure)
        .matched_on(MatchTarget::Document)
        .match_value("secret")
        .reason("waive me")
        .build();
    let waived_report = make_report("b", vec![waived_finding.clone()], Verdict::Suspicious);
    let waivers = WaiverFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        waivers: vec![WaiverEntry {
            rule_id: Some("WAIVE_RULE".to_string()),
            artifact_path: None,
            context: Some(OperationalContext::Secrets),
            reason: "approved".to_string(),
            expires_at: None,
        }],
    };

    let diff = diff_reports_with_policy_state(
        &[],
        &[current_report, waived_report],
        Some(&baseline),
        Some(&waivers),
    );

    assert_eq!(diff.new_findings.len(), 0);
    assert_eq!(diff.waived_findings.len(), 1);
    assert_eq!(diff.baselined_findings.len(), 1);
}

/// Contract: a finding whose `match_value` or `reason` text drifts
/// between scans but whose rule_id + artifact_path still match an
/// active waiver MUST be classified ONLY as `waived_findings`, never
/// double-counted as `resolved_findings`. The earlier behaviour
/// double-counted because fingerprints differed when the text drifted,
/// inflating the resolved bucket on every minor wording change.
#[test]
fn test_diff_reports_waived_finding_with_changed_text_is_not_also_resolved() {
    let previous_finding = Finding::builder("RULE_A", ThreatCategory::CredentialExposure)
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some("scripts/deploy.sh".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("old_token_text")
        .reason("old reason")
        .build();
    let previous_report = make_report("a", vec![previous_finding], Verdict::Suspicious);

    let current_finding = Finding::builder("RULE_A", ThreatCategory::CredentialExposure)
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some("scripts/deploy.sh".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("new_token_text")
        .reason("updated reason")
        .build();
    let current_report = make_report("a", vec![current_finding], Verdict::Suspicious);

    // Waiver matches the current finding by rule_id + artifact_path
    let waivers = WaiverFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        waivers: vec![WaiverEntry {
            rule_id: Some("RULE_A".to_string()),
            artifact_path: Some("scripts/deploy.sh".to_string()),
            context: None,
            reason: "accepted risk".to_string(),
            expires_at: None,
        }],
    };

    let diff =
        diff_reports_with_policy_state(&[previous_report], &[current_report], None, Some(&waivers));

    // The finding should appear as waived, NOT as resolved.
    // Before the fix, the different fingerprints caused it to appear as both.
    assert_eq!(
        diff.waived_findings.len(),
        1,
        "Finding should be classified as waived"
    );
    assert_eq!(
        diff.resolved_findings.len(),
        0,
        "Finding must NOT appear as resolved when it was waived in current scan"
    );
}

/// Contract: when an absolute artifact path on the finding shares a
/// ≥3-component suffix with the waiver's relative `artifact_path`, the
/// fuzzy path match MUST count as a hit so the finding is classified
/// as `waived_findings`, not `resolved_findings`. Earlier exact-equality
/// comparison silently treated waived findings as resolved whenever the
/// scan ran from a different working directory.
#[test]
fn test_diff_reports_waived_finding_with_fuzzy_path_is_not_resolved() {
    let previous_finding = Finding::builder("RULE_B", ThreatCategory::CredentialExposure)
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some("/repo/scripts/deploy.sh".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("token_value")
        .reason("exposed token")
        .build();
    let previous_report = make_report("a", vec![previous_finding], Verdict::Suspicious);

    let current_finding = Finding::builder("RULE_B", ThreatCategory::CredentialExposure)
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some("/repo/scripts/deploy.sh".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("token_value")
        .reason("exposed token")
        .build();
    let current_report = make_report("a", vec![current_finding], Verdict::Suspicious);

    // Waiver uses a 3-component relative path: paths_match's
    // cross-package safety contract requires ≥3 components for suffix
    // matching (a 2-component "scripts/deploy.sh" would silently apply
    // across unrelated packages in monorepo / dataset scans). This
    // qualifying path mirrors `/repo/scripts/deploy.sh` for the suffix
    // match while staying specific enough to avoid cross-package leakage.
    let waivers = WaiverFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        waivers: vec![WaiverEntry {
            rule_id: Some("RULE_B".to_string()),
            artifact_path: Some("repo/scripts/deploy.sh".to_string()),
            context: None,
            reason: "accepted risk".to_string(),
            expires_at: None,
        }],
    };

    let diff =
        diff_reports_with_policy_state(&[previous_report], &[current_report], None, Some(&waivers));

    // The finding should be waived (fuzzy path match), NOT resolved.
    // Before the fix, the exact-equality check on artifact_path in
    // suppressed_logical_ids caused the previous finding to appear as
    // "resolved" because "/repo/scripts/deploy.sh" != "scripts/deploy.sh".
    assert_eq!(
        diff.waived_findings.len(),
        1,
        "Finding should be classified as waived via fuzzy path match"
    );
    assert_eq!(
        diff.resolved_findings.len(),
        0,
        "Finding must NOT appear as resolved when it was waived with a fuzzy path"
    );
}

/// Contract: `PolicyGenerator::generate_sarif` MUST emit a document that
/// satisfies the SARIF 2.1.0 required-field set ($schema, version, runs
/// with a non-empty array of {tool.driver.name, tool.driver.rules,
/// results}, and per-result {ruleId, level, message.text, locations}).
/// Downstream tooling (GitHub code-scanning, IDEs) treats missing fields
/// as a hard parse error, so this contract pins SARIF compatibility.
#[test]
fn sarif_output_conforms_to_2_1_0_schema() {
    let findings = vec![
        Finding::builder("SCHEMA_TEST_RULE", ThreatCategory::RemoteExec)
            .severity(Severity::High)
            .confidence(0.9)
            .matched_on(MatchTarget::Document)
            .match_value("curl | bash")
            .reason("Schema compliance test finding")
            .artifact(
                crate::findings::ArtifactKind::SkillDocument,
                Some("test.md".to_string()),
            )
            .line(42)
            .build(),
    ];

    let generator = PolicyGenerator::new(
        "schema-test-skill",
        "test.md",
        findings,
        ArtifactGraph::new(),
    );
    let sarif = generator.generate_sarif();
    let value = serde_json::to_value(&sarif).expect("SARIF must serialize to JSON");

    // Top-level SARIF 2.1.0 required fields
    assert_eq!(value["$schema"], "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
    assert_eq!(value["version"], "2.1.0");
    assert!(
        value["runs"].is_array() && !value["runs"].as_array().unwrap().is_empty(),
        "runs must be non-empty array"
    );

    // Run structure
    let run = &value["runs"][0];
    assert!(
        run["tool"]["driver"]["name"].is_string(),
        "driver.name required"
    );
    assert!(
        run["tool"]["driver"]["rules"].is_array(),
        "driver.rules required"
    );
    assert!(run["results"].is_array(), "results required");

    // Finding result structure
    let result = &run["results"][0];
    assert!(result["ruleId"].is_string(), "ruleId required");
    assert!(result["level"].is_string(), "level required");
    assert!(
        result["message"]["text"].is_string(),
        "message.text required"
    );
    assert!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].is_string(),
        "location uri required"
    );
    assert_eq!(
        result["locations"][0]["physicalLocation"]["region"]["startLine"], 42,
        "startLine must match"
    );

    // Extension properties
    let props = &result["properties"];
    assert!(
        props["signal_class"].is_string(),
        "signal_class extension required"
    );
    assert!(
        props["recommended_action"].is_string(),
        "recommended_action extension required"
    );
    assert!(
        props["package_verdict"].is_string(),
        "package_verdict extension required"
    );
}
