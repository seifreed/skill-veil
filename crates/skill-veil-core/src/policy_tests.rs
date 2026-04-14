use super::*;
use crate::artifact_graph::{
    ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactGraph,
};
use crate::findings::{
    ArtifactKind, FindingSummary, MatchTarget, PackageVerdictReport, ThreatCategory, Verdict,
};
use chrono::Utc;

#[test]
fn test_generate_shield_md() {
    let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
        .severity(Severity::High)
        .confidence(0.95)
        .matched_on(MatchTarget::Document)
        .match_value("curl | bash")
        .reason("Test finding")
        .build()];

    let generator = PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new());
    let shield = generator.generate_shield_md();

    assert!(shield.contains("SHIELD Policy"));
    assert!(shield.contains("test-skill"));
    // Policy ID is lowercase: test_rule-test-skill
    assert!(shield.to_lowercase().contains("test_rule"));
}

#[test]
fn test_generate_json() {
    let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
        .severity(Severity::High)
        .confidence(0.95)
        .matched_on(MatchTarget::Document)
        .match_value("curl | bash")
        .reason("Test finding")
        .build()];

    let generator = PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new());
    let json = generator.generate_json();

    assert_eq!(json.skill_name, "test-skill");
    assert_eq!(json.findings.len(), 1);
    assert!(json.artifact_graph.nodes.is_empty());
    assert!(json
        .context_policies
        .iter()
        .any(|policy| policy.context == PolicyContext::Install));
}

#[test]
fn test_generate_sarif() {
    let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
        .severity(Severity::High)
        .confidence(0.95)
        .matched_on(MatchTarget::Document)
        .match_value("curl | bash")
        .reason("Test finding")
        .build()];

    let generator = PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new());
    let sarif = generator.generate_sarif();

    assert_eq!(sarif.version, "2.1.0");
    assert_eq!(sarif.runs.len(), 1);
    // 1 finding + 1 synthetic SKILL_VEIL_ACTION_TRIGGER result = 2 total
    assert_eq!(sarif.runs[0].results.len(), 2);
}

#[test]
fn test_generate_policies_uses_strongest_recommended_action() {
    let findings = vec![
        Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
            .severity(Severity::Low)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("bin")
            .reason("Needs review")
            .build(),
        Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .matched_on(MatchTarget::Document)
            .match_value("context")
            .reason("Context only")
            .build(),
    ];

    let generator = PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new());
    let json = generator.generate_json();

    assert_eq!(json.policies.len(), 1);
    assert_eq!(json.policies[0].action, RecommendedAction::RequireApproval);
}

#[test]
fn test_generate_json_escalates_summary_from_graph_capabilities() {
    let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
        .severity(Severity::Low)
        .action(RecommendedAction::Log)
        .matched_on(MatchTarget::Document)
        .match_value("note")
        .reason("note")
        .build()];

    let mut graph = ArtifactGraph::new();
    graph.add_node_with_capabilities(
        "docker-compose.yml",
        crate::findings::ArtifactKind::PackageManifest,
        vec![
            ArtifactCapabilityFact {
                capability: ArtifactCapability::PrivilegedRuntime,
                source: ArtifactCapabilitySource::Declared,
            },
            ArtifactCapabilityFact {
                capability: ArtifactCapability::HostFilesystemAccess,
                source: ArtifactCapabilitySource::Declared,
            },
        ],
    );

    let generator = PolicyGenerator::new("test-skill", "test.md", findings, graph);
    let json = generator.generate_json();

    assert_eq!(json.summary.recommended_action, RecommendedAction::Block);
    assert!(json
        .summary
        .score_breakdown
        .iter()
        .any(|factor| factor.factor == "capability_combo:privileged_host_filesystem"));
    assert!(json
        .policies
        .iter()
        .all(|policy| policy.action == RecommendedAction::Block));
}

#[test]
fn test_generate_json_includes_context_policies_from_profile() {
    let findings = vec![
        Finding::builder("TEST_SECRET", ThreatCategory::CredentialExposure)
            .severity(Severity::Medium)
            .matched_on(MatchTarget::Document)
            .match_value("api_key")
            .reason("Embedded secret")
            .build(),
    ];

    let generator = PolicyGenerator::new("test-skill", "test.md", findings, ArtifactGraph::new())
        .with_profile(PolicyProfile::Team);
    let json = generator.generate_json();

    let policy = json
        .context_policies
        .iter()
        .find(|policy| policy.context == PolicyContext::Secrets)
        .expect("missing secrets context policy");
    assert_eq!(policy.action, RecommendedAction::Block);
    assert_eq!(json.policy_audit.effective_fail_on, None);
}

#[test]
fn test_generate_sarif_includes_action_trigger_results() {
    let findings = vec![Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
        .severity(Severity::Low)
        .action(RecommendedAction::Log)
        .matched_on(MatchTarget::Document)
        .match_value("note")
        .reason("note")
        .build()];

    let mut graph = ArtifactGraph::new();
    graph.add_node_with_capabilities(
        "docker-compose.yml",
        crate::findings::ArtifactKind::PackageManifest,
        vec![
            crate::artifact_graph::ArtifactCapabilityFact {
                capability: ArtifactCapability::PrivilegedRuntime,
                source: crate::artifact_graph::ArtifactCapabilitySource::Declared,
            },
            crate::artifact_graph::ArtifactCapabilityFact {
                capability: ArtifactCapability::HostFilesystemAccess,
                source: crate::artifact_graph::ArtifactCapabilitySource::Declared,
            },
        ],
    );

    let generator = PolicyGenerator::new("test-skill", "test.md", findings, graph);
    let sarif = generator.generate_sarif();

    assert!(sarif.runs[0]
        .results
        .iter()
        .any(|result| result.rule_id == "SKILL_VEIL_ACTION_TRIGGER"));
}

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
            artifact_path: Some("install.sh".to_string()),
            context: None,
            reason: "accepted".to_string(),
            expires_at: None,
        }],
    };

    let filtered = apply_waivers(vec![finding], Some(&waivers));
    assert!(filtered.is_empty());
}

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
            context: Some(PolicyContext::Secrets),
            reason: "accepted".to_string(),
            expires_at: None,
        }],
    };

    let filtered = apply_waivers(vec![finding], Some(&waivers));
    assert!(filtered.is_empty());
}

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
                artifact_path: Some("install.sh".to_string()),
                context: Some(PolicyContext::Install),
                action: RecommendedAction::Log,
                reason: "specific override".to_string(),
                expires_at: None,
            },
        ],
    };

    let overridden = apply_policy_overrides(vec![finding], Some(&policy));
    assert_eq!(overridden[0].recommended_action, RecommendedAction::Log);
}

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
            artifact_path: Some("install.sh".to_string()),
            context: Some(PolicyContext::Install),
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

#[test]
fn test_policy_file_can_override_profile_context_action() {
    let policy = PolicyFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        profiles: PolicyProfiles {
            team: Some(ConfiguredProfile {
                fail_on: Some(Severity::Medium),
                context_actions: vec![ContextActionOverride {
                    context: PolicyContext::Network,
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
        policy.resolve_context_action(PolicyProfile::Team, PolicyContext::Network),
        RecommendedAction::Block
    );
}

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

#[test]
fn test_diff_reports_detects_new_and_resolved_findings() {
    let previous = JsonReport {
        skill_name: "a".to_string(),
        skill_path: "a".to_string(),
        timestamp: Utc::now(),
        extension_kind: AgentExtensionKind::Skill,
        classification: ArtifactClassification::ConfirmedSkill,
        package_id: None,
        identity_source: ArtifactIdentitySource::ExplicitName,
        structural_validity: StructuralValidity::Confirmed,
        heuristic_score: 0,
        findings: vec![Finding::builder("OLD_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("old")
            .reason("old")
            .build()],
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
        verdict: Verdict::Benign,
        verdict_report: PackageVerdictReport {
            verdict: Verdict::Benign,
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
    };
    let current = JsonReport {
        skill_name: "a".to_string(),
        skill_path: "a".to_string(),
        timestamp: Utc::now(),
        extension_kind: AgentExtensionKind::Skill,
        classification: ArtifactClassification::ConfirmedSkill,
        package_id: None,
        identity_source: ArtifactIdentitySource::ExplicitName,
        structural_validity: StructuralValidity::Confirmed,
        heuristic_score: 0,
        findings: vec![Finding::builder("NEW_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("new")
            .reason("new")
            .build()],
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
        verdict: Verdict::Benign,
        verdict_report: PackageVerdictReport {
            verdict: Verdict::Benign,
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
    };

    let diff = diff_reports(&[previous], &[current]);
    assert_eq!(diff.new_findings.len(), 1);
    assert_eq!(diff.resolved_findings.len(), 1);
    assert_eq!(diff.waived_findings.len(), 0);
    assert_eq!(diff.baselined_findings.len(), 0);
    assert_eq!(diff.unchanged_findings, 0);
}

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
    let current_report = JsonReport {
        skill_name: "a".to_string(),
        skill_path: "a".to_string(),
        timestamp: Utc::now(),
        extension_kind: AgentExtensionKind::Skill,
        classification: ArtifactClassification::ConfirmedSkill,
        package_id: None,
        identity_source: ArtifactIdentitySource::ExplicitName,
        structural_validity: StructuralValidity::Confirmed,
        heuristic_score: 0,
        findings: vec![current_finding.clone()],
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
        verdict: Verdict::Suspicious,
        verdict_report: PackageVerdictReport {
            verdict: Verdict::Suspicious,
            package_health: crate::findings::PackageHealth::NeedsReview,
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
    };
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
    let waived_report = JsonReport {
        skill_name: "b".to_string(),
        skill_path: "b".to_string(),
        timestamp: Utc::now(),
        extension_kind: AgentExtensionKind::Skill,
        classification: ArtifactClassification::ConfirmedSkill,
        package_id: None,
        identity_source: ArtifactIdentitySource::ExplicitName,
        structural_validity: StructuralValidity::Confirmed,
        heuristic_score: 0,
        findings: vec![waived_finding.clone()],
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
        verdict: Verdict::Suspicious,
        verdict_report: PackageVerdictReport {
            verdict: Verdict::Suspicious,
            package_health: crate::findings::PackageHealth::NeedsReview,
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
    };
    let waivers = WaiverFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        waivers: vec![WaiverEntry {
            rule_id: Some("WAIVE_RULE".to_string()),
            artifact_path: None,
            context: Some(PolicyContext::Secrets),
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
