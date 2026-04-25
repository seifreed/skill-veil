use super::*;
use crate::benchmark_output::render_benchmark_dashboard;
use crate::cli_args::ColorChoiceArg;
use crate::color::ColorMode;
use crate::dataset::format_dataset_verdicts_text;
use crate::dataset::DatasetPackageVerdictEntry;
use crate::rule_tools::{
    build_rule_pack_info, validate_fixture_case, validate_rules_directory, RuleFixtureCase,
};
use crate::text_output::{format_diff_ci_summary, format_text_output, TextOutputOptions};
use skill_veil_core::{
    ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactGraph,
    ArtifactKind, ArtifactMetadata, BenchmarkHistory, CorpusEvaluation, MatchTarget,
    RecommendedAction, ScanResult, ThreatCategory,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn make_temp_rules_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("skill-veil-rules-{unique}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_format_text_output_includes_policy_escalation_reasons() {
    let findings = vec![
        skill_veil_core::Finding::builder("TEST_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("note")
            .reason("note")
            .action(RecommendedAction::Log)
            .build(),
    ];

    let mut graph = ArtifactGraph::new();
    graph.add_node_with_capabilities(
        "docker-compose.yml",
        ArtifactKind::PackageManifest,
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

    let summary =
        skill_veil_core::findings::FindingSummary::from_findings_and_graph(&findings, &graph);
    let result = ScanResult {
        metadata: ArtifactMetadata {
            path: PathBuf::from("SKILL.md"),
            name: "skill".to_string(),
            extension_kind: skill_veil_core::AgentExtensionKind::Skill,
            classification: skill_veil_core::ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: skill_veil_core::ArtifactIdentitySource::ExplicitName,
            structural_validity: skill_veil_core::StructuralValidity::Confirmed,
            heuristic_score: 0,
            primary_artifact_kind: ArtifactKind::SkillDocument,
        },
        findings: findings.clone(),
        suppressed_findings: vec![],
        primary_findings: findings,
        supporting_findings: Vec::new(),
        primary_summary: summary.clone(),
        supporting_summary: skill_veil_core::findings::FindingSummary::from_findings(&[]),
        summary,
        verdict: skill_veil_core::Verdict::Malicious,
        verdict_report: skill_veil_core::PackageVerdictReport {
            verdict: skill_veil_core::Verdict::Malicious,
            package_health: skill_veil_core::PackageHealth::Healthy,
            hygiene_summary: skill_veil_core::HygieneSummary::default(),
            declared_permissions: Vec::new(),
            effective_capabilities: Vec::new(),
            blast_radius_summary: skill_veil_core::BlastRadiusSummary::default(),
            verdict_reasons: Vec::new(),
            root_cause_groups: Vec::new(),
            top_risk_drivers: Vec::new(),
            calibration_notes: Vec::new(),
            calibration_risk_adjustment: 0,
        },
        deduplication_summary: Default::default(),
        artifact_graph: graph,
        profile: None,
        policy: None,
        suppression_summary: Default::default(),
        policy_audit: Default::default(),
        should_fail: false,
        extracted_iocs: Default::default(),
    };

    let output = format_text_output(&[result], TextOutputOptions::default());

    assert!(output.contains("Policy escalation reasons:"));
    assert!(output.contains("capability_combo:privileged_host_filesystem"));
    assert!(output.contains("Policy escalation triggers:"));
}

#[test]
fn test_format_text_output_quiet_summary_hides_detailed_findings() {
    let findings = vec![
        skill_veil_core::Finding::builder("TEST_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("note")
            .reason("note")
            .action(RecommendedAction::Log)
            .build(),
    ];

    let summary = skill_veil_core::findings::FindingSummary::from_findings(&findings);
    let result = ScanResult {
        metadata: ArtifactMetadata {
            path: PathBuf::from("SKILL.md"),
            name: "skill".to_string(),
            extension_kind: skill_veil_core::AgentExtensionKind::Skill,
            classification: skill_veil_core::ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: skill_veil_core::ArtifactIdentitySource::ExplicitName,
            structural_validity: skill_veil_core::StructuralValidity::Confirmed,
            heuristic_score: 0,
            primary_artifact_kind: ArtifactKind::SkillDocument,
        },
        findings: findings.clone(),
        suppressed_findings: vec![],
        primary_findings: findings,
        supporting_findings: Vec::new(),
        primary_summary: summary.clone(),
        supporting_summary: skill_veil_core::findings::FindingSummary::from_findings(&[]),
        summary,
        verdict: skill_veil_core::Verdict::Benign,
        verdict_report: skill_veil_core::PackageVerdictReport {
            verdict: skill_veil_core::Verdict::Benign,
            package_health: skill_veil_core::PackageHealth::Healthy,
            hygiene_summary: skill_veil_core::HygieneSummary::default(),
            declared_permissions: Vec::new(),
            effective_capabilities: Vec::new(),
            blast_radius_summary: skill_veil_core::BlastRadiusSummary::default(),
            verdict_reasons: Vec::new(),
            root_cause_groups: Vec::new(),
            top_risk_drivers: Vec::new(),
            calibration_notes: Vec::new(),
            calibration_risk_adjustment: 0,
        },
        deduplication_summary: Default::default(),
        artifact_graph: ArtifactGraph::new(),
        profile: None,
        policy: None,
        suppression_summary: Default::default(),
        policy_audit: Default::default(),
        should_fail: false,
        extracted_iocs: Default::default(),
    };

    let output = format_text_output(
        &[result],
        TextOutputOptions {
            quiet_summary: true,
            explain_policy: false,
            finding_limit: None,
            color: ColorMode::from_choice(ColorChoiceArg::Never, false),
        },
    );

    assert!(output.contains("Primary findings: 1"));
    assert!(output.contains("Supporting findings: 0"));
    assert!(output.contains("Total findings: 1"));
    assert!(!output.contains("Match: \"note\""));
}

#[test]
fn test_format_text_output_explain_policy_focuses_on_policy_section() {
    let findings = vec![
        skill_veil_core::Finding::builder("TEST_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("note")
            .reason("note")
            .action(RecommendedAction::Log)
            .build(),
    ];

    let mut graph = ArtifactGraph::new();
    graph.add_node_with_capabilities(
        "docker-compose.yml",
        ArtifactKind::PackageManifest,
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

    let summary =
        skill_veil_core::findings::FindingSummary::from_findings_and_graph(&findings, &graph);
    let result = ScanResult {
        metadata: ArtifactMetadata {
            path: PathBuf::from("SKILL.md"),
            name: "skill".to_string(),
            extension_kind: skill_veil_core::AgentExtensionKind::Skill,
            classification: skill_veil_core::ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: skill_veil_core::ArtifactIdentitySource::ExplicitName,
            structural_validity: skill_veil_core::StructuralValidity::Confirmed,
            heuristic_score: 0,
            primary_artifact_kind: ArtifactKind::SkillDocument,
        },
        findings: findings.clone(),
        suppressed_findings: vec![],
        primary_findings: findings,
        supporting_findings: Vec::new(),
        primary_summary: summary.clone(),
        supporting_summary: skill_veil_core::findings::FindingSummary::from_findings(&[]),
        summary,
        verdict: skill_veil_core::Verdict::Malicious,
        verdict_report: skill_veil_core::PackageVerdictReport {
            verdict: skill_veil_core::Verdict::Malicious,
            package_health: skill_veil_core::PackageHealth::Healthy,
            hygiene_summary: skill_veil_core::HygieneSummary::default(),
            declared_permissions: Vec::new(),
            effective_capabilities: Vec::new(),
            blast_radius_summary: skill_veil_core::BlastRadiusSummary::default(),
            verdict_reasons: Vec::new(),
            root_cause_groups: Vec::new(),
            top_risk_drivers: Vec::new(),
            calibration_notes: Vec::new(),
            calibration_risk_adjustment: 0,
        },
        deduplication_summary: Default::default(),
        artifact_graph: graph,
        profile: None,
        policy: None,
        suppression_summary: Default::default(),
        policy_audit: Default::default(),
        should_fail: false,
        extracted_iocs: Default::default(),
    };

    let output = format_text_output(
        &[result],
        TextOutputOptions {
            quiet_summary: false,
            explain_policy: true,
            finding_limit: None,
            color: ColorMode::from_choice(ColorChoiceArg::Never, false),
        },
    );

    assert!(output.contains("Final recommended action: block"));
    assert!(output.contains("Policy escalation reasons:"));
    assert!(!output.contains("Match: \"note\""));
    assert!(!output.contains("Top score factors:"));
}

#[test]
fn test_format_diff_ci_summary_is_compact() {
    let diff = skill_veil_core::DiffReport {
        new_findings: vec![skill_veil_core::DiffEntry {
            fingerprint: "a".to_string(),
            rule_id: "NEW_RULE".to_string(),
            category: skill_veil_core::ThreatCategory::Generic,
            artifact_path: Some("SKILL.md".to_string()),
            reason: "new".to_string(),
        }],
        resolved_findings: vec![skill_veil_core::DiffEntry {
            fingerprint: "b".to_string(),
            rule_id: "OLD_RULE".to_string(),
            category: skill_veil_core::ThreatCategory::Generic,
            artifact_path: None,
            reason: "old".to_string(),
        }],
        waived_findings: vec![skill_veil_core::DiffEntry {
            fingerprint: "c".to_string(),
            rule_id: "WAIVE_RULE".to_string(),
            category: skill_veil_core::ThreatCategory::Generic,
            artifact_path: None,
            reason: "waived".to_string(),
        }],
        baselined_findings: vec![skill_veil_core::DiffEntry {
            fingerprint: "d".to_string(),
            rule_id: "BASE_RULE".to_string(),
            category: skill_veil_core::ThreatCategory::Generic,
            artifact_path: None,
            reason: "baselined".to_string(),
        }],
        unchanged_findings: 3,
    };

    let output = format_diff_ci_summary(&diff);
    assert_eq!(
        output,
        "DIFF new_active=1 resolved=1 waived=1 baselined=1 unchanged=3\n"
    );
}

#[test]
fn test_validate_rule_pack_reports_duplicates() {
    let dir = make_temp_rules_dir();
    fs::write(
        dir.join("rules.yaml"),
        r#"
schema_version: skill-veil.dev/rules/v1alpha1
metadata:
  name: duplicate-pack
  kind: official
  compatibility:
    - skill-veil.dev/rules/v1alpha1
rules:
  - id: DUP_RULE
    category: generic
    severity: medium
    confidence: 0.8
    when: !regex
      pattern: "dup"
    action: require_approval
    reason: "dup 1"
  - id: DUP_RULE
    category: generic
    severity: medium
    confidence: 0.8
    when: !regex
      pattern: "dup"
    action: require_approval
    reason: "dup 2"
"#,
    )
    .unwrap();

    let report = validate_rules_directory(&dir).unwrap();
    assert!(!report.valid);
    assert_eq!(report.duplicate_rule_ids, vec!["DUP_RULE".to_string()]);
}

#[test]
fn test_build_rule_pack_info_summarizes_rules() {
    let dir = make_temp_rules_dir();
    fs::write(
        dir.join("rules.yaml"),
        r#"
schema_version: skill-veil.dev/rules/v1alpha1
metadata:
  name: info-pack
  kind: community
  compatibility:
    - skill-veil.dev/rules/v1alpha1
rules:
  - id: INFO_RULE
    category: tool_abuse
    severity: high
    confidence: 0.9
    when: !regex
      pattern: "tool"
    action: block
    reason: "tool"
    tags: ["official_pack", "tooling"]
"#,
    )
    .unwrap();

    let info = build_rule_pack_info(&dir).unwrap();
    assert_eq!(info.total_rules, 1);
    assert_eq!(info.enabled_rules, 1);
    assert_eq!(info.pack_files, 1);
    assert!(info.pack_names.contains("info-pack"));
    assert!(info.pack_kinds.contains("community"));
    assert_eq!(info.by_category.get("tool_abuse"), Some(&1));
    assert!(info.tags.contains("official_pack"));
}

#[test]
fn test_validate_fixture_case_checks_full_expectations() {
    let findings = vec![
        skill_veil_core::Finding::builder("TEST_RULE", ThreatCategory::ToolAbuse)
            .severity(Severity::High)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("extract cookies")
            .reason("tool abuse")
            .build(),
    ];
    let case = RuleFixtureCase {
        name: Some("case".to_string()),
        rule_id: "TEST_RULE".to_string(),
        content: "# Skill".to_string(),
        file_name: None,
        expect_match: Some(true),
        expected_count: Some(1),
        expected_severity: Some(Severity::High),
        expected_action: Some(RecommendedAction::RequireApproval),
        expected_category: Some("tool_abuse".to_string()),
    };

    validate_fixture_case(&case, &findings).unwrap();
}

#[test]
fn test_update_benchmark_history_replaces_same_release() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let history_path = std::env::temp_dir().join(format!("skill-veil-history-{unique}.json"));

    let evaluation = CorpusEvaluation {
        metrics: skill_veil_core::RegressionMetrics {
            precision: 1.0,
            recall: 1.0,
            false_positive_rate: 0.0,
            accuracy: 1.0,
            exact_label_accuracy: 1.0,
            true_positive: 1,
            false_positive: 0,
            true_negative: 1,
            false_negative: 0,
        },
        coverage: skill_veil_core::CorpusCoverage {
            total_samples: 2,
            by_label: vec![
                skill_veil_core::CoverageBucket {
                    key: "benign".to_string(),
                    samples: 1,
                },
                skill_veil_core::CoverageBucket {
                    key: "malicious".to_string(),
                    samples: 1,
                },
            ],
            by_focus_category: vec![skill_veil_core::CoverageBucket {
                key: "remote_exec".to_string(),
                samples: 1,
            }],
            by_attack_family: vec![skill_veil_core::CoverageBucket {
                key: "remote_exec".to_string(),
                samples: 1,
            }],
        },
        deduplication: skill_veil_core::DeduplicationMetrics {
            original_findings: 2,
            unique_findings: 1,
            duplicates_removed: 1,
        },
        confidence_calibration: Default::default(),
        threshold_recommendation: skill_veil_core::ThresholdRecommendation {
            current_approval_threshold: 20,
            current_block_threshold: 50,
            recommended_approval_threshold: 25,
            recommended_block_threshold: 55,
            current_metrics: skill_veil_core::RegressionMetrics {
                precision: 0.9,
                recall: 1.0,
                false_positive_rate: 0.1,
                accuracy: 0.95,
                exact_label_accuracy: 0.95,
                true_positive: 2,
                false_positive: 1,
                true_negative: 8,
                false_negative: 0,
            },
            recommended_metrics: skill_veil_core::RegressionMetrics {
                precision: 1.0,
                recall: 1.0,
                false_positive_rate: 0.0,
                accuracy: 1.0,
                exact_label_accuracy: 1.0,
                true_positive: 2,
                false_positive: 0,
                true_negative: 9,
                false_negative: 0,
            },
            rationale: "thresholds tuned".to_string(),
        },
        family_metrics: vec![skill_veil_core::AttackFamilyMetrics {
            family: "remote_exec".to_string(),
            sample_count: 1,
            metrics: skill_veil_core::RegressionMetrics {
                precision: 1.0,
                recall: 1.0,
                false_positive_rate: 0.0,
                accuracy: 1.0,
                exact_label_accuracy: 1.0,
                true_positive: 1,
                false_positive: 0,
                true_negative: 0,
                false_negative: 0,
            },
            threshold_recommendation: skill_veil_core::ThresholdRecommendation {
                current_approval_threshold: 20,
                current_block_threshold: 50,
                recommended_approval_threshold: 24,
                recommended_block_threshold: 54,
                current_metrics: skill_veil_core::RegressionMetrics {
                    precision: 1.0,
                    recall: 1.0,
                    false_positive_rate: 0.0,
                    accuracy: 1.0,
                    exact_label_accuracy: 1.0,
                    true_positive: 1,
                    false_positive: 0,
                    true_negative: 0,
                    false_negative: 0,
                },
                recommended_metrics: skill_veil_core::RegressionMetrics {
                    precision: 1.0,
                    recall: 1.0,
                    false_positive_rate: 0.0,
                    accuracy: 1.0,
                    exact_label_accuracy: 1.0,
                    true_positive: 1,
                    false_positive: 0,
                    true_negative: 0,
                    false_negative: 0,
                },
                rationale: "family thresholds tuned".to_string(),
            },
        }],
        samples: Vec::new(),
    };

    commands::update_benchmark_history(&history_path, "v0.1.0", &evaluation).unwrap();
    commands::update_benchmark_history(&history_path, "v0.1.0", &evaluation).unwrap();

    let content = fs::read_to_string(&history_path).unwrap();
    let history: BenchmarkHistory = serde_json::from_str(&content).unwrap();
    assert_eq!(history.releases.len(), 1);
    assert_eq!(history.releases[0].coverage.total_samples, 2);
    assert!(!render_benchmark_dashboard(&history, &evaluation).is_empty());

    let _ = fs::remove_file(history_path);
}

#[test]
fn test_format_dataset_verdicts_text_analyst_summary_is_compact() {
    let entry = DatasetPackageVerdictEntry {
        package_id: Some("abc123".to_string()),
        final_verdict: skill_veil_core::Verdict::Suspicious,
        package_health: Some(skill_veil_core::PackageHealth::NeedsReview),
        blast_radius: Some(skill_veil_core::BlastRadiusLevel::High),
        declared_permissions: vec![
            skill_veil_core::DeclaredPermission::NetworkAccess,
            skill_veil_core::DeclaredPermission::SecretsAccess,
        ],
        strongest_reason: Some("supporting_artifact/remote_exec/malicious_behavior".to_string()),
        top_rule: Some("UNSAFE_USER_CONTROLLED_EXEC_SHELL".to_string()),
        representative_path: "dataset/pkg/SKILL.md".to_string(),
        main_summary: Vec::new(),
        supporting_summary: vec!["remote_exec/malicious_behavior".to_string()],
        package_root_summary: Vec::new(),
    };

    let output = format_dataset_verdicts_text(
        &[entry],
        true,
        ColorMode::from_choice(ColorChoiceArg::Never, false),
    );

    assert!(output.contains("[suspicious] package=abc123"));
    assert!(output.contains("scope=supporting_artifact"));
    assert!(output.contains("health="));
    assert!(output.contains("rule=UNSAFE_USER_CONTROLLED_EXEC_SHELL"));
    assert!(output.contains("blast=high"));
    assert!(output.contains("perms=network_access,secrets_access"));
    assert!(output.contains("reason=supporting_artifact/remote_exec/malicious_behavior"));
    assert!(!output.contains("main="));
    assert!(!output.contains("path="));
}

#[test]
fn test_format_dataset_verdicts_text_full_includes_detailed_fields() {
    let entry = DatasetPackageVerdictEntry {
        package_id: Some("pkg001".to_string()),
        final_verdict: skill_veil_core::Verdict::Malicious,
        package_health: Some(skill_veil_core::PackageHealth::Healthy),
        blast_radius: Some(skill_veil_core::BlastRadiusLevel::Medium),
        declared_permissions: vec![skill_veil_core::DeclaredPermission::ShellExec],
        strongest_reason: Some("agent_entrypoint/remote_exec/malicious_behavior".to_string()),
        top_rule: Some("SKILL_REMOTE_EXEC_CURL_BASH".to_string()),
        representative_path: "dataset/pkg001/SKILL.md".to_string(),
        main_summary: vec!["remote_exec/malicious_behavior".to_string()],
        supporting_summary: Vec::new(),
        package_root_summary: Vec::new(),
    };

    let output = format_dataset_verdicts_text(
        &[entry],
        false,
        ColorMode::from_choice(ColorChoiceArg::Never, false),
    );

    assert!(output.contains("malicious package=pkg001"));
    assert!(output.contains("health=healthy"));
    assert!(output.contains("blast_radius=medium"));
    assert!(output.contains("declared_permissions=shell_exec"));
    assert!(output.contains("main=remote_exec/malicious_behavior"));
}
