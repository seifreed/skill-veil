use super::*;
use crate::findings::{MatchTarget, ThreatCategory};
use crate::policy::{BaselineEntry, BaselineFile, PolicyProfile, WaiverEntry, WaiverFile};

fn create_finding(rule_id: &str, severity: Severity) -> Finding {
    Finding::builder(rule_id, ThreatCategory::Generic)
        .severity(severity)
        .confidence(0.9)
        .matched_on(MatchTarget::Document)
        .match_value("test")
        .reason("Test finding")
        .build()
}

#[test]
fn test_filter_by_min_severity() {
    let options = ScanOptions {
        min_severity: Some(Severity::High),
        ..Default::default()
    };
    let filter = ScanFilterService::new(options);

    let findings = vec![
        create_finding("R1", Severity::Low),
        create_finding("R2", Severity::Medium),
        create_finding("R3", Severity::High),
        create_finding("R4", Severity::Critical),
    ];

    let filtered = filter.filter_findings(findings);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().all(|f| f.severity >= Severity::High));
}

#[test]
fn test_filter_by_include_rules() {
    let options = ScanOptions {
        include_rules: vec!["R1".to_string(), "R3".to_string()],
        ..Default::default()
    };
    let filter = ScanFilterService::new(options);

    let findings = vec![
        create_finding("R1", Severity::High),
        create_finding("R2", Severity::High),
        create_finding("R3", Severity::High),
        create_finding("R4", Severity::High),
    ];

    let filtered = filter.filter_findings(findings);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().any(|f| f.rule_id == "R1"));
    assert!(filtered.iter().any(|f| f.rule_id == "R3"));
}

#[test]
fn test_filter_by_exclude_rules() {
    let options = ScanOptions {
        exclude_rules: vec!["R2".to_string()],
        ..Default::default()
    };
    let filter = ScanFilterService::new(options);

    let findings = vec![
        create_finding("R1", Severity::High),
        create_finding("R2", Severity::High),
        create_finding("R3", Severity::High),
    ];

    let filtered = filter.filter_findings(findings);
    assert_eq!(filtered.len(), 2);
    assert!(!filtered.iter().any(|f| f.rule_id == "R2"));
}

#[test]
fn test_combined_filters() {
    let options = ScanOptions {
        min_severity: Some(Severity::Medium),
        exclude_rules: vec!["R2".to_string()],
        ..Default::default()
    };
    let filter = ScanFilterService::new(options);

    let findings = vec![
        create_finding("R1", Severity::Low),
        create_finding("R2", Severity::High),
        create_finding("R3", Severity::Medium),
        create_finding("R4", Severity::Critical),
    ];

    let filtered = filter.filter_findings(findings);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().any(|f| f.rule_id == "R3"));
    assert!(filtered.iter().any(|f| f.rule_id == "R4"));
}

#[test]
fn test_should_fail() {
    let options = ScanOptions {
        fail_on: Some(Severity::High),
        ..Default::default()
    };
    let filter = ScanFilterService::new(options);

    let low_findings = vec![
        create_finding("R1", Severity::Low),
        create_finding("R2", Severity::Medium),
    ];
    assert!(!filter.should_fail(&low_findings));

    let high_findings = vec![
        create_finding("R1", Severity::Low),
        create_finding("R2", Severity::High),
    ];
    assert!(filter.should_fail(&high_findings));
}

#[test]
fn test_no_fail_on_threshold() {
    let options = ScanOptions::default();
    let filter = ScanFilterService::new(options);

    let findings = vec![create_finding("R1", Severity::Critical)];
    assert!(!filter.should_fail(&findings));
}

#[test]
fn test_profile_supplies_default_fail_threshold() {
    let options = ScanOptions {
        profile: Some(PolicyProfile::Team),
        ..Default::default()
    };
    let filter = ScanFilterService::new(options);
    let findings = vec![create_finding("R1", Severity::High)];
    assert!(filter.should_fail(&findings));
}

#[test]
fn test_should_fail_respects_overridden_action() {
    let options = ScanOptions {
        fail_on: Some(Severity::High),
        ..Default::default()
    };
    let filter = ScanFilterService::new(options);

    // A High finding with action downgraded to Log (e.g. via policy override)
    // should NOT trigger failure.
    let mut finding = create_finding("R1", Severity::High);
    finding.recommended_action = RecommendedAction::Log;
    assert!(
        !filter.should_fail(&[finding]),
        "Finding with action overridden to Log should not trigger should_fail"
    );
}

/// # Contract
///
/// `should_fail` MUST treat a [`RecommendedAction::Block`] finding as
/// CI-failing whenever a `fail_on` threshold is configured, *regardless*
/// of whether the finding's severity meets the threshold. Pre-fix a
/// High-severity Block-escalated finding under `Personal` profile
/// (`fail_on = Critical`) silently passed CI because `High < Critical`.
/// `Block` is a fail-stop signal that policy overrides use to force halt
/// on rules whose native severity is below the operator's chosen
/// threshold.
#[test]
fn should_fail_treats_block_action_below_threshold_as_failing() {
    let options = ScanOptions {
        fail_on: Some(Severity::Critical),
        ..Default::default()
    };
    let filter = ScanFilterService::new(options);

    // High-severity finding whose action was escalated to Block by a
    // policy override.
    let mut finding = create_finding("R1", Severity::High);
    finding.recommended_action = RecommendedAction::Block;
    assert!(
        filter.should_fail(&[finding]),
        "Block-escalated finding below severity threshold MUST trigger should_fail"
    );

    // Symmetric: a Medium-severity Block-escalated finding (e.g. a custom
    // pack that promotes a low-severity rule to Block) also fails.
    let mut medium = create_finding("R2", Severity::Medium);
    medium.recommended_action = RecommendedAction::Block;
    assert!(
        filter.should_fail(&[medium]),
        "Medium Block-escalated finding MUST trigger should_fail when fail_on=Critical"
    );
}

/// # Contract (negative)
///
/// `should_fail` MUST preserve the historical "no threshold → never
/// fail" contract for informational scans where `fail_on` is `None`. A
/// Block-action finding alone (without a configured threshold) does NOT
/// flip the gate — operators using IDE / editor integrations that scan
/// without a CI threshold should not see exit-code failure.
#[test]
fn should_fail_keeps_no_threshold_contract_even_with_block_action() {
    let options = ScanOptions::default();
    let filter = ScanFilterService::new(options);
    let mut finding = create_finding("R1", Severity::Critical);
    finding.recommended_action = RecommendedAction::Block;
    assert!(
        !filter.should_fail(&[finding]),
        "Without fail_on configured, Block-action finding must NOT trigger should_fail"
    );
}

#[test]
fn test_filter_with_summary_counts_waivers_and_baseline() {
    let finding = create_finding("R1", Severity::High).with_artifact(
        crate::findings::ArtifactKind::ReferencedArtifact,
        "scripts/install.sh",
    );
    let baseline = BaselineFile {
        schema_version: crate::policy::POLICY_SCHEMA_VERSION.to_string(),
        entries: vec![BaselineEntry {
            fingerprint: crate::policy::finding_fingerprint(&finding),
            rule_id: finding.rule_id.clone(),
            artifact_path: finding.artifact_path.clone(),
            reason: finding.reason.clone(),
        }],
    };
    let waivers = WaiverFile {
        schema_version: crate::policy::POLICY_SCHEMA_VERSION.to_string(),
        waivers: vec![WaiverEntry {
            rule_id: Some("R2".to_string()),
            artifact_path: Some("other.sh".to_string()),
            context: None,
            reason: "accepted".to_string(),
            expires_at: None,
        }],
    };
    let filter = ScanFilterService::with_policy_state(
        ScanOptions::default(),
        Some(baseline),
        Some(waivers),
        None,
    );

    let outcome = filter.filter_with_summary(vec![finding]);
    assert_eq!(outcome.findings.len(), 0);
    assert_eq!(outcome.suppression_summary.baseline_suppressed, 1);
    assert_eq!(outcome.suppression_summary.waiver_suppressed, 0);
    assert_eq!(outcome.suppression_summary.active_findings, 0);
}

#[test]
fn test_waiver_wins_over_baseline_for_same_finding() {
    let finding = create_finding("R1", Severity::High).with_artifact(
        crate::findings::ArtifactKind::ReferencedArtifact,
        "scripts/install.sh",
    );
    let baseline = BaselineFile {
        schema_version: crate::policy::POLICY_SCHEMA_VERSION.to_string(),
        entries: vec![BaselineEntry {
            fingerprint: crate::policy::finding_fingerprint(&finding),
            rule_id: finding.rule_id.clone(),
            artifact_path: finding.artifact_path.clone(),
            reason: finding.reason.clone(),
        }],
    };
    // Waiver targets the same finding
    let waivers = WaiverFile {
        schema_version: crate::policy::POLICY_SCHEMA_VERSION.to_string(),
        waivers: vec![WaiverEntry {
            rule_id: Some("R1".to_string()),
            artifact_path: Some("scripts/install.sh".to_string()),
            context: None,
            reason: "accepted".to_string(),
            expires_at: None,
        }],
    };
    let filter = ScanFilterService::with_policy_state(
        ScanOptions::default(),
        Some(baseline),
        Some(waivers),
        None,
    );

    let outcome = filter.filter_with_summary(vec![finding]);
    assert_eq!(outcome.findings.len(), 0);
    // Waiver removed the finding first, so baseline had nothing to suppress
    assert_eq!(outcome.suppression_summary.waiver_suppressed, 1);
    assert_eq!(outcome.suppression_summary.baseline_suppressed, 0);
}

#[test]
fn test_fingerprint_distinguishes_different_match_values() {
    let finding_a = create_finding("R1", Severity::High).with_artifact(
        crate::findings::ArtifactKind::ReferencedArtifact,
        "scripts/install.sh",
    );
    let mut finding_b = create_finding("R1", Severity::High).with_artifact(
        crate::findings::ArtifactKind::ReferencedArtifact,
        "scripts/install.sh",
    );
    finding_b.match_value = "different_value".to_string();

    let fp_a = crate::policy::finding_fingerprint(&finding_a);
    let fp_b = crate::policy::finding_fingerprint(&finding_b);
    assert_ne!(
        fp_a, fp_b,
        "Findings with different match_value must have different fingerprints"
    );

    // Baseline built from finding_a should not suppress finding_b
    let baseline = BaselineFile {
        schema_version: crate::policy::POLICY_SCHEMA_VERSION.to_string(),
        entries: vec![BaselineEntry {
            fingerprint: fp_a,
            rule_id: finding_a.rule_id.clone(),
            artifact_path: finding_a.artifact_path.clone(),
            reason: finding_a.reason.clone(),
        }],
    };
    let filter =
        ScanFilterService::with_policy_state(ScanOptions::default(), Some(baseline), None, None);

    let outcome = filter.filter_with_summary(vec![finding_a, finding_b]);
    assert_eq!(
        outcome.findings.len(),
        1,
        "Only one finding should be suppressed by baseline"
    );
    assert_eq!(outcome.findings[0].match_value, "different_value");
}

#[test]
fn test_fingerprint_is_stable_when_only_reason_changes() {
    // Regression guard: `reason` is a user-facing explanation that gets
    // reworded across scanner versions. It must NOT participate in the
    // baseline fingerprint, otherwise every wording refresh would
    // invalidate every baseline entry silently.
    let mut finding_a = create_finding("R1", Severity::High).with_artifact(
        crate::findings::ArtifactKind::ReferencedArtifact,
        "scripts/install.sh",
    );
    finding_a.reason = "old wording of the reason".to_string();
    finding_a.match_value = "curl evil.sh".to_string();

    let mut finding_b = create_finding("R1", Severity::High).with_artifact(
        crate::findings::ArtifactKind::ReferencedArtifact,
        "scripts/install.sh",
    );
    finding_b.reason = "a different, rephrased wording".to_string();
    finding_b.match_value = "curl evil.sh".to_string();

    let fp_a = crate::policy::finding_fingerprint(&finding_a);
    let fp_b = crate::policy::finding_fingerprint(&finding_b);
    assert_eq!(
        fp_a, fp_b,
        "Fingerprint must ignore reason — otherwise rule wording changes break baselines",
    );
}
