use super::*;
use crate::artifact_graph::{
    ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactGraph,
};
use crate::findings::{Finding, MatchTarget, ThreatCategory};

/// Contract: `PolicyGenerator::generate_shield_md` MUST embed both the
/// SHIELD policy header (so reviewers can recognize the document type)
/// and a per-finding policy id derived from `<rule_id>-<skill_name>`,
/// because downstream SHIELD tooling keys gating decisions off that id.
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

/// Contract: `PolicyGenerator::generate_json` MUST emit a `JsonReport`
/// whose `skill_name`, `findings`, and `context_policies` reflect the
/// scanner inputs verbatim — no findings dropped, no synthetic skill
/// renaming, and the default `OperationalContext::Install` policy
/// always materialised so callers can rely on its presence downstream.
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
        .any(|policy| policy.context == OperationalContext::Install));
}

/// Contract: `PolicyGenerator::generate_sarif` MUST always emit
/// version "2.1.0" and exactly one `Run`, plus a synthetic
/// `SKILL_VEIL_ACTION_TRIGGER` result alongside the real findings so
/// CI consumers can distinguish "scanner ran successfully" from "no
/// findings produced" without inspecting an empty array.
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

/// Contract: when several findings share the same `rule_id` but carry
/// different `RecommendedAction`s, the generated policy MUST surface
/// the STRONGEST action (Block > RequireApproval > Log). A weaker
/// action winning would silently downgrade a `RequireApproval` signal
/// just because a co-occurring `Log` finding was also produced.
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

/// Contract: graph-derived capability combos
/// (`PrivilegedRuntime` + `HostFilesystemAccess`) MUST escalate the
/// top-level `summary.recommended_action` to `Block` and add a
/// `capability_combo:privileged_host_filesystem` factor to the score
/// breakdown, while the per-finding `policies` keep their own action
/// level (the global summary escalation is for CI gating, not for
/// rewriting the meaning of individual findings).
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
    // Individual policies should retain their own action level, NOT be
    // escalated by the global summary. The low-severity finding keeps Log.
    assert!(json
        .policies
        .iter()
        .all(|policy| policy.action == RecommendedAction::Log));
}

/// Contract: when a `PolicyProfile` is attached to the generator, the
/// generated JSON MUST include a `context_policies` entry for every
/// `OperationalContext` covered by that profile, with the action the
/// profile dictates (e.g. `Team` profile → `Block` for `Secrets`).
/// This is what surfaces "this team always blocks secrets" without
/// each scan needing its own override.
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
        .find(|policy| policy.context == OperationalContext::Secrets)
        .expect("missing secrets context policy");
    assert_eq!(policy.action, RecommendedAction::Block);
    assert_eq!(json.policy_audit.effective_fail_on, None);
}

/// Contract: when graph capabilities trigger a `Block`-level escalation
/// the SARIF output MUST contain a synthetic
/// `SKILL_VEIL_ACTION_TRIGGER` result so SARIF consumers (GitHub code
/// scanning, IDE integrations) see a concrete signal anchored to the
/// escalation, not just a metadata-level severity bump that a human
/// could miss when scrolling the results panel.
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
