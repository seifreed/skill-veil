use super::*;
use crate::artifact_graph::{
    ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactGraph,
};
use crate::verdict::derive_package_verdict;

/// Contract: a finding whose `artifact_path` lives in a sibling
/// subdirectory MUST classify as supporting, never as primary, even
/// when the trailing components match. Pre-fix the matcher used
/// `ends_with`, which collapsed sibling packages in dataset scans
/// into the same primary bucket.
#[test]
fn test_split_findings_by_scope_rejects_subdirectory_path() {
    let primary_path = std::path::Path::new("/project/skill.md");
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .artifact(
            ArtifactKind::SkillDocument,
            Some("other/skill.md".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .build();

    let (primary, supporting) =
        split_findings_by_scope(primary_path, ArtifactKind::SkillDocument, &[finding]);

    assert!(
        primary.is_empty(),
        "Finding from 'other/skill.md' should not match primary path '/project/skill.md'"
    );
    assert_eq!(supporting.len(), 1);
}

/// Contract: a single-component relative `artifact_path` (`skill.md`)
/// MUST classify as primary against an absolute primary path that
/// ends with the same filename. Positive twin of the
/// reject-subdirectory test above.
#[test]
fn test_split_findings_by_scope_accepts_short_artifact_path() {
    let primary_path = std::path::Path::new("/project/skill.md");
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .artifact(ArtifactKind::SkillDocument, Some("skill.md".to_string()))
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .build();

    let (primary, supporting) =
        split_findings_by_scope(primary_path, ArtifactKind::SkillDocument, &[finding]);

    assert_eq!(primary.len(), 1);
    assert!(supporting.is_empty());
}

/// Contract: `Severity` orders strictly from `Low` to `Critical`.
/// Pinned because risk-score aggregation and dedup tie-breakers all
/// depend on this monotonic ordering — flipping one variant would
/// silently invert escalation logic.
#[test]
fn test_severity_ordering() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

/// Contract: each `Severity` resolves to its corresponding named
/// weight constant. Locks the mapping so a future tweak to one
/// constant doesn't desynchronise scoring weights from the variant
/// they're meant to govern.
#[test]
fn test_severity_weights() {
    assert_eq!(Severity::Low.weight(), SEVERITY_WEIGHT_LOW);
    assert_eq!(Severity::Medium.weight(), SEVERITY_WEIGHT_MEDIUM);
    assert_eq!(Severity::High.weight(), SEVERITY_WEIGHT_HIGH);
    assert_eq!(Severity::Critical.weight(), SEVERITY_WEIGHT_CRITICAL);
}

/// Contract: `Finding::weighted_score` blends severity weight and
/// confidence into the documented numeric range. Pins the formula so
/// downstream verdict thresholds (which compare against fixed
/// numeric bands) keep working when severity weights are retuned.
#[test]
fn test_finding_weighted_score() {
    let finding = Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
        .severity(Severity::High)
        .confidence(0.95)
        .matched_on(MatchTarget::Document)
        .match_value("curl | bash")
        .reason("Remote execution detected")
        .build();
    assert!((finding.weighted_score() - 56.6).abs() < 0.2);
}

/// Contract: `FindingSummary::from_findings` aggregates total counts,
/// severity histogram, recommended action, and a non-empty score
/// breakdown. Anchors the multi-finding aggregation that callers
/// compare against verdict thresholds.
#[test]
fn test_finding_summary() {
    let findings = vec![
        Finding::builder("R1", ThreatCategory::RemoteExec)
            .severity(Severity::High)
            .confidence(0.9)
            .matched_on(MatchTarget::Document)
            .match_value("test")
            .reason("test")
            .build(),
        Finding::builder("R2", ThreatCategory::SupplyChain)
            .severity(Severity::Medium)
            .confidence(0.8)
            .matched_on(MatchTarget::Document)
            .match_value("test")
            .reason("test")
            .build(),
    ];

    let summary = FindingSummary::from_findings(&findings);
    assert_eq!(summary.total_findings, 2);
    assert_eq!(summary.by_severity.high, 1);
    assert_eq!(summary.by_severity.medium, 1);
    assert_eq!(summary.recommended_action, RecommendedAction::Block);
    assert!(!summary.score_breakdown.is_empty());
}

/// Contract: `Finding::builder` produces a sensible default finding
/// when no optional fields are set. Pins each defaulted field so a
/// future change to the default (e.g. lowering the seed confidence)
/// is caught here instead of skewing the entire corpus baseline.
#[test]
fn test_finding_builder_defaults() {
    let finding = Finding::builder("TEST_RULE", ThreatCategory::Generic).build();
    assert_eq!(finding.rule_id, "TEST_RULE");
    assert_eq!(finding.category, ThreatCategory::Generic);
    assert_eq!(finding.severity, Severity::Medium); // default
    assert!((finding.raw_confidence - 0.9).abs() < 0.01);
    assert!(finding.confidence < finding.raw_confidence);
    assert_eq!(
        finding.recommended_action,
        RecommendedAction::RequireApproval
    );
    assert_eq!(finding.evidence_kind, EvidenceKind::Behavior);
    assert_eq!(finding.artifact_kind, ArtifactKind::SkillDocument);
    assert!(!finding.remediation.is_empty());
    assert!(!finding.confidence_rationale.is_empty());
    assert!(finding.line_number.is_none());
}

/// Contract: `.severity(Critical)` paired with an explicit line
/// number flows into `recommended_action = Block`. Locks the
/// severity-to-action escalation rule that drives the SARIF output
/// and CI gating.
#[test]
fn test_finding_builder_with_line() {
    let finding = Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
        .severity(Severity::Critical)
        .line(42)
        .build();
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.line_number, Some(42));
    assert_eq!(finding.recommended_action, RecommendedAction::Block);
}

/// Contract: setting `evidence_kind`, `artifact_kind`, and
/// `artifact_path` on the builder propagates verbatim to the built
/// finding AND triggers the `OperationalContext::Install` heuristic
/// when the path lives under `scripts/`. Pins the path-derivation
/// rule that powers operational-context tagging downstream.
#[test]
fn test_finding_builder_with_evidence_and_artifact() {
    let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
        .severity(Severity::High)
        .evidence_kind(EvidenceKind::Ioc)
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some("scripts/install.sh".to_string()),
        )
        .build();

    assert_eq!(finding.evidence_kind, EvidenceKind::Ioc);
    assert_eq!(finding.artifact_kind, ArtifactKind::ReferencedArtifact);
    assert_eq!(finding.artifact_path.as_deref(), Some("scripts/install.sh"));
    assert!(finding
        .operational_contexts
        .contains(&OperationalContext::Install));
}

/// Contract: an explicit per-finding `RecommendedAction::Block`
/// overrides the otherwise-low risk profile (Low severity + 0.1
/// confidence) when it bubbles up to the package summary. Prevents a
/// future scoring tweak from silently masking a hand-marked block.
#[test]
fn test_summary_respects_highest_recommended_action() {
    let findings = vec![Finding::builder("R1", ThreatCategory::SupplyChain)
        .severity(Severity::Low)
        .confidence(0.1)
        .action(RecommendedAction::Block)
        .matched_on(MatchTarget::Document)
        .match_value("danger")
        .reason("explicit block")
        .build()];

    let summary = FindingSummary::from_findings(&findings);
    assert_eq!(summary.recommended_action, RecommendedAction::Block);
}

/// Contract: when artifact-graph capabilities cross the
/// privileged-runtime + host-filesystem-access combo, the package
/// summary escalates to `Block` and surfaces a
/// `capability_combo:privileged_host_filesystem` factor in the
/// score breakdown — even when the underlying findings are weak.
/// Pins the cross-artifact escalation contract that the verdict
/// pipeline relies on.
#[test]
fn test_summary_escalates_for_high_risk_capability_combo() {
    let findings = vec![Finding::builder("R1", ThreatCategory::Generic)
        .severity(Severity::Low)
        .confidence(0.2)
        .action(RecommendedAction::Log)
        .matched_on(MatchTarget::Document)
        .match_value("note")
        .reason("note")
        .build()];

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

    let summary = FindingSummary::from_findings_and_graph(&findings, &graph);
    assert_eq!(summary.recommended_action, RecommendedAction::Block);
    assert!(summary
        .score_breakdown
        .iter()
        .any(|factor| factor.factor == "capability_combo:privileged_host_filesystem"));
}

/// Contract: when two findings share a dedup key, the merge keeps
/// the strongest severity, max confidence, longer reason text, and
/// the explicit remediation/line — yielding one canonical entry per
/// match site. Anchors the dedup happy path; the more elaborate
/// strength-winner rules below pin the corner cases.
#[test]
fn test_deduplicate_findings_keeps_strongest_variant() {
    let duplicate_a = Finding::builder("RULE_DUP", ThreatCategory::SupplyChain)
        .severity(Severity::Medium)
        .confidence(0.55)
        .matched_on(MatchTarget::Document)
        .match_value("curl https://example.com/install.sh")
        .reason("Short reason")
        .build();
    let duplicate_b = Finding::builder("RULE_DUP", ThreatCategory::SupplyChain)
        .severity(Severity::High)
        .confidence(0.9)
        .matched_on(MatchTarget::Document)
        .match_value("curl https://example.com/install.sh")
        .reason("Longer reason with more context")
        .remediation("Pinned remediation text with extra context about provenance and review gates")
        .line(12)
        .build();

    let (findings, summary) = deduplicate_findings(vec![duplicate_a, duplicate_b]);

    assert_eq!(summary.original_findings, 2);
    assert_eq!(summary.unique_findings, 1);
    assert_eq!(summary.duplicates_removed, 1);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].confidence >= 0.85);
    assert_eq!(findings[0].line_number, Some(12));
    assert_eq!(findings[0].reason, "Longer reason with more context");
    assert_eq!(
        findings[0].remediation,
        "Pinned remediation text with extra context about provenance and review gates"
    );
}

/// Contract: each Phase-2 threat category derives a deterministic
/// set of `OperationalContext` tags from its `evidence_kind`. Pins
/// the category→context mapping so SARIF output and policy filters
/// (which group findings by operational context) keep classifying
/// the same kinds of threats consistently.
#[test]
fn test_operational_contexts_capture_phase2_categories() {
    let prompt_tampering =
        Finding::builder("PROMPT_TAMPER", ThreatCategory::PersistentPromptTampering)
            .evidence_kind(EvidenceKind::Intent)
            .build();
    let tool_abuse = Finding::builder("TOOL_ABUSE", ThreatCategory::ToolAbuse)
        .evidence_kind(EvidenceKind::Behavior)
        .build();
    let autonomy = Finding::builder("AUTO", ThreatCategory::AutonomyEscalation)
        .evidence_kind(EvidenceKind::Intent)
        .build();
    let social = Finding::builder("SOCIAL", ThreatCategory::SocialManipulation)
        .evidence_kind(EvidenceKind::Intent)
        .build();

    assert!(prompt_tampering
        .operational_contexts
        .contains(&OperationalContext::CodeModification));
    assert!(tool_abuse
        .operational_contexts
        .contains(&OperationalContext::Secrets));
    assert!(autonomy
        .operational_contexts
        .contains(&OperationalContext::ExternalComms));
    assert!(social
        .operational_contexts
        .contains(&OperationalContext::ExternalComms));
}

/// Contract: at equal raw confidence, a `Behavior` finding's
/// calibrated confidence beats an `Intent` finding's. Pins the
/// asymmetry so prompt-injection (Intent) doesn't silently
/// out-rank concrete remote-exec evidence (Behavior).
#[test]
fn test_confidence_calibration_prefers_behavior_over_intent() {
    let behavior = Finding::builder("BEHAVIOR", ThreatCategory::RemoteExec)
        .confidence(0.8)
        .evidence_kind(EvidenceKind::Behavior)
        .build();
    let intent = Finding::builder("INTENT", ThreatCategory::SocialManipulation)
        .confidence(0.8)
        .evidence_kind(EvidenceKind::Intent)
        .build();

    assert!(behavior.confidence > intent.confidence);
    assert!(behavior.confidence_rationale.contains("evidence=behavior"));
    assert!(intent.confidence_rationale.contains("evidence=intent"));
}

/// Contract: prompt-override + remote-exec is a compound signal
/// that escalates a package to `Verdict::Malicious` even when each
/// finding individually is `RequireApproval`. Pins the rationale
/// text so downstream consumers can rely on the canonical phrasing
/// in audits.
#[test]
fn test_compound_verdict_escalates_prompt_override_plus_exec() {
    let findings = vec![
        Finding::builder(
            "OFFICIAL_PROMPT_OVERRIDE_WITH_PERSISTENCE",
            ThreatCategory::PersistentPromptTampering,
        )
        .artifact_scope(ArtifactScope::AgentEntrypoint)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("override + persistence")
        .reason("prompt override")
        .build(),
        Finding::builder(
            "OFFICIAL_REMOTE_FETCH_EXEC_POLYGLOT",
            ThreatCategory::RemoteExec,
        )
        .artifact_scope(ArtifactScope::SupportingArtifact)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("fetch + exec")
        .reason("remote exec")
        .build(),
    ];

    let primary = FindingSummary::from_findings(&findings[..1]);
    let supporting = FindingSummary::from_findings(&findings[1..]);
    let package = FindingSummary::from_findings(&findings);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

    assert_eq!(verdict.verdict, Verdict::Malicious);
    assert!(verdict.verdict_reasons.iter().any(|reason| reason
        .rationale
        .contains("prompt override is paired with execution")));
}

/// Contract: package.json `postinstall` hook + remote-fetch in a
/// supporting script escalates to `Malicious`. Captures the
/// supply-chain compound that drives most real-world npm
/// post-install attacks; pins the rationale phrase consumers grep.
#[test]
fn test_compound_verdict_escalates_remote_fetch_plus_install_hook() {
    let findings = vec![
        Finding::builder(
            "MANIFEST_PACKAGE_JSON_INSTALL_HOOK",
            ThreatCategory::SupplyChain,
        )
        .artifact_scope(ArtifactScope::PackageRootArtifact)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("postinstall")
        .reason("install hook")
        .build(),
        Finding::builder(
            "OFFICIAL_REMOTE_FETCH_EXEC_POLYGLOT",
            ThreatCategory::RemoteExec,
        )
        .artifact_scope(ArtifactScope::SupportingArtifact)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("requests.get + exec")
        .reason("remote exec")
        .build(),
    ];

    let primary = FindingSummary::from_findings(&[]);
    let supporting = FindingSummary::from_findings(&findings[1..]);
    let package = FindingSummary::from_findings(&findings);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

    assert_eq!(verdict.verdict, Verdict::Malicious);
    assert!(verdict.verdict_reasons.iter().any(|reason| reason
        .rationale
        .contains("install hook is paired with remote fetch")));
}

/// Contract: broad declared permissions + autonomy-escalation
/// signal escalates to `Malicious`. Mirrors the "permission +
/// approval-bypass" attack pattern from the regression corpus.
#[test]
fn test_compound_verdict_escalates_broad_permissions_plus_autonomy() {
    let findings = vec![
        Finding::builder(
            "DECLARED_PERMISSION_BROWSER_FULL",
            ThreatCategory::ScopeCreep,
        )
        .artifact_scope(ArtifactScope::AgentEntrypoint)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("browser full")
        .reason("declared permission")
        .build(),
        Finding::builder(
            "OFFICIAL_FORCED_APPROVAL_BYPASS",
            ThreatCategory::AutonomyEscalation,
        )
        .artifact_scope(ArtifactScope::AgentEntrypoint)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("skip approval gate")
        .reason("approval bypass")
        .build(),
    ];

    let primary = FindingSummary::from_findings(&findings);
    let supporting = FindingSummary::from_findings(&[]);
    let package = FindingSummary::from_findings(&findings);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

    assert_eq!(verdict.verdict, Verdict::Malicious);
    assert!(verdict.verdict_reasons.iter().any(|reason| reason
        .rationale
        .contains("broad permissions are paired with autonomous execution semantics")));
}

/// Contract: an OAuth-scope declaration paired with
/// approval-bypass wording (without a concrete high-risk action)
/// stays `Suspicious`, NOT `Malicious`. Negative-direction pin so
/// the broad-permissions+autonomy escalation above can't widen to
/// catch benign declared-permission-plus-prose patterns.
#[test]
fn test_oauth_without_high_risk_autonomy_does_not_escalate_to_malicious() {
    let findings = vec![
        Finding::builder(
            "DECLARED_PERMISSION_OAUTH_SCOPES",
            ThreatCategory::ScopeCreep,
        )
        .artifact_scope(ArtifactScope::AgentEntrypoint)
        .action(RecommendedAction::Log)
        .matched_on(MatchTarget::Document)
        .match_value("oauth scopes")
        .reason("declared permission")
        .build(),
        Finding::builder(
            "OFFICIAL_AUTONOMY_ESCALATION_NO_REVIEW",
            ThreatCategory::AutonomyEscalation,
        )
        .artifact_scope(ArtifactScope::AgentEntrypoint)
        .signal_class(SignalClass::SuspiciousPackageBehavior)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("continue automatically")
        .reason("approval wording without explicit high-risk action")
        .build(),
    ];

    let primary = FindingSummary::from_findings(&findings);
    let supporting = FindingSummary::from_findings(&[]);
    let package = FindingSummary::from_findings(&findings);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

    assert_eq!(verdict.verdict, Verdict::Suspicious);
}

/// Contract: an MCP server config that declares a remote endpoint
/// AND advertises a stdio/exec surface escalates to `Malicious`.
/// Closes the MCP-specific compound that combines two
/// individually-`RequireApproval` signals.
#[test]
fn test_compound_verdict_escalates_mcp_remote_endpoint_plus_exec_surface() {
    let findings = vec![
        Finding::builder("MCP_REMOTE_SERVER_ENDPOINT", ThreatCategory::SupplyChain)
            .artifact_scope(ArtifactScope::PackageRootArtifact)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("remote endpoint")
            .reason("mcp remote endpoint")
            .build(),
        Finding::builder("MCP_REMOTE_EXEC_SURFACE", ThreatCategory::RemoteExec)
            .artifact_scope(ArtifactScope::PackageRootArtifact)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("remote endpoint with stdio")
            .reason("mcp remote exec")
            .build(),
    ];

    let primary = FindingSummary::from_findings(&[]);
    let supporting = FindingSummary::from_findings(&[]);
    let package = FindingSummary::from_findings(&findings);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

    assert_eq!(verdict.verdict, Verdict::Malicious);
    assert!(verdict.verdict_reasons.iter().any(|reason| reason
        .rationale
        .contains("MCP remote endpoint is paired with command or stdio")));
}

/// Contract: a single low-severity Log-action finding on a
/// package-root artifact downgrades the package to `Benign`.
/// Pins the calibration safety net that prevents an isolated
/// hygiene signal (e.g. "MCP transport declared") from inflating
/// the verdict on otherwise-clean packages.
#[test]
fn test_isolated_weak_package_root_signal_downgrades_to_benign() {
    let findings =
        vec![
            Finding::builder("MCP_TOOLING_TRANSPORT_DECLARED", ThreatCategory::ToolAbuse)
                .severity(Severity::Low)
                .artifact_scope(ArtifactScope::PackageRootArtifact)
                .action(RecommendedAction::Log)
                .matched_on(MatchTarget::Document)
                .match_value("mcp transport")
                .reason("transport declared")
                .build(),
        ];

    let primary = FindingSummary::from_findings(&[]);
    let supporting = FindingSummary::from_findings(&[]);
    let package = FindingSummary::from_findings(&findings);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

    assert_eq!(verdict.verdict, Verdict::Benign);
}

/// Contract: hygiene-only signals on an agent entrypoint
/// (declared network access + a permission mismatch) keep the
/// verdict `Benign` while flagging `PackageHealth::NeedsReview`.
/// Pins the contradictory-state contract: Benign + Elevated must
/// surface as NeedsReview, never as silent agreement.
#[test]
fn test_hygiene_only_agent_entrypoint_signal_stays_benign() {
    let findings = vec![
        Finding::builder(
            "DECLARED_PERMISSION_NETWORK_ACCESS",
            ThreatCategory::ScopeCreep,
        )
        .artifact_scope(ArtifactScope::AgentEntrypoint)
        .action(RecommendedAction::Log)
        .matched_on(MatchTarget::Document)
        .match_value("network access")
        .reason("declared network access")
        .build(),
        Finding::builder("CAPABILITY_PERMISSION_MISMATCH", ThreatCategory::ScopeCreep)
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("narrow intent with broad capability request")
            .reason("permission mismatch")
            .build(),
    ];

    let primary = FindingSummary::from_findings(&findings);
    let supporting = FindingSummary::from_findings(&[]);
    let package = FindingSummary::from_findings(&findings);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

    assert_eq!(verdict.verdict, Verdict::Benign);
    // Benign + Elevated is contradictory, so health is downgraded to NeedsReview
    assert_eq!(verdict.package_health, PackageHealth::NeedsReview);
}

/// Contract: hygiene-only findings with `RequireApproval` action
/// stay `Benign + NeedsReview`; only `Block`-action hygiene
/// findings escalate to `Suspicious`. Pins the asymmetry between
/// the two action levels so a future tweak doesn't conflate them.
#[test]
fn test_severe_hygiene_only_produces_needs_review() {
    let findings: Vec<Finding> = (0..4)
        .map(|i| {
            Finding::builder(format!("HYGIENE_RULE_{}", i), ThreatCategory::ScopeCreep)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .signal_class(SignalClass::Hygiene)
                .artifact_scope(ArtifactScope::AgentEntrypoint)
                .matched_on(MatchTarget::Document)
                .match_value(format!("hygiene issue {}", i))
                .reason(format!("hygiene rule {} fired", i))
                .build()
        })
        .collect();

    let primary = FindingSummary::from_findings(&findings);
    let supporting = FindingSummary::from_findings(&[]);
    let package = FindingSummary::from_findings(&findings);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

    assert_eq!(verdict.verdict, Verdict::Benign);
    assert_eq!(verdict.package_health, PackageHealth::NeedsReview);

    // Block-level hygiene findings DO escalate to Suspicious.
    let block_findings: Vec<Finding> = (0..2)
        .map(|i| {
            Finding::builder(format!("HYGIENE_BLOCK_{}", i), ThreatCategory::ScopeCreep)
                .severity(Severity::High)
                .action(RecommendedAction::Block)
                .signal_class(SignalClass::Hygiene)
                .artifact_scope(ArtifactScope::AgentEntrypoint)
                .matched_on(MatchTarget::Document)
                .match_value(format!("severe hygiene {}", i))
                .reason(format!("hygiene block rule {}", i))
                .build()
        })
        .collect();

    let primary_b = FindingSummary::from_findings(&block_findings);
    let package_b = FindingSummary::from_findings(&block_findings);
    let verdict_b = derive_package_verdict(&block_findings, &primary_b, &supporting, &package_b);

    assert_eq!(verdict_b.verdict, Verdict::Suspicious);
    assert_eq!(verdict_b.package_health, PackageHealth::NeedsReview);
}

/// Contract: an actionable Hygiene group (non-Log action)
/// disables the isolated-weak-package-root downgrade. With two
/// actionable groups present, `isolated_weak_package_root_signal`
/// must evaluate to `false` and the verdict cannot collapse to
/// `Benign`.
#[test]
fn test_hygiene_with_non_log_action_prevents_isolated_weak_downgrade() {
    let findings = vec![
        Finding::builder("WEAK_PKG_SIGNAL", ThreatCategory::Generic)
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .signal_class(SignalClass::ReviewSignal)
            .artifact(
                ArtifactKind::PackageManifest,
                Some("package.json".to_string()),
            )
            .matched_on(MatchTarget::Document)
            .match_value("weak signal")
            .reason("Weak package root signal")
            .build(),
        Finding::builder("HYGIENE_ACTION", ThreatCategory::ScopeCreep)
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .signal_class(SignalClass::Hygiene)
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .matched_on(MatchTarget::Document)
            .match_value("scope creep")
            .reason("Hygiene with explicit action")
            .build(),
    ];

    let summary = FindingSummary::from_findings(&findings);
    let primary = FindingSummary::from_findings(&[]);
    let supporting = FindingSummary::from_findings(&[]);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &summary);

    // Must NOT be Benign: the Hygiene group with RequireApproval counts as actionable,
    // so there are 2 actionable groups and isolated_weak_package_root_signal is false.
    assert_ne!(
        verdict.verdict,
        Verdict::Benign,
        "Hygiene group with non-Log action must prevent isolated weak downgrade"
    );
}

/// Contract: a 2-component relative artifact_path (e.g. `config/skill.md`) must
/// NOT be classified as primary against a primary path that happens to share
/// the same trailing components. This is the bug case where sibling packages
/// in monorepo / dataset scans (`/repo-a/config/skill.md` vs
/// `/repo-b/config/skill.md`) would otherwise silently collide.
#[test]
fn split_findings_by_scope_rejects_two_component_cross_package_suffix() {
    let primary_path = std::path::Path::new("/repo-a/config/skill.md");
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .artifact(
            ArtifactKind::SkillDocument,
            Some("config/skill.md".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .build();

    let (primary, supporting) =
        split_findings_by_scope(primary_path, ArtifactKind::SkillDocument, &[finding]);

    assert!(
        primary.is_empty(),
        "2-component relative artifact_path must be rejected to avoid cross-package collision"
    );
    assert_eq!(supporting.len(), 1);
}

/// Contract: a 3+ component qualified relative suffix correctly identifies the
/// primary artifact (mirrors `paths_match_accepts_three_component_specific_suffix`
/// in `policy/state.rs`).
#[test]
fn split_findings_by_scope_accepts_three_component_qualified_suffix() {
    let primary_path = std::path::Path::new("/wrk/repo-a/config/skill.md");
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .artifact(
            ArtifactKind::SkillDocument,
            Some("repo-a/config/skill.md".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .build();

    let (primary, supporting) =
        split_findings_by_scope(primary_path, ArtifactKind::SkillDocument, &[finding]);

    assert_eq!(primary.len(), 1);
    assert!(supporting.is_empty());
}

/// Contract: an absolute artifact_path that doesn't equal the (relative or
/// otherwise) primary path is supporting, never primary. Mixing absolute and
/// relative paths via suffix-match would lose the explicit-path semantic.
#[test]
fn split_findings_by_scope_rejects_absolute_artifact_path_against_relative_primary() {
    let primary_path = std::path::Path::new("skill.md");
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .artifact(
            ArtifactKind::SkillDocument,
            Some("/elsewhere/skill.md".to_string()),
        )
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .build();

    let (primary, supporting) =
        split_findings_by_scope(primary_path, ArtifactKind::SkillDocument, &[finding]);

    assert!(primary.is_empty());
    assert_eq!(supporting.len(), 1);
}

/// Contract: an empty artifact_path string is treated as "explicit but unknown",
/// not as "matches everything". It must classify as supporting.
#[test]
fn split_findings_by_scope_rejects_empty_artifact_path() {
    let primary_path = std::path::Path::new("/project/skill.md");
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .artifact(ArtifactKind::SkillDocument, Some(String::new()))
        .matched_on(MatchTarget::Document)
        .match_value("x")
        .reason("x")
        .build();

    let (primary, supporting) =
        split_findings_by_scope(primary_path, ArtifactKind::SkillDocument, &[finding]);

    assert!(primary.is_empty());
    assert_eq!(supporting.len(), 1);
}

/// Contract: when two dedupe-key-equal findings are merged, `signal_class`,
/// `evidence_kind`, and `recommended_action` must come from the same finding —
/// the strength winner by `(action, severity, confidence)` tuple. Without this,
/// `verdict::predicates` and `verdict::blast_radius` (which read these fields
/// jointly) can be fooled into the wrong tier or blast-radius level.
#[test]
fn deduplicate_findings_aligns_signal_class_with_action_winner() {
    let high_severity_log = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::High)
        .confidence(0.5)
        .action(RecommendedAction::Log)
        .signal_class(SignalClass::Hygiene)
        .evidence_kind(EvidenceKind::Behavior)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("weak by action, strong by severity")
        .build();
    let medium_severity_block = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::Medium)
        .confidence(0.9)
        .action(RecommendedAction::Block)
        .signal_class(SignalClass::MaliciousBehavior)
        .evidence_kind(EvidenceKind::Ioc)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("strong by action, weaker by severity")
        .build();

    let (findings, _) = deduplicate_findings(vec![high_severity_log, medium_severity_block]);

    assert_eq!(findings.len(), 1);
    let merged = &findings[0];
    assert_eq!(
        merged.severity,
        Severity::High,
        "severity is max-aggregated"
    );
    assert!(
        merged.confidence >= 0.85,
        "confidence is max-aggregated (got {})",
        merged.confidence
    );
    assert_eq!(
        merged.recommended_action,
        RecommendedAction::Block,
        "action winner: Block"
    );
    assert_eq!(
        merged.signal_class,
        SignalClass::MaliciousBehavior,
        "signal_class must align with action winner, not severity winner"
    );
    assert_eq!(
        merged.evidence_kind,
        EvidenceKind::Ioc,
        "evidence_kind must align with action winner, not severity winner"
    );
    assert_eq!(merged.reason, "strong by action, weaker by severity");
}

/// Contract: findings that share a dedup key but differ in `signal_class` are
/// MERGED (not kept as separate findings). Splitting them on signal_class would
/// silently inflate finding counts and risk score on emitter quirks.
#[test]
fn deduplicate_findings_does_not_split_on_signal_class_mismatch() {
    let hygiene = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .signal_class(SignalClass::Hygiene)
        .matched_on(MatchTarget::Document)
        .match_value("identical match value")
        .reason("hygiene variant")
        .build();
    let malicious = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .signal_class(SignalClass::MaliciousBehavior)
        .matched_on(MatchTarget::Document)
        .match_value("identical match value")
        .reason("malicious variant")
        .build();

    let (findings, summary) = deduplicate_findings(vec![hygiene, malicious]);

    assert_eq!(
        findings.len(),
        1,
        "differing signal_class with identical dedup key must merge, not split"
    );
    assert_eq!(summary.duplicates_removed, 1);
}

/// Contract: when severities tie, the action winner determines the qualitative
/// fields (signal_class, evidence_kind, reason, remediation).
#[test]
fn deduplicate_findings_keeps_strongest_action_when_severities_tie() {
    let high_log = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::High)
        .action(RecommendedAction::Log)
        .signal_class(SignalClass::Hygiene)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("log variant")
        .build();
    let high_block = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::High)
        .action(RecommendedAction::Block)
        .signal_class(SignalClass::MaliciousBehavior)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("block variant")
        .build();

    let (findings, _) = deduplicate_findings(vec![high_log, high_block]);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].recommended_action, RecommendedAction::Block);
    assert_eq!(findings[0].signal_class, SignalClass::MaliciousBehavior);
    assert_eq!(findings[0].reason, "block variant");
}

/// Contract: when actions tie, the tuple ordering falls through to severity.
/// The severity winner's qualitative fields are taken.
#[test]
fn deduplicate_findings_keeps_strongest_severity_when_actions_tie() {
    let medium_block = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::Medium)
        .action(RecommendedAction::Block)
        .signal_class(SignalClass::SuspiciousPackageBehavior)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("medium severity variant")
        .build();
    let high_block = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::High)
        .action(RecommendedAction::Block)
        .signal_class(SignalClass::MaliciousBehavior)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("high severity variant")
        .build();

    let (findings, _) = deduplicate_findings(vec![medium_block, high_block]);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].signal_class, SignalClass::MaliciousBehavior);
    assert_eq!(findings[0].reason, "high severity variant");
}

/// Contract: `raw_confidence` and `confidence_rationale` follow the strength
/// winner — NOT the max-confidence finding. This pins the deliberate decision
/// to keep the audit trail aligned with the qualitative-field source even when
/// a different finding happens to carry a higher calibrated confidence.
#[test]
fn deduplicate_findings_aligns_raw_confidence_with_strength_winner() {
    let high_log_high_conf = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::High)
        .confidence(0.95)
        .action(RecommendedAction::Log)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("high severity but log action")
        .build();
    let medium_block_low_conf = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::Medium)
        .confidence(0.55)
        .action(RecommendedAction::Block)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("medium severity but block action")
        .build();
    // Capture pre-merge values so the assertion stays correct under any future
    // change to confidence calibration in the builder.
    let max_calibrated = high_log_high_conf
        .confidence
        .max(medium_block_low_conf.confidence);
    let strength_winner_raw = medium_block_low_conf.raw_confidence;
    let strength_winner_rationale = medium_block_low_conf.confidence_rationale.clone();
    assert!(
        high_log_high_conf.confidence > medium_block_low_conf.confidence,
        "test precondition: high-severity-log finding must carry the higher calibrated confidence"
    );

    let (findings, _) = deduplicate_findings(vec![high_log_high_conf, medium_block_low_conf]);

    assert_eq!(findings.len(), 1);
    let merged = &findings[0];
    assert!(
        (merged.confidence - max_calibrated).abs() < f32::EPSILON,
        "calibrated confidence is max-aggregated (got {}, expected {})",
        merged.confidence,
        max_calibrated
    );
    assert!(
        (merged.raw_confidence - strength_winner_raw).abs() < f32::EPSILON,
        "raw_confidence must come from the strength winner (Block action), not from the max-confidence finding"
    );
    assert_eq!(merged.confidence_rationale, strength_winner_rationale);
}

/// Contract: when `(action, severity, confidence)` tie exactly, the longer
/// `reason` text wins (preserves stable audit-trail behavior so that the most
/// informative entry survives merge).
#[test]
fn deduplicate_findings_prefers_longer_reason_on_total_tuple_tie() {
    let short_reason = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::Medium)
        .confidence(0.7)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("short")
        .build();
    let long_reason = Finding::builder("RULE_DUP", ThreatCategory::Generic)
        .severity(Severity::Medium)
        .confidence(0.7)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("same match site")
        .reason("a much longer and more informative reason text for the audit trail")
        .build();

    let (findings, _) = deduplicate_findings(vec![short_reason, long_reason]);

    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].reason,
        "a much longer and more informative reason text for the audit trail"
    );
}

/// Contract: empty findings produce `Verdict::Benign` AND
/// `PackageHealth::Healthy`, with empty supporting collections
/// (root cause groups, calibration notes, declared permissions,
/// effective capabilities) and a `Low` blast radius. Closes
/// issue #8 — empty input must NOT collapse to `NeedsReview` on
/// the contradictory-state path.
#[test]
fn test_empty_findings_produce_benign_healthy_verdict() {
    let findings: Vec<Finding> = vec![];

    let primary = FindingSummary::from_findings(&[]);
    let supporting = FindingSummary::from_findings(&[]);
    let package = FindingSummary::from_findings(&[]);
    let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

    assert_eq!(verdict.verdict, Verdict::Benign);
    assert_eq!(verdict.package_health, PackageHealth::Healthy);
    assert!(verdict.verdict_reasons.is_empty());
    assert!(verdict.root_cause_groups.is_empty());
    assert!(verdict.top_risk_drivers.is_empty());
    assert!(verdict.calibration_notes.is_empty());
    assert_eq!(verdict.calibration_risk_adjustment, 0);
    assert!(verdict.declared_permissions.is_empty());
    assert!(verdict.effective_capabilities.is_empty());
    // Empty findings produce Low blast radius (no risk factors)
    assert_eq!(verdict.blast_radius_summary.level, BlastRadiusLevel::Low);
}

/// Contract: a NaN passed to `.confidence(...)` after a finite value must
/// preserve the finite value — the merge-semantics docs in
/// `findings/dedup.rs:100-101` rely on `Finding.confidence` being finite.
#[test]
fn confidence_builder_rejects_nan_keeps_previous_value() {
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .confidence(0.5)
        .confidence(f32::NAN)
        .build();
    assert!(
        !finding.confidence.is_nan(),
        "NaN must not propagate to Finding.confidence"
    );
    assert!(
        !finding.raw_confidence.is_nan(),
        "NaN must not propagate to Finding.raw_confidence"
    );
    assert!((finding.raw_confidence - 0.5).abs() < f32::EPSILON);
}

/// Contract: a NaN passed to `.confidence(...)` with no prior call falls
/// back to the constructor default (0.9), not NaN.
#[test]
fn confidence_builder_rejects_nan_with_no_prior_value() {
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .confidence(f32::NAN)
        .build();
    assert!(!finding.confidence.is_nan());
    assert!(!finding.raw_confidence.is_nan());
    assert!((finding.raw_confidence - 0.9).abs() < 0.01);
}

/// Contract: confidence values above 1.0 clamp to 1.0 (existing behavior,
/// pinned alongside the NaN guard so future readers see the contract
/// together).
#[test]
fn confidence_builder_clamps_above_one() {
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .confidence(2.5)
        .build();
    assert!((finding.raw_confidence - 1.0).abs() < f32::EPSILON);
}

/// Contract: confidence values below 0.0 clamp to 0.0.
#[test]
fn confidence_builder_clamps_below_zero() {
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .confidence(-0.3)
        .build();
    assert!(finding.raw_confidence.abs() < f32::EPSILON);
}

/// Contract: positive infinity clamps to 1.0 (Rust's `f32::clamp` handles
/// finite-but-overflowing values correctly; pinned to anchor the behavior
/// distinction between Inf and NaN).
#[test]
fn confidence_builder_handles_positive_infinity() {
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .confidence(f32::INFINITY)
        .build();
    assert!(!finding.raw_confidence.is_nan());
    assert!((finding.raw_confidence - 1.0).abs() < f32::EPSILON);
}

/// Contract: negative infinity clamps to 0.0.
#[test]
fn confidence_builder_handles_negative_infinity() {
    let finding = Finding::builder("RULE", ThreatCategory::Generic)
        .confidence(f32::NEG_INFINITY)
        .build();
    assert!(!finding.raw_confidence.is_nan());
    assert!(finding.raw_confidence.abs() < f32::EPSILON);
}
