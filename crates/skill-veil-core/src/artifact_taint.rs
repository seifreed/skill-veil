mod analysis;
mod patterns;
mod summarization;
mod taint_rules;
mod trusted_hosts;
mod utils;

use crate::artifact_graph::ArtifactGraph;
use crate::findings::{
    deduplicate_findings, Finding, RecommendedAction, Severity, SignalClass, ThreatCategory,
};

/// Threat categories that count as *independent* corroboration of
/// malice for the trusted/first-party taint downgrade. Deliberately
/// excludes `CredentialExposure` and `DataExfiltration`: those fire on
/// the SAME benign API-client gestalt as the secret/identity→network
/// taint rules (read `<SVC>_API_KEY`, POST to the vendor API trips
/// `SKILL_OAUTH_TOKEN_THEFT`, `SKILL_CRED_HARDCODED_KEY`, …), so
/// counting them would defeat the downgrade on the exact FP class it
/// exists for. Also excludes the weak/advisory categories
/// (`PersuasiveLanguage`, `ScopeCreep`, `Generic`).
const INDEPENDENT_MALICE_CATEGORIES: &[ThreatCategory] = &[
    ThreatCategory::RemoteExec,
    ThreatCategory::PersistentPromptTampering,
    ThreatCategory::PrivilegeEscalation,
    ThreatCategory::AutonomyEscalation,
    ThreatCategory::SocialManipulation,
    ThreatCategory::Obfuscation,
    ThreatCategory::UnsafeBinary,
    ThreatCategory::ToolAbuse,
    ThreatCategory::SupplyChain,
];

/// `true` when `existing` (the rule-engine findings collected *before*
/// taint runs) already contains an independent malicious-behavior
/// block finding from a non-exfil/non-credential family. The
/// trusted/first-party taint downgrade's premise — "this is a benign
/// upstream-API integration" — is falsified when the same package
/// independently looks malicious for an unrelated reason (prompt
/// injection, remote exec, rootkit, …). Suppressing the downgrade
/// there keeps the secret→network signal at full strength so the
/// verdict layer still sees the exfil leg of real malware, while
/// benign API clients (which carry only credential/exfil-family
/// findings, mostly prose-downgraded) remain downgraded.
fn has_independent_malice(existing: &[Finding]) -> bool {
    existing.iter().any(|f| {
        f.signal_class == SignalClass::MaliciousBehavior
            && f.recommended_action == RecommendedAction::Block
            && INDEPENDENT_MALICE_CATEGORIES.contains(&f.category)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TaintSourceKind {
    SecretAccess,
    RemoteDownload,
    FilesystemWrite,
    IdentityAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TaintSinkKind {
    ExternalNetwork,
    Execution,
    Persistence,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct ArtifactTaintRule {
    pub id: String,
    pub family: String,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub confidence: f32,
    pub action: RecommendedAction,
    pub reason: String,
    pub source: TaintSourceKind,
    pub sink: TaintSinkKind,
}

#[derive(Debug, Clone)]
pub(crate) struct ArtifactTaintRuleGroup {
    pub source: TaintSourceKind,
    pub sink: TaintSinkKind,
    pub rules: Vec<ArtifactTaintRule>,
}

/// Derive artifact-graph taint findings.
///
/// `existing_findings` are the rule-engine/orchestration findings
/// collected for the same package *before* this stage runs (taint is
/// appended last in `collect_raw_findings`). They gate the
/// trusted/first-party downgrade: when the package already shows
/// independent malice (`has_independent_malice`), the
/// secret/identity→network finding keeps full `Block` /
/// `MaliciousBehavior` strength instead of softening to
/// `RequireApproval` / `ReviewSignal`.
pub fn derive_taint_findings(graph: &ArtifactGraph, existing_findings: &[Finding]) -> Vec<Finding> {
    let groups = taint_rules::group_rules(taint_rules::default_rules());
    let suppress_downgrade = has_independent_malice(existing_findings);
    let mut findings = analysis::derive_per_node_taint_findings(graph, &groups, suppress_downgrade);
    findings.extend(analysis::derive_cross_node_taint_findings(
        graph,
        &groups,
        suppress_downgrade,
    ));
    // Local deduplication to reduce overhead before returning to caller.
    // Cross-node taint analysis can generate duplicate findings when multiple
    // sink nodes match the same source-rule combination.
    let (deduped, _summary) = deduplicate_findings(findings);
    deduped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_graph::ArtifactRelation;
    use crate::findings::ArtifactKind;

    #[test]
    fn taint_ignores_registry_download_to_exec() {
        let mut graph = ArtifactGraph::new();
        graph.add_node("package.json", ArtifactKind::PackageManifest);
        graph.add_edge(
            "package.json",
            "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
            ArtifactRelation::Downloads,
        );
        graph.add_edge(
            "package.json",
            "node install.js",
            ArtifactRelation::Executes,
        );

        let findings = derive_taint_findings(&graph, &[]);
        assert!(findings
            .iter()
            .all(|finding| finding.rule_id != "ARTIFACT_TAINT_DOWNLOAD_TO_EXECUTION"));
    }

    #[test]
    fn taint_flags_transient_identity_to_network() {
        let mut graph = ArtifactGraph::new();
        graph.add_node("skill.md", ArtifactKind::SkillDocument);
        graph.add_edge("skill.md", "oauth_token", ArtifactRelation::Reads);
        graph.add_edge(
            "skill.md",
            "https://attacker.ngrok-free.app/hook",
            ArtifactRelation::ConnectsTo,
        );

        let findings = derive_taint_findings(&graph, &[]);
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK"));
    }

    #[test]
    fn taint_detects_parent_child_secret_to_network() {
        let mut graph = ArtifactGraph::new();
        graph.add_node("skill.md", ArtifactKind::SkillDocument);
        graph.add_node("deploy.sh", ArtifactKind::ReferencedArtifact);
        // Parent reads a secret
        graph.add_edge("skill.md", ".env", ArtifactRelation::AccessesSecrets);
        // Parent references child
        graph.add_edge("skill.md", "deploy.sh", ArtifactRelation::References);
        // Child connects to external network
        graph.add_edge(
            "deploy.sh",
            "https://attacker.example.com/exfil",
            ArtifactRelation::ConnectsTo,
        );

        let findings = derive_taint_findings(&graph, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK"),
            "Expected cross-node parent→child taint finding, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    /// # Contract
    ///
    /// A cross-node taint finding's `artifact_path` and `matched_on`
    /// MUST point at the same source node. Pre-fix `artifact_path`
    /// was the source while `matched_on` was the sink, so a single
    /// finding referenced two different files in its evidence trail
    /// — confusing for auditors and breaking suppression
    /// path-matching (`policy::fingerprint::paths_match` keys on
    /// `artifact_path`). The source/sink relationship is preserved
    /// verbatim in `match_value` so no information is lost.
    #[test]
    fn cross_node_taint_finding_attributes_artifact_and_match_to_source() {
        let mut graph = ArtifactGraph::new();
        graph.add_node("skill.md", ArtifactKind::SkillDocument);
        graph.add_node("deploy.sh", ArtifactKind::ReferencedArtifact);
        graph.add_edge("skill.md", ".env", ArtifactRelation::AccessesSecrets);
        graph.add_edge("skill.md", "deploy.sh", ArtifactRelation::References);
        graph.add_edge(
            "deploy.sh",
            "https://attacker.example.com/exfil",
            ArtifactRelation::ConnectsTo,
        );

        let findings = derive_taint_findings(&graph, &[]);
        let cross = findings
            .iter()
            .find(|f| f.rule_id == "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK")
            .expect("expected cross-node SECRET_TO_EXTERNAL_NETWORK finding");

        let crate::findings::MatchTarget::ReferencedFile {
            path: ref matched_path,
        } = cross.matched_on
        else {
            unreachable!(
                "cross-node taint finding MUST use ReferencedFile; got {:?}",
                cross.matched_on
            );
        };
        let matched_path = matched_path.as_str();
        assert_eq!(
            cross.artifact_path.as_deref(),
            Some(matched_path),
            "artifact_path and matched_on MUST point at the same node; \
             got artifact_path={:?}, matched_on={matched_path:?}",
            cross.artifact_path
        );
        assert!(
            cross.match_value.contains("source=") && cross.match_value.contains("sink="),
            "source/sink detail MUST be preserved in match_value; got {:?}",
            cross.match_value
        );
    }

    #[test]
    fn taint_requires_observed_external_network_sink() {
        let mut graph = ArtifactGraph::new();
        graph.add_node_with_capabilities(
            "skill.md",
            ArtifactKind::SkillDocument,
            vec![
                crate::artifact_graph::ArtifactCapabilityFact {
                    capability: crate::artifact_graph::ArtifactCapability::SecretAccess,
                    source: crate::artifact_graph::ArtifactCapabilitySource::Observed,
                },
                crate::artifact_graph::ArtifactCapabilityFact {
                    capability: crate::artifact_graph::ArtifactCapability::NetworkAccess,
                    source: crate::artifact_graph::ArtifactCapabilitySource::Observed,
                },
            ],
        );

        let findings = derive_taint_findings(&graph, &[]);
        assert!(findings.iter().all(|finding| {
            finding.rule_id != "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK"
                && finding.rule_id != "ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK"
        }));
    }

    /// Contract: when EVERY external sink for a tainted node resolves
    /// to a host on the trusted-API allowlist, the
    /// `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK` finding is
    /// downgraded to `ReviewSignal` / `RequireApproval`. Mirrors the
    /// dominant FP pattern from the cross-LLM triage: a skill that
    /// reads `YOUTUBE_API_KEY` and POSTs to `googleapis.com` is the
    /// modal benign API client, not an exfil tool.
    #[test]
    fn secret_to_trusted_api_host_is_downgraded() {
        let mut graph = ArtifactGraph::new();
        graph.add_node("skill.md", ArtifactKind::SkillDocument);
        graph.add_edge("skill.md", ".env", ArtifactRelation::AccessesSecrets);
        graph.add_edge(
            "skill.md",
            "https://sheets.googleapis.com/v4/spreadsheets/123/values/A1",
            ArtifactRelation::ConnectsTo,
        );

        let findings = derive_taint_findings(&graph, &[]);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK")
            .expect("rule must still emit a finding when sinks are trusted");
        assert_eq!(
            f.recommended_action,
            crate::findings::RecommendedAction::RequireApproval,
            "trusted sink must downgrade Block to RequireApproval; got {:?}",
            f.recommended_action,
        );
        assert_eq!(
            f.signal_class,
            crate::findings::SignalClass::ReviewSignal,
            "trusted sink must downgrade signal_class to ReviewSignal; got {:?}",
            f.signal_class,
        );
        assert!(
            f.match_value.contains("sinks_trusted=true"),
            "match_value must record the downgrade; got {:?}",
            f.match_value,
        );
    }

    /// Contract (negative): mixing one trusted sink with one untrusted
    /// sink MUST keep the rule at full strength. The downgrade is
    /// conditional on EVERY external sink resolving to the allowlist;
    /// a single attacker-controlled sink is enough to keep the block.
    /// Pre-fix a permissive `any_trusted` predicate would have let
    /// attackers bypass detection by also pinging a benign endpoint.
    #[test]
    fn mixed_trusted_and_untrusted_sinks_keep_block() {
        let mut graph = ArtifactGraph::new();
        graph.add_node("skill.md", ArtifactKind::SkillDocument);
        graph.add_edge("skill.md", ".env", ArtifactRelation::AccessesSecrets);
        graph.add_edge(
            "skill.md",
            "https://api.openai.com/v1/chat/completions",
            ArtifactRelation::ConnectsTo,
        );
        // Use a non-RFC2606 hostname so the documentation-host
        // strip in `all_external_sinks_trusted` does not mistake
        // this attacker sink for a placeholder URL. `example.com`
        // and friends are reserved for documentation by RFC2606
        // and skipped by the trust check.
        graph.add_edge(
            "skill.md",
            "https://attacker-controlled.io/exfil",
            ArtifactRelation::ConnectsTo,
        );

        let findings = derive_taint_findings(&graph, &[]);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK")
            .expect("rule must fire");
        assert_eq!(
            f.recommended_action,
            crate::findings::RecommendedAction::Block,
            "an untrusted sink MUST defeat the downgrade; got {:?}",
            f.recommended_action,
        );
        assert!(
            !f.match_value.contains("sinks_trusted=true"),
            "match_value must NOT claim the downgrade; got {:?}",
            f.match_value,
        );
    }

    /// Contract: a trusted-API sink combined with an RFC2606
    /// documentation/example sink (which appears constantly in skill
    /// prose: "POST to `https://example.com/api`...") MUST still
    /// trigger the trust downgrade. Pre-fix a single
    /// `https://example.com/...` reference defeated the downgrade
    /// and the exfil rule fired at full strength on benign skills
    /// that linked an example URL alongside a real Atlassian /
    /// OpenAI / GitHub call.
    #[test]
    fn documentation_sink_does_not_defeat_trust_downgrade() {
        let mut graph = ArtifactGraph::new();
        graph.add_node("skill.md", ArtifactKind::SkillDocument);
        graph.add_edge("skill.md", ".env", ArtifactRelation::AccessesSecrets);
        graph.add_edge(
            "skill.md",
            "https://api.openai.com/v1/chat/completions",
            ArtifactRelation::ConnectsTo,
        );
        graph.add_edge(
            "skill.md",
            "https://example.com/api",
            ArtifactRelation::ConnectsTo,
        );
        graph.add_edge(
            "skill.md",
            "http://localhost:8080/health",
            ArtifactRelation::ConnectsTo,
        );

        let findings = derive_taint_findings(&graph, &[]);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK")
            .expect("rule must still emit when sinks are trusted");
        assert_eq!(
            f.recommended_action,
            crate::findings::RecommendedAction::RequireApproval,
            "documentation/loopback sinks must be stripped before trust check",
        );
        assert!(
            f.match_value.contains("sinks_trusted=true"),
            "match_value must record the downgrade after doc-host strip",
        );
    }

    /// Contract: identity-source rule (`oauth_token`) gets the same
    /// downgrade treatment as the secret-source rule. Without this
    /// the cross-LLM-triage measured ~272 secret/identity FPs would
    /// only be partially addressed.
    #[test]
    fn identity_to_trusted_api_host_is_downgraded() {
        let mut graph = ArtifactGraph::new();
        graph.add_node("skill.md", ArtifactKind::SkillDocument);
        graph.add_edge("skill.md", "oauth_token", ArtifactRelation::Reads);
        graph.add_edge(
            "skill.md",
            "https://api.notion.com/v1/pages",
            ArtifactRelation::ConnectsTo,
        );

        let findings = derive_taint_findings(&graph, &[]);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK")
            .expect("rule must still emit when sinks are trusted");
        assert_eq!(
            f.recommended_action,
            crate::findings::RecommendedAction::RequireApproval,
        );
        assert_eq!(f.signal_class, crate::findings::SignalClass::ReviewSignal);
    }

    fn secret_to_trusted_host_graph() -> ArtifactGraph {
        let mut graph = ArtifactGraph::new();
        graph.add_node("skill.md", ArtifactKind::SkillDocument);
        graph.add_edge("skill.md", ".env", ArtifactRelation::AccessesSecrets);
        graph.add_edge(
            "skill.md",
            "https://api.notion.com/v1/pages",
            ArtifactRelation::ConnectsTo,
        );
        graph
    }

    fn malice_finding(rule: &str, category: ThreatCategory) -> Finding {
        Finding::builder(rule, category)
            .severity(Severity::Critical)
            .action(RecommendedAction::Block)
            .signal_class(SignalClass::MaliciousBehavior)
            .matched_on(crate::findings::MatchTarget::Document)
            .match_value("x")
            .reason("y")
            .build()
    }

    /// # Contract
    /// When the package independently shows malice from a non-exfil
    /// family (here `RemoteExec`), the secret→trusted-host taint
    /// finding MUST keep full `Block`/`MaliciousBehavior` strength —
    /// the "benign upstream-API integration" premise is falsified, so
    /// the verdict layer still sees the exfil leg of real malware.
    #[test]
    fn corroborated_malice_suppresses_taint_downgrade() {
        let graph = secret_to_trusted_host_graph();
        let existing = vec![malice_finding(
            "SKILL_REMOTE_EXEC_CURL_BASH",
            ThreatCategory::RemoteExec,
        )];
        let findings = derive_taint_findings(&graph, &existing);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK")
            .expect("secret→network rule must still emit");
        assert_eq!(f.recommended_action, RecommendedAction::Block);
        assert_eq!(f.signal_class, SignalClass::MaliciousBehavior);
    }

    /// # Contract (negative — protects the FP win)
    /// A credential/exfil-family malice finding fires on the SAME
    /// benign API-client gestalt as the taint rule, so it MUST NOT
    /// count as independent corroboration: the trusted-host downgrade
    /// still applies. Without this exclusion the downgrade would be
    /// defeated on the exact false-positive class it exists for.
    #[test]
    fn credential_family_does_not_corroborate_taint() {
        let graph = secret_to_trusted_host_graph();
        let existing = vec![malice_finding(
            "SKILL_OAUTH_TOKEN_THEFT",
            ThreatCategory::CredentialExposure,
        )];
        let findings = derive_taint_findings(&graph, &existing);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK")
            .expect("secret→network rule must still emit");
        assert_eq!(f.recommended_action, RecommendedAction::RequireApproval);
        assert_eq!(f.signal_class, SignalClass::ReviewSignal);
    }
}
