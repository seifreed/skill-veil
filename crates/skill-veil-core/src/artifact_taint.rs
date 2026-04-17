mod analysis;
mod patterns;
mod summarization;
mod taint_rules;
mod utils;

use crate::artifact_graph::ArtifactGraph;
use crate::findings::{deduplicate_findings, Finding, RecommendedAction, Severity, ThreatCategory};

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

pub fn derive_taint_findings(graph: &ArtifactGraph) -> Vec<Finding> {
    let groups = taint_rules::group_rules(taint_rules::default_rules());
    let mut findings = analysis::derive_per_node_taint_findings(graph, &groups);
    findings.extend(analysis::derive_cross_node_taint_findings(graph, &groups));
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

        let findings = derive_taint_findings(&graph);
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

        let findings = derive_taint_findings(&graph);
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

        let findings = derive_taint_findings(&graph);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK"),
            "Expected cross-node parent→child taint finding, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
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

        let findings = derive_taint_findings(&graph);
        assert!(findings.iter().all(|finding| {
            finding.rule_id != "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK"
                && finding.rule_id != "ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK"
        }));
    }
}
