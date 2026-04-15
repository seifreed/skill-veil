use crate::artifact_graph::{ArtifactCapability, ArtifactGraph, ArtifactRelation, EndpointKind};
use crate::findings::{
    deduplicate_findings, ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction,
    Severity, ThreatCategory,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourceSelector {
    SecretAccess,
    RemoteDownload,
    FilesystemWrite,
    IdentityAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SinkSelector {
    ExternalNetwork,
    Execution,
    Persistence,
}

#[derive(Debug, Clone)]
struct ArtifactTaintRule {
    id: &'static str,
    family: &'static str,
    category: ThreatCategory,
    severity: Severity,
    confidence: f32,
    action: RecommendedAction,
    reason: &'static str,
    source: SourceSelector,
    sink: SinkSelector,
}

#[derive(Debug, Clone)]
struct ArtifactTaintRuleGroup {
    source: SourceSelector,
    sink: SinkSelector,
    rules: Vec<ArtifactTaintRule>,
}

pub fn derive_taint_findings(graph: &ArtifactGraph) -> Vec<Finding> {
    let groups = group_rules(default_rules());
    let mut findings = Vec::new();
    let paths = artifact_paths(graph);

    // Per-node taint: source and sink on the same artifact
    for node_path in &paths {
        for group in &groups {
            if !node_has_source(graph, node_path, group.source)
                || !node_has_sink(graph, node_path, group.sink)
            {
                continue;
            }

            let src = source_summary(graph, node_path, group.source);
            let snk = sink_summary(graph, node_path, group.sink);
            let kind = artifact_kind_for_node(graph, node_path);

            for rule in &group.rules {
                findings.push(
                    Finding::builder(rule.id, rule.category)
                        .severity(rule.severity)
                        .confidence(rule.confidence)
                        .action(rule.action)
                        .evidence_kind(EvidenceKind::Behavior)
                        .artifact(kind, Some(node_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: node_path.clone(),
                        })
                        .match_value(format!(
                            "family={} source={} sink={}",
                            rule.family, src, snk
                        ))
                        .reason(rule.reason)
                        .build(),
                );
            }
        }
    }

    // Cross-node taint: source on node A, sink on sibling node B
    // (siblings = nodes sharing a parent via References/Contains edges)
    //
    // Cap per-cluster findings to avoid quadratic explosion when a parent
    // references many children that each expose sources and sinks.
    const MAX_CROSS_NODE_FINDINGS_PER_CLUSTER: usize = 50;
    let sibling_clusters = build_sibling_clusters(graph);
    for cluster in &sibling_clusters {
        if cluster.len() < 2 {
            continue;
        }
        let mut cluster_finding_count = 0_usize;
        'cluster: for group in &groups {
            let source_nodes: Vec<&String> = cluster
                .iter()
                .filter(|path| node_has_source(graph, path, group.source))
                .collect();
            let sink_nodes: Vec<&String> = cluster
                .iter()
                .filter(|path| node_has_sink(graph, path, group.sink))
                .collect();
            for source_node in &source_nodes {
                for sink_node in &sink_nodes {
                    if source_node == sink_node {
                        continue; // already covered by per-node pass
                    }
                    let src = source_summary(graph, source_node, group.source);
                    let snk = sink_summary(graph, sink_node, group.sink);
                    let kind = artifact_kind_for_node(graph, source_node);

                    for rule in &group.rules {
                        findings.push(
                            Finding::builder(rule.id, rule.category)
                                .severity(rule.severity)
                                .confidence(rule.confidence * 0.9)
                                .action(rule.action)
                                .evidence_kind(EvidenceKind::Behavior)
                                .artifact(kind, Some((*source_node).clone()))
                                .matched_on(MatchTarget::ReferencedFile {
                                    path: (*sink_node).clone(),
                                })
                                .match_value(format!(
                                    "family={} source={} sink={}",
                                    rule.family, src, snk
                                ))
                                .reason(rule.reason)
                                .build(),
                        );
                        cluster_finding_count += 1;
                        if cluster_finding_count >= MAX_CROSS_NODE_FINDINGS_PER_CLUSTER {
                            break 'cluster;
                        }
                    }
                }
            }
        }
    }

    // Local deduplication to reduce overhead before returning to caller.
    // Cross-node taint analysis can generate duplicate findings when multiple
    // sink nodes match the same source-rule combination.
    let (deduped, _summary) = deduplicate_findings(findings);
    deduped
}

fn build_sibling_clusters(graph: &ArtifactGraph) -> Vec<BTreeSet<String>> {
    let mut parent_to_cluster: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for edge in &graph.edges {
        if matches!(
            edge.relation,
            ArtifactRelation::References | ArtifactRelation::Contains
        ) {
            let cluster = parent_to_cluster.entry(edge.from.clone()).or_default();
            // Include the parent so parent→child taint paths are detected.
            // The cross-node loop skips source_node == sink_node, so
            // per-node findings are not double-counted.
            cluster.insert(edge.from.clone());
            cluster.insert(edge.to.clone());
        }
    }
    parent_to_cluster.into_values().collect()
}

fn default_rules() -> Vec<ArtifactTaintRule> {
    vec![
        ArtifactTaintRule {
            id: "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
            family: "exfil",
            category: ThreatCategory::DataExfiltration,
            severity: Severity::Critical,
            confidence: 0.94,
            action: RecommendedAction::Block,
            reason: "Artifact combines access to secret material with outbound network communication, consistent with secret exfiltration",
            source: SourceSelector::SecretAccess,
            sink: SinkSelector::ExternalNetwork,
        },
        ArtifactTaintRule {
            id: "ARTIFACT_TAINT_DOWNLOAD_TO_EXECUTION",
            family: "remote_exec",
            category: ThreatCategory::RemoteExec,
            severity: Severity::Critical,
            confidence: 0.93,
            action: RecommendedAction::Block,
            reason: "Artifact combines remote download with subsequent execution behavior",
            source: SourceSelector::RemoteDownload,
            sink: SinkSelector::Execution,
        },
        ArtifactTaintRule {
            id: "ARTIFACT_TAINT_WRITE_TO_PERSISTENCE",
            family: "persistence",
            category: ThreatCategory::PersistentPromptTampering,
            severity: Severity::High,
            confidence: 0.87,
            action: RecommendedAction::RequireApproval,
            reason: "Artifact combines write behavior with persistence behavior, suggesting durable modification of future runtime state",
            source: SourceSelector::FilesystemWrite,
            sink: SinkSelector::Persistence,
        },
        ArtifactTaintRule {
            id: "ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK",
            family: "identity_exfil",
            category: ThreatCategory::DataExfiltration,
            severity: Severity::High,
            confidence: 0.88,
            action: RecommendedAction::RequireApproval,
            reason: "Artifact combines identity or OAuth access with outbound network communication, consistent with token or session exfiltration",
            source: SourceSelector::IdentityAccess,
            sink: SinkSelector::ExternalNetwork,
        },
    ]
}

fn group_rules(rules: Vec<ArtifactTaintRule>) -> Vec<ArtifactTaintRuleGroup> {
    let mut groups: BTreeMap<(SourceSelector, SinkSelector), Vec<ArtifactTaintRule>> =
        BTreeMap::new();
    for rule in rules {
        groups
            .entry((rule.source, rule.sink))
            .or_default()
            .push(rule);
    }

    let mut result: Vec<_> = groups
        .into_iter()
        .map(|((source, sink), rules)| ArtifactTaintRuleGroup {
            source,
            sink,
            rules,
        })
        .collect();

    // Sort by max severity descending so the per-cluster budget is consumed
    // by the highest-severity rules first (not by enum declaration order).
    result.sort_by(|a, b| {
        let max_sev = |group: &ArtifactTaintRuleGroup| group.rules.iter().map(|r| r.severity).max();
        max_sev(b).cmp(&max_sev(a))
    });

    result
}

fn artifact_paths(graph: &ArtifactGraph) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for node in &graph.nodes {
        paths.insert(node.path.clone());
    }
    paths.into_iter().collect()
}

fn artifact_kind_for_node(graph: &ArtifactGraph, path: &str) -> ArtifactKind {
    graph
        .nodes
        .iter()
        .find(|node| node.path == path)
        .map(|node| node.kind)
        .unwrap_or(ArtifactKind::GenericArtifact)
}

fn node_has_source(graph: &ArtifactGraph, node_path: &str, source: SourceSelector) -> bool {
    match source {
        SourceSelector::SecretAccess => {
            node_has_capability(graph, node_path, ArtifactCapability::SecretAccess)
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path
                        && matches!(edge.relation, ArtifactRelation::AccessesSecrets)
                })
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path
                        && matches!(edge.relation, ArtifactRelation::Reads)
                        && looks_like_secret_target(&edge.to)
                })
        }
        SourceSelector::RemoteDownload => graph.edges.iter().any(|edge| {
            edge.from == node_path
                && matches!(edge.relation, ArtifactRelation::Downloads)
                && edge.endpoint_kind != Some(EndpointKind::Registry)
                && !looks_like_registry_url(&edge.to)
        }),
        SourceSelector::FilesystemWrite => {
            node_has_capability(graph, node_path, ArtifactCapability::FilesystemWrite)
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path && matches!(edge.relation, ArtifactRelation::Writes)
                })
        }
        SourceSelector::IdentityAccess => {
            node_has_capability(graph, node_path, ArtifactCapability::IdentityAccess)
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path
                        && matches!(edge.relation, ArtifactRelation::Reads)
                        && looks_like_identity_target(&edge.to)
                })
        }
    }
}

fn node_has_sink(graph: &ArtifactGraph, node_path: &str, sink: SinkSelector) -> bool {
    match sink {
        SinkSelector::ExternalNetwork => graph.edges.iter().any(|edge| {
            edge.from == node_path
                && matches!(edge.relation, ArtifactRelation::ConnectsTo)
                && looks_like_external_sink(edge)
        }),
        SinkSelector::Execution => {
            node_has_capability(graph, node_path, ArtifactCapability::ProcessExecution)
                || node_has_capability(graph, node_path, ArtifactCapability::InstallExecution)
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path && matches!(edge.relation, ArtifactRelation::Executes)
                })
        }
        SinkSelector::Persistence => {
            node_has_capability(graph, node_path, ArtifactCapability::PersistenceSurface)
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path && matches!(edge.relation, ArtifactRelation::Persists)
                })
        }
    }
}

fn node_has_capability(
    graph: &ArtifactGraph,
    node_path: &str,
    capability: ArtifactCapability,
) -> bool {
    graph.nodes.iter().any(|node| {
        node.path == node_path
            && node
                .capabilities
                .iter()
                .any(|fact| fact.capability == capability)
    })
}

fn source_summary(graph: &ArtifactGraph, node_path: &str, source: SourceSelector) -> String {
    match source {
        SourceSelector::SecretAccess => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path
                    && (matches!(edge.relation, ArtifactRelation::AccessesSecrets)
                        || (matches!(edge.relation, ArtifactRelation::Reads)
                            && looks_like_secret_target(&edge.to)))
            })
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "secret_access".to_string()),
        SourceSelector::RemoteDownload => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path
                    && matches!(edge.relation, ArtifactRelation::Downloads)
                    && edge.endpoint_kind != Some(EndpointKind::Registry)
                    && !looks_like_registry_url(&edge.to)
            })
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "remote_download".to_string()),
        SourceSelector::FilesystemWrite => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path && matches!(edge.relation, ArtifactRelation::Writes)
            })
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "filesystem_write".to_string()),
        SourceSelector::IdentityAccess => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path
                    && matches!(edge.relation, ArtifactRelation::Reads)
                    && looks_like_identity_target(&edge.to)
            })
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "identity_access".to_string()),
    }
}

fn sink_summary(graph: &ArtifactGraph, node_path: &str, sink: SinkSelector) -> String {
    match sink {
        SinkSelector::ExternalNetwork => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path
                    && matches!(edge.relation, ArtifactRelation::ConnectsTo)
                    && looks_like_external_sink(edge)
            })
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "external_network".to_string()),
        SinkSelector::Execution => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path && matches!(edge.relation, ArtifactRelation::Executes)
            })
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "execution".to_string()),
        SinkSelector::Persistence => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path && matches!(edge.relation, ArtifactRelation::Persists)
            })
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "persistence".to_string()),
    }
}

fn looks_like_secret_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    [
        ".env",
        ".npmrc",
        ".ssh",
        "id_rsa",
        "known_hosts",
        "aws_secret_access_key",
        "aws_session_token",
        "openai_api_key",
        "github_token",
        "gh_token",
        "google_application_credentials",
        "slack_bot_token",
        "token",
        "secret",
        "cookie",
        "session",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn looks_like_identity_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.contains("oauth")
        || lower.contains("token")
        || lower.contains("session")
        || lower.contains("cookie")
        || lower.contains("credential")
        || lower.contains("identity")
}

fn looks_like_external_sink(edge: &crate::artifact_graph::ArtifactEdge) -> bool {
    // Known external endpoint kinds are conclusive
    if matches!(
        edge.endpoint_kind,
        Some(EndpointKind::Remote | EndpointKind::Transient | EndpointKind::ControlPlane)
    ) {
        return true;
    }
    // Registry and Local endpoints are not external sinks
    if matches!(
        edge.endpoint_kind,
        Some(EndpointKind::Registry | EndpointKind::Local)
    ) {
        return false;
    }
    // When endpoint_kind is None, fall back to string matching on the URL
    // This is a best-effort heuristic that may miss some external sinks

    let lower = edge.to.to_ascii_lowercase();

    // Known malicious patterns (high confidence)
    let known_external = [
        "discord.com/api/webhooks",
        "api.telegram.org/bot",
        "pastebin.com",
        "ngrok",
        "trycloudflare",
        "raw.githubusercontent.com",
        "sendgrid",
        "mailgun",
        "webhook",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    if known_external {
        return true;
    }

    // Generic HTTP/HTTPS URLs that aren't known-safe registries or local endpoints
    (lower.starts_with("http://") || lower.starts_with("https://"))
        && !looks_like_registry_url(&edge.to)
        && !looks_like_local_endpoint(&lower)
}

fn looks_like_local_endpoint(lower: &str) -> bool {
    lower.contains("localhost")
        || lower.contains("127.0.0.1")
        || lower.contains("0.0.0.0")
        || lower.contains("::1")
        || lower.contains(".local")
        || lower.contains(".internal")
}

fn looks_like_registry_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "files.pythonhosted.org",
        "pypi.org/packages",
        "crates.io/api",
        "static.crates.io",
        "index.crates.io",
        "registry.hub.docker.com",
        "ghcr.io",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    capability: ArtifactCapability::SecretAccess,
                    source: crate::artifact_graph::ArtifactCapabilitySource::Observed,
                },
                crate::artifact_graph::ArtifactCapabilityFact {
                    capability: ArtifactCapability::NetworkAccess,
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
