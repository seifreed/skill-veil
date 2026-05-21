use super::patterns::{
    is_real_external_sink, looks_like_identity_target, looks_like_registry_url,
    looks_like_secret_target,
};
use super::trusted_hosts::is_documentation_or_reserved_host;
use super::utils::node_has_capability;
use super::{TaintSinkKind, TaintSourceKind};
use crate::artifact_graph::{
    ArtifactCapability, ArtifactEdge, ArtifactGraph, ArtifactRelation, EndpointKind,
};

/// Identify a `Downloads` edge that represents a real external fetch and
/// should be treated as a `RemoteDownload` taint source.
///
/// # Filter consistency contract
///
/// `node_has_source(_, _, RemoteDownload)` and `source_summary(_, _, RemoteDownload)`
/// MUST agree on which edges qualify. Previously the two sites filtered
/// differently — `node_has_source` excluded `endpoint_kind == Registry`
/// while `source_summary` only checked `looks_like_registry_url`. The
/// consequence was that `source_summary` could attribute a triggered
/// taint finding to a legitimate registry edge sitting earlier in the
/// edge list, polluting `match_value` with a registry URL instead of the
/// attacker-controlled one. This helper is the single source of truth.
pub(super) fn is_external_download_edge(edge: &ArtifactEdge) -> bool {
    matches!(edge.relation, ArtifactRelation::Downloads)
        && edge.endpoint_kind != Some(EndpointKind::Registry)
        && !looks_like_registry_url(&edge.to)
        && !is_documentation_or_reserved_host(&edge.to)
}

pub(super) fn source_summary(
    graph: &ArtifactGraph,
    node_path: &str,
    source: TaintSourceKind,
) -> String {
    match source {
        TaintSourceKind::SecretAccess => collect_matching_edges(
            graph,
            |edge| {
                edge.from == node_path
                    && (matches!(edge.relation, ArtifactRelation::AccessesSecrets)
                        || (matches!(edge.relation, ArtifactRelation::Reads)
                            && looks_like_secret_target(&edge.to)))
            },
            "secret_access",
        ),
        TaintSourceKind::RemoteDownload => collect_matching_edges(
            graph,
            |edge| edge.from == node_path && is_external_download_edge(edge),
            "remote_download",
        ),
        TaintSourceKind::FilesystemWrite => collect_matching_edges(
            graph,
            |edge| edge.from == node_path && matches!(edge.relation, ArtifactRelation::Writes),
            "filesystem_write",
        ),
        TaintSourceKind::IdentityAccess => collect_matching_edges(
            graph,
            |edge| {
                edge.from == node_path
                    && matches!(edge.relation, ArtifactRelation::Reads)
                    && looks_like_identity_target(&edge.to)
            },
            "identity_access",
        ),
    }
}

pub(super) fn sink_summary(graph: &ArtifactGraph, node_path: &str, sink: TaintSinkKind) -> String {
    match sink {
        TaintSinkKind::ExternalNetwork => collect_matching_edges(
            graph,
            |edge| {
                edge.from == node_path
                    && matches!(edge.relation, ArtifactRelation::ConnectsTo)
                    && is_real_external_sink(edge)
            },
            "external_network",
        ),
        TaintSinkKind::Execution => {
            let from_edges = collect_matching_edges_or_empty(graph, |edge| {
                edge.from == node_path && matches!(edge.relation, ArtifactRelation::Executes)
            });
            if !from_edges.is_empty() {
                return from_edges;
            }
            if node_has_capability(graph, node_path, ArtifactCapability::ProcessExecution) {
                "process_execution".to_string()
            } else if node_has_capability(graph, node_path, ArtifactCapability::InstallExecution) {
                "install_execution".to_string()
            } else {
                "execution".to_string()
            }
        }
        TaintSinkKind::Persistence => {
            let from_edges = collect_matching_edges_or_empty(graph, |edge| {
                edge.from == node_path && matches!(edge.relation, ArtifactRelation::Persists)
            });
            if !from_edges.is_empty() {
                return from_edges;
            }
            if node_has_capability(graph, node_path, ArtifactCapability::PersistenceSurface) {
                "persistence_surface".to_string()
            } else {
                "persistence".to_string()
            }
        }
    }
}

/// Collect all edges matching a predicate, join their targets with ", ".
/// Returns the fallback string when no edges match, preserving the old
/// single-edge behavior for the common case of one match.
fn collect_matching_edges(
    graph: &ArtifactGraph,
    predicate: impl Fn(&ArtifactEdge) -> bool,
    fallback: &str,
) -> String {
    let targets: Vec<&str> = graph
        .edges
        .iter()
        .filter(|edge| predicate(edge))
        .map(|edge| edge.to.as_str())
        .collect();
    if targets.is_empty() {
        fallback.to_string()
    } else if targets.len() == 1 {
        targets[0].to_string()
    } else {
        targets.join(", ")
    }
}

fn collect_matching_edges_or_empty(
    graph: &ArtifactGraph,
    predicate: impl Fn(&ArtifactEdge) -> bool,
) -> String {
    let targets: Vec<&str> = graph
        .edges
        .iter()
        .filter(|edge| predicate(edge))
        .map(|edge| edge.to.as_str())
        .collect();
    if targets.is_empty() {
        String::new()
    } else if targets.len() == 1 {
        targets[0].to_string()
    } else {
        targets.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_graph::{ArtifactEdge, ArtifactNode};
    use crate::findings::ArtifactKind;

    fn graph_with_download_edges() -> ArtifactGraph {
        let mut g = ArtifactGraph::new();
        g.nodes.push(ArtifactNode {
            path: "node_a".to_string(),
            kind: ArtifactKind::ReferencedArtifact,
            capabilities: Vec::new(),
        });
        // First (in iteration order): registry endpoint that LOOKS like a
        // generic URL — would slip past `looks_like_registry_url` alone.
        g.edges.push(ArtifactEdge {
            from: "node_a".to_string(),
            to: "https://corp-registry.example/pkg/installer".to_string(),
            relation: ArtifactRelation::Downloads,
            endpoint_kind: Some(EndpointKind::Registry),
        });
        // Second: actually-malicious external download.
        g.edges.push(ArtifactEdge {
            from: "node_a".to_string(),
            to: "https://attacker-controlled.io/payload.sh".to_string(),
            relation: ArtifactRelation::Downloads,
            endpoint_kind: None,
        });
        g.edges.push(ArtifactEdge {
            from: "node_a".to_string(),
            to: "https://example.com/payload.sh".to_string(),
            relation: ArtifactRelation::Downloads,
            endpoint_kind: None,
        });
        g
    }

    /// Contract: `source_summary(RemoteDownload)` MUST skip
    /// `endpoint_kind == Registry` edges, matching `node_has_source`.
    /// Otherwise the registry edge is reported as the taint source even
    /// though it is the malicious second edge that triggered the finding.
    #[test]
    fn source_summary_skips_registry_endpoint_when_choosing_match_value() {
        let graph = graph_with_download_edges();
        let summary = source_summary(&graph, "node_a", TaintSourceKind::RemoteDownload);
        assert_eq!(
            summary, "https://attacker-controlled.io/payload.sh",
            "RemoteDownload summary must use the real external edge"
        );
    }

    #[test]
    fn is_external_download_edge_filters_registry_and_documentation_endpoints() {
        let graph = graph_with_download_edges();
        let registry = &graph.edges[0];
        let external = &graph.edges[1];
        let documentation = &graph.edges[2];
        assert!(!is_external_download_edge(registry));
        assert!(is_external_download_edge(external));
        assert!(!is_external_download_edge(documentation));
    }
}
