use super::patterns::{
    looks_like_external_sink, looks_like_identity_target, looks_like_registry_url,
    looks_like_secret_target,
};
use super::utils::node_has_capability;
use super::{TaintSinkKind, TaintSourceKind};
use crate::artifact_graph::{
    ArtifactCapability, ArtifactEdge, ArtifactGraph, ArtifactRelation, EndpointKind,
};

/// Identify a `Downloads` edge that represents an EXTERNAL (non-registry)
/// fetch and should be treated as a `RemoteDownload` taint source.
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
}

pub(super) fn source_summary(
    graph: &ArtifactGraph,
    node_path: &str,
    source: TaintSourceKind,
) -> String {
    match source {
        TaintSourceKind::SecretAccess => graph
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
        TaintSourceKind::RemoteDownload => graph
            .edges
            .iter()
            .find(|edge| edge.from == node_path && is_external_download_edge(edge))
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "remote_download".to_string()),
        TaintSourceKind::FilesystemWrite => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path && matches!(edge.relation, ArtifactRelation::Writes)
            })
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "filesystem_write".to_string()),
        TaintSourceKind::IdentityAccess => graph
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

pub(super) fn sink_summary(graph: &ArtifactGraph, node_path: &str, sink: TaintSinkKind) -> String {
    match sink {
        TaintSinkKind::ExternalNetwork => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path
                    && matches!(edge.relation, ArtifactRelation::ConnectsTo)
                    && looks_like_external_sink(edge)
            })
            .map(|edge| edge.to.clone())
            .unwrap_or_else(|| "external_network".to_string()),
        TaintSinkKind::Execution => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path && matches!(edge.relation, ArtifactRelation::Executes)
            })
            .map(|edge| edge.to.clone())
            .or_else(|| {
                if node_has_capability(graph, node_path, ArtifactCapability::ProcessExecution) {
                    Some("process_execution".to_string())
                } else if node_has_capability(
                    graph,
                    node_path,
                    ArtifactCapability::InstallExecution,
                ) {
                    Some("install_execution".to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "execution".to_string()),
        TaintSinkKind::Persistence => graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == node_path && matches!(edge.relation, ArtifactRelation::Persists)
            })
            .map(|edge| edge.to.clone())
            .or_else(|| {
                if node_has_capability(graph, node_path, ArtifactCapability::PersistenceSurface) {
                    Some("persistence_surface".to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "persistence".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_graph::{ArtifactEdge, ArtifactNode};
    use crate::findings::ArtifactKind;

    fn graph_with_two_download_edges() -> ArtifactGraph {
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
            to: "https://attacker.example/payload.sh".to_string(),
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
        let graph = graph_with_two_download_edges();
        let summary = source_summary(&graph, "node_a", TaintSourceKind::RemoteDownload);
        assert_eq!(
            summary, "https://attacker.example/payload.sh",
            "RemoteDownload summary must use the external (non-registry) edge"
        );
    }

    #[test]
    fn is_external_download_edge_filters_registry_endpoint() {
        let graph = graph_with_two_download_edges();
        let registry = &graph.edges[0];
        let external = &graph.edges[1];
        assert!(!is_external_download_edge(registry));
        assert!(is_external_download_edge(external));
    }
}
