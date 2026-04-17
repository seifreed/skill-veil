use super::patterns::{
    looks_like_external_sink, looks_like_identity_target, looks_like_registry_url,
    looks_like_secret_target,
};
use super::{TaintSinkKind, TaintSourceKind};
use crate::artifact_graph::{ArtifactCapability, ArtifactGraph, ArtifactRelation, EndpointKind};
use crate::findings::ArtifactKind;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn artifact_paths(graph: &ArtifactGraph) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for node in &graph.nodes {
        paths.insert(node.path.clone());
    }
    paths.into_iter().collect()
}

pub(super) fn artifact_kind_for_node(graph: &ArtifactGraph, path: &str) -> ArtifactKind {
    graph
        .nodes
        .iter()
        .find(|node| node.path == path)
        .map(|node| node.kind)
        .unwrap_or(ArtifactKind::GenericArtifact)
}

pub(super) fn node_has_capability(
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

pub(super) fn node_has_source(
    graph: &ArtifactGraph,
    node_path: &str,
    source: TaintSourceKind,
) -> bool {
    match source {
        TaintSourceKind::SecretAccess => {
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
        TaintSourceKind::RemoteDownload => graph.edges.iter().any(|edge| {
            edge.from == node_path
                && matches!(edge.relation, ArtifactRelation::Downloads)
                && edge.endpoint_kind != Some(EndpointKind::Registry)
                && !looks_like_registry_url(&edge.to)
        }),
        TaintSourceKind::FilesystemWrite => {
            node_has_capability(graph, node_path, ArtifactCapability::FilesystemWrite)
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path && matches!(edge.relation, ArtifactRelation::Writes)
                })
        }
        TaintSourceKind::IdentityAccess => {
            node_has_capability(graph, node_path, ArtifactCapability::IdentityAccess)
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path
                        && matches!(edge.relation, ArtifactRelation::Reads)
                        && looks_like_identity_target(&edge.to)
                })
        }
    }
}

pub(super) fn node_has_sink(graph: &ArtifactGraph, node_path: &str, sink: TaintSinkKind) -> bool {
    match sink {
        TaintSinkKind::ExternalNetwork => graph.edges.iter().any(|edge| {
            edge.from == node_path
                && matches!(edge.relation, ArtifactRelation::ConnectsTo)
                && looks_like_external_sink(edge)
        }),
        TaintSinkKind::Execution => {
            node_has_capability(graph, node_path, ArtifactCapability::ProcessExecution)
                || node_has_capability(graph, node_path, ArtifactCapability::InstallExecution)
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path && matches!(edge.relation, ArtifactRelation::Executes)
                })
        }
        TaintSinkKind::Persistence => {
            node_has_capability(graph, node_path, ArtifactCapability::PersistenceSurface)
                || graph.edges.iter().any(|edge| {
                    edge.from == node_path && matches!(edge.relation, ArtifactRelation::Persists)
                })
        }
    }
}

pub(super) fn build_sibling_clusters(graph: &ArtifactGraph) -> Vec<BTreeSet<String>> {
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
