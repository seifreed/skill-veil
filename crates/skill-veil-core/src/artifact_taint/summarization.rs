use super::patterns::{
    looks_like_external_sink, looks_like_identity_target, looks_like_registry_url,
    looks_like_secret_target,
};
use super::utils::node_has_capability;
use super::{TaintSinkKind, TaintSourceKind};
use crate::artifact_graph::{ArtifactCapability, ArtifactGraph, ArtifactRelation};

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
            .find(|edge| {
                edge.from == node_path
                    && matches!(edge.relation, ArtifactRelation::Downloads)
                    && !looks_like_registry_url(&edge.to)
            })
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
