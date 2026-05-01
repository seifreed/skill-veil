use super::patterns::{
    looks_like_external_sink, looks_like_identity_target, looks_like_secret_target,
};
use super::{TaintSinkKind, TaintSourceKind};
use crate::artifact_graph::{ArtifactCapability, ArtifactGraph, ArtifactRelation};
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
            edge.from == node_path && super::summarization::is_external_download_edge(edge)
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

/// `true` for edge relations that establish a parent → child structural
/// link strong enough that taint can propagate across the boundary. Pre-fix
/// only `References` and `Contains` formed clusters; `Loads` and `Mounts`
/// were silently excluded, so a `skill.md --Loads--> plugin.wasm
/// --ConnectsTo--> attacker` chain produced no cross-node taint finding
/// even though the parent had `SecretAccess`. Both relations describe a
/// runtime dependency the parent pulled in deliberately, so the parent's
/// secrets are reachable from the child's network sinks.
fn relation_forms_sibling_cluster(relation: ArtifactRelation) -> bool {
    matches!(
        relation,
        ArtifactRelation::References
            | ArtifactRelation::Contains
            | ArtifactRelation::Loads
            | ArtifactRelation::Mounts
    )
}

pub(super) fn build_sibling_clusters(graph: &ArtifactGraph) -> Vec<BTreeSet<String>> {
    let mut parent_to_cluster: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for edge in &graph.edges {
        if relation_forms_sibling_cluster(edge.relation) {
            let cluster = parent_to_cluster.entry(edge.from.clone()).or_default();
            // Include the parent so parent→child taint paths are detected.
            // The cross-node loop skips source_node == sink_node, so
            // per-node findings are not double-counted.
            cluster.insert(edge.from.clone());
            cluster.insert(edge.to.clone());
        }
    }
    // Deduplicate overlapping clusters: when two clusters share nodes,
    // merge them so that cross-node taint findings have consistent
    // attribution. Without this, the same source-sink pair could produce
    // findings with different `artifact_path` values depending on which
    // cluster produced them.
    let clusters = parent_to_cluster.into_values().collect::<Vec<_>>();
    merge_overlapping_clusters(clusters)
}

/// Merge clusters that share any node. Two clusters {A,B,C} and {C,D}
/// both contain C, so taint findings for (B,C) and (C,D) should share
/// a single cluster {A,B,C,D} with consistent attribution.
fn merge_overlapping_clusters(mut clusters: Vec<BTreeSet<String>>) -> Vec<BTreeSet<String>> {
    if clusters.is_empty() {
        return clusters;
    }
    // Sort by size descending so larger clusters absorb smaller ones.
    clusters.sort_by_key(|b| std::cmp::Reverse(b.len()));
    let mut merged: Vec<BTreeSet<String>> = Vec::new();
    for cluster in clusters {
        let mut found_overlap = false;
        for existing in &mut merged {
            if !existing.is_disjoint(&cluster) {
                existing.extend(cluster.iter().cloned());
                found_overlap = true;
                break;
            }
        }
        if !found_overlap {
            merged.push(cluster);
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_graph::{ArtifactEdge, ArtifactNode, ArtifactRelation};
    use crate::findings::ArtifactKind;

    fn node(path: &str) -> ArtifactNode {
        ArtifactNode {
            path: path.to_string(),
            kind: ArtifactKind::GenericArtifact,
            capabilities: Vec::new(),
        }
    }

    fn edge(from: &str, to: &str, relation: ArtifactRelation) -> ArtifactEdge {
        ArtifactEdge {
            from: from.to_string(),
            to: to.to_string(),
            relation,
            endpoint_kind: None,
        }
    }

    /// # Contract
    ///
    /// `Loads` and `Mounts` MUST form sibling clusters alongside
    /// `References` and `Contains`. Pre-fix only the latter two
    /// participated, leaving the parent → loaded-plugin path off the
    /// taint engine's radar so a `skill.md --Loads--> plugin.wasm`
    /// chain never tainted the plugin from the parent's secrets.
    #[test]
    fn build_sibling_clusters_includes_loads_and_mounts() {
        let graph = ArtifactGraph {
            nodes: vec![node("skill.md"), node("plugin.wasm"), node("vol")],
            edges: vec![
                edge("skill.md", "plugin.wasm", ArtifactRelation::Loads),
                edge("skill.md", "vol", ArtifactRelation::Mounts),
            ],
        };
        let clusters = build_sibling_clusters(&graph);
        assert!(
            clusters
                .iter()
                .any(|c| c.contains("skill.md") && c.contains("plugin.wasm")),
            "Loads edge must form a cluster; got {clusters:?}"
        );
        assert!(
            clusters
                .iter()
                .any(|c| c.contains("skill.md") && c.contains("vol")),
            "Mounts edge must form a cluster; got {clusters:?}"
        );
    }

    /// # Contract (negative)
    ///
    /// Edge relations that do NOT establish a parent→child structural
    /// link — e.g. `ConnectsTo`, `Reads`, `Writes` — MUST NOT form
    /// sibling clusters; clustering them would produce spurious
    /// cross-node taint findings. Pins the membership of the
    /// `relation_forms_sibling_cluster` helper.
    #[test]
    fn build_sibling_clusters_excludes_non_structural_edges() {
        let graph = ArtifactGraph {
            nodes: vec![node("a"), node("b")],
            edges: vec![
                edge("a", "b", ArtifactRelation::ConnectsTo),
                edge("a", "b", ArtifactRelation::Reads),
                edge("a", "b", ArtifactRelation::Writes),
            ],
        };
        let clusters = build_sibling_clusters(&graph);
        assert!(
            clusters.is_empty(),
            "non-structural edges must NOT form clusters; got {clusters:?}"
        );
    }
}
