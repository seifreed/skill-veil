use super::patterns::{
    looks_like_external_sink, looks_like_identity_target, looks_like_secret_target,
};
use super::trusted_hosts::{is_documentation_or_reserved_host, is_trusted_api_host};
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

/// `true` if `node_path` has at least one external-network sink AND
/// every such sink resolves to a host on the trusted-API allowlist.
///
/// # Why
///
/// `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK` and
/// `ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK` legitimately fire on
/// every benign skill that integrates with an upstream API: the
/// skill reads `<API>_KEY` from env (source) and posts to that
/// upstream API (sink). The cross-LLM triage on a 4000-skill
/// VT-clean corpus showed this pair contributes ~272 of ~449
/// consensus FPs. When EVERY external sink for the node is a
/// well-known API host, the calling code downgrades the rule's
/// emitted finding from `block` / `MaliciousBehavior` to
/// `require_approval` / `ReviewSignal` rather than suppressing it
/// outright.
///
/// Returns `false` when no external-network sink is present (so
/// callers get a clean "downgrade does not apply" signal) AND when
/// at least one sink is untrusted (the operator-relevant case).
pub(super) fn all_external_sinks_trusted(graph: &ArtifactGraph, node_path: &str) -> bool {
    let mut saw_real_external = false;
    for edge in &graph.edges {
        if edge.from != node_path {
            continue;
        }
        if !matches!(edge.relation, ArtifactRelation::ConnectsTo) {
            continue;
        }
        if !looks_like_external_sink(edge) {
            continue;
        }
        // Documentation / RFC2606-reserved / loopback hosts are not
        // real exfil sinks — strip them before deciding whether the
        // remaining real sinks are all trusted. Without this strip
        // a single `https://example.com/...` reference in skill prose
        // (or a `http://localhost:8080` self-talk URL) defeats the
        // downgrade and the exfil rule fires at full strength.
        if is_documentation_or_reserved_host(&edge.to) {
            continue;
        }
        saw_real_external = true;
        if !is_trusted_api_host(&edge.to) {
            return false;
        }
    }
    saw_real_external
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
///
/// Uses a union-find approach so transitive overlaps are correctly
/// merged: if cluster A overlaps B and B overlaps C, all three end up
/// in one cluster regardless of processing order. Pre-fix the greedy
/// single-pass merge only merged into the first overlapping cluster,
/// so A-C transitivity via B could be lost if B was processed after A
/// and C were checked.
fn merge_overlapping_clusters(clusters: Vec<BTreeSet<String>>) -> Vec<BTreeSet<String>> {
    if clusters.is_empty() {
        return Vec::new();
    }

    // Collect all unique nodes and assign each an index.
    let mut node_index: BTreeMap<String, usize> = BTreeMap::new();
    for cluster in &clusters {
        for node in cluster {
            if !node_index.contains_key(node) {
                let idx = node_index.len();
                node_index.insert(node.clone(), idx);
            }
        }
    }

    let n = node_index.len();
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]]; // path compression
            i = parent[i];
        }
        i
    }

    fn union(parent: &mut [usize], a: usize, b: usize) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent[ra] = rb;
        }
    }

    // Union all nodes within each cluster.
    for cluster in &clusters {
        let mut iter = cluster.iter();
        let first = iter.next();
        if let Some(first_node) = first {
            let first_idx = node_index[first_node];
            for node in iter {
                union(&mut parent, first_idx, node_index[node]);
            }
        }
    }

    // Collect clusters by root.
    let mut root_to_set: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    for (node, idx) in &node_index {
        let root = find(&mut parent, *idx);
        root_to_set.entry(root).or_default().insert(node.clone());
    }

    root_to_set.into_values().collect()
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

    /// # Contract
    ///
    /// `merge_overlapping_clusters` MUST merge transitively connected
    /// clusters. If cluster {A,B} overlaps with {B,C} (via B), and {B,C}
    /// overlaps with {C,D} (via C), all four nodes must end up in one
    /// cluster. Pre-fix the greedy single-pass merge only merged into the
    /// first overlapping cluster, so transitivity was order-dependent:
    /// processing A and C before B left {A,B} and {C,D} separate when
    /// B bridges them both.
    #[test]
    fn merge_overlapping_clusters_merges_transitively() {
        let c1: BTreeSet<String> = ["a".to_string(), "b".to_string()].into_iter().collect();
        let c2: BTreeSet<String> = ["c".to_string(), "d".to_string()].into_iter().collect();
        let c3: BTreeSet<String> = ["b".to_string(), "c".to_string()].into_iter().collect();
        let merged = merge_overlapping_clusters(vec![c1, c2, c3]);
        assert_eq!(
            merged.len(),
            1,
            "transitively connected clusters must merge into one; got {merged:?}"
        );
        assert!(
            merged[0].contains("a") && merged[0].contains("d"),
            "all transitively connected nodes must be in the merged cluster; got {:?}",
            merged[0]
        );
    }

    /// # Contract
    ///
    /// Disjoint clusters (no shared nodes) MUST NOT be merged.
    #[test]
    fn merge_overlapping_clusters_preserves_disjoint() {
        let c1: BTreeSet<String> = ["a".to_string(), "b".to_string()].into_iter().collect();
        let c2: BTreeSet<String> = ["c".to_string(), "d".to_string()].into_iter().collect();
        let merged = merge_overlapping_clusters(vec![c1, c2]);
        assert_eq!(
            merged.len(),
            2,
            "disjoint clusters must not merge; got {merged:?}"
        );
    }
}
