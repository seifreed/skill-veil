use super::summarization::{sink_summary, source_summary};
use super::utils::{
    artifact_kind_for_node, artifact_paths, build_sibling_clusters, node_has_sink, node_has_source,
};
use super::ArtifactTaintRuleGroup;
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{EvidenceKind, Finding, MatchTarget};
use std::collections::BTreeSet;

pub(super) fn derive_per_node_taint_findings(
    graph: &ArtifactGraph,
    groups: &[ArtifactTaintRuleGroup],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for node_path in &artifact_paths(graph) {
        for group in groups {
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
                    Finding::builder(rule.id.clone(), rule.category)
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
                        .reason(rule.reason.clone())
                        .build(),
                );
            }
        }
    }
    findings
}

pub(super) fn derive_cross_node_taint_findings(
    graph: &ArtifactGraph,
    groups: &[ArtifactTaintRuleGroup],
) -> Vec<Finding> {
    // Cap per-cluster findings to avoid quadratic explosion when a parent
    // references many children that each expose sources and sinks.
    const MAX_CROSS_NODE_FINDINGS_PER_CLUSTER: usize = 50;
    let sibling_clusters = build_sibling_clusters(graph);
    // Divide budget across groups so every source-sink family gets representation,
    // even when a high-volume group would otherwise exhaust the entire budget.
    debug_assert!(
        groups.len() <= MAX_CROSS_NODE_FINDINGS_PER_CLUSTER,
        "Number of taint rule groups ({}) exceeds per-cluster budget ({}); each group will be capped to 1 finding",
        groups.len(),
        MAX_CROSS_NODE_FINDINGS_PER_CLUSTER
    );
    let per_group_budget = if groups.is_empty() {
        0
    } else {
        (MAX_CROSS_NODE_FINDINGS_PER_CLUSTER / groups.len()).max(1)
    };
    let mut findings = Vec::new();
    for cluster in &sibling_clusters {
        if cluster.len() < 2 {
            continue;
        }
        for group in groups {
            let source_nodes: Vec<&String> = cluster
                .iter()
                .filter(|path| node_has_source(graph, path, group.source))
                .collect();
            let sink_nodes: Vec<&String> = cluster
                .iter()
                .filter(|path| node_has_sink(graph, path, group.sink))
                .collect();
            let mut group_finding_count = 0_usize;
            'group: for source_node in &source_nodes {
                for sink_node in &sink_nodes {
                    if source_node == sink_node {
                        continue; // already covered by per-node pass
                    }
                    let src = source_summary(graph, source_node, group.source);
                    let snk = sink_summary(graph, sink_node, group.sink);
                    let kind = artifact_kind_for_node(graph, source_node);
                    for rule in &group.rules {
                        // Check budget *before* pushing each finding. Counting
                        // post-push allowed the last (source, sink) pair to
                        // emit `rules.len()` findings before breaking,
                        // exceeding the cap by `rules.len() - 1` per group.
                        if group_finding_count >= per_group_budget {
                            break 'group;
                        }
                        findings.push(
                            Finding::builder(rule.id.clone(), rule.category)
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
                                .reason(rule.reason.clone())
                                .build(),
                        );
                        group_finding_count += 1;
                    }
                }
            }
        }
    }
    findings
}

// Suppress the unused import warning — BTreeSet is used by build_sibling_clusters
// which returns Vec<BTreeSet<String>> but the type is inferred.
const _: () = {
    let _ = std::mem::size_of::<BTreeSet<String>>();
};
