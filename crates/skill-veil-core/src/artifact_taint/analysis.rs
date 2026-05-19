use super::summarization::{sink_summary, source_summary};
use super::utils::{
    all_external_sinks_first_party_or_trusted, artifact_kind_for_node, artifact_paths,
    build_sibling_clusters, node_has_sink, node_has_source,
};
use super::{ArtifactTaintRule, ArtifactTaintRuleGroup, TaintSinkKind, TaintSourceKind};
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{EvidenceKind, Finding, MatchTarget, RecommendedAction, SignalClass};
use std::collections::BTreeSet;

/// Rule IDs whose finding emission opts in to the external-sink
/// downgrade. When EVERY real external sink for the tainted node is
/// either on `trusted_hosts::TRUSTED_API_HOSTS` or first-party to a
/// credential the same node reads (see
/// `all_external_sinks_first_party_or_trusted`), the finding is
/// emitted with `RecommendedAction::RequireApproval` instead of
/// `Block` and `SignalClass::ReviewSignal` instead of the rule's
/// natural `MaliciousBehavior`. The signal stays visible for analyst
/// triage but no longer auto-blocks at the verdict layer.
///
/// Limited to the SECRET- and IDENTITY-flavoured external-network
/// rules because cross-LLM triage on a 4000-skill VT-clean corpus
/// showed those two are the dominant FP contributors among taint
/// rules. Other taint rules (download→exec, write→persistence)
/// have different FP profiles and remain at full strength.
const TRUSTED_HOST_DOWNGRADE_RULE_IDS: &[&str] = &[
    "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
    "ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK",
];

fn rule_opts_into_trusted_host_downgrade(rule: &ArtifactTaintRule) -> bool {
    TRUSTED_HOST_DOWNGRADE_RULE_IDS.contains(&rule.id.as_str())
}

/// Build a finding for a single (rule, node) pair, applying the
/// trusted-API-host downgrade when applicable. Centralised so the
/// per-node and cross-node loops use identical emission semantics —
/// pre-fix the per-node path applied the downgrade but the
/// cross-node path emitted the un-downgraded finding, leaving the
/// dominant FP rule firing at full strength on monorepo packages.
///
/// `confidence_multiplier` lets the cross-node call site keep its
/// historical 0.9× attenuation (cross-node taint is weaker evidence
/// than per-node taint) without forking a second helper.
fn build_taint_finding(
    rule: &ArtifactTaintRule,
    node_path: &str,
    src: &str,
    snk: &str,
    kind: crate::findings::ArtifactKind,
    apply_downgrade: bool,
    confidence_multiplier: f32,
) -> Finding {
    let mut action = rule.action;
    let mut signal_class_override: Option<SignalClass> = None;
    let mut reason = rule.reason.clone();
    let mut sink_note = String::new();

    if apply_downgrade && rule_opts_into_trusted_host_downgrade(rule) {
        // Downgrade: keep the signal visible but stop auto-blocking
        // verdicts driven by the API-client benign pattern.
        action = match action {
            RecommendedAction::Block => RecommendedAction::RequireApproval,
            other => other,
        };
        signal_class_override = Some(SignalClass::ReviewSignal);
        reason.push_str(
            " (downgraded: every external sink is a trusted-API host or first-party to a credential the artifact reads)",
        );
        sink_note = " sinks_trusted=true".to_string();
    }

    let mut builder = Finding::builder(rule.id.clone(), rule.category)
        .severity(rule.severity)
        .confidence(rule.confidence * confidence_multiplier)
        .action(action)
        .evidence_kind(EvidenceKind::Behavior)
        .artifact(kind, Some(node_path.to_string()))
        .matched_on(MatchTarget::ReferencedFile {
            path: node_path.to_string(),
        })
        .match_value(format!(
            "family={} source={} sink={}{}",
            rule.family, src, snk, sink_note,
        ))
        .reason(reason);
    if let Some(sc) = signal_class_override {
        builder = builder.signal_class(sc);
    }
    builder.build()
}

pub(super) fn derive_per_node_taint_findings(
    graph: &ArtifactGraph,
    groups: &[ArtifactTaintRuleGroup],
    suppress_downgrade: bool,
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
            // Cache the trusted-sink predicate per (node, group) since
            // the inner rule loop re-emits findings under the same
            // sink. The check is also a no-op for non-external sinks
            // because `all_external_sinks_first_party_or_trusted` returns false when
            // the node has no external sink at all.
            // Downgrade applies only when the sinks are
            // trusted/first-party AND the package shows no independent
            // malice — `suppress_downgrade` falsifies the
            // benign-integration premise (see `has_independent_malice`).
            let apply_downgrade = !suppress_downgrade
                && matches!(group.sink, TaintSinkKind::ExternalNetwork)
                && matches!(
                    group.source,
                    TaintSourceKind::SecretAccess | TaintSourceKind::IdentityAccess,
                )
                && all_external_sinks_first_party_or_trusted(graph, node_path);
            for rule in &group.rules {
                findings.push(build_taint_finding(
                    rule,
                    node_path,
                    &src,
                    &snk,
                    kind,
                    apply_downgrade,
                    /*confidence_multiplier=*/ 1.0,
                ));
            }
        }
    }
    findings
}

pub(super) fn derive_cross_node_taint_findings(
    graph: &ArtifactGraph,
    groups: &[ArtifactTaintRuleGroup],
    suppress_downgrade: bool,
) -> Vec<Finding> {
    // Cap per-cluster findings to avoid quadratic explosion when a parent
    // references many children that each expose sources and sinks.
    const MAX_CROSS_NODE_FINDINGS_PER_CLUSTER: usize = 50;
    // Global cap across all clusters: without this, `per_group_budget * N
    // sibling_clusters` can far exceed the per-cluster constant. Monorepo-style
    // packages with many parent-child relationships are the typical trigger.
    const MAX_CROSS_NODE_FINDINGS_TOTAL: usize = 100;
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
        if findings.len() >= MAX_CROSS_NODE_FINDINGS_TOTAL {
            break;
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
                    // The trusted-host downgrade is keyed on the SINK
                    // node since that is where the external-network
                    // edges live. Apply the same gating as the
                    // per-node pass so a single rule cannot fire at
                    // full strength via the cross-node path while
                    // being downgraded via the per-node path.
                    let apply_downgrade = !suppress_downgrade
                        && matches!(group.sink, TaintSinkKind::ExternalNetwork)
                        && matches!(
                            group.source,
                            TaintSourceKind::SecretAccess | TaintSourceKind::IdentityAccess,
                        )
                        && all_external_sinks_first_party_or_trusted(graph, sink_node);
                    for rule in &group.rules {
                        // Check budgets *before* pushing each finding.
                        // Per-group budget prevents a single group from
                        // monopolising the cluster budget. Global total
                        // cap prevents `per_group_budget * N clusters`
                        // from exceeding the intended ceiling.
                        if findings.len() >= MAX_CROSS_NODE_FINDINGS_TOTAL {
                            break 'group;
                        }
                        if group_finding_count >= per_group_budget {
                            break 'group;
                        }
                        // `artifact_path` and `matched_on` BOTH point at the
                        // source node. Pre-fix the artifact was attributed to
                        // the source while `matched_on` pointed at the sink,
                        // so a single finding referenced two distinct files —
                        // confusing for auditors and breaking suppression
                        // path-matching (which keys on `artifact_path`). The
                        // source/sink relationship is preserved verbatim in
                        // `match_value` (`source={src} sink={snk}`).
                        findings.push(build_taint_finding(
                            rule,
                            source_node,
                            &src,
                            &snk,
                            kind,
                            apply_downgrade,
                            /*confidence_multiplier=*/ 0.9,
                        ));
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
