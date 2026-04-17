use super::{
    Finding, RecommendedAction, Severity, ThreatCategory, CAPABILITY_COMBO_WEIGHT_BROWSER_IDENTITY,
    CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY, CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK,
    CAPABILITY_COMBO_WEIGHT_PERSISTENCE_NETWORK, CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST,
    CAPABILITY_COMBO_WEIGHT_SECRET_NETWORK, CAPABILITY_WEIGHT_BROWSER_ACCESS,
    CAPABILITY_WEIGHT_EXPOSES_BINARY, CAPABILITY_WEIGHT_FILESYSTEM_WRITE,
    CAPABILITY_WEIGHT_HOST_FILESYSTEM_ACCESS, CAPABILITY_WEIGHT_IDENTITY_ACCESS,
    CAPABILITY_WEIGHT_INBOUND_SURFACE, CAPABILITY_WEIGHT_INSTALL_EXECUTION,
    CAPABILITY_WEIGHT_NETWORK_ACCESS, CAPABILITY_WEIGHT_PERSISTENCE_SURFACE,
    CAPABILITY_WEIGHT_PRIVILEGED_RUNTIME, CAPABILITY_WEIGHT_PROCESS_EXECUTION,
    CAPABILITY_WEIGHT_SECRET_ACCESS, RISK_THRESHOLD_APPROVAL, RISK_THRESHOLD_BLOCK,
};
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilitySource, ArtifactGraph};
use serde::{Deserialize, Serialize};

/// Summary of all findings for a skill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    /// Total number of findings
    pub total_findings: usize,
    /// Breakdown by severity
    pub by_severity: SeverityCounts,
    /// Breakdown by category
    pub by_category: Vec<(ThreatCategory, usize)>,
    /// Overall risk score (0-100)
    pub risk_score: u32,
    /// Recommended action based on score
    pub recommended_action: RecommendedAction,
    /// Explainable score factors that contributed to the risk score
    pub score_breakdown: Vec<RiskFactor>,
    /// Contextual triggers that forced or escalated the recommended action.
    pub action_triggers: Vec<ActionTrigger>,
}

/// Count of findings by severity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

/// Explainable score factor aggregated across findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor: String,
    pub contribution: u32,
    pub rationale: String,
}

/// Explicit contextual reason that escalated enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTrigger {
    pub action: RecommendedAction,
    pub factor: String,
    pub rationale: String,
}

impl FindingSummary {
    /// Calculate summary from a list of findings
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self::from_findings_and_graph(findings, &ArtifactGraph::new())
    }

    /// Calculate summary from findings plus graph-derived contextual risk.
    #[must_use]
    pub fn from_findings_and_graph(findings: &[Finding], artifact_graph: &ArtifactGraph) -> Self {
        let mut by_severity = SeverityCounts::default();
        let mut category_map = std::collections::HashMap::new();
        let mut factor_map = std::collections::HashMap::<String, RiskFactor>::new();

        let mut total_score: f32 = 0.0;

        for finding in findings {
            match finding.severity {
                Severity::Low => by_severity.low += 1,
                Severity::Medium => by_severity.medium += 1,
                Severity::High => by_severity.high += 1,
                Severity::Critical => by_severity.critical += 1,
            }

            *category_map.entry(finding.category).or_insert(0) += 1;
            total_score += finding.weighted_score();

            let evidence_factor = format!("evidence:{}", finding.evidence_kind);
            let evidence_weight = finding.evidence_kind.weight();
            factor_map
                .entry(evidence_factor.clone())
                .and_modify(|factor| factor.contribution += evidence_weight)
                .or_insert(RiskFactor {
                    factor: evidence_factor,
                    contribution: evidence_weight,
                    rationale: finding.evidence_kind.description().to_string(),
                });

            let artifact_factor = format!("artifact:{}", finding.artifact_kind);
            factor_map
                .entry(artifact_factor.clone())
                .and_modify(|factor| factor.contribution += 1)
                .or_insert(RiskFactor {
                    factor: artifact_factor,
                    contribution: 1,
                    rationale: "Risk observed in this artifact class".to_string(),
                });
        }

        let (graph_score, graph_action, graph_factors, mut action_triggers) =
            graph_risk_context(artifact_graph);
        total_score += graph_score as f32;

        for factor in graph_factors {
            factor_map
                .entry(factor.factor.clone())
                .and_modify(|existing| existing.contribution += factor.contribution)
                .or_insert(factor);
        }

        let risk_score = if total_score.is_finite() {
            total_score.clamp(0.0, 100.0).round() as u32
        } else {
            100 // treat non-finite as max risk
        };

        let score_based_action = if risk_score >= RISK_THRESHOLD_BLOCK {
            RecommendedAction::Block
        } else if risk_score >= RISK_THRESHOLD_APPROVAL {
            RecommendedAction::RequireApproval
        } else {
            RecommendedAction::Log
        };

        let finding_based_action = findings
            .iter()
            .fold(RecommendedAction::Log, |current, finding| {
                current.max(finding.recommended_action)
            });
        let recommended_action = score_based_action
            .max(finding_based_action)
            .max(graph_action);

        let mut by_category: Vec<_> = category_map.into_iter().collect();
        by_category.sort_by_key(|(category, _)| *category);
        let mut score_breakdown: Vec<_> = factor_map.into_values().collect();
        score_breakdown.sort_by(|left, right| right.contribution.cmp(&left.contribution));

        Self {
            total_findings: findings.len(),
            by_severity,
            by_category,
            risk_score,
            recommended_action,
            score_breakdown,
            action_triggers: {
                action_triggers.sort_by(|left, right| right.action.cmp(&left.action));
                action_triggers
            },
        }
    }
}

/// Accumulates capability combination scores, risk factors, and action triggers.
struct CapabilityScoreAccumulator {
    scored_combos: std::collections::HashSet<&'static str>,
    total_score: u32,
    action: RecommendedAction,
    factors: Vec<RiskFactor>,
    triggers: Vec<ActionTrigger>,
}

impl CapabilityScoreAccumulator {
    fn new() -> Self {
        Self {
            scored_combos: std::collections::HashSet::new(),
            total_score: 0,
            action: RecommendedAction::Log,
            factors: Vec::new(),
            triggers: Vec::new(),
        }
    }

    fn score_combo(
        &mut self,
        key: &'static str,
        combo_action: RecommendedAction,
        weight: u32,
        factor_label: &str,
        combo_rationale: &str,
        trigger_rationale: &str,
    ) {
        self.action = self.action.max(combo_action);
        if self.scored_combos.insert(key) {
            self.total_score += weight;
            self.factors.push(RiskFactor {
                factor: factor_label.to_string(),
                contribution: weight,
                rationale: combo_rationale.to_string(),
            });
            self.triggers.push(ActionTrigger {
                action: combo_action,
                factor: factor_label.to_string(),
                rationale: trigger_rationale.to_string(),
            });
        }
    }

    fn into_parts(self) -> (u32, RecommendedAction, Vec<RiskFactor>, Vec<ActionTrigger>) {
        (self.total_score, self.action, self.factors, self.triggers)
    }
}

/// Detect and score capability combinations on a single artifact node.
fn detect_node_capability_combos(
    node: &crate::artifact_graph::ArtifactNode,
    acc: &mut CapabilityScoreAccumulator,
) {
    let has_cap = |cap: ArtifactCapability| -> bool {
        node.capabilities.iter().any(|fact| fact.capability == cap)
    };
    let has_privileged = has_cap(ArtifactCapability::PrivilegedRuntime);
    let has_host_fs = has_cap(ArtifactCapability::HostFilesystemAccess);
    let has_install = has_cap(ArtifactCapability::InstallExecution);
    let has_network = has_cap(ArtifactCapability::NetworkAccess);
    let has_binary = has_cap(ArtifactCapability::ExposesBinary);
    let has_secret_access = has_cap(ArtifactCapability::SecretAccess);
    let has_persistence = has_cap(ArtifactCapability::PersistenceSurface);
    let has_browser_access = has_cap(ArtifactCapability::BrowserAccess);
    let has_identity_access = has_cap(ArtifactCapability::IdentityAccess);

    if has_privileged && has_host_fs {
        acc.score_combo(
            "privileged_host_filesystem",
            RecommendedAction::Block,
            CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST,
            "capability_combo:privileged_host_filesystem",
            &format!(
                "Artifact combines privileged runtime with host filesystem access: {}",
                node.path
            ),
            &format!(
                "Block forced because {} combines privileged runtime with host filesystem access",
                node.path
            ),
        );
    }

    if has_install && has_network {
        acc.score_combo(
            "install_network",
            RecommendedAction::RequireApproval,
            CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK,
            "capability_combo:install_network",
            &format!(
                "Artifact combines install-time execution with network access: {}",
                node.path
            ),
            &format!(
                "Approval forced because {} combines install-time execution with network access",
                node.path
            ),
        );
    }

    if has_install && has_binary {
        acc.score_combo(
            "install_binary",
            RecommendedAction::RequireApproval,
            CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY,
            "capability_combo:install_binary",
            &format!(
                "Artifact combines install-time execution with exposed binaries: {}",
                node.path
            ),
            &format!(
                "Approval forced because {} combines install-time execution with exposed binaries",
                node.path
            ),
        );
    }

    if has_secret_access && has_network {
        acc.score_combo(
            "secret_access_network",
            RecommendedAction::RequireApproval,
            CAPABILITY_COMBO_WEIGHT_SECRET_NETWORK,
            "capability_combo:secret_access_network",
            &format!(
                "Artifact combines secret access with network connectivity: {}",
                node.path
            ),
            &format!(
                "Approval forced because {} combines secret access with network connectivity",
                node.path
            ),
        );
    }

    if has_persistence && has_network {
        acc.score_combo(
            "persistence_network",
            RecommendedAction::RequireApproval,
            CAPABILITY_COMBO_WEIGHT_PERSISTENCE_NETWORK,
            "capability_combo:persistence_network",
            &format!(
                "Artifact combines persistence with network connectivity: {}",
                node.path
            ),
            &format!(
                "Approval forced because {} combines persistence with network connectivity",
                node.path
            ),
        );
    }

    if has_browser_access && has_identity_access {
        acc.score_combo(
            "browser_identity_scope",
            RecommendedAction::RequireApproval,
            CAPABILITY_COMBO_WEIGHT_BROWSER_IDENTITY,
            "capability_combo:browser_identity_scope",
            &format!(
                "Artifact combines broad browser automation with identity-linked access: {}",
                node.path
            ),
            &format!(
                "Approval forced because {} combines broad browser automation with identity-linked access",
                node.path
            ),
        );
    }
}

fn graph_risk_context(
    artifact_graph: &ArtifactGraph,
) -> (u32, RecommendedAction, Vec<RiskFactor>, Vec<ActionTrigger>) {
    let mut acc = CapabilityScoreAccumulator::new();
    // Track scored capability types to avoid double-counting
    // the same capability across multiple nodes.
    let mut scored_capabilities = std::collections::HashSet::<String>::new();

    for node in &artifact_graph.nodes {
        for capability in &node.capabilities {
            let source_label = match capability.source {
                ArtifactCapabilitySource::Declared => "declared",
                ArtifactCapabilitySource::Observed => "observed",
            };
            let (factor, contribution, rationale) = match capability.capability {
                ArtifactCapability::InstallExecution => (
                    format!("capability:{source_label}:install_execution"),
                    CAPABILITY_WEIGHT_INSTALL_EXECUTION,
                    format!("Artifact can execute code during installation ({source_label})"),
                ),
                ArtifactCapability::BrowserAccess => (
                    format!("capability:{source_label}:browser_access"),
                    CAPABILITY_WEIGHT_BROWSER_ACCESS,
                    format!("Artifact requests broad browser automation access ({source_label})"),
                ),
                ArtifactCapability::NetworkAccess => (
                    format!("capability:{source_label}:network_access"),
                    CAPABILITY_WEIGHT_NETWORK_ACCESS,
                    format!("Artifact can expose or request network connectivity ({source_label})"),
                ),
                ArtifactCapability::ExposesBinary => (
                    format!("capability:{source_label}:exposes_binary"),
                    CAPABILITY_WEIGHT_EXPOSES_BINARY,
                    format!("Artifact exposes executable entrypoints ({source_label})"),
                ),
                ArtifactCapability::PrivilegedRuntime => (
                    format!("capability:{source_label}:privileged_runtime"),
                    CAPABILITY_WEIGHT_PRIVILEGED_RUNTIME,
                    format!("Artifact requests privileged runtime access ({source_label})"),
                ),
                ArtifactCapability::HostFilesystemAccess => (
                    format!("capability:{source_label}:host_filesystem_access"),
                    CAPABILITY_WEIGHT_HOST_FILESYSTEM_ACCESS,
                    format!("Artifact can access host filesystem paths ({source_label})"),
                ),
                ArtifactCapability::ProcessExecution => (
                    format!("capability:{source_label}:process_execution"),
                    CAPABILITY_WEIGHT_PROCESS_EXECUTION,
                    format!("Artifact can execute child processes ({source_label})"),
                ),
                ArtifactCapability::SecretAccess => (
                    format!("capability:{source_label}:secret_access"),
                    CAPABILITY_WEIGHT_SECRET_ACCESS,
                    format!("Artifact can access or expose secrets ({source_label})"),
                ),
                ArtifactCapability::PersistenceSurface => (
                    format!("capability:{source_label}:persistence_surface"),
                    CAPABILITY_WEIGHT_PERSISTENCE_SURFACE,
                    format!("Artifact can establish persistence ({source_label})"),
                ),
                ArtifactCapability::FilesystemWrite => (
                    format!("capability:{source_label}:filesystem_write"),
                    CAPABILITY_WEIGHT_FILESYSTEM_WRITE,
                    format!("Artifact can write to the filesystem ({source_label})"),
                ),
                ArtifactCapability::IdentityAccess => (
                    format!("capability:{source_label}:identity_access"),
                    CAPABILITY_WEIGHT_IDENTITY_ACCESS,
                    format!("Artifact requests access to OAuth or identity-linked resources ({source_label})"),
                ),
                ArtifactCapability::InboundNetworkSurface => (
                    format!("capability:{source_label}:inbound_network_surface"),
                    CAPABILITY_WEIGHT_INBOUND_SURFACE,
                    format!("Artifact exposes an inbound network or webhook surface ({source_label})"),
                ),
            };

            // Only count each capability type (by factor key) once across all nodes
            // to prevent score inflation from duplicate capabilities on multiple artifacts.
            if scored_capabilities.insert(factor.clone()) {
                acc.total_score += contribution;
                acc.factors.push(RiskFactor {
                    factor,
                    contribution,
                    rationale: format!("{rationale}: {}", node.path),
                });
            }
        }

        detect_node_capability_combos(node, &mut acc);
    }

    acc.into_parts()
}
