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
        let (by_severity, category_map, mut factor_map, findings_score) =
            aggregate_findings(findings);

        let (graph_score, graph_action, graph_factors, mut action_triggers) =
            graph_risk_context(artifact_graph);

        for factor in graph_factors {
            factor_map
                .entry(factor.factor.clone())
                .and_modify(|existing| existing.contribution += factor.contribution)
                .or_insert(factor);
        }

        let total_score = findings_score + graph_score as f32;
        let risk_score = normalize_score(total_score);
        let score_based_action = score_to_action(risk_score);
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
        action_triggers.sort_by(|left, right| right.action.cmp(&left.action));

        Self {
            total_findings: findings.len(),
            by_severity,
            by_category,
            risk_score,
            recommended_action,
            score_breakdown,
            action_triggers,
        }
    }
}

type FactorMap = std::collections::HashMap<String, RiskFactor>;
type CategoryMap = std::collections::HashMap<ThreatCategory, usize>;

fn aggregate_findings(findings: &[Finding]) -> (SeverityCounts, CategoryMap, FactorMap, f32) {
    let mut by_severity = SeverityCounts::default();
    let mut category_map = CategoryMap::new();
    let mut factor_map = FactorMap::new();
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
        accumulate_evidence_factor(&mut factor_map, finding);
        accumulate_artifact_factor(&mut factor_map, finding);
    }

    (by_severity, category_map, factor_map, total_score)
}

fn accumulate_evidence_factor(factors: &mut FactorMap, finding: &Finding) {
    let key = format!("evidence:{}", finding.evidence_kind);
    let weight = finding.evidence_kind.weight();
    factors
        .entry(key.clone())
        .and_modify(|f| f.contribution += weight)
        .or_insert(RiskFactor {
            factor: key,
            contribution: weight,
            rationale: finding.evidence_kind.description().to_string(),
        });
}

fn accumulate_artifact_factor(factors: &mut FactorMap, finding: &Finding) {
    let key = format!("artifact:{}", finding.artifact_kind);
    factors
        .entry(key.clone())
        .and_modify(|f| f.contribution += 1)
        .or_insert(RiskFactor {
            factor: key,
            contribution: 1,
            rationale: "Risk observed in this artifact class".to_string(),
        });
}

fn normalize_score(total: f32) -> u32 {
    if total.is_finite() {
        total.clamp(0.0, 100.0).round() as u32
    } else {
        100
    }
}

fn score_to_action(risk_score: u32) -> RecommendedAction {
    if risk_score >= RISK_THRESHOLD_BLOCK {
        RecommendedAction::Block
    } else if risk_score >= RISK_THRESHOLD_APPROVAL {
        RecommendedAction::RequireApproval
    } else {
        RecommendedAction::Log
    }
}

/// Accumulates capability combination scores, risk factors, and action triggers.
struct CapabilityScoreAccumulator {
    scored_combos: std::collections::HashSet<&'static str>,
    scored_capabilities: std::collections::HashSet<String>,
    total_score: u32,
    action: RecommendedAction,
    factors: Vec<RiskFactor>,
    triggers: Vec<ActionTrigger>,
}

impl CapabilityScoreAccumulator {
    fn new() -> Self {
        Self {
            scored_combos: std::collections::HashSet::new(),
            scored_capabilities: std::collections::HashSet::new(),
            total_score: 0,
            action: RecommendedAction::Log,
            factors: Vec::new(),
            triggers: Vec::new(),
        }
    }

    fn score_capability(&mut self, factor: String, contribution: u32, rationale: String) {
        if self.scored_capabilities.insert(factor.clone()) {
            self.total_score += contribution;
            self.factors.push(RiskFactor {
                factor,
                contribution,
                rationale,
            });
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

struct CapabilityComboSpec {
    key: &'static str,
    cap_a: ArtifactCapability,
    cap_b: ArtifactCapability,
    action: RecommendedAction,
    weight: u32,
    description: &'static str,
}

static CAPABILITY_COMBOS: &[CapabilityComboSpec] = &[
    CapabilityComboSpec {
        key: "privileged_host_filesystem",
        cap_a: ArtifactCapability::PrivilegedRuntime,
        cap_b: ArtifactCapability::HostFilesystemAccess,
        action: RecommendedAction::Block,
        weight: CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST,
        description: "privileged runtime with host filesystem access",
    },
    CapabilityComboSpec {
        key: "install_network",
        cap_a: ArtifactCapability::InstallExecution,
        cap_b: ArtifactCapability::NetworkAccess,
        action: RecommendedAction::RequireApproval,
        weight: CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK,
        description: "install-time execution with network access",
    },
    CapabilityComboSpec {
        key: "install_binary",
        cap_a: ArtifactCapability::InstallExecution,
        cap_b: ArtifactCapability::ExposesBinary,
        action: RecommendedAction::RequireApproval,
        weight: CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY,
        description: "install-time execution with exposed binaries",
    },
    CapabilityComboSpec {
        key: "secret_access_network",
        cap_a: ArtifactCapability::SecretAccess,
        cap_b: ArtifactCapability::NetworkAccess,
        action: RecommendedAction::RequireApproval,
        weight: CAPABILITY_COMBO_WEIGHT_SECRET_NETWORK,
        description: "secret access with network connectivity",
    },
    CapabilityComboSpec {
        key: "persistence_network",
        cap_a: ArtifactCapability::PersistenceSurface,
        cap_b: ArtifactCapability::NetworkAccess,
        action: RecommendedAction::RequireApproval,
        weight: CAPABILITY_COMBO_WEIGHT_PERSISTENCE_NETWORK,
        description: "persistence with network connectivity",
    },
    CapabilityComboSpec {
        key: "browser_identity_scope",
        cap_a: ArtifactCapability::BrowserAccess,
        cap_b: ArtifactCapability::IdentityAccess,
        action: RecommendedAction::RequireApproval,
        weight: CAPABILITY_COMBO_WEIGHT_BROWSER_IDENTITY,
        description: "broad browser automation with identity-linked access",
    },
];

/// Detect and score capability combinations on a single artifact node.
fn detect_node_capability_combos(
    node: &crate::artifact_graph::ArtifactNode,
    acc: &mut CapabilityScoreAccumulator,
) {
    let has_cap = |cap: ArtifactCapability| -> bool {
        node.capabilities.iter().any(|fact| fact.capability == cap)
    };
    for spec in CAPABILITY_COMBOS {
        if has_cap(spec.cap_a) && has_cap(spec.cap_b) {
            let verb = match spec.action {
                RecommendedAction::Block => "Block",
                _ => "Approval",
            };
            let factor = format!("capability_combo:{}", spec.key);
            acc.score_combo(
                spec.key,
                spec.action,
                spec.weight,
                &factor,
                &format!("Artifact combines {}: {}", spec.description, node.path),
                &format!(
                    "{verb} forced because {} combines {}",
                    node.path, spec.description
                ),
            );
        }
    }
}

fn capability_score_params(
    capability: ArtifactCapability,
    source_label: &str,
) -> (String, u32, String) {
    match capability {
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
            format!(
                "Artifact requests access to OAuth or identity-linked resources ({source_label})"
            ),
        ),
        ArtifactCapability::InboundNetworkSurface => (
            format!("capability:{source_label}:inbound_network_surface"),
            CAPABILITY_WEIGHT_INBOUND_SURFACE,
            format!("Artifact exposes an inbound network or webhook surface ({source_label})"),
        ),
    }
}

fn graph_risk_context(
    artifact_graph: &ArtifactGraph,
) -> (u32, RecommendedAction, Vec<RiskFactor>, Vec<ActionTrigger>) {
    let mut acc = CapabilityScoreAccumulator::new();

    for node in &artifact_graph.nodes {
        for capability in &node.capabilities {
            let source_label = match capability.source {
                ArtifactCapabilitySource::Declared => "declared",
                ArtifactCapabilitySource::Observed => "observed",
            };
            let (factor, contribution, rationale) =
                capability_score_params(capability.capability, source_label);
            acc.score_capability(factor, contribution, format!("{rationale}: {}", node.path));
        }

        detect_node_capability_combos(node, &mut acc);
    }

    acc.into_parts()
}
