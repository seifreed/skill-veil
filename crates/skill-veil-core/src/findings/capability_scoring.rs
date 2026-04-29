//! Capability-scoring subsystem for the artifact graph.
//!
//! Translates per-node `ArtifactCapability` facts and cross-capability
//! combinations into the `(score, action, factors, triggers)` tuple consumed
//! by `FindingSummary`. Lives in its own module so `summary.rs` stays focused
//! on aggregation and so the capability tables (`CAPABILITY_COMBOS`, weight
//! matchers) are co-located with the code that interprets them.

use super::{
    ActionTrigger, RecommendedAction, RiskFactor, CAPABILITY_COMBO_WEIGHT_BROWSER_IDENTITY,
    CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY, CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK,
    CAPABILITY_COMBO_WEIGHT_PERSISTENCE_NETWORK, CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST,
    CAPABILITY_COMBO_WEIGHT_SECRET_NETWORK, CAPABILITY_WEIGHT_BROWSER_ACCESS,
    CAPABILITY_WEIGHT_EXPOSES_BINARY, CAPABILITY_WEIGHT_FILESYSTEM_WRITE,
    CAPABILITY_WEIGHT_HOST_FILESYSTEM_ACCESS, CAPABILITY_WEIGHT_IDENTITY_ACCESS,
    CAPABILITY_WEIGHT_INBOUND_SURFACE, CAPABILITY_WEIGHT_INSTALL_EXECUTION,
    CAPABILITY_WEIGHT_NETWORK_ACCESS, CAPABILITY_WEIGHT_PERSISTENCE_SURFACE,
    CAPABILITY_WEIGHT_PRIVILEGED_RUNTIME, CAPABILITY_WEIGHT_PROCESS_EXECUTION,
    CAPABILITY_WEIGHT_SECRET_ACCESS,
};
use crate::artifact_graph::{
    ArtifactCapability, ArtifactCapabilitySource, ArtifactGraph, ArtifactNode,
};

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

    /// Score a capability against the package's accumulated risk.
    ///
    /// # Per-package dedup contract
    ///
    /// Capabilities are deduplicated by `factor` (capability + source label),
    /// **not by node**. A package where multiple nodes declare the same
    /// capability (e.g. every script imports `requests`, so each node carries
    /// `NetworkAccess (declared)`) contributes the capability weight ONCE per
    /// package — not once per node. This prevents multi-file packages from
    /// inflating their risk score for benign shared imports.
    ///
    /// `rationale` is allowed to vary per node (it is human-readable text)
    /// without breaking the dedup invariant — the `factor` field is the
    /// load-bearing key.
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
fn detect_node_capability_combos(node: &ArtifactNode, acc: &mut CapabilityScoreAccumulator) {
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

pub(crate) fn graph_risk_context(
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
