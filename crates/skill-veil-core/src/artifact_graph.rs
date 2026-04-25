//! Artifact graph for representing relationships between scanned assets.

use crate::findings::ArtifactKind;
use serde::{Deserialize, Serialize};

/// Capability exposed or requested by an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCapability {
    BrowserAccess,
    NetworkAccess,
    InstallExecution,
    ExposesBinary,
    PrivilegedRuntime,
    HostFilesystemAccess,
    ProcessExecution,
    SecretAccess,
    PersistenceSurface,
    FilesystemWrite,
    IdentityAccess,
    InboundNetworkSurface,
}

/// Origin of a capability assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCapabilitySource {
    Declared,
    Observed,
}

/// A capability attached to an artifact, including how it was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCapabilityFact {
    pub capability: ArtifactCapability,
    pub source: ArtifactCapabilitySource,
}

/// A node in the scanned artifact graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactNode {
    pub path: String,
    pub kind: ArtifactKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<ArtifactCapabilityFact>,
}

/// Describes the network endpoint category for a ConnectsTo or Downloads edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// Publicly addressable remote endpoint (attacker-controlled or external service).
    Remote,
    /// Known package registry (npm, PyPI, crates.io, …). Downloads from these are lower risk.
    Registry,
    /// Ephemeral or tunneled endpoint (ngrok, trycloudflare, …).
    Transient,
    /// Cloud provider metadata/control-plane endpoint (169.254.169.254, …).
    ControlPlane,
    /// Loopback or LAN-local endpoint.
    Local,
}

/// A directed edge between two artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEdge {
    pub from: String,
    pub to: String,
    pub relation: ArtifactRelation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_kind: Option<EndpointKind>,
}

/// Relationship between two artifacts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRelation {
    References,
    Contains,
    Locks,
    Downloads,
    Executes,
    Loads,
    Persists,
    Mounts,
    ConnectsTo,
    Reads,
    Writes,
    AccessesSecrets,
}

/// Lightweight graph describing scanned artifacts and their relationships.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactGraph {
    pub nodes: Vec<ArtifactNode>,
    pub edges: Vec<ArtifactEdge>,
}

impl ArtifactGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, path: impl Into<String>, kind: ArtifactKind) {
        let path = path.into();
        self.add_node_with_capabilities(path, kind, Vec::new());
    }

    pub fn add_node_with_capabilities(
        &mut self,
        path: impl Into<String>,
        kind: ArtifactKind,
        capabilities: Vec<ArtifactCapabilityFact>,
    ) {
        let path = path.into();
        if let Some(existing) = self.nodes.iter_mut().find(|node| node.path == path) {
            // Promote `kind` to the more specific classification. Pipeline
            // ordering is not deterministic, so a "first wins" rule would
            // silently lose more-specific kinds discovered later (e.g.
            // `McpServerManifest` arriving after a generic `AgentInstruction`
            // pre-classification). See `ArtifactKind::specificity` for the
            // tier ordering and the tests in this module that pin the
            // contract.
            if kind.specificity() > existing.kind.specificity() {
                existing.kind = kind;
            }
            for capability in capabilities {
                if !existing.capabilities.iter().any(|fact| {
                    fact.capability == capability.capability && fact.source == capability.source
                }) {
                    existing.capabilities.push(capability);
                }
            }
            return;
        }

        self.nodes.push(ArtifactNode {
            path,
            kind,
            capabilities,
        });
    }

    pub fn add_edge(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        relation: ArtifactRelation,
    ) {
        self.add_edge_with_endpoint(from, to, relation, None);
    }

    pub fn add_edge_with_endpoint(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        relation: ArtifactRelation,
        endpoint_kind: Option<EndpointKind>,
    ) {
        let edge = ArtifactEdge {
            from: from.into(),
            to: to.into(),
            relation,
            endpoint_kind,
        };

        if self.edges.iter().any(|existing| {
            existing.from == edge.from
                && existing.to == edge.to
                && std::mem::discriminant(&existing.relation)
                    == std::mem::discriminant(&edge.relation)
                && existing.endpoint_kind == edge.endpoint_kind
        }) {
            return;
        }

        self.edges.push(edge);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: re-inserting the same path with a more specific
    /// `ArtifactKind` upgrades the recorded kind. Without this,
    /// pipeline-ordering randomness silently shadowed
    /// `McpServerManifest` (specificity 4) behind an earlier
    /// `AgentInstruction` (specificity 3) classification.
    #[test]
    fn add_node_promotes_to_more_specific_kind() {
        let mut g = ArtifactGraph::new();
        g.add_node("/pkg/manifest", ArtifactKind::AgentInstruction);
        g.add_node("/pkg/manifest", ArtifactKind::McpServerManifest);
        let node = g
            .nodes
            .iter()
            .find(|n| n.path == "/pkg/manifest")
            .expect("node must exist");
        assert_eq!(
            node.kind,
            ArtifactKind::McpServerManifest,
            "More specific kind MUST replace less specific one"
        );
    }

    /// Inverse direction: a less specific later insertion does NOT demote.
    #[test]
    fn add_node_does_not_demote_kind() {
        let mut g = ArtifactGraph::new();
        g.add_node("/pkg/manifest", ArtifactKind::McpServerManifest);
        g.add_node("/pkg/manifest", ArtifactKind::GenericArtifact);
        let node = g.nodes.iter().find(|n| n.path == "/pkg/manifest").unwrap();
        assert_eq!(
            node.kind,
            ArtifactKind::McpServerManifest,
            "Less specific kind MUST NOT demote a more specific one"
        );
    }

    /// Idempotent: same kind twice doesn't change anything.
    #[test]
    fn add_node_is_idempotent_for_same_kind() {
        let mut g = ArtifactGraph::new();
        g.add_node("/pkg/x", ArtifactKind::PackageManifest);
        g.add_node("/pkg/x", ArtifactKind::PackageManifest);
        assert_eq!(
            g.nodes.iter().filter(|n| n.path == "/pkg/x").count(),
            1,
            "Re-inserting the same path must NOT duplicate the node"
        );
    }

    /// Equal-specificity insertions keep the first one (stable behaviour
    /// within a tier; only cross-tier upgrades fire).
    #[test]
    fn add_node_keeps_first_within_same_specificity_tier() {
        let mut g = ArtifactGraph::new();
        g.add_node("/pkg/x", ArtifactKind::PackageManifest); // tier 4
        g.add_node("/pkg/x", ArtifactKind::McpServerManifest); // tier 4
        let node = g.nodes.iter().find(|n| n.path == "/pkg/x").unwrap();
        assert_eq!(node.kind, ArtifactKind::PackageManifest);
    }
}
