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

/// A directed edge between two artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEdge {
    pub from: String,
    pub to: String,
    pub relation: ArtifactRelation,
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
            existing.kind = kind;
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
        let edge = ArtifactEdge {
            from: from.into(),
            to: to.into(),
            relation,
        };

        if self
            .edges
            .iter()
            .any(|existing| {
                existing.from == edge.from
                    && existing.to == edge.to
                    && std::mem::discriminant(&existing.relation)
                        == std::mem::discriminant(&edge.relation)
            })
        {
            return;
        }

        self.edges.push(edge);
    }
}
