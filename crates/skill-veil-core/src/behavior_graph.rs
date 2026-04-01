use crate::artifact_graph::{ArtifactGraph, ArtifactRelation};
use crate::findings::{PackageVerdictReport, SkillCapability};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorNodeKind {
    Skill,
    Artifact,
    Target,
    Capability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorRelation {
    References,
    Executes,
    Reads,
    Writes,
    ConnectsTo,
    Downloads,
    Persists,
    AccessesSecrets,
    ExposesCapability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorNode {
    pub id: String,
    pub label: String,
    pub kind: BehaviorNodeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEdge {
    pub from: String,
    pub to: String,
    pub relation: BehaviorRelation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSummaryEntry {
    pub capability: SkillCapability,
    pub label: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehaviorGraph {
    pub root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<BehaviorNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<BehaviorEdge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub summary: Vec<BehaviorSummaryEntry>,
}

impl BehaviorGraph {
    #[must_use]
    pub fn derive(
        root_path: &Path,
        artifact_graph: &ArtifactGraph,
        verdict_report: &PackageVerdictReport,
    ) -> Self {
        let root = root_path.display().to_string();
        let root_label = root_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("skill")
            .to_string();

        let mut nodes = vec![BehaviorNode {
            id: root.clone(),
            label: root_label,
            kind: BehaviorNodeKind::Skill,
        }];
        let mut node_ids: HashSet<String> = [root.clone()].into_iter().collect();
        let mut edges = Vec::new();

        for node in &artifact_graph.nodes {
            if node_ids.insert(node.path.clone()) {
                nodes.push(BehaviorNode {
                    id: node.path.clone(),
                    label: display_label(&node.path),
                    kind: BehaviorNodeKind::Artifact,
                });
            }
        }

        for edge in &artifact_graph.edges {
            if !node_ids.contains(&edge.from) {
                nodes.push(BehaviorNode {
                    id: edge.from.clone(),
                    label: display_label(&edge.from),
                    kind: classify_behavior_node(&edge.from, artifact_graph),
                });
                node_ids.insert(edge.from.clone());
            }
            if !node_ids.contains(&edge.to) {
                nodes.push(BehaviorNode {
                    id: edge.to.clone(),
                    label: display_label(&edge.to),
                    kind: classify_behavior_node(&edge.to, artifact_graph),
                });
                node_ids.insert(edge.to.clone());
            }

            if let Some(relation) = map_relation(edge.relation) {
                edges.push(BehaviorEdge {
                    from: edge.from.clone(),
                    to: edge.to.clone(),
                    relation,
                });
            }
        }

        // Ensure all artifact nodes are reachable from root via BFS.
        // Nodes in disconnected subgraphs (e.g., C→A where neither C nor A
        // is reachable from root) get a synthetic root→node edge.
        let reachable = {
            let mut visited = HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            visited.insert(root.clone());
            queue.push_back(root.clone());
            while let Some(current) = queue.pop_front() {
                for edge in &edges {
                    if edge.from == current && visited.insert(edge.to.clone()) {
                        queue.push_back(edge.to.clone());
                    }
                }
            }
            visited
        };
        for node in &nodes {
            if node.id == root || reachable.contains(&node.id) {
                continue;
            }
            if matches!(
                node.kind,
                BehaviorNodeKind::Artifact | BehaviorNodeKind::Target
            ) {
                edges.push(BehaviorEdge {
                    from: root.clone(),
                    to: node.id.clone(),
                    relation: BehaviorRelation::References,
                });
            }
        }

        let summary = build_summary(verdict_report);
        for item in &summary {
            let capability_id = format!("cap:{}", item.capability);
            if node_ids.insert(capability_id.clone()) {
                nodes.push(BehaviorNode {
                    id: capability_id.clone(),
                    label: item.label.clone(),
                    kind: BehaviorNodeKind::Capability,
                });
            }
            edges.push(BehaviorEdge {
                from: root.clone(),
                to: capability_id,
                relation: BehaviorRelation::ExposesCapability,
            });
        }

        Self {
            root,
            nodes,
            edges,
            summary,
        }
    }
}

fn build_summary(verdict_report: &PackageVerdictReport) -> Vec<BehaviorSummaryEntry> {
    let mut summary = Vec::new();
    let mut seen = BTreeSet::new();

    for capability in &verdict_report.effective_capabilities {
        if seen.insert(*capability) {
            summary.push(BehaviorSummaryEntry {
                capability: *capability,
                label: capability_label(*capability).to_string(),
            });
        }
    }

    summary
}

fn capability_label(capability: SkillCapability) -> &'static str {
    match capability {
        SkillCapability::FilesystemRead => "reads local files",
        SkillCapability::FilesystemWrite => "writes local files",
        SkillCapability::ShellExec => "executes shell commands",
        SkillCapability::ProcessSpawn => "spawns local processes",
        SkillCapability::NetworkHttp => "sends HTTP requests",
        SkillCapability::NetworkWebsocket => "opens WebSocket connections",
        SkillCapability::NetworkInternal => "reaches internal network targets",
        SkillCapability::SecretsAccess => "accesses secrets",
        SkillCapability::IdentityOauth => "uses OAuth identity scopes",
        SkillCapability::InboundWebhook => "exposes inbound webhook surface",
        SkillCapability::PersistenceSemantic => "persists instructions across sessions",
        SkillCapability::ToolsBrowser => "uses browser tooling",
        SkillCapability::ToolsMcpRemote => "uses remote MCP tooling",
    }
}

fn map_relation(relation: ArtifactRelation) -> Option<BehaviorRelation> {
    Some(match relation {
        ArtifactRelation::References | ArtifactRelation::Contains | ArtifactRelation::Loads => {
            BehaviorRelation::References
        }
        ArtifactRelation::Produces | ArtifactRelation::Installs => BehaviorRelation::References,
        ArtifactRelation::Executes | ArtifactRelation::ExecutesViaHook => {
            BehaviorRelation::Executes
        }
        ArtifactRelation::Reads => BehaviorRelation::Reads,
        ArtifactRelation::Writes => BehaviorRelation::Writes,
        ArtifactRelation::ConnectsTo => BehaviorRelation::ConnectsTo,
        ArtifactRelation::Downloads => BehaviorRelation::Downloads,
        ArtifactRelation::Persists | ArtifactRelation::PersistsViaConfig => {
            BehaviorRelation::Persists
        }
        ArtifactRelation::AccessesSecrets => BehaviorRelation::AccessesSecrets,
        ArtifactRelation::Mounts | ArtifactRelation::Locks => return None,
    })
}

fn classify_behavior_node(path: &str, artifact_graph: &ArtifactGraph) -> BehaviorNodeKind {
    if artifact_graph.nodes.iter().any(|node| node.path == path) {
        BehaviorNodeKind::Artifact
    } else {
        BehaviorNodeKind::Target
    }
}

fn display_label(value: &str) -> String {
    Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(value)
        .to_string()
}
