use crate::behavior_graph::{BehaviorGraph, BehaviorRelation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub order: usize,
    pub label: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionModel {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub summary: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<ExecutionStep>,
}

impl ExecutionModel {
    #[must_use]
    pub fn derive(graph: &BehaviorGraph) -> Self {
        let mut summary = graph
            .summary
            .iter()
            .map(|entry| entry.label.clone())
            .collect::<Vec<_>>();

        let mut raw_steps: Vec<(u8, String)> = Vec::new();
        let mut seen = HashSet::new();

        for edge in &graph.edges {
            let to_label = graph
                .nodes
                .iter()
                .find(|node| node.id == edge.to)
                .map(|node| node.label.as_str())
                .unwrap_or(edge.to.as_str());

            let label = match edge.relation {
                BehaviorRelation::References => format!("reads or loads {}", to_label),
                BehaviorRelation::Executes => format!("executes {}", to_label),
                BehaviorRelation::Reads => format!("reads {}", to_label),
                BehaviorRelation::Writes => format!("writes {}", to_label),
                BehaviorRelation::ConnectsTo => format!("sends network request to {}", to_label),
                BehaviorRelation::Downloads => format!("downloads from {}", to_label),
                BehaviorRelation::Persists => format!("persists via {}", to_label),
                BehaviorRelation::AccessesSecrets => format!("accesses secrets from {}", to_label),
                BehaviorRelation::ExposesCapability => to_label.to_string(),
            };

            if seen.insert(label.clone()) {
                let phase = causal_phase(edge.relation);
                raw_steps.push((phase, label));
            }
        }

        raw_steps.sort_by_key(|(phase, _)| *phase);
        let steps: Vec<ExecutionStep> = raw_steps
            .into_iter()
            .enumerate()
            .map(|(index, (_, label))| ExecutionStep {
                order: index + 1,
                label,
            })
            .collect();

        if steps.is_empty() {
            let steps = summary
                .iter()
                .enumerate()
                .filter(|(_, item)| seen.insert((*item).clone()))
                .map(|(index, item)| ExecutionStep {
                    order: index + 1,
                    label: item.clone(),
                })
                .collect();
            summary.dedup();
            return Self { summary, steps };
        }

        summary.dedup();
        Self { summary, steps }
    }
}

/// Assign a causal phase number so steps are ordered by typical attack chain:
/// load/read first, then secrets access, then execution, then network/exfil, then persistence.
fn causal_phase(relation: BehaviorRelation) -> u8 {
    match relation {
        BehaviorRelation::References => 1,
        BehaviorRelation::Reads => 2,
        BehaviorRelation::AccessesSecrets => 3,
        BehaviorRelation::Downloads => 4,
        BehaviorRelation::Executes => 5,
        BehaviorRelation::Writes => 6,
        BehaviorRelation::ConnectsTo => 7,
        BehaviorRelation::Persists => 8,
        BehaviorRelation::ExposesCapability => 9,
    }
}
