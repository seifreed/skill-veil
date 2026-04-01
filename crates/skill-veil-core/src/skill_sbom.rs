use crate::artifact_graph::{ArtifactGraph, ArtifactRelation};
use crate::findings::{BlastRadiusLevel, DeclaredPermission, RiskBand, SkillCapability, Verdict};
use crate::scanner_types::{PackageScanResult, ScanResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSbom {
    pub skill: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,
    pub extension_kind: String,
    pub ecosystem_profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<SbomComponent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<SkillCapability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_permissions: Vec<DeclaredPermission>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_endpoints: Vec<String>,
    pub risk_score: u32,
    pub risk_band: RiskBand,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blast_radius: Option<BlastRadiusLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SbomComponent {
    pub path: String,
    pub kind: String,
}

impl SkillSbom {
    #[must_use]
    pub fn from_scan_result(result: &ScanResult) -> Self {
        Self {
            skill: result.name.clone(),
            version: None,
            package_id: result.package_id.clone(),
            extension_kind: result.extension_kind.to_string(),
            ecosystem_profile: result.ecosystem_profile.to_string(),
            components: derive_components(&result.artifact_graph),
            capabilities: result.verdict_report.effective_capabilities.clone(),
            declared_permissions: result.verdict_report.declared_permissions.clone(),
            dependencies: derive_dependencies(result),
            remote_endpoints: derive_remote_endpoints(&result.artifact_graph),
            risk_score: result.verdict_report.risk_score,
            risk_band: result.verdict_report.risk_band,
            verdict: result.verdict,
            blast_radius: result.verdict_report.blast_radius_summary.level,
        }
    }

    #[must_use]
    pub fn from_package_scan_result(result: &PackageScanResult) -> Self {
        let components = result
            .artifacts
            .iter()
            .flat_map(|artifact| derive_components(&artifact.artifact_graph))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let dependencies = result
            .artifacts
            .iter()
            .flat_map(derive_dependencies)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let remote_endpoints = result
            .artifacts
            .iter()
            .flat_map(|artifact| derive_remote_endpoints(&artifact.artifact_graph))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let extension_kinds = result
            .artifacts
            .iter()
            .map(|artifact| artifact.extension_kind.to_string())
            .collect::<BTreeSet<_>>();
        let ecosystem_profiles = result
            .artifacts
            .iter()
            .map(|artifact| artifact.ecosystem_profile.to_string())
            .collect::<BTreeSet<_>>();

        Self {
            skill: result.package_root.display().to_string(),
            version: None,
            package_id: result.package_id.clone(),
            extension_kind: if extension_kinds.len() == 1 {
                extension_kinds
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| "generic_extension".to_string())
            } else {
                "package".to_string()
            },
            ecosystem_profile: if ecosystem_profiles.len() == 1 {
                ecosystem_profiles
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| "generic".to_string())
            } else {
                "mixed".to_string()
            },
            components,
            capabilities: result.effective_capabilities.clone(),
            declared_permissions: result.declared_permissions.clone(),
            dependencies,
            remote_endpoints,
            risk_score: result.risk_score,
            risk_band: result.risk_band,
            verdict: result.final_verdict,
            blast_radius: result.blast_radius,
        }
    }
}

fn derive_components(graph: &ArtifactGraph) -> Vec<SbomComponent> {
    graph
        .nodes
        .iter()
        .map(|node| SbomComponent {
            path: node.path.clone(),
            kind: node.kind.to_string(),
        })
        .collect()
}

fn derive_dependencies(result: &ScanResult) -> Vec<String> {
    let mut deps = BTreeSet::new();
    let tokens = [
        "curl",
        "wget",
        "git",
        "bash",
        "sh",
        "python",
        "python3",
        "node",
        "npm",
        "yarn",
        "pnpm",
        "uv",
        "poetry",
        "docker",
        "powershell",
        "pwsh",
    ];

    for step in &result.execution_model.steps {
        let label = step.label.to_ascii_lowercase();
        for token in tokens {
            if label.contains(token) {
                deps.insert(token.to_string());
            }
        }
    }

    for factor in &result.verdict_report.top_risk_drivers {
        let label = factor.factor.to_ascii_lowercase();
        for token in tokens {
            if label.contains(token) {
                deps.insert(token.to_string());
            }
        }
    }

    deps.into_iter().collect()
}

fn derive_remote_endpoints(graph: &ArtifactGraph) -> Vec<String> {
    let mut endpoints = BTreeSet::new();
    for edge in &graph.edges {
        if matches!(
            edge.relation,
            ArtifactRelation::ConnectsTo | ArtifactRelation::Downloads
        ) && (edge.to.starts_with("http://") || edge.to.starts_with("https://"))
        {
            endpoints.insert(edge.to.clone());
        }
    }
    endpoints.into_iter().collect()
}
