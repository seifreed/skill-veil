use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::{ArtifactAnalysisService, ArtifactLink};
use std::path::Path;

pub(crate) fn analyze_makefile(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();
    for line in content.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if !lower.starts_with('#') && (lower.contains("curl ") || lower.contains("wget ")) {
            findings.push(
                Finding::builder(
                    "MANIFEST_MAKEFILE_REMOTE_DOWNLOAD",
                    ThreatCategory::SupplyChain,
                )
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .match_value(line)
                .reason("Makefile performs remote downloads")
                .build(),
            );
        }
    }
    findings
}

pub(crate) fn makefile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut has_network = false;
    let mut has_exec = false;
    for line in content.lines() {
        let lower = line.trim_start().to_ascii_lowercase();
        if lower.starts_with('#') {
            continue;
        }
        if !has_network && (lower.contains("curl ") || lower.contains("wget ")) {
            has_network = true;
        }
        if !has_exec
            && (lower.contains("bash ")
                || lower.contains("python ")
                || lower.contains("node ")
                || lower.contains("sh "))
        {
            has_exec = true;
        }
    }
    let mut capabilities = Vec::new();
    if has_network {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_exec {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }
    capabilities
}

pub(crate) fn makefile_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    for line in content.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if !lower.starts_with('#') && (lower.contains("curl ") || lower.contains("wget ")) {
            links.push(ArtifactLink {
                target: "remote-resource".to_string(),
                relation: ArtifactRelation::Downloads,
            });
        }
        if !lower.starts_with('#')
            && (lower.contains("bash ") || lower.contains("python ") || lower.contains("node "))
        {
            links.push(ArtifactLink {
                target: line.to_string(),
                relation: ArtifactRelation::Executes,
            });
        }
    }
    links
}
