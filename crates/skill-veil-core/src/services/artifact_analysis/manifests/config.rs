use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::ArtifactLink;
use std::path::Path;

pub(super) fn analyze_makefile(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();
    for line in content.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("curl ") || lower.contains("wget ") {
            findings.push(
                Finding::builder(
                    "MANIFEST_MAKEFILE_REMOTE_DOWNLOAD",
                    ThreatCategory::SupplyChain,
                )
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value(line)
                .reason("Makefile performs remote downloads")
                .build(),
            );
        }
    }
    findings
}

pub(super) fn analyze_npmrc(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings: Vec<_> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.to_ascii_lowercase().contains("_authtoken="))
        .map(|line| {
            Finding::builder(
                "MANIFEST_NPMRC_EMBEDDED_TOKEN",
                ThreatCategory::CredentialExposure,
            )
            .severity(Severity::High)
            .action(RecommendedAction::Block)
            .evidence_kind(EvidenceKind::Behavior)
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value(line)
            .reason("npm configuration embeds an authentication token")
            .build()
        })
        .collect();

    if content.lines().any(|line| {
        line.trim()
            .to_ascii_lowercase()
            .starts_with("registry=http")
    }) {
        findings.push(
            Finding::builder(
                "MANIFEST_NPMRC_CUSTOM_REGISTRY",
                ThreatCategory::SupplyChain,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Context)
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value("registry")
            .reason("npm configuration overrides the default registry")
            .build(),
        );
    }

    findings
}

pub(super) fn analyze_pip_conf(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings: Vec<_> = content
        .lines()
        .map(str::trim)
        .filter(|line| line.to_ascii_lowercase().contains("extra-index-url"))
        .map(|line| {
            Finding::builder("MANIFEST_PIP_CONF_EXTRA_INDEX", ThreatCategory::SupplyChain)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value(line)
                .reason("pip configuration adds an extra package index")
                .build()
        })
        .collect();

    if content
        .lines()
        .any(|line| line.to_ascii_lowercase().contains("trusted-host"))
    {
        findings.push(
            Finding::builder(
                "MANIFEST_PIP_CONF_TRUSTED_HOST",
                ThreatCategory::SupplyChain,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Context)
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value("trusted-host")
            .reason("pip configuration trusts a custom package host")
            .build(),
        );
    }

    findings
}

pub(super) fn makefile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("curl ") || lower.contains("wget ") {
        capabilities.push(super::super::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if lower.contains("bash ")
        || lower.contains("python ")
        || lower.contains("node ")
        || lower.contains("sh ")
    {
        capabilities.push(super::super::observed_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }
    capabilities
}

pub(super) fn npmrc_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("_authtoken=") {
        capabilities.push(super::super::declared_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    if lower.contains("registry=http") {
        capabilities.push(super::super::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    capabilities
}

pub(super) fn pip_conf_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("extra-index-url") || lower.contains("index-url") {
        capabilities.push(super::super::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if lower.contains("client-cert") {
        capabilities.push(super::super::declared_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    capabilities
}

pub(super) fn makefile_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    for line in content.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("curl ") || lower.contains("wget ") {
            links.push(ArtifactLink {
                target: "remote-resource".to_string(),
                relation: ArtifactRelation::Downloads,
            });
        }
        if lower.contains("bash ") || lower.contains("python ") || lower.contains("node ") {
            links.push(ArtifactLink {
                target: line.to_string(),
                relation: ArtifactRelation::Executes,
            });
        }
    }
    links
}

pub(super) fn npmrc_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    let lower = content.to_ascii_lowercase();
    if lower.contains("_authtoken=") {
        links.push(ArtifactLink {
            target: "credential-store".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    if lower.contains("registry=http") {
        links.push(ArtifactLink {
            target: "package-registry".to_string(),
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    links
}

pub(super) fn pip_conf_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    let lower = content.to_ascii_lowercase();
    if lower.contains("extra-index-url") || lower.contains("index-url") {
        links.push(ArtifactLink {
            target: "package-index".to_string(),
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    if lower.contains("client-cert") {
        links.push(ArtifactLink {
            target: "client-cert".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    links
}
