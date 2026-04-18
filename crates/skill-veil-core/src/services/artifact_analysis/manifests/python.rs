use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::{ArtifactAnalysisService, ArtifactLink};
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

pub(crate) fn analyze_requirements_txt(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| !line.starts_with("-r ") && !line.starts_with("--requirement"))
        .filter(|line| !line.starts_with("git+") && !line.starts_with("http"))
        .filter(|line| !line.starts_with("-c ") && !line.starts_with("--"))
        .filter(|line| !line.contains("==") && !line.contains("~=") && !line.contains("!="))
        .map(|line| {
            Finding::builder(
                "MANIFEST_REQUIREMENTS_UNPINNED_DEP",
                ThreatCategory::SupplyChain,
            )
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .evidence_kind(EvidenceKind::Context)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .match_value(line)
            .reason("Python requirement is not strictly pinned")
            .build()
        })
        .collect()
}

pub(crate) fn analyze_pyproject_toml(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();

    if let Some(dependencies) = toml
        .get("project")
        .and_then(|project| project.get("dependencies"))
        .and_then(TomlValue::as_array)
    {
        for dependency in dependencies.iter().filter_map(TomlValue::as_str) {
            if !(dependency.contains("==") || dependency.contains("~=") || dependency.contains("@"))
            {
                findings.push(
                    Finding::builder(
                        "MANIFEST_PYPROJECT_UNPINNED_DEP",
                        ThreatCategory::SupplyChain,
                    )
                    .severity(Severity::Low)
                    .action(RecommendedAction::Log)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(dependency)
                    .reason("pyproject dependency is not strictly pinned")
                    .build(),
                );
            }
        }
    }

    let expected_lockfiles = pyproject_expected_lockfiles(content);
    if !expected_lockfiles.is_empty() {
        findings.extend(service.missing_lockfile_findings(
            path,
            sibling_files,
            &expected_lockfiles,
            "MANIFEST_PYPROJECT_MISSING_LOCKFILE",
            "pyproject manifest has no matching nearby lockfile",
        ));
    }

    findings
}

pub(crate) fn analyze_pip_conf(path: &Path, content: &str) -> Vec<Finding> {
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
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .match_value("trusted-host")
            .reason("pip configuration trusts a custom package host")
            .build(),
        );
    }

    findings
}

pub(crate) fn requirements_txt_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();
    let network_deps = [
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "paramiko",
        "grpcio",
        "websockets",
        "tornado",
    ];
    let exec_deps = ["subprocess32", "pexpect", "fabric", "invoke"];

    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let dep_name = line
            .split(['=', '>', '<', '~', '[', ';'])
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if network_deps.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactAnalysisService::observed_capability(
                ArtifactCapability::NetworkAccess,
            ));
        }
        if exec_deps.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactAnalysisService::observed_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }
    capabilities.dedup_by_key(|c| c.capability);
    capabilities
}

pub(crate) fn pyproject_toml_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    let mut dep_strings = Vec::new();
    if let Some(deps) = toml
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(TomlValue::as_array)
    {
        dep_strings.extend(deps.iter().filter_map(TomlValue::as_str));
    }
    if let Some(deps) = toml
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(TomlValue::as_table)
    {
        dep_strings.extend(deps.keys().map(String::as_str));
    }

    let network_deps = [
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "paramiko",
        "grpcio",
        "websockets",
        "tornado",
    ];
    let exec_deps = ["subprocess32", "pexpect", "fabric", "invoke"];
    let mut capabilities = Vec::new();

    for dep in &dep_strings {
        let dep_name = dep
            .split(['=', '>', '<', '~', '[', ';'])
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if network_deps.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactAnalysisService::observed_capability(
                ArtifactCapability::NetworkAccess,
            ));
        }
        if exec_deps.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactAnalysisService::observed_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }
    capabilities.dedup_by_key(|c| c.capability);
    capabilities
}

pub(crate) fn pyproject_expected_lockfiles(content: &str) -> Vec<&'static str> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    if toml
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .is_some()
    {
        return vec!["poetry.lock"];
    }
    if toml.get("tool").and_then(|tool| tool.get("uv")).is_some() {
        return vec!["uv.lock"];
    }
    Vec::new()
}

pub(crate) fn pip_conf_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("extra-index-url") || lower.contains("index-url") {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if lower.contains("client-cert") {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    capabilities
}

pub(crate) fn pip_conf_relations(content: &str) -> Vec<ArtifactLink> {
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
