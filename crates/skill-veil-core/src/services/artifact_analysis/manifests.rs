use super::ArtifactAnalysisService;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity,
    ThreatCategory,
};
use crate::services::artifact_analysis::ArtifactLink;
use serde_json::Value;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

pub(super) fn analyze_package_json(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let artifact_path = path.display().to_string();

    for dependency_field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(dependencies) = json.get(dependency_field).and_then(Value::as_object) else {
            continue;
        };

        for (name, version) in dependencies {
            let Some(version_str) = version.as_str() else {
                continue;
            };

            if version_str.starts_with('^')
                || version_str.starts_with('~')
                || version_str == "latest"
                || version_str == "*"
            {
                findings.push(
                    Finding::builder("MANIFEST_PACKAGE_JSON_UNPINNED_DEP", ThreatCategory::SupplyChain)
                        .severity(Severity::Low)
                        .action(RecommendedAction::Log)
                        .evidence_kind(EvidenceKind::Context)
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .match_value(format!("{name}@{version_str}"))
                        .reason("Manifest dependency is not strictly pinned")
                        .build(),
                );
            }
        }
    }

    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        for hook in ["preinstall", "install", "postinstall"] {
            if let Some(command) = scripts.get(hook).and_then(Value::as_str) {
                let lower_command = command.to_ascii_lowercase();
                let risky_install_hook = [
                    "curl ",
                    "wget ",
                    "http://",
                    "https://",
                    "powershell",
                    "invoke-webrequest",
                    "iwr ",
                    "bash -c",
                    "sh -c",
                    "python -c",
                    "node -e",
                ]
                .iter()
                .any(|needle| lower_command.contains(needle));
                findings.push(
                    Finding::builder("MANIFEST_PACKAGE_JSON_INSTALL_HOOK", ThreatCategory::SupplyChain)
                        .severity(if risky_install_hook {
                            Severity::Medium
                        } else {
                            Severity::Low
                        })
                        .action(if risky_install_hook {
                            RecommendedAction::RequireApproval
                        } else {
                            RecommendedAction::Log
                        })
                        .evidence_kind(if risky_install_hook {
                            EvidenceKind::Behavior
                        } else {
                            EvidenceKind::Context
                        })
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .match_value(format!("{hook}: {command}"))
                        .reason(if risky_install_hook {
                            "Manifest defines an install lifecycle hook that fetches or executes code"
                        } else {
                            "Manifest defines an install lifecycle hook"
                        })
                        .build(),
                );
            }
        }
    }

    if json.get("bin").is_some() {
        findings.push(
            Finding::builder("MANIFEST_PACKAGE_JSON_BIN_EXPOSED", ThreatCategory::ScopeCreep)
                .severity(Severity::Low)
                .action(RecommendedAction::Log)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("bin")
                .reason("Manifest exposes executable binaries")
                .build(),
        );
    }

    let expected_lockfiles = package_json_expected_lockfiles(content);
    if !expected_lockfiles.is_empty() {
        findings.extend(service.missing_lockfile_findings(
            path,
            sibling_files,
            &expected_lockfiles,
            "MANIFEST_PACKAGE_JSON_MISSING_LOCKFILE",
            "JavaScript manifest has no matching nearby lockfile",
        ));
    }

    findings
}

pub(super) fn analyze_requirements_txt(
    path: &Path,
    content: &str,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| !line.starts_with("-r ") && !line.starts_with("--requirement"))
        .filter(|line| !line.contains("=="))
        .map(|line| {
            Finding::builder("MANIFEST_REQUIREMENTS_UNPINNED_DEP", ThreatCategory::SupplyChain)
                .severity(Severity::Low)
                .action(RecommendedAction::Log)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value(line)
                .reason("Python requirement is not strictly pinned")
                .build()
        })
        .collect()
}

pub(super) fn analyze_dockerfile(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();

    for line in content.lines().map(str::trim) {
        if line.to_ascii_lowercase().starts_with("from ") && line.ends_with(":latest") {
            findings.push(
                Finding::builder("MANIFEST_DOCKER_LATEST_TAG", ThreatCategory::SupplyChain)
                    .severity(Severity::Low)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(line)
                    .reason("Docker base image uses the mutable latest tag")
                    .build(),
            );
        }
    }

    findings
}

pub(super) fn analyze_pyproject_toml(
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
            if !(dependency.contains("==") || dependency.contains("@")) {
                findings.push(
                    Finding::builder("MANIFEST_PYPROJECT_UNPINNED_DEP", ThreatCategory::SupplyChain)
                        .severity(Severity::Low)
                        .action(RecommendedAction::RequireApproval)
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

pub(super) fn analyze_cargo_toml(
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

    if let Some(dependencies) = toml.get("dependencies").and_then(TomlValue::as_table) {
        for (name, dependency) in dependencies {
            let version = match dependency {
                TomlValue::String(version) => Some(version.as_str()),
                TomlValue::Table(table) => table.get("version").and_then(TomlValue::as_str),
                _ => None,
            };

            if let Some(version) = version {
                if version.starts_with('^') || version.starts_with('~') || version == "*" {
                    findings.push(
                        Finding::builder("MANIFEST_CARGO_UNPINNED_DEP", ThreatCategory::SupplyChain)
                            .severity(Severity::Low)
                            .action(RecommendedAction::RequireApproval)
                            .evidence_kind(EvidenceKind::Context)
                            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                            .matched_on(MatchTarget::ReferencedFile {
                                path: artifact_path.clone(),
                            })
                            .match_value(format!("{name} = {version}"))
                            .reason("Cargo dependency is not strictly pinned")
                            .build(),
                    );
                }
            }
        }
    }

    findings.extend(service.missing_lockfile_findings(
        path,
        sibling_files,
        &["Cargo.lock"],
        "MANIFEST_CARGO_MISSING_LOCKFILE",
        "Cargo manifest has no matching nearby lockfile",
    ));

    findings
}

pub(super) fn analyze_docker_compose(path: &Path, content: &str) -> Vec<Finding> {
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return Vec::new();
    };

    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();

    let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
        return findings;
    };

    for (service_name, service) in services {
        let service_name = service_name.as_str().unwrap_or("unknown");
        let Some(mapping) = service.as_mapping() else {
            continue;
        };

        if let Some(image) = mapping
            .get(serde_yaml::Value::String("image".to_string()))
            .and_then(serde_yaml::Value::as_str)
        {
            if image.ends_with(":latest") {
                findings.push(
                    Finding::builder("MANIFEST_DOCKER_COMPOSE_LATEST_TAG", ThreatCategory::SupplyChain)
                        .severity(Severity::Low)
                        .action(RecommendedAction::RequireApproval)
                        .evidence_kind(EvidenceKind::Context)
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .match_value(format!("{service_name}: {image}"))
                        .reason("docker-compose service uses a mutable latest image tag")
                        .build(),
                );
            }
        }

        if mapping.contains_key(serde_yaml::Value::String("privileged".to_string()))
            && mapping
                .get(serde_yaml::Value::String("privileged".to_string()))
                .and_then(serde_yaml::Value::as_bool)
                == Some(true)
        {
            findings.push(
                Finding::builder("MANIFEST_DOCKER_COMPOSE_PRIVILEGED", ThreatCategory::PrivilegeEscalation)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(format!("{service_name}: privileged=true"))
                    .reason("docker-compose service requests privileged execution")
                    .build(),
            );
        }

        if let Some(volumes) = mapping
            .get(serde_yaml::Value::String("volumes".to_string()))
            .and_then(serde_yaml::Value::as_sequence)
        {
            for volume in volumes.iter().filter_map(serde_yaml::Value::as_str) {
                if volume.starts_with("/:") || volume.starts_with("/:/") || volume.contains(":/host") {
                    findings.push(
                        Finding::builder("MANIFEST_DOCKER_COMPOSE_HOST_MOUNT", ThreatCategory::PrivilegeEscalation)
                            .severity(Severity::Medium)
                            .action(RecommendedAction::RequireApproval)
                            .evidence_kind(EvidenceKind::Behavior)
                            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                            .matched_on(MatchTarget::ReferencedFile {
                                path: artifact_path.clone(),
                            })
                            .match_value(format!("{service_name}: {volume}"))
                            .reason("docker-compose service mounts sensitive host paths")
                            .build(),
                    );
                }
            }
        }

        if let Some(network_mode) = mapping
            .get(serde_yaml::Value::String("network_mode".to_string()))
            .and_then(serde_yaml::Value::as_str)
        {
            if matches!(network_mode, "host" | "service:host") {
                findings.push(
                    Finding::builder("MANIFEST_DOCKER_COMPOSE_HOST_NETWORK", ThreatCategory::PrivilegeEscalation)
                        .severity(Severity::Medium)
                        .action(RecommendedAction::RequireApproval)
                        .evidence_kind(EvidenceKind::Behavior)
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .match_value(format!("{service_name}: network_mode={network_mode}"))
                        .reason("docker-compose service shares the host network namespace")
                        .build(),
                );
            }
        }

        if let Some(env_file) = mapping.get(serde_yaml::Value::String("env_file".to_string())) {
            findings.push(
                Finding::builder("MANIFEST_DOCKER_COMPOSE_ENV_FILE", ThreatCategory::CredentialExposure)
                    .severity(Severity::Low)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(format!("{service_name}: {:?}", env_file))
                    .reason("docker-compose service loads environment files that may contain secrets")
                    .build(),
            );
        }
    }

    findings
}

pub(super) fn analyze_makefile(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();
    for line in content.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("curl ") || lower.contains("wget ") {
            findings.push(
                Finding::builder("MANIFEST_MAKEFILE_REMOTE_DOWNLOAD", ThreatCategory::SupplyChain)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
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
            Finding::builder("MANIFEST_NPMRC_EMBEDDED_TOKEN", ThreatCategory::CredentialExposure)
                .severity(Severity::High)
                .action(RecommendedAction::Block)
                .evidence_kind(EvidenceKind::Behavior)
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                .match_value(line)
                .reason("npm configuration embeds an authentication token")
                .build()
        })
        .collect();

    if content
        .lines()
        .any(|line| line.trim().to_ascii_lowercase().starts_with("registry=http"))
    {
        findings.push(
            Finding::builder("MANIFEST_NPMRC_CUSTOM_REGISTRY", ThreatCategory::SupplyChain)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
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
                .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
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
            Finding::builder("MANIFEST_PIP_CONF_TRUSTED_HOST", ThreatCategory::SupplyChain)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                .match_value("trusted-host")
                .reason("pip configuration trusts a custom package host")
                .build(),
        );
    }

    findings
}

pub(super) fn package_json_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let mut capabilities = Vec::new();

    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        if ["preinstall", "install", "postinstall"]
            .iter()
            .any(|hook| scripts.contains_key(*hook))
        {
            capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::InstallExecution));
            capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::ProcessExecution));
        }
    }

    if json.get("bin").is_some() {
        capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::ExposesBinary));
    }

    capabilities
}

pub(super) fn package_json_expected_lockfiles(content: &str) -> Vec<&'static str> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let package_manager = json
        .get("packageManager")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if package_manager.starts_with("pnpm@") {
        return vec!["pnpm-lock.yaml"];
    }
    if package_manager.starts_with("yarn@") {
        return vec!["yarn.lock"];
    }
    if package_manager.starts_with("npm@") {
        return vec!["package-lock.json", "npm-shrinkwrap.json"];
    }

    vec!["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]
}

pub(super) fn pyproject_expected_lockfiles(content: &str) -> Vec<&'static str> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    if toml.get("tool").and_then(|tool| tool.get("poetry")).is_some() {
        return vec!["poetry.lock"];
    }
    if toml.get("tool").and_then(|tool| tool.get("uv")).is_some() {
        return vec!["uv.lock"];
    }
    Vec::new()
}

pub(super) fn dockerfile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();
    let lower = content.to_ascii_lowercase();

    if lower.contains(" expose ") || lower.lines().any(|line| line.trim_start().starts_with("EXPOSE ")) {
        capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::NetworkAccess));
    }
    if lower.contains("curl ") || lower.contains("wget ") || lower.contains("invoke-webrequest") {
        capabilities.push(ArtifactAnalysisService::observed_capability(ArtifactCapability::NetworkAccess));
    }
    if lower.contains("run ") {
        capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::ProcessExecution));
    }
    if lower.contains(" copy ") || lower.contains(" add ") {
        capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::FilesystemWrite));
    }

    capabilities
}

pub(super) fn docker_compose_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return Vec::new();
    };

    let mut capabilities = Vec::new();
    let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
        return capabilities;
    };

    for (_, service) in services {
        let Some(mapping) = service.as_mapping() else {
            continue;
        };

        if mapping
            .get(serde_yaml::Value::String("privileged".to_string()))
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(false)
            && !capabilities.iter().any(|fact| {
                fact.capability == ArtifactCapability::PrivilegedRuntime
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
            })
        {
            capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::PrivilegedRuntime));
        }

        if let Some(volumes) = mapping
            .get(serde_yaml::Value::String("volumes".to_string()))
            .and_then(serde_yaml::Value::as_sequence)
        {
            if volumes.iter().any(|volume| {
                volume.as_str().is_some_and(|value| value.starts_with('/') || value.starts_with("./"))
            }) && !capabilities.iter().any(|fact| {
                fact.capability == ArtifactCapability::HostFilesystemAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
            })
            {
                capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::HostFilesystemAccess));
                capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::FilesystemWrite));
            }
        }

        if mapping.contains_key(serde_yaml::Value::String("ports".to_string()))
            && !capabilities.iter().any(|fact| {
                fact.capability == ArtifactCapability::NetworkAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
            })
        {
            capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::NetworkAccess));
        }

        if mapping.contains_key(serde_yaml::Value::String("env_file".to_string())) {
            capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::SecretAccess));
        }

        if mapping.contains_key(serde_yaml::Value::String("command".to_string()))
            || mapping.contains_key(serde_yaml::Value::String("entrypoint".to_string()))
        {
            capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::ProcessExecution));
        }
    }

    capabilities
}

pub(super) fn makefile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("curl ") || lower.contains("wget ") {
        capabilities.push(ArtifactAnalysisService::observed_capability(ArtifactCapability::NetworkAccess));
    }
    if lower.contains("bash ") || lower.contains("python ") || lower.contains("node ") || lower.contains("sh ") {
        capabilities.push(ArtifactAnalysisService::observed_capability(ArtifactCapability::ProcessExecution));
    }
    capabilities
}

pub(super) fn npmrc_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("_authtoken=") {
        capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::SecretAccess));
    }
    if lower.contains("registry=http") {
        capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::NetworkAccess));
    }
    capabilities
}

pub(super) fn pip_conf_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("extra-index-url") || lower.contains("index-url") {
        capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::NetworkAccess));
    }
    if lower.contains("client-cert") {
        capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::SecretAccess));
    }
    capabilities
}

pub(super) fn dockerfile_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    for line in content.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("from ") {
            links.push(ArtifactLink {
                target: line[5..].trim().to_string(),
                relation: ArtifactRelation::Loads,
            });
        }
        if lower.contains("curl ") || lower.contains("wget ") {
            links.push(ArtifactLink {
                target: "remote-resource".to_string(),
                relation: ArtifactRelation::Downloads,
            });
        }
    }
    links
}

pub(super) fn docker_compose_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return links;
    };
    let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
        return links;
    };
    for (_, service) in services {
        let Some(mapping) = service.as_mapping() else { continue; };
        if let Some(image) = mapping
            .get(serde_yaml::Value::String("image".to_string()))
            .and_then(serde_yaml::Value::as_str)
        {
            links.push(ArtifactLink {
                target: image.to_string(),
                relation: ArtifactRelation::Loads,
            });
        }
        if mapping.contains_key(serde_yaml::Value::String("ports".to_string())) {
            links.push(ArtifactLink {
                target: "network".to_string(),
                relation: ArtifactRelation::ConnectsTo,
            });
        }
        if mapping.contains_key(serde_yaml::Value::String("volumes".to_string())) {
            links.push(ArtifactLink {
                target: "host-filesystem".to_string(),
                relation: ArtifactRelation::Mounts,
            });
        }
        if mapping.contains_key(serde_yaml::Value::String("env_file".to_string())) {
            links.push(ArtifactLink {
                target: ".env".to_string(),
                relation: ArtifactRelation::AccessesSecrets,
            });
        }
        if mapping.contains_key(serde_yaml::Value::String("command".to_string()))
            || mapping.contains_key(serde_yaml::Value::String("entrypoint".to_string()))
        {
            links.push(ArtifactLink {
                target: "process".to_string(),
                relation: ArtifactRelation::Executes,
            });
        }
    }
    links
}

pub(super) fn package_json_relations(content: &str) -> Vec<ArtifactLink> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let mut links = Vec::new();
    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        for hook in ["preinstall", "install", "postinstall"] {
            if let Some(command) = scripts.get(hook).and_then(Value::as_str) {
                links.push(ArtifactLink {
                    target: command.to_string(),
                    relation: ArtifactRelation::Executes,
                });
            }
        }
    }
    links
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
