use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::{ArtifactAnalysisService, ArtifactLink};
use std::path::Path;

pub(crate) fn analyze_dockerfile(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();

    for line in content.lines().map(str::trim) {
        let lower_line = line.to_ascii_lowercase();
        if lower_line.starts_with("from ") && lower_line.contains(":latest") {
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

pub(crate) fn analyze_docker_compose(path: &Path, content: &str) -> Vec<Finding> {
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
                    Finding::builder(
                        "MANIFEST_DOCKER_COMPOSE_LATEST_TAG",
                        ThreatCategory::SupplyChain,
                    )
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
                Finding::builder(
                    "MANIFEST_DOCKER_COMPOSE_PRIVILEGED",
                    ThreatCategory::PrivilegeEscalation,
                )
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
                if volume.starts_with("/:")
                    || volume.contains(":/host")
                    || volume.starts_with("/var/run/docker.sock:")
                    || volume.starts_with("/etc/")
                    || volume.starts_with("/root")
                    || volume.starts_with("/proc")
                    || volume.starts_with("/sys")
                    || (volume.starts_with('/') && volume.contains(":/"))
                {
                    findings.push(
                        Finding::builder(
                            "MANIFEST_DOCKER_COMPOSE_HOST_MOUNT",
                            ThreatCategory::PrivilegeEscalation,
                        )
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
                    Finding::builder(
                        "MANIFEST_DOCKER_COMPOSE_HOST_NETWORK",
                        ThreatCategory::PrivilegeEscalation,
                    )
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
                Finding::builder(
                    "MANIFEST_DOCKER_COMPOSE_ENV_FILE",
                    ThreatCategory::CredentialExposure,
                )
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

pub(crate) fn dockerfile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut has_expose = false;
    let mut has_run = false;
    let mut has_copy_or_add = false;
    let mut has_network_download = false;

    for line in content.lines() {
        let trimmed = line.trim_start().to_ascii_lowercase();
        if !has_expose && (trimmed.starts_with("expose ") || trimmed == "expose") {
            has_expose = true;
        }
        if !has_run && trimmed.starts_with("run ") {
            has_run = true;
        }
        if !has_copy_or_add && (trimmed.starts_with("copy ") || trimmed.starts_with("add ")) {
            has_copy_or_add = true;
        }
        if !has_network_download
            && !trimmed.starts_with('#')
            && (trimmed.contains("curl ")
                || trimmed.contains("wget ")
                || trimmed.contains("invoke-webrequest"))
        {
            has_network_download = true;
        }
    }

    let mut capabilities = Vec::new();
    if has_expose {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_network_download {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_run {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }
    if has_copy_or_add {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::FilesystemWrite,
        ));
    }

    capabilities
}

pub(crate) fn docker_compose_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
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
            capabilities.push(ArtifactAnalysisService::declared_capability(
                ArtifactCapability::PrivilegedRuntime,
            ));
        }

        if let Some(volumes) = mapping
            .get(serde_yaml::Value::String("volumes".to_string()))
            .and_then(serde_yaml::Value::as_sequence)
        {
            if volumes.iter().any(|volume| {
                volume
                    .as_str()
                    .is_some_and(|value| value.starts_with('/') || value.starts_with("./"))
            }) && !capabilities.iter().any(|fact| {
                fact.capability == ArtifactCapability::HostFilesystemAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
            }) {
                capabilities.push(ArtifactAnalysisService::declared_capability(
                    ArtifactCapability::HostFilesystemAccess,
                ));
                capabilities.push(ArtifactAnalysisService::declared_capability(
                    ArtifactCapability::FilesystemWrite,
                ));
            }
        }

        if mapping.contains_key(serde_yaml::Value::String("ports".to_string()))
            && !capabilities.iter().any(|fact| {
                fact.capability == ArtifactCapability::NetworkAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
            })
        {
            capabilities.push(ArtifactAnalysisService::declared_capability(
                ArtifactCapability::NetworkAccess,
            ));
        }

        if mapping.contains_key(serde_yaml::Value::String("env_file".to_string()))
            && !capabilities.iter().any(|fact| {
                fact.capability == ArtifactCapability::SecretAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
            })
        {
            capabilities.push(ArtifactAnalysisService::declared_capability(
                ArtifactCapability::SecretAccess,
            ));
        }

        if (mapping.contains_key(serde_yaml::Value::String("command".to_string()))
            || mapping.contains_key(serde_yaml::Value::String("entrypoint".to_string())))
            && !capabilities.iter().any(|fact| {
                fact.capability == ArtifactCapability::ProcessExecution
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
            })
        {
            capabilities.push(ArtifactAnalysisService::declared_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }

    capabilities
}

pub(crate) fn dockerfile_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    for line in content.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("from ") {
            links.push(ArtifactLink {
                target: line[5..].trim().to_string(),
                relation: ArtifactRelation::Loads,
            });
        }
        if !lower.starts_with('#') && (lower.contains("curl ") || lower.contains("wget ")) {
            links.push(ArtifactLink {
                target: "remote-resource".to_string(),
                relation: ArtifactRelation::Downloads,
            });
        }
    }
    links
}

pub(crate) fn docker_compose_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return links;
    };
    let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
        return links;
    };
    for (_, service) in services {
        let Some(mapping) = service.as_mapping() else {
            continue;
        };
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
