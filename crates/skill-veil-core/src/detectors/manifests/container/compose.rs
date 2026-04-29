//! docker-compose manifest analysis: findings, capability inference, and
//! artifact relations. Dockerfile logic lives in the sibling `dockerfile`
//! module; volume + env_file classifiers shared by this module live in
//! `volumes`.

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};
use std::path::Path;

use super::volumes::{env_file_has_real_paths, is_sensitive_host_volume, render_env_file};

pub(crate) fn analyze_docker_compose(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let yaml = match parse_compose_yaml(content) {
        Ok(value) => value,
        Err(err) => return vec![parse_failure_finding(&artifact_path, &err)],
    };
    let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for (raw_name, service) in services {
        let service_name = raw_name.as_str().unwrap_or("unknown");
        let Some(mapping) = service.as_mapping() else {
            continue;
        };
        findings.extend(detect_latest_image_tag(
            service_name,
            mapping,
            &artifact_path,
        ));
        findings.extend(detect_privileged(service_name, mapping, &artifact_path));
        findings.extend(detect_host_volumes(service_name, mapping, &artifact_path));
        findings.extend(detect_host_network(service_name, mapping, &artifact_path));
        findings.extend(detect_env_file(service_name, mapping, &artifact_path));
    }
    findings
}

fn parse_compose_yaml(content: &str) -> Result<serde_yaml::Value, serde_yaml::Error> {
    serde_yaml::from_str::<serde_yaml::Value>(content)
}

/// A `docker-compose.yml` whose YAML body is unparseable is suspicious on
/// its own: the manifest is shipped, the rest of the analysis pipeline
/// (capabilities, relations) silently drops it for lack of structure, and
/// an attacker can intentionally craft "almost valid" YAML to bypass every
/// host-mount / privilege / env_file detector. Emit an explicit finding so
/// the manifest's existence — and our inability to analyze it — is recorded
/// in the audit output instead of being swallowed.
fn parse_failure_finding(artifact_path: &str, err: &serde_yaml::Error) -> Finding {
    Finding::builder(
        "MANIFEST_DOCKER_COMPOSE_PARSE_FAILURE",
        ThreatCategory::Generic,
    )
    .severity(Severity::Low)
    .action(RecommendedAction::Log)
    .evidence_kind(EvidenceKind::Context)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::PackageManifest,
        Some(artifact_path.to_string()),
    )
    .match_value(err.to_string())
    .reason(
        "docker-compose manifest is not valid YAML; capability and \
         volume/env analyses cannot run against this file",
    )
    .build()
}

fn detect_latest_image_tag(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Option<Finding> {
    let image = mapping
        .get(serde_yaml::Value::String("image".to_string()))
        .and_then(serde_yaml::Value::as_str)?;
    if !image.ends_with(":latest") {
        return None;
    }
    Some(
        Finding::builder(
            "MANIFEST_DOCKER_COMPOSE_LATEST_TAG",
            ThreatCategory::SupplyChain,
        )
        .severity(Severity::Low)
        .action(RecommendedAction::RequireApproval)
        .evidence_kind(EvidenceKind::Context)
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .artifact(
            ArtifactKind::PackageManifest,
            Some(artifact_path.to_string()),
        )
        .match_value(format!("{service_name}: {image}"))
        .reason("docker-compose service uses a mutable latest image tag")
        .build(),
    )
}

fn detect_privileged(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Option<Finding> {
    let privileged = mapping
        .get(serde_yaml::Value::String("privileged".to_string()))
        .and_then(serde_yaml::Value::as_bool)?;
    if !privileged {
        return None;
    }
    Some(
        Finding::builder(
            "MANIFEST_DOCKER_COMPOSE_PRIVILEGED",
            ThreatCategory::PrivilegeEscalation,
        )
        .severity(Severity::Medium)
        .action(RecommendedAction::RequireApproval)
        .evidence_kind(EvidenceKind::Behavior)
        .artifact(
            ArtifactKind::PackageManifest,
            Some(artifact_path.to_string()),
        )
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .match_value(format!("{service_name}: privileged=true"))
        .reason("docker-compose service requests privileged execution")
        .build(),
    )
}

fn detect_host_volumes(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Vec<Finding> {
    let Some(volumes) = mapping
        .get(serde_yaml::Value::String("volumes".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return Vec::new();
    };
    volumes
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .filter(|volume| is_sensitive_host_volume(volume))
        .map(|volume| {
            Finding::builder(
                "MANIFEST_DOCKER_COMPOSE_HOST_MOUNT",
                ThreatCategory::PrivilegeEscalation,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Behavior)
            .artifact(
                ArtifactKind::PackageManifest,
                Some(artifact_path.to_string()),
            )
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .match_value(format!("{service_name}: {volume}"))
            .reason("docker-compose service mounts sensitive host paths")
            .build()
        })
        .collect()
}

fn detect_host_network(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Option<Finding> {
    let network_mode = mapping
        .get(serde_yaml::Value::String("network_mode".to_string()))
        .and_then(serde_yaml::Value::as_str)?;
    if !matches!(network_mode, "host" | "service:host") {
        return None;
    }
    Some(
        Finding::builder(
            "MANIFEST_DOCKER_COMPOSE_HOST_NETWORK",
            ThreatCategory::PrivilegeEscalation,
        )
        .severity(Severity::Medium)
        .action(RecommendedAction::RequireApproval)
        .evidence_kind(EvidenceKind::Behavior)
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .artifact(
            ArtifactKind::PackageManifest,
            Some(artifact_path.to_string()),
        )
        .match_value(format!("{service_name}: network_mode={network_mode}"))
        .reason("docker-compose service shares the host network namespace")
        .build(),
    )
}

fn detect_env_file(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Option<Finding> {
    let env_file = mapping
        .get(serde_yaml::Value::String("env_file".to_string()))
        .filter(|value| env_file_has_real_paths(value))?;
    Some(
        Finding::builder(
            "MANIFEST_DOCKER_COMPOSE_ENV_FILE",
            ThreatCategory::CredentialExposure,
        )
        .severity(Severity::Low)
        .action(RecommendedAction::RequireApproval)
        .evidence_kind(EvidenceKind::Context)
        .artifact(
            ArtifactKind::PackageManifest,
            Some(artifact_path.to_string()),
        )
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .match_value(format!("{service_name}: {}", render_env_file(env_file)))
        .reason("docker-compose service loads environment files that may contain secrets")
        .build(),
    )
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
            capabilities.push(ArtifactOrchestratorService::declared_capability(
                ArtifactCapability::PrivilegedRuntime,
            ));
        }

        if let Some(volumes) = mapping
            .get(serde_yaml::Value::String("volumes".to_string()))
            .and_then(serde_yaml::Value::as_sequence)
        {
            if volumes
                .iter()
                .any(|volume| volume.as_str().is_some_and(is_sensitive_host_volume))
                && !capabilities.iter().any(|fact| {
                    fact.capability == ArtifactCapability::HostFilesystemAccess
                        && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
                })
            {
                capabilities.push(ArtifactOrchestratorService::declared_capability(
                    ArtifactCapability::HostFilesystemAccess,
                ));
                capabilities.push(ArtifactOrchestratorService::declared_capability(
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
            capabilities.push(ArtifactOrchestratorService::declared_capability(
                ArtifactCapability::NetworkAccess,
            ));
        }

        if mapping
            .get(serde_yaml::Value::String("env_file".to_string()))
            .is_some_and(env_file_has_real_paths)
            && !capabilities.iter().any(|fact| {
                fact.capability == ArtifactCapability::SecretAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
            })
        {
            capabilities.push(ArtifactOrchestratorService::declared_capability(
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
            capabilities.push(ArtifactOrchestratorService::declared_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }

    capabilities
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

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_present(caps: &[ArtifactCapabilityFact], target: ArtifactCapability) -> bool {
        caps.iter().any(|fact| fact.capability == target)
    }

    fn finding_present(findings: &[Finding], rule_id: &str) -> bool {
        findings.iter().any(|finding| finding.rule_id == rule_id)
    }

    fn match_value_for(findings: &[Finding], rule_id: &str) -> Option<String> {
        findings
            .iter()
            .find(|finding| finding.rule_id == rule_id)
            .map(|finding| finding.match_value.clone())
    }

    /// Contract: a relative bind mount contained in the project (`./data:/data`)
    /// does NOT escalate `HostFilesystemAccess` / `FilesystemWrite`. Only
    /// host-trust-boundary mounts do.
    #[test]
    fn docker_compose_host_filesystem_capability_skips_relative_project_volume() {
        let yaml = "services:\n  app:\n    image: nginx\n    volumes:\n      - \"./data:/data\"\n";
        let caps = docker_compose_capabilities(yaml);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::HostFilesystemAccess
        ));
        assert!(!capability_present(
            &caps,
            ArtifactCapability::FilesystemWrite
        ));
    }

    /// Contract: mounting the docker socket exposes the host control plane and
    /// MUST emit `HostFilesystemAccess` and `FilesystemWrite`.
    #[test]
    fn docker_compose_host_filesystem_capability_fires_for_docker_socket() {
        let yaml = "services:\n  app:\n    image: nginx\n    volumes:\n      - \"/var/run/docker.sock:/var/run/docker.sock\"\n";
        let caps = docker_compose_capabilities(yaml);
        assert!(capability_present(
            &caps,
            ArtifactCapability::HostFilesystemAccess
        ));
        assert!(capability_present(
            &caps,
            ArtifactCapability::FilesystemWrite
        ));
    }

    /// Contract: mounting `/etc` from the host is sensitive and MUST escalate.
    #[test]
    fn docker_compose_host_filesystem_capability_fires_for_etc_mount() {
        let yaml =
            "services:\n  app:\n    image: nginx\n    volumes:\n      - \"/etc/passwd:/host-etc/passwd\"\n";
        let caps = docker_compose_capabilities(yaml);
        assert!(capability_present(
            &caps,
            ArtifactCapability::HostFilesystemAccess
        ));
    }

    /// Contract: the HOST_MOUNT finding matches the capability rule — relative
    /// project volumes do not fire it.
    #[test]
    fn docker_compose_host_mount_finding_skips_relative_project_volume() {
        let yaml = "services:\n  app:\n    image: nginx\n    volumes:\n      - \"./data:/data\"\n";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, yaml);
        assert!(!finding_present(
            &findings,
            "MANIFEST_DOCKER_COMPOSE_HOST_MOUNT"
        ));
    }

    /// Contract: `env_file: null` carries no path; the finding and SecretAccess
    /// capability must NOT fire.
    #[test]
    fn docker_compose_env_file_finding_skips_null_value() {
        let yaml = "services:\n  app:\n    image: nginx\n    env_file: null\n";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, yaml);
        let caps = docker_compose_capabilities(yaml);
        assert!(!finding_present(
            &findings,
            "MANIFEST_DOCKER_COMPOSE_ENV_FILE"
        ));
        assert!(!capability_present(&caps, ArtifactCapability::SecretAccess));
    }

    /// Contract: `env_file: []` (empty list) carries no path; finding and
    /// capability must NOT fire.
    #[test]
    fn docker_compose_env_file_finding_skips_empty_sequence() {
        let yaml = "services:\n  app:\n    image: nginx\n    env_file: []\n";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, yaml);
        let caps = docker_compose_capabilities(yaml);
        assert!(!finding_present(
            &findings,
            "MANIFEST_DOCKER_COMPOSE_ENV_FILE"
        ));
        assert!(!capability_present(&caps, ArtifactCapability::SecretAccess));
    }

    /// Contract: a string `env_file` renders as the bare path in `match_value`,
    /// not as the YAML debug wrapper `String("…")`.
    #[test]
    fn docker_compose_env_file_finding_uses_clean_match_value_for_string() {
        let yaml = "services:\n  app:\n    image: nginx\n    env_file: .env\n";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, yaml);
        let value = match_value_for(&findings, "MANIFEST_DOCKER_COMPOSE_ENV_FILE")
            .expect("env_file finding should fire for non-empty string");
        assert_eq!(value, "app: .env");
        assert!(!value.contains("String("));
    }

    /// Contract: a sequence `env_file` renders entries comma-separated in
    /// `match_value`, not as the YAML debug wrapper.
    #[test]
    fn docker_compose_env_file_finding_uses_clean_match_value_for_sequence() {
        let yaml =
            "services:\n  app:\n    image: nginx\n    env_file:\n      - .env\n      - .env.prod\n";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, yaml);
        let value = match_value_for(&findings, "MANIFEST_DOCKER_COMPOSE_ENV_FILE")
            .expect("env_file finding should fire for non-empty sequence");
        assert_eq!(value, "app: .env, .env.prod");
        assert!(!value.contains("String("));
    }

    /// Contract: a `docker-compose.yml` whose body fails to parse MUST emit
    /// an explicit `MANIFEST_DOCKER_COMPOSE_PARSE_FAILURE` finding. Pre-fix
    /// the function silently returned `Vec::new()`, so an attacker could
    /// ship intentionally-broken YAML to suppress every host-mount /
    /// privilege / env_file detector in this file without leaving any audit
    /// trail of the manifest's existence.
    #[test]
    fn analyze_docker_compose_emits_parse_failure_finding_for_invalid_yaml() {
        // `:` after `services` must be followed by mapping indentation; a
        // bare scalar produces a parse error in serde_yaml.
        let bad = "services: [unterminated\n  app:\n    image: nginx\n";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, bad);
        assert!(
            finding_present(&findings, "MANIFEST_DOCKER_COMPOSE_PARSE_FAILURE"),
            "invalid YAML must produce a parse-failure finding; got {findings:?}",
        );
        // And no other detector should fire — there's no parsed structure
        // to derive host-mount / privileged / env_file findings from.
        let only_parse_failure = findings
            .iter()
            .all(|f| f.rule_id == "MANIFEST_DOCKER_COMPOSE_PARSE_FAILURE");
        assert!(
            only_parse_failure,
            "no other detector should fire on invalid YAML; got {findings:?}",
        );
    }

    /// Contract: a valid `docker-compose.yml` MUST NOT produce a parse-failure
    /// finding. Negative case for the parse-failure detector — pins that the
    /// gate is on the YAML error, not on the absence of services etc.
    #[test]
    fn analyze_docker_compose_does_not_emit_parse_failure_for_valid_yaml() {
        let good = "services:\n  app:\n    image: nginx:1.25\n";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, good);
        assert!(
            !finding_present(&findings, "MANIFEST_DOCKER_COMPOSE_PARSE_FAILURE"),
            "valid YAML must not produce a parse-failure finding; got {findings:?}",
        );
    }
}
