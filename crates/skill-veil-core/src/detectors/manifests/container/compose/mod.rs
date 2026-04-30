//! docker-compose manifest analysis: findings, capability inference,
//! and artifact relations. The per-detector emission helpers
//! (`detect_latest_image_tag`, `detect_privileged`, …) live in the
//! sibling [`detectors`] submodule. This module owns the public API
//! and the iteration helpers that walk the `services` mapping shared
//! by all three entry points.
//!
//! Volume + env_file classifiers shared with these detectors live in
//! `super::volumes`. Dockerfile logic lives in the parent
//! `dockerfile` module.

mod detectors;

use std::path::Path;

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::Finding;
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};

use super::volumes::{env_file_has_real_paths, is_sensitive_host_volume, volume_entry_string};
use detectors::{
    detect_env_file, detect_host_network, detect_host_volumes, detect_latest_image_tag,
    detect_privileged, parse_compose_yaml, parse_failure_finding,
};

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
    for_each_service(services, |service_name, mapping| {
        findings.extend(detect_latest_image_tag(
            service_name,
            mapping,
            &artifact_path,
        ));
        findings.extend(detect_privileged(service_name, mapping, &artifact_path));
        findings.extend(detect_host_volumes(service_name, mapping, &artifact_path));
        findings.extend(detect_host_network(service_name, mapping, &artifact_path));
        findings.extend(detect_env_file(service_name, mapping, &artifact_path));
    });
    findings
}

/// Parse the docker-compose YAML body and call `visit` once per service
/// mapping. Silent on parse failure: callers that need to surface
/// invalid YAML (such as [`analyze_docker_compose`]) should call
/// [`detectors::parse_compose_yaml`] directly. Callers that only care
/// about well-formed manifests (capabilities, relations) use this
/// helper to avoid restating the parse + `services` lookup +
/// per-service destructure boilerplate.
fn with_compose_services<F: FnMut(&str, &serde_yaml::Mapping)>(content: &str, mut visit: F) {
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return;
    };
    let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
        return;
    };
    for_each_service(services, |service_name, mapping| {
        visit(service_name, mapping);
    });
}

/// Iterate the entries of an already-resolved `services` mapping,
/// skipping entries whose value is not a mapping.
fn for_each_service<F: FnMut(&str, &serde_yaml::Mapping)>(
    services: &serde_yaml::Mapping,
    mut visit: F,
) {
    for (raw_name, service) in services {
        let service_name = raw_name.as_str().unwrap_or("unknown");
        let Some(mapping) = service.as_mapping() else {
            continue;
        };
        visit(service_name, mapping);
    }
}

pub(crate) fn docker_compose_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities: Vec<ArtifactCapabilityFact> = Vec::new();

    with_compose_services(content, |_, mapping| {
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
            // Pre-fix this called `volume.as_str()` directly, missing
            // long-syntax bind mounts; route through
            // `volume_entry_string` so both shapes raise the
            // capability consistently with the finding pass.
            if volumes.iter().any(|volume| {
                volume_entry_string(volume).is_some_and(|v| is_sensitive_host_volume(&v))
            }) && !capabilities.iter().any(|fact| {
                fact.capability == ArtifactCapability::HostFilesystemAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
            }) {
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
    });

    capabilities
}

pub(crate) fn docker_compose_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links: Vec<ArtifactLink> = Vec::new();
    with_compose_services(content, |_, mapping| {
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
    });
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

    /// Contract: the long-syntax bind mount MUST raise
    /// `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT` when its `source` is the
    /// docker socket. Pre-fix `detect_host_volumes` filtered with
    /// `Value::as_str`, silently skipping every long-syntax entry, so
    /// an attacker could mount the host control plane via
    /// `{type: bind, source: /var/run/docker.sock, target: ...}` and
    /// bypass the finding entirely.
    #[test]
    fn analyze_docker_compose_detects_long_syntax_docker_socket_mount() {
        let yaml = "\
services:
  app:
    image: nginx
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, yaml);
        assert!(
            finding_present(&findings, "MANIFEST_DOCKER_COMPOSE_HOST_MOUNT"),
            "long-syntax docker-socket bind mount must fire HOST_MOUNT; got {findings:?}",
        );
    }

    /// Contract: the long-syntax fix is mirrored on the capability
    /// pass — `HostFilesystemAccess` and `FilesystemWrite` MUST both
    /// escalate when a long-syntax bind mount targets a sensitive host
    /// path. Pins both halves of the pre-fix bypass: not only did the
    /// finding go missing, but the verdict pipeline also lost the
    /// capability that drives blast-radius scoring.
    #[test]
    fn docker_compose_capabilities_detect_long_syntax_etc_mount() {
        let yaml = "\
services:
  app:
    image: nginx
    volumes:
      - type: bind
        source: /etc
        target: /host-etc
";
        let caps = docker_compose_capabilities(yaml);
        assert!(
            capability_present(&caps, ArtifactCapability::HostFilesystemAccess),
            "long-syntax /etc bind mount must escalate HostFilesystemAccess; got {caps:?}",
        );
        assert!(
            capability_present(&caps, ArtifactCapability::FilesystemWrite),
            "long-syntax /etc bind mount must escalate FilesystemWrite; got {caps:?}",
        );
    }

    /// Contract: long-syntax `type: volume` is a named docker volume,
    /// NOT a host bind, and MUST NOT escalate `HostFilesystemAccess`
    /// even when `source` happens to look like a host path. Pins the
    /// negative half of the bug-1 fix so a future refactor can't widen
    /// the classifier into named volumes.
    #[test]
    fn docker_compose_capabilities_skip_long_syntax_named_volume() {
        let yaml = "\
services:
  app:
    image: nginx
    volumes:
      - type: volume
        source: db-data
        target: /var/lib/db
";
        let caps = docker_compose_capabilities(yaml);
        assert!(
            !capability_present(&caps, ArtifactCapability::HostFilesystemAccess),
            "named volume must not escalate HostFilesystemAccess; got {caps:?}",
        );
    }

    /// Contract: a project-relative bind mount whose destination merely
    /// *starts* with `host` (e.g. `:/hostname`) is NOT a host alias and
    /// MUST NOT raise `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT`. Pre-fix the
    /// destination check was a `volume.contains(":/host")` substring
    /// match, falsely classifying every legitimate `:/host*` mount as
    /// sensitive.
    #[test]
    fn analyze_docker_compose_skips_host_alias_lookalike_destinations() {
        let yaml = "\
services:
  app:
    image: nginx
    volumes:
      - \"./data:/hostname\"
      - \"./data:/host-backup\"
      - \"./data:/hostpath\"
";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, yaml);
        assert!(
            !finding_present(&findings, "MANIFEST_DOCKER_COMPOSE_HOST_MOUNT"),
            "`/host*` look-alike destinations on relative sources must not fire HOST_MOUNT; got {findings:?}",
        );
        let caps = docker_compose_capabilities(yaml);
        assert!(
            !capability_present(&caps, ArtifactCapability::HostFilesystemAccess),
            "`/host*` look-alike destinations must not escalate HostFilesystemAccess; got {caps:?}",
        );
    }

    /// Contract: the actual `:/host` alias still fires (positive
    /// regression guard for the bounded destination check).
    #[test]
    fn analyze_docker_compose_detects_exact_host_alias_destination() {
        let yaml = "\
services:
  app:
    image: nginx
    volumes:
      - \"./data:/host:ro\"
";
        let path = std::path::Path::new("/pkg/docker-compose.yml");
        let findings = analyze_docker_compose(path, yaml);
        assert!(
            finding_present(&findings, "MANIFEST_DOCKER_COMPOSE_HOST_MOUNT"),
            "exact `:/host` alias must still fire HOST_MOUNT; got {findings:?}",
        );
    }
}
