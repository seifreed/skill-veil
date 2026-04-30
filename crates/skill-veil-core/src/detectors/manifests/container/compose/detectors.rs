//! Per-detector helpers for `analyze_docker_compose`. Each function
//! inspects one service-level field (image tag, privileged flag,
//! sensitive volumes, host network mode, env_file) and emits the
//! corresponding finding(s). `parse_compose_yaml` and
//! `parse_failure_finding` live here too because they are part of the
//! detection contract: the parse-failure finding is itself a detector
//! output that records the manifest's presence when its body is
//! unparseable.

use crate::detectors::manifests::container::volumes::{
    env_file_has_real_paths, is_sensitive_host_volume, render_env_file, volume_entry_string,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

pub(super) fn parse_compose_yaml(content: &str) -> Result<serde_yaml::Value, serde_yaml::Error> {
    serde_yaml::from_str::<serde_yaml::Value>(content)
}

/// A `docker-compose.yml` whose YAML body is unparseable is suspicious on
/// its own: the manifest is shipped, the rest of the analysis pipeline
/// (capabilities, relations) silently drops it for lack of structure, and
/// an attacker can intentionally craft "almost valid" YAML to bypass every
/// host-mount / privilege / env_file detector. Emit an explicit finding so
/// the manifest's existence — and our inability to analyze it — is recorded
/// in the audit output instead of being swallowed.
pub(super) fn parse_failure_finding(artifact_path: &str, err: &serde_yaml::Error) -> Finding {
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

pub(super) fn detect_latest_image_tag(
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

pub(super) fn detect_privileged(
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

pub(super) fn detect_host_volumes(
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
        // Pre-fix this filtered with `Value::as_str`, silently dropping
        // long-syntax bind mounts (`{type: bind, source: ..., target:
        // ...}`). `volume_entry_string` accepts both shapes and yields
        // the equivalent `SOURCE[:TARGET]` string for classification.
        .filter_map(volume_entry_string)
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

pub(super) fn detect_host_network(
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

pub(super) fn detect_env_file(
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
