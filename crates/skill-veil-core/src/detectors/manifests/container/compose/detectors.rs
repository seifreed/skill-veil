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

use super::super::image_uses_mutable_latest;

/// Maximum YAML content size accepted by [`parse_compose_yaml`]. Beyond
/// this limit, the parse is rejected outright — deeply nested adversarial
/// YAML can cause stack overflow in `serde_yaml::from_str`, and legitimate
/// Docker Compose files are well under 1 MiB.
const MAX_YAML_CONTENT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum YAML nesting depth accepted by [`parse_compose_yaml`].
/// `serde_yaml` uses recursive descent parsing, so deeply nested YAML
/// within the size limit can still cause a stack overflow. Legitimate
/// Docker Compose files rarely exceed 10 levels; 64 provides ample
/// headroom without risking stack exhaustion.
const MAX_YAML_NESTING_DEPTH: usize = 64;

pub(super) fn parse_compose_yaml(content: &str) -> Result<serde_yaml::Value, String> {
    if content.len() > MAX_YAML_CONTENT_BYTES {
        return Err(format!(
            "YAML content exceeds {MAX_YAML_CONTENT_BYTES} byte limit (got {} bytes)",
            content.len()
        ));
    }
    let value = serde_yaml::from_str::<serde_yaml::Value>(content).map_err(|e| e.to_string())?;
    if yaml_nesting_depth(&value) > MAX_YAML_NESTING_DEPTH {
        return Err(format!(
            "YAML nesting depth exceeds {MAX_YAML_NESTING_DEPTH} level limit"
        ));
    }
    Ok(value)
}

/// Recursively compute the maximum nesting depth of a [`serde_yaml::Value`].
fn yaml_nesting_depth(value: &serde_yaml::Value) -> usize {
    match value {
        serde_yaml::Value::Mapping(m) => {
            1 + m
                .iter()
                .flat_map(|(k, v)| [yaml_nesting_depth(k), yaml_nesting_depth(v)])
                .max()
                .unwrap_or(0)
        }
        serde_yaml::Value::Sequence(s) => 1 + s.iter().map(yaml_nesting_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// A `docker-compose.yml` whose YAML body is unparseable is suspicious on
/// its own: the manifest is shipped, the rest of the analysis pipeline
/// (capabilities, relations) silently drops it for lack of structure, and
/// an attacker can intentionally craft "almost valid" YAML to bypass every
/// host-mount / privilege / env_file detector. Emit an explicit finding so
/// the manifest's existence — and our inability to analyze it — is recorded
/// in the audit output instead of being swallowed.
pub(super) fn parse_failure_finding(artifact_path: &str, err: &str) -> Finding {
    crate::detectors::manifests::manifest_parse_failure_finding(
        "MANIFEST_DOCKER_COMPOSE_PARSE_FAILURE",
        artifact_path,
        err.to_string(),
        "docker-compose manifest is not valid YAML; capability and \
         volume/env analyses cannot run against this file",
    )
}

pub(super) fn detect_latest_image_tag(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Option<Finding> {
    let image = mapping
        .get(serde_yaml::Value::String("image".to_string()))
        .and_then(serde_yaml::Value::as_str)?;
    if !image_uses_mutable_latest(image) {
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

/// Linux capabilities that grant kernel-level privileges equivalent to
/// `privileged: true` for many container-escape vectors. Sourced from
/// CIS Docker Benchmark §5.3 and the Trivy/Falco capability rationales:
///
/// - `SYS_ADMIN` — mount namespaces, eBPF, FUSE → full host kernel access.
/// - `NET_ADMIN` — full network stack control (route tables, firewall).
/// - `SYS_PTRACE` — ptrace any process; cross-container memory inspection.
/// - `SYS_MODULE` — load kernel modules.
/// - `DAC_OVERRIDE` / `DAC_READ_SEARCH` — bypass POSIX permission checks.
/// - `SYS_RAWIO` — direct port I/O and raw memory access.
/// - `SYS_BOOT` — reboot the host.
/// - `SYS_TIME` — set the system clock (covert channel / break TLS time).
/// - `MAC_ADMIN` / `MAC_OVERRIDE` — bypass MAC frameworks (SELinux, AppArmor).
/// - `AUDIT_CONTROL` — disable kernel auditing (anti-forensics).
const DANGEROUS_LINUX_CAPABILITIES: &[&str] = &[
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "SYS_RAWIO",
    "SYS_BOOT",
    "SYS_TIME",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "AUDIT_CONTROL",
];

/// Normalise a capability token from compose `cap_add`. Compose accepts
/// both the bare CIS form (`SYS_ADMIN`) and the kernel-prefixed form
/// (`CAP_SYS_ADMIN`) interchangeably; emit a canonical bare form for
/// matching against [`DANGEROUS_LINUX_CAPABILITIES`].
fn canonicalise_capability(raw: &str) -> String {
    let stripped = raw
        .trim()
        .trim_start_matches("cap_")
        .trim_start_matches("CAP_");
    stripped.to_ascii_uppercase()
}

pub(super) fn detect_dangerous_cap_add(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Vec<Finding> {
    let Some(cap_add) = mapping
        .get(serde_yaml::Value::String("cap_add".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return Vec::new();
    };
    cap_add
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .filter_map(|raw| {
            let canonical = canonicalise_capability(raw);
            DANGEROUS_LINUX_CAPABILITIES
                .contains(&canonical.as_str())
                .then_some((raw, canonical))
        })
        .map(|(raw, canonical)| {
            Finding::builder(
                "MANIFEST_DOCKER_COMPOSE_DANGEROUS_CAP_ADD",
                ThreatCategory::PrivilegeEscalation,
            )
            .severity(Severity::High)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Behavior)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .artifact(
                ArtifactKind::PackageManifest,
                Some(artifact_path.to_string()),
            )
            .match_value(format!("{service_name}: cap_add={raw}"))
            .reason(format!(
                "docker-compose service requests dangerous Linux capability {canonical} \
                 — equivalent to privileged execution for container-escape vectors"
            ))
            .build()
        })
        .collect()
}

/// `true` when `mapping` declares any high-risk Linux capability via
/// `cap_add`. Used by capability inference (`docker_compose_capabilities`)
/// to raise `PrivilegedRuntime` so the verdict pipeline treats `cap_add:
/// [SYS_ADMIN]` the same as `privileged: true`.
pub(super) fn mapping_declares_dangerous_cap(mapping: &serde_yaml::Mapping) -> bool {
    let Some(cap_add) = mapping
        .get(serde_yaml::Value::String("cap_add".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return false;
    };
    cap_add
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .any(|raw| {
            let canonical = canonicalise_capability(raw);
            DANGEROUS_LINUX_CAPABILITIES.contains(&canonical.as_str())
        })
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
    if !is_host_network_mode(network_mode) {
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

pub(super) fn mapping_declares_host_network(mapping: &serde_yaml::Mapping) -> bool {
    mapping
        .get(serde_yaml::Value::String("network_mode".to_string()))
        .and_then(serde_yaml::Value::as_str)
        .is_some_and(is_host_network_mode)
}

fn is_host_network_mode(network_mode: &str) -> bool {
    matches!(network_mode, "host" | "service:host")
}

/// Host-namespace share keys. `pid: host` joins the host PID namespace
/// (enabling `nsenter` into host PID 1 → host root); `ipc: host` shares the
/// host IPC namespace (shared-memory access to host processes). `service:` /
/// `container:` targets are not host shares.
const HOST_NAMESPACE_KEYS: &[&str] = &["pid", "ipc"];

pub(super) fn detect_host_namespace(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Vec<Finding> {
    HOST_NAMESPACE_KEYS
        .iter()
        .filter_map(|key| {
            let mode = mapping
                .get(serde_yaml::Value::String((*key).to_string()))
                .and_then(serde_yaml::Value::as_str)?;
            (mode.trim() == "host").then(|| {
                Finding::builder(
                    "MANIFEST_DOCKER_COMPOSE_HOST_NAMESPACE",
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
                .match_value(format!("{service_name}: {key}=host"))
                .reason("docker-compose service shares a host namespace (pid/ipc), enabling escape to host processes")
                .build()
            })
        })
        .collect()
}

pub(super) fn detect_unconfined_security_opt(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Vec<Finding> {
    let Some(opts) = mapping
        .get(serde_yaml::Value::String("security_opt".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return Vec::new();
    };
    opts.iter()
        .filter_map(serde_yaml::Value::as_str)
        .filter(|opt| security_opt_is_unconfined(opt))
        .map(|opt| {
            Finding::builder(
                "MANIFEST_DOCKER_COMPOSE_UNCONFINED",
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
            .match_value(format!("{service_name}: security_opt={opt}"))
            .reason("docker-compose service disables its seccomp/AppArmor sandbox (unconfined)")
            .build()
        })
        .collect()
}

/// `seccomp`/`apparmor` set to `unconfined` (via `:` or `=`). A custom profile
/// path or the hardening `no-new-privileges:true` must NOT match.
fn security_opt_is_unconfined(opt: &str) -> bool {
    let lower = opt.to_ascii_lowercase();
    (lower.starts_with("seccomp") || lower.starts_with("apparmor")) && lower.contains("unconfined")
}

/// Raw host device prefixes that grant direct hardware access (whole-disk,
/// physical memory, I/O ports). Deliberately excludes common benign device
/// mappings such as GPUs (`/dev/dri`, `/dev/nvidia*`) and sound (`/dev/snd`).
const DANGEROUS_HOST_DEVICE_PREFIXES: &[&str] = &[
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
    "/dev/sd",
    "/dev/hd",
    "/dev/nvme",
    "/dev/vd",
    "/dev/xvd",
    "/dev/disk",
    "/dev/loop",
];

pub(super) fn detect_host_devices(
    service_name: &str,
    mapping: &serde_yaml::Mapping,
    artifact_path: &str,
) -> Vec<Finding> {
    let Some(devices) = mapping
        .get(serde_yaml::Value::String("devices".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return Vec::new();
    };
    devices
        .iter()
        .filter_map(device_host_path)
        .filter(|host_path| is_dangerous_host_device(host_path))
        .map(|host_path| {
            Finding::builder(
                "MANIFEST_DOCKER_COMPOSE_HOST_DEVICE",
                ThreatCategory::PrivilegeEscalation,
            )
            .severity(Severity::High)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Behavior)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .artifact(
                ArtifactKind::PackageManifest,
                Some(artifact_path.to_string()),
            )
            .match_value(format!("{service_name}: {host_path}"))
            .reason("docker-compose service maps a raw host disk/memory device into the container")
            .build()
        })
        .collect()
}

/// Extract the host-side path of a compose `devices` entry. Short syntax is
/// `"HOST:CONTAINER[:perms]"`; long syntax is `{source: HOST, target: ...}`.
fn device_host_path(value: &serde_yaml::Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        return Some(s.split(':').next().unwrap_or(s).trim().to_string());
    }
    value
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::String("source".to_string())))
        .and_then(serde_yaml::Value::as_str)
        .map(|s| s.trim().to_string())
}

fn is_dangerous_host_device(host_path: &str) -> bool {
    let lower = host_path.to_ascii_lowercase();
    DANGEROUS_HOST_DEVICE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// `true` when a service declares a host-namespace share or disables its
/// sandbox — used by capability inference to raise `PrivilegedRuntime`, so the
/// verdict pipeline treats these escapes the same as `privileged: true`.
pub(super) fn mapping_declares_namespace_or_security_escape(mapping: &serde_yaml::Mapping) -> bool {
    let host_ns = HOST_NAMESPACE_KEYS.iter().any(|key| {
        mapping
            .get(serde_yaml::Value::String((*key).to_string()))
            .and_then(serde_yaml::Value::as_str)
            .is_some_and(|mode| mode.trim() == "host")
    });
    let unconfined = mapping
        .get(serde_yaml::Value::String("security_opt".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .is_some_and(|opts| {
            opts.iter()
                .filter_map(serde_yaml::Value::as_str)
                .any(security_opt_is_unconfined)
        });
    let host_device = mapping
        .get(serde_yaml::Value::String("devices".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .is_some_and(|devices| {
            devices
                .iter()
                .filter_map(device_host_path)
                .any(|host_path| is_dangerous_host_device(&host_path))
        });
    host_ns || unconfined || host_device
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
