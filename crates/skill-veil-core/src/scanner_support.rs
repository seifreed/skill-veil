use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::policy::{
    load_baseline, load_policy, load_waivers, BaselineFile, PolicyFile, WaiverFile,
};
use crate::ports::{FileSystemError, FileSystemProvider};
use crate::scanner::ScanError;
use crate::services::{DOCKER_COMPOSE_NAMES, MCP_NAMES, TOML_ARTIFACT_NAMES};
use std::path::Path;

/// JSON-shaped manifest filenames recognised by `structured_parse_warning`.
/// `npm-shrinkwrap.json` is included because it is a semantic alternative
/// to `package-lock.json` (both produced by npm; both consumed by the
/// `lockfiles::analyze_package_lock` analyzer per dispatch.rs:53). Pre-fix
/// the list omitted it, so a malformed `npm-shrinkwrap.json` never emitted
/// `ARTIFACT_PARSE_WARNING` even though the dispatcher routed it to the
/// same lockfile analyzer.
const JSON_MANIFEST_NAMES: &[&str] = &["package.json", "package-lock.json", "npm-shrinkwrap.json"];

pub(crate) fn read_text_file_lossy<F: FileSystemProvider>(
    path: &Path,
    fs: &F,
) -> Result<(String, bool), FileSystemError> {
    let bytes = fs.read_file_bytes(path)?.as_bytes().to_vec();
    let decode_warning = std::str::from_utf8(&bytes).is_err();
    Ok((String::from_utf8_lossy(&bytes).into_owned(), decode_warning))
}

/// Builds the Critical/Block finding for an artifact whose bytes start
/// with binary magic but whose path advertises markdown. `kind` is the
/// magic-family label (`"ZIP"`, `"ELF"`, ...). `match_target` lets
/// callers point at either the document itself (entrypoint case) or a
/// referenced file.
pub(crate) fn binary_disguise_finding(
    path: &Path,
    kind: &str,
    artifact_kind: ArtifactKind,
    match_target: MatchTarget,
) -> Finding {
    let artifact_path = path.display().to_string();
    Finding::builder(
        "ARTIFACT_BINARY_DISGUISED_AS_MARKDOWN",
        ThreatCategory::Obfuscation,
    )
    .severity(Severity::Critical)
    .action(RecommendedAction::Block)
    .evidence_kind(EvidenceKind::Behavior)
    .signal_class(crate::findings::SignalClass::MaliciousBehavior)
    .matched_on(match_target)
    .artifact(artifact_kind, Some(artifact_path))
    .match_value(format!("{kind} archive disguised as markdown"))
    .reason(
        "Markdown-named artifact starts with binary magic bytes — content obfuscation / payload smuggling",
    )
    .build()
}

pub(crate) fn decode_warning_finding(path: &Path, artifact_kind: ArtifactKind) -> Finding {
    Finding::builder("ARTIFACT_DECODE_WARNING", crate::findings::ThreatCategory::Generic)
        .severity(Severity::Low)
        .action(RecommendedAction::Log)
        .evidence_kind(crate::findings::EvidenceKind::Context)
        .artifact(artifact_kind, Some(path.display().to_string()))
        .match_value(path.display().to_string())
        .reason("Artifact required lossy UTF-8 decoding during analysis")
        .remediation("Review the artifact encoding manually. Lossy decoding was used so the package could still be analyzed.")
        .signal_class(crate::findings::SignalClass::ReviewSignal)
        .build()
}

pub(crate) fn parse_warning_finding(
    path: &Path,
    artifact_kind: ArtifactKind,
    reason: &str,
) -> Finding {
    Finding::builder("ARTIFACT_PARSE_WARNING", crate::findings::ThreatCategory::Generic)
        .severity(Severity::Low)
        .action(RecommendedAction::Log)
        .evidence_kind(crate::findings::EvidenceKind::Context)
        .artifact(artifact_kind, Some(path.display().to_string()))
        .match_value(path.display().to_string())
        .reason(reason)
        .remediation(
            "Review the artifact manually. Structured parsing failed, so analysis used a defensive fallback.",
        )
        .signal_class(crate::findings::SignalClass::ReviewSignal)
        .build()
}

pub(crate) fn artifact_parse_error_finding(
    path: &Path,
    artifact_kind: ArtifactKind,
    error_msg: &str,
) -> Finding {
    Finding::builder("ARTIFACT_PARSE_ERROR", crate::findings::ThreatCategory::Obfuscation)
        .severity(Severity::Medium)
        .action(RecommendedAction::RequireApproval)
        .evidence_kind(crate::findings::EvidenceKind::Context)
        .artifact(artifact_kind, Some(path.display().to_string()))
        .match_value(path.display().to_string())
        .reason(format!(
            "Referenced artifact could not be parsed: {}",
            error_msg
        ))
        .remediation(
            "Review the artifact manually. The file exists but could not be parsed as markdown or code, which may indicate obfuscation or corruption.",
        )
        .signal_class(crate::findings::SignalClass::SuspiciousPackageBehavior)
        .build()
}

pub(crate) fn structured_parse_warning(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
    let name = file_name.as_str();
    const YAML_LOCKFILE_NAMES: &[&str] = &["pnpm-lock.yaml", "yarn.lock"];
    let mcp_json = MCP_NAMES.contains(&name) && name.ends_with(".json");
    let mcp_yaml = MCP_NAMES.contains(&name) && !name.ends_with(".json");
    let is_json = JSON_MANIFEST_NAMES.contains(&name) || mcp_json;
    let is_yaml =
        DOCKER_COMPOSE_NAMES.contains(&name) || YAML_LOCKFILE_NAMES.contains(&name) || mcp_yaml;
    let parse_failed = if is_json {
        serde_json::from_str::<serde_json::Value>(content).is_err()
    } else if is_yaml {
        serde_yaml::from_str::<serde_yaml::Value>(content).is_err()
    } else if TOML_ARTIFACT_NAMES.contains(&name) {
        toml::from_str::<toml::Value>(content).is_err()
    } else {
        false
    };

    parse_failed.then(|| {
        parse_warning_finding(
            path,
            artifact_kind,
            "Artifact could not be fully parsed as its expected structured format",
        )
    })
}

pub(crate) fn load_optional_baseline<F: FileSystemProvider>(
    fs: &F,
    path: Option<&Path>,
) -> Result<Option<BaselineFile>, ScanError> {
    path.map(|p| load_baseline(fs, p))
        .transpose()
        .map_err(ScanError::Policy)
}

pub(crate) fn load_optional_waivers<F: FileSystemProvider>(
    fs: &F,
    path: Option<&Path>,
) -> Result<Option<WaiverFile>, ScanError> {
    path.map(|p| load_waivers(fs, p))
        .transpose()
        .map_err(ScanError::Policy)
}

pub(crate) fn load_optional_policy<F: FileSystemProvider>(
    fs: &F,
    path: Option<&Path>,
) -> Result<Option<PolicyFile>, ScanError> {
    path.map(|p| load_policy(fs, p))
        .transpose()
        .map_err(ScanError::Policy)
}
