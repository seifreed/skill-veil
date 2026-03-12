use crate::findings::{ArtifactKind, Finding, RecommendedAction, Severity};
use crate::policy::{
    load_baseline, load_policy, load_waivers, BaselineFile, PolicyFile, WaiverFile,
};
use crate::scanner::ScanError;
use std::path::Path;

pub(crate) fn read_text_file_lossy(path: &Path) -> Result<(String, bool), std::io::Error> {
    let bytes = std::fs::read(path)?;
    let decode_warning = std::str::from_utf8(&bytes).is_err();
    Ok((String::from_utf8_lossy(&bytes).into_owned(), decode_warning))
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

pub(crate) fn structured_parse_warning(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
    let parse_failed = match file_name.as_str() {
        "package.json" | "package-lock.json" | "mcp.json" => {
            serde_json::from_str::<serde_json::Value>(content).is_err()
        }
        "docker-compose.yml"
        | "docker-compose.yaml"
        | "mcp.yaml"
        | "mcp.yml"
        | "pnpm-lock.yaml"
        | "yarn.lock" => serde_yaml::from_str::<serde_yaml::Value>(content).is_err(),
        "cargo.toml" | "pyproject.toml" => toml::from_str::<toml::Value>(content).is_err(),
        _ => false,
    };

    parse_failed.then(|| {
        parse_warning_finding(
            path,
            artifact_kind,
            "Artifact could not be fully parsed as its expected structured format",
        )
    })
}

pub(crate) fn load_optional_baseline(
    path: Option<&Path>,
) -> Result<Option<BaselineFile>, ScanError> {
    path.map(load_baseline).transpose().map_err(ScanError::Io)
}

pub(crate) fn load_optional_waivers(path: Option<&Path>) -> Result<Option<WaiverFile>, ScanError> {
    path.map(load_waivers).transpose().map_err(ScanError::Io)
}

pub(crate) fn load_optional_policy(path: Option<&Path>) -> Result<Option<PolicyFile>, ScanError> {
    path.map(load_policy).transpose().map_err(ScanError::Io)
}
