use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::ArtifactAnalysisService;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

pub(crate) fn analyze_cargo_toml(
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

    // Suppress unpinned dep findings when Cargo.lock exists, since the
    // lockfile pins exact versions. In Cargo, `^` is the default operator.
    let has_lockfile = super::sibling_has_file(sibling_files, "Cargo.lock");

    if !has_lockfile {
        if let Some(dependencies) = toml.get("dependencies").and_then(TomlValue::as_table) {
            findings.extend(
                dependencies.iter().filter_map(|(name, dep)| {
                    cargo_unpinned_dep_finding(name, dep, &artifact_path)
                }),
            );
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

pub(crate) fn cargo_toml_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    let mut dep_names = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(deps) = toml.get(section).and_then(TomlValue::as_table) {
            dep_names.extend(deps.keys().map(String::as_str));
        }
    }

    let network_crates = [
        "reqwest",
        "hyper",
        "surf",
        "ureq",
        "attohttpc",
        "tonic",
        "tarpc",
    ];
    let exec_crates = ["nix", "command-fds", "duct"];
    let mut capabilities = Vec::new();

    for dep in &dep_names {
        let name = dep.to_ascii_lowercase();
        if network_crates.iter().any(|d| name == *d) {
            capabilities.push(ArtifactAnalysisService::observed_capability(
                ArtifactCapability::NetworkAccess,
            ));
        }
        if exec_crates.iter().any(|d| name == *d) {
            capabilities.push(ArtifactAnalysisService::observed_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }
    capabilities.dedup_by_key(|c| c.capability);
    capabilities
}

fn cargo_unpinned_dep_finding(name: &str, dep: &TomlValue, artifact_path: &str) -> Option<Finding> {
    let version = match dep {
        TomlValue::String(v) => Some(v.as_str()),
        TomlValue::Table(t) => t.get("version").and_then(TomlValue::as_str),
        _ => None,
    }?;
    if !(version.starts_with('^') || version.starts_with('~') || version == "*") {
        return None;
    }
    Some(
        Finding::builder("MANIFEST_CARGO_UNPINNED_DEP", ThreatCategory::SupplyChain)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .evidence_kind(EvidenceKind::Context)
            .artifact(
                ArtifactKind::PackageManifest,
                Some(artifact_path.to_string()),
            )
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .match_value(format!("{name} = {version}"))
            .reason("Cargo dependency is not strictly pinned")
            .build(),
    )
}
