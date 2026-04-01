mod dependency_policy;
mod hook_policy;
mod lockfile_policy;

use crate::artifact_graph::ArtifactCapabilityFact;
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::ArtifactLink;
use self::dependency_policy::{
    cargo_dependency_findings, package_json_dependency_findings, pyproject_dependency_findings,
    requirements_txt_findings,
};
use self::hook_policy::{
    package_json_capabilities as hook_package_json_capabilities,
    package_json_install_hook_findings, package_json_relations as hook_package_json_relations,
    PackageBinaryExposure,
};
use self::lockfile_policy::{PackageJsonLockPolicy, PyprojectLockPolicy};
use serde_json::Value;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

pub(super) fn analyze_package_json(
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let artifact_path = path.display().to_string();

    findings.extend(package_json_dependency_findings(&json, &artifact_path));
    findings.extend(package_json_install_hook_findings(&json, &artifact_path));

    if PackageBinaryExposure::detect(&json) == PackageBinaryExposure::Exposed {
        findings.push(
            Finding::builder(
                "MANIFEST_PACKAGE_JSON_BIN_EXPOSED",
                ThreatCategory::ScopeCreep,
            )
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

    let expected_lockfiles = PackageJsonLockPolicy::detect(&json).expected_lockfiles();
    if !expected_lockfiles.is_empty() {
        findings.extend(super::super::missing_lockfile_findings(
            path,
            sibling_files,
            &expected_lockfiles,
            "MANIFEST_PACKAGE_JSON_MISSING_LOCKFILE",
            "JavaScript manifest has no matching nearby lockfile",
        ));
    }

    findings
}

pub(super) fn analyze_requirements_txt(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    requirements_txt_findings(content, &artifact_path)
}

pub(super) fn analyze_pyproject_toml(
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    let artifact_path = path.display().to_string();
    let mut findings = pyproject_dependency_findings(&toml, &artifact_path);

    let expected_lockfiles = PyprojectLockPolicy::detect(&toml).expected_lockfiles();
    if !expected_lockfiles.is_empty() {
        findings.extend(super::super::missing_lockfile_findings(
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
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    let artifact_path = path.display().to_string();
    let mut findings = cargo_dependency_findings(&toml, &artifact_path);

    findings.extend(super::super::missing_lockfile_findings(
        path,
        sibling_files,
        &["Cargo.lock"],
        "MANIFEST_CARGO_MISSING_LOCKFILE",
        "Cargo manifest has no matching nearby lockfile",
    ));

    findings
}

pub(super) fn package_json_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    hook_package_json_capabilities(&json)
}

pub(super) fn package_json_expected_lockfiles(content: &str) -> Vec<&'static str> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    PackageJsonLockPolicy::detect(&json).expected_lockfiles()
}

pub(super) fn pyproject_expected_lockfiles(content: &str) -> Vec<&'static str> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };
    PyprojectLockPolicy::detect(&toml).expected_lockfiles()
}

pub(super) fn package_json_relations(content: &str) -> Vec<ArtifactLink> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    hook_package_json_relations(&json)
}
