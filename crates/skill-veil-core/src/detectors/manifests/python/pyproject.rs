//! `pyproject.toml` detector: PEP 621 `dependencies` array, Poetry's
//! `tool.poetry.dependencies` table, and lockfile expectations driven by
//! the build backend (Poetry → `poetry.lock`, uv → `uv.lock`).

use std::path::{Path, PathBuf};

use toml::Value as TomlValue;

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::ArtifactOrchestratorService;

use super::{parse_python_dep_name, PYTHON_EXEC_DEPS, PYTHON_NETWORK_DEPS};

pub(crate) fn analyze_pyproject_toml(
    service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();

    if let Some(dependencies) = toml
        .get("project")
        .and_then(|project| project.get("dependencies"))
        .and_then(TomlValue::as_array)
    {
        for dependency in dependencies.iter().filter_map(TomlValue::as_str) {
            if !(dependency.contains("==") || dependency.contains("~=") || dependency.contains("@"))
            {
                findings.push(
                    Finding::builder(
                        "MANIFEST_PYPROJECT_UNPINNED_DEP",
                        ThreatCategory::SupplyChain,
                    )
                    .severity(Severity::Low)
                    .action(RecommendedAction::Log)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(dependency)
                    .reason("pyproject dependency is not strictly pinned")
                    .build(),
                );
            }
        }
    }

    let expected_lockfiles = pyproject_expected_lockfiles(content);
    if !expected_lockfiles.is_empty() {
        findings.extend(service.missing_lockfile_findings(
            path,
            sibling_files,
            &expected_lockfiles,
            "MANIFEST_PYPROJECT_MISSING_LOCKFILE",
            "pyproject manifest has no matching nearby lockfile",
        ));
    }

    findings
}

pub(crate) fn pyproject_toml_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    let mut dep_strings = Vec::new();
    if let Some(deps) = toml
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(TomlValue::as_array)
    {
        dep_strings.extend(deps.iter().filter_map(TomlValue::as_str));
    }
    if let Some(deps) = toml
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(TomlValue::as_table)
    {
        dep_strings.extend(deps.keys().map(String::as_str));
    }

    let mut capabilities = Vec::new();

    for dep in &dep_strings {
        let Some(dep_name) = parse_python_dep_name(dep.trim()) else {
            continue;
        };
        if PYTHON_NETWORK_DEPS.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactOrchestratorService::observed_capability(
                ArtifactCapability::NetworkAccess,
            ));
        }
        if PYTHON_EXEC_DEPS.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactOrchestratorService::observed_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }
    // `dedup_by_key` only collapses adjacent runs; deps emit interleaved
    // capabilities, so sort first.
    capabilities.sort_by_key(|c| c.capability);
    capabilities.dedup_by_key(|c| c.capability);
    capabilities
}

pub(crate) fn pyproject_expected_lockfiles(content: &str) -> Vec<&'static str> {
    let Ok(toml) = content.parse::<TomlValue>() else {
        return Vec::new();
    };

    if toml
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .is_some()
    {
        return vec!["poetry.lock"];
    }
    if toml.get("tool").and_then(|tool| tool.get("uv")).is_some() {
        return vec!["uv.lock"];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_present(caps: &[ArtifactCapabilityFact], target: ArtifactCapability) -> bool {
        caps.iter().any(|fact| fact.capability == target)
    }

    /// Contract: same VCS / PEP 508 recovery applies to `pyproject.toml`
    /// dependencies (PEP 621 `dependencies` array). The two paths share
    /// `parse_python_dep_name` so this test pins that the helper is wired
    /// in both places.
    #[test]
    fn pyproject_toml_capabilities_detects_pep508_direct_reference() {
        let content = r#"[project]
name = "x"
version = "0"
dependencies = ["requests @ git+https://github.com/psf/requests.git"]
"#;
        let caps = pyproject_toml_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "PEP 508 direct reference in pyproject must flip NetworkAccess; got {caps:?}",
        );
    }

    /// # Contract
    /// Same dedup contract for `pyproject.toml`. The pre-fix `dedup_by_key`
    /// silently passed when all deps of one kind were grouped together, so
    /// the regression only surfaces when the array intentionally interleaves
    /// network and exec deps.
    #[test]
    fn pyproject_toml_capabilities_collapses_interleaved_capabilities() {
        let content = r#"[project]
name = "x"
version = "0"
dependencies = ["requests", "fabric", "httpx", "invoke"]
"#;
        let caps = pyproject_toml_capabilities(content);
        let net_count = caps
            .iter()
            .filter(|c| c.capability == ArtifactCapability::NetworkAccess)
            .count();
        let exec_count = caps
            .iter()
            .filter(|c| c.capability == ArtifactCapability::ProcessExecution)
            .count();
        assert_eq!(net_count, 1, "NetworkAccess must appear once; got {caps:?}");
        assert_eq!(
            exec_count, 1,
            "ProcessExecution must appear once; got {caps:?}",
        );
    }
}
