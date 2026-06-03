//! `pyproject.toml` detector: PEP 621 `dependencies` array, Poetry's
//! `tool.poetry.dependencies` table, and lockfile expectations driven by
//! the build backend (Poetry → `poetry.lock`, uv → `uv.lock`).

use std::path::{Path, PathBuf};

use toml::Value as TomlValue;

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact};
use crate::findings::Finding;
use crate::services::artifact_orchestration::ArtifactOrchestratorService;

use super::{parse_python_dep_name, PYTHON_EXEC_DEPS, PYTHON_NETWORK_DEPS};

pub(crate) fn analyze_pyproject_toml(
    service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let toml = match content.parse::<TomlValue>() {
        Ok(value) => value,
        Err(err) => return vec![pyproject_parse_failure_finding(&artifact_path, &err)],
    };

    let mut findings = Vec::new();

    if let Some(dependencies) = toml
        .get("project")
        .and_then(|project| project.get("dependencies"))
        .and_then(TomlValue::as_array)
    {
        for dependency in dependencies.iter().filter_map(TomlValue::as_str) {
            if is_unpinned_pep621_dependency(dependency) {
                findings.push(pyproject_unpinned_dep_finding(
                    &artifact_path,
                    dependency.to_string(),
                ));
            }
        }
    }

    if let Some(dependencies) = toml
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|poetry| poetry.get("dependencies"))
        .and_then(TomlValue::as_table)
    {
        for (name, spec) in dependencies {
            if name.eq_ignore_ascii_case("python") {
                continue;
            }
            if is_unpinned_poetry_dependency(spec) {
                findings.push(pyproject_unpinned_dep_finding(
                    &artifact_path,
                    poetry_dependency_match_value(name, spec),
                ));
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

fn pyproject_unpinned_dep_finding(artifact_path: &str, match_value: String) -> Finding {
    super::super::manifest_unpinned_dep_finding(
        "MANIFEST_PYPROJECT_UNPINNED_DEP",
        artifact_path,
        match_value,
        "pyproject dependency is not strictly pinned",
    )
}

fn is_unpinned_pep621_dependency(dependency: &str) -> bool {
    // Strip the PEP 508 environment marker (`requests; python_version ==
    // '3.8'`) before testing for a version operator: the `==`/`~=` inside
    // a marker compares a marker variable, not a package version, so
    // checking the whole string let a floating dependency masquerade as
    // pinned. The version constraint, if any, lives in the requirement
    // part before the `;`.
    let requirement = dependency.split(';').next().unwrap_or(dependency);
    !(requirement.contains("==") || requirement.contains("~=") || requirement.contains("@"))
}

fn is_unpinned_poetry_dependency(spec: &TomlValue) -> bool {
    if let Some(version) = spec.as_str() {
        return is_unpinned_poetry_version(version);
    }
    spec.get("version")
        .and_then(TomlValue::as_str)
        .is_some_and(is_unpinned_poetry_version)
}

fn is_unpinned_poetry_version(version: &str) -> bool {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(lower.as_str(), "*" | "latest") {
        return true;
    }
    if trimmed.starts_with(['^', '~', '>', '<', '!']) {
        return true;
    }
    if trimmed.contains('*') || trimmed.contains(',') || trimmed.contains("||") {
        return true;
    }
    !is_exact_poetry_version_pin(trimmed)
}

fn is_exact_poetry_version_pin(version: &str) -> bool {
    let version = version.strip_prefix("==").unwrap_or(version);
    super::super::version_pin::is_exact_dotted_version_pin(version)
}

fn poetry_dependency_match_value(name: &str, spec: &TomlValue) -> String {
    if let Some(version) = spec.as_str() {
        return format!("{name}@{version}");
    }
    if let Some(version) = spec.get("version").and_then(TomlValue::as_str) {
        return format!("{name}@{version}");
    }
    name.to_string()
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
    super::super::dedup_capabilities_by_kind(&mut capabilities);
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

/// A `pyproject.toml` whose body fails to parse is suspicious on its own:
/// the rest of the analysis pipeline (dependency pinning, lockfile
/// expectations, network/exec capability inference) silently drops it for
/// lack of structure, and an attacker can intentionally craft "almost
/// valid" TOML to bypass every dependency detector. Emit an explicit
/// finding so the manifest's existence — and our inability to analyze it
/// — is recorded in the audit output instead of being swallowed. Mirrors
/// the contract pinned by `MANIFEST_DOCKER_COMPOSE_PARSE_FAILURE` in
/// `detectors/manifests/container/compose/detectors.rs`.
fn pyproject_parse_failure_finding(artifact_path: &str, err: &toml::de::Error) -> Finding {
    super::super::manifest_parse_failure_finding(
        "MANIFEST_PYPROJECT_PARSE_FAILURE",
        artifact_path,
        err.to_string(),
        "pyproject manifest is not valid TOML; dependency-pinning and \
         lockfile analyses cannot run against this file",
    )
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

    /// Contract: a `pyproject.toml` whose body fails to parse MUST emit
    /// `MANIFEST_PYPROJECT_PARSE_FAILURE`. Pre-fix the function silently
    /// returned `Vec::new()`, so an attacker could ship intentionally
    /// broken TOML to suppress every dependency-pinning / lockfile
    /// detector without any audit trail. Mirrors the contract pinned by
    /// `analyze_docker_compose_emits_parse_failure_finding_for_invalid_yaml`.
    #[test]
    fn analyze_pyproject_emits_parse_failure_finding_for_invalid_toml() {
        // Unterminated string is unambiguous TOML syntax error.
        let bad = "[project]\nname = \"";
        let path = std::path::Path::new("/pkg/pyproject.toml");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_pyproject_toml(&service, path, bad, &[]);
        assert!(
            finding_present(&findings, "MANIFEST_PYPROJECT_PARSE_FAILURE"),
            "invalid TOML must produce a parse-failure finding; got {findings:?}",
        );
        let only_parse_failure = findings
            .iter()
            .all(|f| f.rule_id == "MANIFEST_PYPROJECT_PARSE_FAILURE");
        assert!(
            only_parse_failure,
            "no other detector should fire on invalid TOML; got {findings:?}",
        );
    }

    /// Contract: a valid `pyproject.toml` MUST NOT produce a parse-failure
    /// finding. Negative case for the parse-failure detector — pins that
    /// the gate is on the TOML error, not on the absence of dependencies.
    #[test]
    fn analyze_pyproject_does_not_emit_parse_failure_for_valid_toml() {
        let good = r#"[project]
name = "x"
version = "0"
dependencies = ["requests==2.31.0"]
"#;
        let path = std::path::Path::new("/pkg/pyproject.toml");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_pyproject_toml(&service, path, good, &[]);
        assert!(
            !finding_present(&findings, "MANIFEST_PYPROJECT_PARSE_FAILURE"),
            "valid TOML must not produce a parse-failure finding; got {findings:?}",
        );
    }

    /// Contract: Poetry dependency tables are part of the pyproject
    /// dependency surface. Floating Poetry constraints must raise the
    /// same unpinned-dependency finding as PEP 621 dependencies.
    #[test]
    fn analyze_pyproject_flags_poetry_unpinned_dependencies() {
        let content = r#"[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
httpx = { version = ">=0.27" }
"#;
        let path = std::path::Path::new("/pkg/pyproject.toml");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_pyproject_toml(&service, path, content, &[]);

        assert!(
            findings.iter().any(|finding| {
                finding.rule_id == "MANIFEST_PYPROJECT_UNPINNED_DEP"
                    && finding.match_value == "requests@^2.31.0"
            }),
            "Poetry caret constraint must fire; got {findings:?}",
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule_id == "MANIFEST_PYPROJECT_UNPINNED_DEP"
                    && finding.match_value == "httpx@>=0.27"
            }),
            "Poetry table version constraint must fire; got {findings:?}",
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.match_value != "python@^3.11"),
            "the Python interpreter constraint is not a package dependency; got {findings:?}",
        );
    }

    /// Contract: exact Poetry versions are already pinned and must stay
    /// clean.
    #[test]
    fn analyze_pyproject_keeps_exact_poetry_versions_clean() {
        let content = r#"[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"
httpx = { version = "0.27.0" }
"#;
        let path = std::path::Path::new("/pkg/pyproject.toml");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_pyproject_toml(&service, path, content, &[]);

        assert!(
            !finding_present(&findings, "MANIFEST_PYPROJECT_UNPINNED_DEP"),
            "exact Poetry versions must not fire; got {findings:?}",
        );
    }

    /// Contract: a PEP 621 dependency that is unpinned but carries an
    /// environment marker containing `==` (`requests; python_version ==
    /// '3.8'`) MUST still fire — the `==` belongs to the marker, not a
    /// version constraint. Pre-fix the whole-string `contains("==")`
    /// treated it as pinned, so appending a common marker suppressed the
    /// finding. A genuinely pinned dep with a marker stays clean.
    #[test]
    fn analyze_pyproject_flags_unpinned_pep621_dep_with_env_marker() {
        let content = r#"[project]
name = "x"
version = "0"
dependencies = ["requests; python_version == '3.8'", "flask==2.0; python_version == '3.8'"]
"#;
        let path = std::path::Path::new("/pkg/pyproject.toml");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_pyproject_toml(&service, path, content, &[]);
        assert!(
            findings.iter().any(|f| {
                f.rule_id == "MANIFEST_PYPROJECT_UNPINNED_DEP"
                    && f.match_value.starts_with("requests")
            }),
            "unpinned dep with env marker must fire; got {findings:?}",
        );
        assert!(
            findings.iter().all(|f| !f.match_value.starts_with("flask")),
            "a pinned dep with an env marker must stay clean; got {findings:?}",
        );
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

    /// Contract: compact PEP 508 direct references with extras still use
    /// the base dependency name for capability inference.
    #[test]
    fn pyproject_toml_capabilities_detects_compact_direct_reference_with_extras() {
        let content = r#"[project]
name = "x"
version = "0"
dependencies = ["requests[security]@git+https://github.com/psf/requests.git"]
"#;
        let caps = pyproject_toml_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "compact direct reference with extras must flip NetworkAccess; got {caps:?}",
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
