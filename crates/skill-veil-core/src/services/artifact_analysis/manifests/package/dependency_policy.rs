use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use serde_json::Value;
use toml::Value as TomlValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DependencyPinning {
    Strict,
    Floating,
}

impl DependencyPinning {
    pub(super) fn from_semver(version: &str) -> Self {
        if version.starts_with('^')
            || version.starts_with('~')
            || version == "*"
            || version.eq_ignore_ascii_case("latest")
        {
            Self::Floating
        } else {
            Self::Strict
        }
    }

    pub(super) fn from_python_requirement(requirement: &str) -> Self {
        if requirement.contains("==") || requirement.contains('@') {
            Self::Strict
        } else {
            Self::Floating
        }
    }

    pub(super) fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct DependencySpec<'a> {
    name: &'a str,
    version: &'a str,
}

impl<'a> DependencySpec<'a> {
    pub(super) fn new(name: &'a str, version: &'a str) -> Self {
        Self { name, version }
    }

    pub(super) fn npm_display(self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    pub(super) fn cargo_display(self) -> String {
        format!("{} = {}", self.name, self.version)
    }
}

pub(super) fn package_json_dependency_findings(json: &Value, artifact_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for dependency_field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(dependencies) = json.get(dependency_field).and_then(Value::as_object) else {
            continue;
        };

        for (name, version) in dependencies {
            let Some(version_str) = version.as_str() else {
                continue;
            };

            if !DependencyPinning::from_semver(version_str).is_strict() {
                let spec = DependencySpec::new(name, version_str);
                findings.push(unpinned_finding(
                    artifact_path,
                    "MANIFEST_PACKAGE_JSON_UNPINNED_DEP",
                    RecommendedAction::Log,
                    spec.npm_display(),
                    "Manifest dependency is not strictly pinned",
                ));
            }
        }
    }

    findings
}

pub(super) fn requirements_txt_findings(content: &str, artifact_path: &str) -> Vec<Finding> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| !line.starts_with("-r ") && !line.starts_with("--requirement"))
        .filter(|line| !DependencyPinning::from_python_requirement(line).is_strict())
        .map(|line| {
            unpinned_finding(
                artifact_path,
                "MANIFEST_REQUIREMENTS_UNPINNED_DEP",
                RecommendedAction::Log,
                line.to_string(),
                "Python requirement is not strictly pinned",
            )
        })
        .collect()
}

pub(super) fn pyproject_dependency_findings(
    toml: &TomlValue,
    artifact_path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(dependencies) = toml
        .get("project")
        .and_then(|project| project.get("dependencies"))
        .and_then(TomlValue::as_array)
    {
        for dependency in dependencies.iter().filter_map(TomlValue::as_str) {
            if !DependencyPinning::from_python_requirement(dependency).is_strict() {
                findings.push(unpinned_finding(
                    artifact_path,
                    "MANIFEST_PYPROJECT_UNPINNED_DEP",
                    RecommendedAction::RequireApproval,
                    dependency.to_string(),
                    "pyproject dependency is not strictly pinned",
                ));
            }
        }
    }
    findings
}

pub(super) fn cargo_dependency_findings(toml: &TomlValue, artifact_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(dependencies) = toml.get("dependencies").and_then(TomlValue::as_table) {
        for (name, dependency) in dependencies {
            let version = match dependency {
                TomlValue::String(version) => Some(version.as_str()),
                TomlValue::Table(table) => table.get("version").and_then(TomlValue::as_str),
                _ => None,
            };

            if let Some(version) = version {
                if !DependencyPinning::from_semver(version).is_strict() {
                    findings.push(unpinned_finding(
                        artifact_path,
                        "MANIFEST_CARGO_UNPINNED_DEP",
                        RecommendedAction::RequireApproval,
                        DependencySpec::new(name, version).cargo_display(),
                        "Cargo dependency is not strictly pinned",
                    ));
                }
            }
        }
    }
    findings
}

fn unpinned_finding(
    artifact_path: &str,
    rule_id: &'static str,
    action: RecommendedAction,
    match_value: String,
    reason: &'static str,
) -> Finding {
    Finding::builder(rule_id, ThreatCategory::SupplyChain)
        .severity(Severity::Low)
        .action(action)
        .evidence_kind(EvidenceKind::Context)
        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.to_string()))
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .match_value(match_value)
        .reason(reason)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_dependency_is_floating() {
        assert_eq!(DependencyPinning::from_semver("latest"), DependencyPinning::Floating);
        assert_eq!(DependencyPinning::from_semver("1.2.3"), DependencyPinning::Strict);
    }

    #[test]
    fn requirements_policy_flags_unpinned_lines() {
        let findings = requirements_txt_findings("requests\nurllib3==1.2.3\n# note", "requirements.txt");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "MANIFEST_REQUIREMENTS_UNPINNED_DEP");
    }
}
