use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::{ArtifactAnalysisService, ArtifactLink};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub(crate) fn analyze_package_json(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let artifact_path = path.display().to_string();

    // Suppress unpinned dep findings when a lockfile exists, since the
    // lockfile pins exact versions regardless of the version specifier.
    let has_lockfile = package_json_expected_lockfiles(content)
        .iter()
        .any(|lockfile| super::sibling_has_file(sibling_files, lockfile));

    for dependency_field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(dependencies) = json.get(dependency_field).and_then(Value::as_object) else {
            continue;
        };

        for (name, version) in dependencies {
            let Some(version_str) = version.as_str() else {
                continue;
            };

            if !has_lockfile
                && (version_str.starts_with('^')
                    || version_str.starts_with('~')
                    || version_str == "latest"
                    || version_str == "*")
            {
                findings.push(
                    Finding::builder(
                        "MANIFEST_PACKAGE_JSON_UNPINNED_DEP",
                        ThreatCategory::SupplyChain,
                    )
                    .severity(Severity::Low)
                    .action(RecommendedAction::Log)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(format!("{name}@{version_str}"))
                    .reason("Manifest dependency is not strictly pinned")
                    .build(),
                );
            }
        }
    }

    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        for hook in ["preinstall", "install", "postinstall"] {
            if let Some(command) = scripts.get(hook).and_then(Value::as_str) {
                let lower_command = command.to_ascii_lowercase();
                let risky_install_hook = [
                    "curl ",
                    "wget ",
                    "http://",
                    "https://",
                    "powershell",
                    "invoke-webrequest",
                    "iwr ",
                    "bash -c",
                    "sh -c",
                    "python -c",
                    "node -e",
                ]
                .iter()
                .any(|needle| lower_command.contains(needle));
                findings.push(
                    Finding::builder(
                        "MANIFEST_PACKAGE_JSON_INSTALL_HOOK",
                        ThreatCategory::SupplyChain,
                    )
                    .severity(if risky_install_hook {
                        Severity::Medium
                    } else {
                        Severity::Low
                    })
                    .action(if risky_install_hook {
                        RecommendedAction::RequireApproval
                    } else {
                        RecommendedAction::Log
                    })
                    .evidence_kind(if risky_install_hook {
                        EvidenceKind::Behavior
                    } else {
                        EvidenceKind::Context
                    })
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(format!("{hook}: {command}"))
                    .reason(if risky_install_hook {
                        "Manifest defines an install lifecycle hook that fetches or executes code"
                    } else {
                        "Manifest defines an install lifecycle hook"
                    })
                    .build(),
                );
            }
        }
    }

    if json.get("bin").is_some() {
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

    let expected_lockfiles = package_json_expected_lockfiles(content);
    if !expected_lockfiles.is_empty() {
        findings.extend(service.missing_lockfile_findings(
            path,
            sibling_files,
            &expected_lockfiles,
            "MANIFEST_PACKAGE_JSON_MISSING_LOCKFILE",
            "JavaScript manifest has no matching nearby lockfile",
        ));
    }

    findings
}

pub(crate) fn analyze_npmrc(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings: Vec<_> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.to_ascii_lowercase().contains("_authtoken="))
        .map(|line| {
            Finding::builder(
                "MANIFEST_NPMRC_EMBEDDED_TOKEN",
                ThreatCategory::CredentialExposure,
            )
            .severity(Severity::High)
            .action(RecommendedAction::Block)
            .evidence_kind(EvidenceKind::Behavior)
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value(line)
            .reason("npm configuration embeds an authentication token")
            .build()
        })
        .collect();

    if content.lines().any(|line| {
        line.trim()
            .to_ascii_lowercase()
            .starts_with("registry=http")
    }) {
        findings.push(
            Finding::builder(
                "MANIFEST_NPMRC_CUSTOM_REGISTRY",
                ThreatCategory::SupplyChain,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Context)
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value("registry")
            .reason("npm configuration overrides the default registry")
            .build(),
        );
    }

    findings
}

pub(crate) fn package_json_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let mut capabilities = Vec::new();

    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        if ["preinstall", "install", "postinstall"]
            .iter()
            .any(|hook| scripts.contains_key(*hook))
        {
            capabilities.push(ArtifactAnalysisService::declared_capability(
                ArtifactCapability::InstallExecution,
            ));
            capabilities.push(ArtifactAnalysisService::declared_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }

    if json.get("bin").is_some() {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::ExposesBinary,
        ));
    }

    capabilities
}

pub(crate) fn package_json_expected_lockfiles(content: &str) -> Vec<&'static str> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let package_manager = json
        .get("packageManager")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if package_manager.starts_with("pnpm@") {
        return vec!["pnpm-lock.yaml"];
    }
    if package_manager.starts_with("yarn@") {
        return vec!["yarn.lock"];
    }
    if package_manager.starts_with("npm@") {
        return vec!["package-lock.json", "npm-shrinkwrap.json"];
    }

    vec![
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ]
}

pub(crate) fn package_json_relations(content: &str) -> Vec<ArtifactLink> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let mut links = Vec::new();
    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        for hook in ["preinstall", "install", "postinstall"] {
            if let Some(command) = scripts.get(hook).and_then(Value::as_str) {
                links.push(ArtifactLink {
                    target: command.to_string(),
                    relation: ArtifactRelation::Executes,
                });
            }
        }
    }
    links
}

pub(crate) fn npmrc_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("_authtoken=") {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    if lower.contains("registry=http") {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    capabilities
}

pub(crate) fn npmrc_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    let lower = content.to_ascii_lowercase();
    if lower.contains("_authtoken=") {
        links.push(ArtifactLink {
            target: "credential-store".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    if lower.contains("registry=http") {
        links.push(ArtifactLink {
            target: "package-registry".to_string(),
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    links
}
