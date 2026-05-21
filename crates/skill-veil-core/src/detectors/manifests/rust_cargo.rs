use std::path::{Path, PathBuf};

use toml::{Table as TomlTable, Value as TomlValue};

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::ArtifactOrchestratorService;

const CARGO_DEPENDENCY_SECTIONS: &[&str] =
    &["dependencies", "dev-dependencies", "build-dependencies"];

pub(crate) fn analyze_cargo_toml(
    service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let toml = match content.parse::<TomlValue>() {
        Ok(value) => value,
        Err(err) => return vec![cargo_toml_parse_failure_finding(&artifact_path, &err)],
    };

    let mut findings = Vec::new();

    // Suppress unpinned dep findings when Cargo.lock exists, since the
    // lockfile pins exact versions. In Cargo, `^` is the default operator.
    let has_lockfile = crate::services::artifact_orchestration::manifests::sibling_has_file(
        sibling_files,
        "Cargo.lock",
    );

    if !has_lockfile {
        visit_cargo_dependency_tables(&toml, |section, dependencies| {
            findings.extend(dependencies.iter().filter_map(|(name, dep)| {
                cargo_unpinned_dep_finding(section, name, dep, &artifact_path)
            }));
        });
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

    visit_cargo_dependency_tables(&toml, |_section, dependencies| {
        for dep in dependencies.keys() {
            let name = dep.to_ascii_lowercase();
            if network_crates.iter().any(|d| name == *d) {
                capabilities.push(ArtifactOrchestratorService::observed_capability(
                    ArtifactCapability::NetworkAccess,
                ));
            }
            if exec_crates.iter().any(|d| name == *d) {
                capabilities.push(ArtifactOrchestratorService::observed_capability(
                    ArtifactCapability::ProcessExecution,
                ));
            }
        }
    });
    // `dedup_by_key` only collapses adjacent runs; crates emit interleaved
    // capabilities (e.g. reqwest, nix, hyper, duct), so sort first.
    capabilities.sort_by_key(|c| c.capability);
    capabilities.dedup_by_key(|c| c.capability);
    capabilities
}

fn visit_cargo_dependency_tables(toml: &TomlValue, mut visit: impl FnMut(&str, &TomlTable)) {
    for section in CARGO_DEPENDENCY_SECTIONS {
        if let Some(dependencies) = toml.get(*section).and_then(TomlValue::as_table) {
            visit(section, dependencies);
        }
    }

    if let Some(workspace_dependencies) = toml
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(TomlValue::as_table)
    {
        visit("workspace.dependencies", workspace_dependencies);
    }

    if let Some(targets) = toml.get("target").and_then(TomlValue::as_table) {
        for (target, target_value) in targets {
            let Some(target_table) = target_value.as_table() else {
                continue;
            };
            for section in CARGO_DEPENDENCY_SECTIONS {
                if let Some(dependencies) = target_table.get(*section).and_then(TomlValue::as_table)
                {
                    let target_section = format!("target.{target}.{section}");
                    visit(&target_section, dependencies);
                }
            }
        }
    }
}

fn cargo_unpinned_dep_finding(
    section: &str,
    name: &str,
    dep: &TomlValue,
    artifact_path: &str,
) -> Option<Finding> {
    let match_value = cargo_unpinned_dep_match_value(section, name, dep)?;
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
            .match_value(match_value)
            .reason("Cargo dependency is not strictly pinned")
            .build(),
    )
}

fn cargo_unpinned_dep_match_value(section: &str, name: &str, dep: &TomlValue) -> Option<String> {
    match dep {
        TomlValue::String(version) => (!is_strict_cargo_pin(version))
            .then(|| cargo_dependency_match_value(section, name, version)),
        TomlValue::Table(table) => {
            if let Some(git_source) = unpinned_git_source(table) {
                return Some(cargo_dependency_match_value(section, name, &git_source));
            }
            let version = table.get("version").and_then(TomlValue::as_str)?;
            (!is_strict_cargo_pin(version))
                .then(|| cargo_dependency_match_value(section, name, version))
        }
        _ => None,
    }
}

fn unpinned_git_source(table: &TomlTable) -> Option<String> {
    let git = non_empty_toml_str(table, "git")?;
    if non_empty_toml_str(table, "rev").is_some() {
        return None;
    }
    let mut source = format!("git:{git}");
    if let Some(branch) = non_empty_toml_str(table, "branch") {
        source.push_str("#branch=");
        source.push_str(branch);
    } else if let Some(tag) = non_empty_toml_str(table, "tag") {
        source.push_str("#tag=");
        source.push_str(tag);
    }
    Some(source)
}

fn non_empty_toml_str<'a>(table: &'a TomlTable, key: &str) -> Option<&'a str> {
    let value = table.get(key).and_then(TomlValue::as_str)?.trim();
    (!value.is_empty()).then_some(value)
}

fn cargo_dependency_match_value(section: &str, name: &str, spec: &str) -> String {
    if section == "dependencies" {
        return format!("{name} = {spec}");
    }
    format!("{section}.{name} = {spec}")
}

/// A `Cargo.toml` whose body fails to parse is suspicious on its own:
/// dependency pinning, lockfile expectations, and capability inference
/// cannot run against it.
fn cargo_toml_parse_failure_finding(artifact_path: &str, err: &toml::de::Error) -> Finding {
    Finding::builder("MANIFEST_CARGO_PARSE_FAILURE", ThreatCategory::Generic)
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
            "Cargo manifest is not valid TOML; dependency-pinning and \
             lockfile analyses cannot run against this file",
        )
        .build()
}

/// Whether a Cargo dependency `version` string is a strict pin to one
/// release. Only `=X.Y.Z` qualifies — bare versions (`"1.0.0"`) and the
/// `^`, `~`, `*` operators all resolve to a *range* under Cargo's default
/// caret semantics, and ranges are unpinned by definition.
///
/// # Contract
/// - Strict pins start with `=` after trimming whitespace (e.g. `=1.0.0`,
///   `= 1.0`).
/// - Bare versions like `1.0.0` are NOT strict pins: Cargo treats them as
///   `^1.0.0`, so they upgrade automatically when a compatible release ships.
/// - Empty strings are NOT strict pins.
fn is_strict_cargo_pin(version: &str) -> bool {
    let trimmed = version.trim();
    !trimmed.is_empty() && trimmed.starts_with('=')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// `cargo_toml_capabilities` must collapse capabilities to a unique set
    /// even when matching crates are interleaved across the dependency
    /// table. Pre-fix `Vec::dedup_by_key` only removed adjacent duplicates,
    /// so a manifest listing `reqwest, nix, hyper, duct` produced
    /// `[Net, Exec, Net, Exec]` (four facts) instead of `[Net, Exec]`,
    /// inflating the artifact graph and the capability-bonus risk score.
    #[test]
    fn cargo_toml_capabilities_collapses_interleaved_capabilities() {
        let content = r#"
[dependencies]
reqwest = "0.12"
nix = "0.27"
hyper = "1"
duct = "0.13"
"#;
        let caps = cargo_toml_capabilities(content);
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

    fn finding_present(findings: &[Finding], rule_id: &str) -> bool {
        findings.iter().any(|f| f.rule_id == rule_id)
    }

    fn unpinned_match_values(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .filter(|finding| finding.rule_id == "MANIFEST_CARGO_UNPINNED_DEP")
            .map(|finding| finding.match_value.as_str())
            .collect()
    }

    /// # Contract
    ///
    /// Invalid `Cargo.toml` must produce an explicit parse-failure
    /// finding instead of silently disabling dependency and lockfile
    /// analysis for that manifest.
    #[test]
    fn analyze_cargo_toml_emits_parse_failure_finding_for_invalid_toml() {
        let service = ArtifactOrchestratorService::new();
        let content = "[package\nname = \"broken\"\n";
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &[]);

        assert!(
            finding_present(&findings, "MANIFEST_CARGO_PARSE_FAILURE"),
            "invalid TOML must produce parse-failure finding; got {findings:?}",
        );
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id == "MANIFEST_CARGO_PARSE_FAILURE"),
            "no other detector should fire on invalid TOML; got {findings:?}",
        );
    }

    /// # Contract (negative)
    ///
    /// Valid `Cargo.toml` must not produce a parse-failure finding.
    #[test]
    fn analyze_cargo_toml_does_not_emit_parse_failure_for_valid_toml() {
        let service = ArtifactOrchestratorService::new();
        let content = "[package]\nname = \"ok\"\nversion = \"0.1.0\"\n";
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &["Cargo.lock".into()]);

        assert!(
            !finding_present(&findings, "MANIFEST_CARGO_PARSE_FAILURE"),
            "valid TOML must not produce parse-failure finding; got {findings:?}",
        );
    }

    /// Contract: a bare-version Cargo dep like `serde = "1.0.0"` is NOT
    /// strictly pinned — Cargo treats bare versions as `^1.0.0`, which
    /// auto-upgrades to any compatible release at lock time. Pre-fix the
    /// predicate only flagged explicit `^|~|*` operators, so the (very
    /// common) bare-version form silently passed as "pinned".
    #[test]
    fn analyze_cargo_toml_flags_bare_version_as_unpinned() {
        let service = ArtifactOrchestratorService::new();
        let content = r#"
[package]
name = "x"
version = "0.1.0"

[dependencies]
serde = "1.0.0"
"#;
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &[]);
        assert!(
            finding_present(&findings, "MANIFEST_CARGO_UNPINNED_DEP"),
            "bare-version dep must fire MANIFEST_CARGO_UNPINNED_DEP; got {findings:?}",
        );
    }

    /// Contract: every Cargo dependency table that can affect the build
    /// must share the same no-lockfile pinning policy as top-level
    /// `[dependencies]`.
    #[test]
    fn test_analyze_cargo_toml_flags_all_unlocked_dependency_tables() {
        let service = ArtifactOrchestratorService::new();
        let content = r#"
[package]
name = "x"
version = "0.1.0"

[dependencies]
serde = "1.0.0"

[dev-dependencies]
assert_cmd = "2.0.0"

[build-dependencies]
cc = "1.0.0"

[workspace.dependencies]
reqwest = "0.12.0"

[target.'cfg(unix)'.dependencies]
nix = "0.27.0"
"#;
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &[]);
        let values = unpinned_match_values(&findings);

        assert!(
            values.contains(&"serde = 1.0.0"),
            "top-level dependencies must fire; got {findings:?}",
        );
        assert!(
            values.contains(&"dev-dependencies.assert_cmd = 2.0.0"),
            "dev-dependencies must fire; got {findings:?}",
        );
        assert!(
            values.contains(&"build-dependencies.cc = 1.0.0"),
            "build-dependencies must fire; got {findings:?}",
        );
        assert!(
            values.contains(&"workspace.dependencies.reqwest = 0.12.0"),
            "workspace dependencies must fire; got {findings:?}",
        );
        assert!(
            values.contains(&"target.cfg(unix).dependencies.nix = 0.27.0"),
            "target dependencies must fire; got {findings:?}",
        );
    }

    /// Contract: git dependencies are strictly pinned only when the
    /// manifest names an exact `rev`; branch, tag, and default-branch
    /// sources can move without changing `Cargo.toml`.
    #[test]
    fn test_analyze_cargo_toml_flags_git_dependency_without_rev() {
        let service = ArtifactOrchestratorService::new();
        let content = r#"
[package]
name = "x"
version = "0.1.0"

[dependencies]
plugin = { git = "https://github.com/example/plugin.git", branch = "main" }
"#;
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &[]);
        let values = unpinned_match_values(&findings);

        assert!(
            values.contains(&"plugin = git:https://github.com/example/plugin.git#branch=main"),
            "git dependency without rev must fire; got {findings:?}",
        );
    }

    /// Contract: a git dependency with an explicit `rev` is pinned to one
    /// commit and must not raise the unpinned-dependency finding.
    #[test]
    fn test_analyze_cargo_toml_keeps_git_rev_dependency_clean() {
        let service = ArtifactOrchestratorService::new();
        let content = r#"
[package]
name = "x"
version = "0.1.0"

[dependencies]
plugin = { git = "https://github.com/example/plugin.git", rev = "0123456789abcdef0123456789abcdef01234567" }
"#;
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &[]);

        assert!(
            !finding_present(&findings, "MANIFEST_CARGO_UNPINNED_DEP"),
            "git dependency with rev must not fire unpinned-dep finding; got {findings:?}",
        );
    }

    /// Contract: local path dependencies without a registry/git source do
    /// not represent floating remote resolution on their own.
    #[test]
    fn test_analyze_cargo_toml_keeps_path_dependency_without_version_clean() {
        let service = ArtifactOrchestratorService::new();
        let content = r#"
[package]
name = "x"
version = "0.1.0"

[dependencies]
local_helper = { path = "../local-helper" }
"#;
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &[]);

        assert!(
            !finding_present(&findings, "MANIFEST_CARGO_UNPINNED_DEP"),
            "local path dependency without version must stay clean; got {findings:?}",
        );
    }

    /// Contract: a present `Cargo.lock` pins resolution for every Cargo
    /// dependency table, not just top-level `[dependencies]`.
    #[test]
    fn test_analyze_cargo_toml_suppresses_all_unpinned_tables_when_lockfile_exists() {
        let service = ArtifactOrchestratorService::new();
        let content = r#"
[package]
name = "x"
version = "0.1.0"

[dev-dependencies]
assert_cmd = "2.0.0"

[build-dependencies]
cc = "1.0.0"

[target.'cfg(unix)'.dependencies]
nix = "0.27.0"
"#;
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &["Cargo.lock".into()]);

        assert!(
            !finding_present(&findings, "MANIFEST_CARGO_UNPINNED_DEP"),
            "Cargo.lock must suppress unpinned findings for every table; got {findings:?}",
        );
    }

    /// Contract: capability inference must traverse the same Cargo
    /// dependency tables as the unpinned detector.
    #[test]
    fn test_cargo_toml_capabilities_include_workspace_and_target_dependencies() {
        let content = r#"
[package]
name = "x"
version = "0.1.0"

[workspace.dependencies]
reqwest = "0.12.0"

[target.'cfg(unix)'.dependencies]
duct = "0.13.0"
"#;
        let caps = cargo_toml_capabilities(content);

        assert!(
            caps.iter()
                .any(|fact| fact.capability == ArtifactCapability::NetworkAccess),
            "workspace reqwest must flip NetworkAccess; got {caps:?}",
        );
        assert!(
            caps.iter()
                .any(|fact| fact.capability == ArtifactCapability::ProcessExecution),
            "target duct must flip ProcessExecution; got {caps:?}",
        );
    }

    /// Contract: explicit-`=` version (the only form that strictly pins in
    /// Cargo) suppresses the unpinned finding. Negative case to ensure the
    /// fix does not over-fire on actually-pinned manifests.
    #[test]
    fn analyze_cargo_toml_respects_strict_equal_pin() {
        let service = ArtifactOrchestratorService::new();
        let content = r#"
[package]
name = "x"
version = "0.1.0"

[dependencies]
serde = "=1.0.0"
"#;
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &[]);
        assert!(
            !finding_present(&findings, "MANIFEST_CARGO_UNPINNED_DEP"),
            "`=X.Y.Z` strict pin must suppress MANIFEST_CARGO_UNPINNED_DEP; got {findings:?}",
        );
    }

    /// Contract: caret/tilde/wildcard operators continue to fire the
    /// unpinned finding (regression guard for the pre-existing detection).
    #[test]
    fn analyze_cargo_toml_still_flags_caret_tilde_wildcard() {
        let service = ArtifactOrchestratorService::new();
        let content = r#"
[package]
name = "x"
version = "0.1.0"

[dependencies]
foo = "^1.0"
bar = "~1.0"
baz = "*"
"#;
        let path = std::path::Path::new("/pkg/Cargo.toml");
        let findings = analyze_cargo_toml(&service, path, content, &[]);
        let unpinned = findings
            .iter()
            .filter(|f| f.rule_id == "MANIFEST_CARGO_UNPINNED_DEP")
            .count();
        assert_eq!(
            unpinned, 3,
            "caret, tilde, and wildcard versions must each fire; got {findings:?}",
        );
    }

    /// Contract: unit-level test for the strict-pin predicate. Pins the
    /// exact set of strings recognised as strict pins so future refactors
    /// cannot widen "pinned" to include bare versions or operator forms.
    #[test]
    fn is_strict_cargo_pin_only_accepts_equals_prefix() {
        assert!(is_strict_cargo_pin("=1.0.0"));
        assert!(is_strict_cargo_pin(" =1.0.0 "));
        assert!(is_strict_cargo_pin("= 1.0.0"));
        assert!(!is_strict_cargo_pin("1.0.0"));
        assert!(!is_strict_cargo_pin("^1.0"));
        assert!(!is_strict_cargo_pin("~1.0"));
        assert!(!is_strict_cargo_pin("*"));
        assert!(!is_strict_cargo_pin(">=1.0, <2.0"));
        assert!(!is_strict_cargo_pin(""));
        assert!(!is_strict_cargo_pin("   "));
    }
}
