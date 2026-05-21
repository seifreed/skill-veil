use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::ArtifactOrchestratorService;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

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
    // `dedup_by_key` only collapses adjacent runs; crates emit interleaved
    // capabilities (e.g. reqwest, nix, hyper, duct), so sort first.
    capabilities.sort_by_key(|c| c.capability);
    capabilities.dedup_by_key(|c| c.capability);
    capabilities
}

fn cargo_unpinned_dep_finding(name: &str, dep: &TomlValue, artifact_path: &str) -> Option<Finding> {
    let version = match dep {
        TomlValue::String(v) => Some(v.as_str()),
        TomlValue::Table(t) => t.get("version").and_then(TomlValue::as_str),
        _ => None,
    }?;
    if is_strict_cargo_pin(version) {
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
