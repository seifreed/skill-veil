use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::manifests::{
    strip_inline_hash_comment, strip_inline_ini_comment,
};
use crate::services::artifact_analysis::{ArtifactAnalysisService, ArtifactLink};
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

/// Yields trimmed `pip.conf` lines with their inline comment portion
/// removed and any blank-only result discarded.
///
/// `pip.conf` follows INI syntax: `#` and `;` start comments — both as
/// full-line markers AND inline trailing markers — and blank lines are
/// ignored. Directives like `extra-index-url=...` only take effect on
/// the non-comment portion. Stripping inline comments here keeps
/// downstream substring scans honest: a line like
/// `extra-index-url=https://internal.example/simple ; rotate quarterly`
/// would otherwise let the `;`-tail leak through, and a documentation
/// line like `# do NOT enable extra-index-url here` would otherwise
/// match before the helper got a chance to filter it (it now collapses
/// to empty and is skipped).
fn pip_conf_significant_lines(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .map(|line| strip_inline_ini_comment(line).trim())
        .filter(|line| !line.is_empty())
}

pub(crate) fn analyze_requirements_txt(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    content
        .lines()
        // `requirements.txt` uses `#` for comments. `;` is the PEP 508
        // environment-marker separator (`requests; python_version>='3.6'`)
        // and MUST NOT be treated as a comment marker — that's why we use
        // the `#`-only stripper here, not the INI variant.
        .map(|line| strip_inline_hash_comment(line).trim())
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("-r ") && !line.starts_with("--requirement"))
        .filter(|line| !line.starts_with("git+") && !line.starts_with("http"))
        .filter(|line| !line.starts_with("-c ") && !line.starts_with("--"))
        // `==` and `~=` are pinning operators; `!=` is exclusion
        // (`requests!=2.0` means "any version except 2.0") and is NOT a
        // pin — pre-fix it was lumped in here, so deps that combined an
        // exclusion with no real pin (e.g. `requests!=2.0`) silently
        // escaped MANIFEST_REQUIREMENTS_UNPINNED_DEP.
        .filter(|line| !line.contains("==") && !line.contains("~="))
        .map(|line| {
            Finding::builder(
                "MANIFEST_REQUIREMENTS_UNPINNED_DEP",
                ThreatCategory::SupplyChain,
            )
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .evidence_kind(EvidenceKind::Context)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .match_value(line)
            .reason("Python requirement is not strictly pinned")
            .build()
        })
        .collect()
}

pub(crate) fn analyze_pyproject_toml(
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

pub(crate) fn analyze_pip_conf(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings: Vec<_> = pip_conf_significant_lines(content)
        .filter(|line| line.to_ascii_lowercase().contains("extra-index-url"))
        .map(|line| {
            Finding::builder("MANIFEST_PIP_CONF_EXTRA_INDEX", ThreatCategory::SupplyChain)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value(line)
                .reason("pip configuration adds an extra package index")
                .build()
        })
        .collect();

    if pip_conf_significant_lines(content)
        .any(|line| line.to_ascii_lowercase().contains("trusted-host"))
    {
        findings.push(
            Finding::builder(
                "MANIFEST_PIP_CONF_TRUSTED_HOST",
                ThreatCategory::SupplyChain,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Context)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .match_value("trusted-host")
            .reason("pip configuration trusts a custom package host")
            .build(),
        );
    }

    findings
}

const PYTHON_NETWORK_DEPS: &[&str] = &[
    "requests",
    "httpx",
    "aiohttp",
    "urllib3",
    "paramiko",
    "grpcio",
    "websockets",
    "tornado",
];

const PYTHON_EXEC_DEPS: &[&str] = &["subprocess32", "pexpect", "fabric", "invoke"];

const PYTHON_VCS_PREFIXES: &[&str] = &["git+", "hg+", "svn+", "bzr+"];

/// Extract the canonical lowercase package name from a single dependency
/// spec line (already stripped of inline comments and trimmed).
///
/// # Contract
///
/// Recognised shapes:
/// - Plain: `requests`, `requests==2.0.0`, `requests>=2.0`, `requests~=2.0`,
///   `requests[security]>=2.0`, `requests; python_version>='3.6'`.
/// - PEP 508 direct reference: `NAME @ URL` (any URL form, including
///   `git+https://...`). The name precedes the ` @ ` separator.
/// - Legacy VCS with egg fragment: `git+https://host/repo.git#egg=NAME`,
///   plus `hg+`, `svn+`, `bzr+`. The name comes from the `egg=` fragment.
///
/// Returns `None` for VCS specs without a recoverable name (no `egg=`,
/// no PEP 508 prefix) — the caller cannot map those to a known dep.
fn parse_python_dep_name(line: &str) -> Option<String> {
    if let Some((name, _)) = line.split_once(" @ ") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Some(canonical_python_name(trimmed));
        }
    }
    if PYTHON_VCS_PREFIXES.iter().any(|p| line.starts_with(p)) {
        for fragment in line.split('#').skip(1) {
            for kv in fragment.split('&') {
                if let Some(value) = kv.trim().strip_prefix("egg=") {
                    let name = value.split(['[', ';']).next().unwrap_or("").trim();
                    if !name.is_empty() {
                        return Some(canonical_python_name(name));
                    }
                }
            }
        }
        return None;
    }
    let name = line
        .split(['=', '>', '<', '~', '!', '[', ';', ' '])
        .next()
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return None;
    }
    Some(canonical_python_name(name))
}

fn canonical_python_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

pub(crate) fn requirements_txt_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();

    for raw_line in content.lines() {
        // VCS specs use `#egg=NAME` as a meaningful URL fragment, NOT a
        // comment — strip-on-`#` would discard the only place the package
        // name appears. Keep the line verbatim when it starts with a VCS
        // scheme, and strip the inline `#` comment everywhere else so
        // `requests # http client` still resolves to `requests`. `;` is
        // kept as a splitter, not a comment marker, so the PEP 508 env
        // marker (`requests; python_version>='3.6'`) cuts at the right spot.
        let trimmed = raw_line.trim();
        let line = if PYTHON_VCS_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
            trimmed
        } else {
            strip_inline_hash_comment(raw_line).trim()
        };
        if line.is_empty() {
            continue;
        }
        let Some(dep_name) = parse_python_dep_name(line) else {
            continue;
        };
        if PYTHON_NETWORK_DEPS.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactAnalysisService::observed_capability(
                ArtifactCapability::NetworkAccess,
            ));
        }
        if PYTHON_EXEC_DEPS.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactAnalysisService::observed_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }
    // `dedup_by_key` only collapses adjacent runs; deps emit interleaved
    // capabilities (e.g. requests, fabric, httpx, invoke), so sort first.
    capabilities.sort_by_key(|c| c.capability);
    capabilities.dedup_by_key(|c| c.capability);
    capabilities
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
            capabilities.push(ArtifactAnalysisService::observed_capability(
                ArtifactCapability::NetworkAccess,
            ));
        }
        if PYTHON_EXEC_DEPS.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactAnalysisService::observed_capability(
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

pub(crate) fn pip_conf_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();
    let mut has_index_directive = false;
    let mut has_client_cert = false;
    for line in pip_conf_significant_lines(content) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("extra-index-url") || lower.contains("index-url") {
            has_index_directive = true;
        }
        if lower.contains("client-cert") {
            has_client_cert = true;
        }
    }
    if has_index_directive {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_client_cert {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    capabilities
}

pub(crate) fn pip_conf_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    let mut has_index_directive = false;
    let mut has_client_cert = false;
    for line in pip_conf_significant_lines(content) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("extra-index-url") || lower.contains("index-url") {
            has_index_directive = true;
        }
        if lower.contains("client-cert") {
            has_client_cert = true;
        }
    }
    if has_index_directive {
        links.push(ArtifactLink {
            target: "package-index".to_string(),
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    if has_client_cert {
        links.push(ArtifactLink {
            target: "client-cert".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_present(caps: &[ArtifactCapabilityFact], target: ArtifactCapability) -> bool {
        caps.iter().any(|fact| fact.capability == target)
    }

    fn relation_target_present(links: &[ArtifactLink], target: &str) -> bool {
        links.iter().any(|link| link.target == target)
    }

    fn finding_present(findings: &[Finding], rule_id: &str) -> bool {
        findings.iter().any(|finding| finding.rule_id == rule_id)
    }

    /// Contract: a `pip.conf` directive that appears only inside a `#` comment
    /// is documentation, not configuration; it must NOT raise NetworkAccess.
    #[test]
    fn pip_conf_capabilities_ignores_extra_index_url_inside_comment() {
        let content = "# Don't enable extra-index-url here\n";
        let caps = pip_conf_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
    }

    /// Contract: an uncommented `extra-index-url=...` directive raises NetworkAccess
    /// (positive case to pin the happy path).
    #[test]
    fn pip_conf_capabilities_fires_for_uncommented_extra_index_url() {
        let content = "[global]\nextra-index-url = https://internal.example.com/simple\n";
        let caps = pip_conf_capabilities(content);
        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
    }

    /// Contract: a `client-cert` directive only mentioned in a comment must NOT
    /// raise SecretAccess.
    #[test]
    fn pip_conf_capabilities_ignores_client_cert_inside_comment() {
        let content = "# client-cert support is documented in the README\n";
        let caps = pip_conf_capabilities(content);
        assert!(!capability_present(&caps, ArtifactCapability::SecretAccess));
    }

    /// Contract: a commented `index-url` does not produce a `package-index`
    /// relation either — relations and capabilities use the same gate.
    #[test]
    fn pip_conf_relations_ignores_commented_index_url() {
        let content = "# index-url = https://internal.example.com/simple\n";
        let links = pip_conf_relations(content);
        assert!(!relation_target_present(&links, "package-index"));
    }

    /// Contract: `analyze_pip_conf` ignores `extra-index-url` inside a `#`
    /// comment — same comment-aware contract as the capability/relation paths.
    #[test]
    fn analyze_pip_conf_ignores_extra_index_url_inside_comment() {
        let content = "# extra-index-url is risky, see security notes\n";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        assert!(!finding_present(&findings, "MANIFEST_PIP_CONF_EXTRA_INDEX"));
    }

    /// Contract: `trusted-host` mentioned only in a comment does not fire the
    /// trusted-host finding.
    #[test]
    fn analyze_pip_conf_ignores_trusted_host_inside_comment() {
        let content = "# trusted-host should not be set in shared configs\n";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        assert!(!finding_present(
            &findings,
            "MANIFEST_PIP_CONF_TRUSTED_HOST"
        ));
    }

    /// Contract: `;` is the alternate INI comment marker (matches the syntax
    /// pip itself uses); directives on `;`-prefixed lines must NOT fire.
    #[test]
    fn analyze_pip_conf_treats_semicolon_comments_as_comments() {
        let content = "; extra-index-url = https://internal.example.com/simple\n";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        let caps = pip_conf_capabilities(content);
        assert!(!finding_present(&findings, "MANIFEST_PIP_CONF_EXTRA_INDEX"));
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
    }

    /// Contract: an inline `#` comment in `requirements.txt` is the
    /// comment portion. The pre-fix code applied the `!line.contains("==")`
    /// filter to the whole line including the comment, so a line like
    /// `requests # was: requests==2.0.0` was silently classified as
    /// pinned (the historical `==` in the comment satisfied the filter)
    /// and the real `requests` (unpinned) was never reported.
    #[test]
    fn analyze_requirements_txt_does_not_treat_comment_pin_as_pin() {
        let content = "requests # was: requests==2.0.0\n";
        let path = std::path::Path::new("/pkg/requirements.txt");
        let findings = analyze_requirements_txt(path, content);
        assert!(
            finding_present(&findings, "MANIFEST_REQUIREMENTS_UNPINNED_DEP"),
            "real unpinned dep must fire even when a comment contains `==`; got {findings:?}",
        );
    }

    /// Contract: a real `==` pin (no surrounding comment) suppresses the
    /// unpinned finding. Pins the positive case so the inline-comment
    /// strip doesn't accidentally widen the unpinned set.
    #[test]
    fn analyze_requirements_txt_respects_real_pin() {
        let content = "requests==2.31.0\n";
        let path = std::path::Path::new("/pkg/requirements.txt");
        let findings = analyze_requirements_txt(path, content);
        assert!(
            !finding_present(&findings, "MANIFEST_REQUIREMENTS_UNPINNED_DEP"),
            "real `==` pin must suppress the unpinned finding; got {findings:?}",
        );
    }

    /// Contract: `!=` is exclusion, NOT a pin. A line like `requests!=2.0`
    /// constrains the resolver to exclude 2.0 but still resolves the latest
    /// compatible release at install time, so it MUST fire the unpinned
    /// finding. Pre-fix the `.contains("!=")` clause silently swallowed
    /// these lines as if they were pinned.
    #[test]
    fn analyze_requirements_txt_flags_not_equal_as_unpinned() {
        let content = "requests!=2.0\n";
        let path = std::path::Path::new("/pkg/requirements.txt");
        let findings = analyze_requirements_txt(path, content);
        assert!(
            finding_present(&findings, "MANIFEST_REQUIREMENTS_UNPINNED_DEP"),
            "`!=` exclusion is not a pin and MUST fire MANIFEST_REQUIREMENTS_UNPINNED_DEP; \
             got {findings:?}",
        );
    }

    /// Contract: a line that combines an exclusion with a real pin (e.g.
    /// `requests==2.31.0,!=2.30.0`) is still pinned and does NOT fire.
    /// Negative case to ensure the `!=` fix didn't accidentally inflate
    /// the unpinned set when a `==` pin co-exists.
    #[test]
    fn analyze_requirements_txt_keeps_compound_pin_with_exclusion() {
        let content = "requests==2.31.0,!=2.30.0\n";
        let path = std::path::Path::new("/pkg/requirements.txt");
        let findings = analyze_requirements_txt(path, content);
        assert!(
            !finding_present(&findings, "MANIFEST_REQUIREMENTS_UNPINNED_DEP"),
            "compound spec containing `==` is pinned; must not fire; got {findings:?}",
        );
    }

    /// Contract: `requirements_txt_capabilities` parses the dep name
    /// after stripping any inline `#` comment, so `requests # http
    /// client` still flips `NetworkAccess`. Pre-fix the whole line
    /// (with comment) became the dep_name and the exact-match check
    /// against `"requests"` failed silently.
    #[test]
    fn requirements_txt_capabilities_handles_inline_hash_comment() {
        let content = "requests # http client\nsubprocess32 # back-port\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "inline-commented `requests` must still flip NetworkAccess; got {caps:?}",
        );
        assert!(
            capability_present(&caps, ArtifactCapability::ProcessExecution),
            "inline-commented `subprocess32` must still flip ProcessExecution; got {caps:?}",
        );
    }

    /// Contract: PEP 508 environment markers like `requests;
    /// python_version=="3.6"` MUST still split the dep_name correctly —
    /// for `requirements.txt` we treat `;` as a version-spec splitter,
    /// NOT as a comment marker. Pins that the inline-`#` strip didn't
    /// accidentally swap to the INI-style strip.
    #[test]
    fn requirements_txt_capabilities_keeps_pep508_env_marker_as_splitter() {
        let content = "requests; python_version >= \"3.6\"\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "PEP 508 marker must split dep_name correctly; got {caps:?}",
        );
    }

    /// Contract: `parse_python_dep_name` recovers the package name from the
    /// legacy VCS form `git+https://host/repo.git#egg=NAME` (also `hg+`,
    /// `svn+`, `bzr+`). Pre-fix the split-on-`=` parser produced
    /// `git+https://github.com/psf/requests.git#egg` as the dep_name, which
    /// silently failed the exact-match check against `requests`, so VCS deps
    /// for known network libs never flipped `NetworkAccess`.
    #[test]
    fn requirements_txt_capabilities_detects_vcs_egg_fragment() {
        let content = "git+https://github.com/psf/requests.git#egg=requests\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "VCS egg=requests must flip NetworkAccess; got {caps:?}",
        );
    }

    /// Contract: PEP 508 direct reference `NAME @ URL` MUST extract `NAME`
    /// even when the URL is a VCS spec. Without the ` @ ` split, the parser
    /// falls back to splitting on `=` inside the URL and produces garbage.
    #[test]
    fn requirements_txt_capabilities_detects_pep508_direct_reference() {
        let content = "requests @ git+https://github.com/psf/requests.git\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "PEP 508 `NAME @ URL` must flip NetworkAccess; got {caps:?}",
        );
    }

    /// Contract: VCS specs WITHOUT a recoverable name (no `egg=`, no PEP 508
    /// prefix) are not silently mapped to a wrong package — they yield
    /// `None` from `parse_python_dep_name` and contribute no capability.
    /// Negative case to ensure the VCS branch doesn't over-fire.
    #[test]
    fn requirements_txt_capabilities_skips_vcs_without_name() {
        let content = "git+https://github.com/example/internal-tool.git\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            !capability_present(&caps, ArtifactCapability::NetworkAccess),
            "anonymous VCS spec must not flip NetworkAccess; got {caps:?}",
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

    /// Contract: `pip_conf_significant_lines` strips inline `;` comments
    /// before yielding lines, so `extra-index-url=https://x ; rotate
    /// quarterly` is reported via `analyze_pip_conf` without the
    /// `;`-tail leaking into the `match_value`.
    #[test]
    fn analyze_pip_conf_strips_inline_semicolon_comment_in_match_value() {
        let content = "extra-index-url=https://internal.example/simple ; rotate quarterly\n";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        let finding = findings
            .iter()
            .find(|f| f.rule_id == "MANIFEST_PIP_CONF_EXTRA_INDEX")
            .expect("uncommented extra-index-url must still fire");
        assert!(
            !finding.match_value.contains(';'),
            "inline `;` comment must be stripped from match_value; got {:?}",
            finding.match_value,
        );
    }

    /// # Contract
    /// `requirements_txt_capabilities` must collapse capabilities to a unique
    /// set even when matching deps are interleaved across the file. Pre-fix
    /// `Vec::dedup_by_key` only removed adjacent duplicates, so a file like
    /// `requests / fabric / httpx / invoke` produced `[Net, Exec, Net, Exec]`
    /// (four facts) instead of `[Net, Exec]`, inflating the artifact graph
    /// and the capability-bonus risk score.
    #[test]
    fn requirements_txt_capabilities_collapses_interleaved_capabilities() {
        let content = "requests\nfabric\nhttpx\ninvoke\n";
        let caps = requirements_txt_capabilities(content);
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
