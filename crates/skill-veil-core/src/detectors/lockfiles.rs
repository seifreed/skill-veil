use std::path::Path;

use serde_json::Value;
use toml::Value as TomlValue;

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::lazy_pattern;
use crate::services::artifact_orchestration::network::{
    extract_http_urls, is_common_lockfile_source,
};
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};

lazy_pattern!(RE_CARGO_GIT_SOURCE, r#"(?i)\bsource\s*=\s*"git\+"#);
lazy_pattern!(RE_POETRY_URL_SOURCE, r#"(?i)\burl\s*=\s*"https?://"#);
lazy_pattern!(
    RE_UV_GIT_SOURCE,
    r#"(?i)(?:\bgit\s*=\s*"https?://|git\+https?://)"#
);
lazy_pattern!(RE_YARN_REMOTE_TARBALL, r#"(?i)\bresolved\s+"https?://"#);
lazy_pattern!(RE_PNPM_REMOTE_TARBALL, r"(?i)\btarball:\s*https?://");

const GIT_SOURCE_PREFIX: &str = "git+";
const FILE_SOURCE_PREFIX: &str = "file://";
const REMOTE_HTTP_SOURCE_PREFIXES: &[&str] = &["http://", "https://"];
const REMOTE_NON_HTTP_GIT_SOURCE_PREFIXES: &[&str] = &["ssh://", "git://"];

pub(crate) fn analyze_package_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile(
        path,
        content,
        "LOCKFILE_PACKAGE_REMOTE_TARBALL",
        LockfilePattern::JsonKey("resolved"),
        "package-lock resolves dependencies from remote tarballs",
    )
}

pub(crate) fn analyze_pipfile_lock(path: &Path, content: &str) -> Vec<Finding> {
    lockfile_findings_for_sources(
        path,
        "LOCKFILE_PIPFILE_REMOTE_SOURCE",
        "Pipfile.lock references remote dependency sources",
        pipfile_lock_sources(content),
    )
}

pub(crate) fn analyze_cargo_lock(path: &Path, content: &str) -> Vec<Finding> {
    let Some(git_sources) = cargo_lock_git_sources(content) else {
        return analyze_lockfile(
            path,
            content,
            "LOCKFILE_CARGO_GIT_SOURCE",
            LockfilePattern::Regex(&RE_CARGO_GIT_SOURCE),
            "Cargo.lock references git-based dependency sources",
        );
    };

    lockfile_findings_for_sources(
        path,
        "LOCKFILE_CARGO_GIT_SOURCE",
        "Cargo.lock references git-based dependency sources",
        git_sources,
    )
}

pub(crate) fn analyze_poetry_lock(path: &Path, content: &str) -> Vec<Finding> {
    let Some(sources) = poetry_lock_sources(content) else {
        return analyze_lockfile(
            path,
            content,
            "LOCKFILE_POETRY_URL_SOURCE",
            LockfilePattern::Regex(&RE_POETRY_URL_SOURCE),
            "poetry.lock references URL-based dependency sources",
        );
    };

    lockfile_findings_for_sources(
        path,
        "LOCKFILE_POETRY_URL_SOURCE",
        "poetry.lock references URL-based dependency sources",
        sources,
    )
}

pub(crate) fn analyze_uv_lock(path: &Path, content: &str) -> Vec<Finding> {
    let Some(git_sources) = uv_lock_git_sources(content) else {
        return analyze_lockfile(
            path,
            content,
            "LOCKFILE_UV_GIT_SOURCE",
            LockfilePattern::Regex(&RE_UV_GIT_SOURCE),
            "uv.lock references git-based dependency sources",
        );
    };

    lockfile_findings_for_sources(
        path,
        "LOCKFILE_UV_GIT_SOURCE",
        "uv.lock references git-based dependency sources",
        git_sources,
    )
}

pub(crate) fn analyze_yarn_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile(
        path,
        content,
        "LOCKFILE_YARN_REMOTE_TARBALL",
        LockfilePattern::Regex(&RE_YARN_REMOTE_TARBALL),
        "yarn.lock resolves dependencies from remote tarballs",
    )
}

pub(crate) fn analyze_pnpm_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile(
        path,
        content,
        "LOCKFILE_PNPM_REMOTE_TARBALL",
        LockfilePattern::Regex(&RE_PNPM_REMOTE_TARBALL),
        "pnpm lockfile references remote tarballs",
    )
}

pub(crate) fn lockfile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();
    if lockfile_mentions_remote_source(content) {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    capabilities
}

pub(crate) fn lockfile_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    if lockfile_mentions_remote_source(content) {
        links.push(ArtifactLink {
            target: "registry".to_string(),
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    links
}

enum LockfilePattern<'a> {
    JsonKey(&'a str),
    Regex(&'a crate::ports::CompiledPattern),
}

fn analyze_lockfile(
    path: &Path,
    content: &str,
    rule_id: &str,
    pattern: LockfilePattern<'_>,
    reason: &str,
) -> Vec<Finding> {
    let urls = match &pattern {
        LockfilePattern::JsonKey(key) => remote_urls_for_json_key(content, key),
        LockfilePattern::Regex(regex) => {
            if regex.is_match(content) {
                extract_http_urls(content)
            } else {
                Vec::new()
            }
        }
    };
    lockfile_findings_for_sources(path, rule_id, reason, urls)
}

fn lockfile_findings_for_sources(
    path: &Path,
    rule_id: &str,
    reason: &str,
    sources: Vec<String>,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let suspicious_sources: Vec<_> = sources
        .into_iter()
        .filter(|source| !is_common_lockfile_source(source))
        .collect();
    if suspicious_sources.is_empty() {
        return Vec::new();
    }
    vec![Finding::builder(rule_id, ThreatCategory::SupplyChain)
        .severity(Severity::Low)
        .action(RecommendedAction::Log)
        .evidence_kind(EvidenceKind::Context)
        .artifact(ArtifactKind::Lockfile, Some(artifact_path.clone()))
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path,
        })
        .match_value(suspicious_sources[0].clone())
        .reason(format!("{reason} from a non-standard remote source"))
        .build()]
}

fn cargo_lock_git_sources(content: &str) -> Option<Vec<String>> {
    let toml = content.parse::<TomlValue>().ok()?;
    let packages = toml.get("package").and_then(TomlValue::as_array)?;
    Some(
        packages
            .iter()
            .filter_map(|package| package.get("source").and_then(TomlValue::as_str))
            .filter_map(remote_cargo_git_source)
            .collect(),
    )
}

fn remote_cargo_git_source(source: &str) -> Option<String> {
    let trimmed = source.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with(GIT_SOURCE_PREFIX) {
        return None;
    }
    remote_dependency_source_match_value(trimmed)
}

fn poetry_lock_sources(content: &str) -> Option<Vec<String>> {
    let toml = content.parse::<TomlValue>().ok()?;
    let packages = toml.get("package").and_then(TomlValue::as_array)?;
    let mut saw_package_source = false;
    let mut sources = Vec::new();
    for package in packages {
        let Some(source) = package.get("source") else {
            continue;
        };
        saw_package_source = true;
        if let Some(source_url) = poetry_source_url(source) {
            sources.push(source_url);
        }
    }
    saw_package_source.then_some(sources)
}

fn poetry_source_url(source: &TomlValue) -> Option<String> {
    let table = source.as_table()?;
    table
        .get("url")
        .and_then(TomlValue::as_str)
        .and_then(remote_dependency_source_match_value)
}

fn uv_lock_git_sources(content: &str) -> Option<Vec<String>> {
    let toml = content.parse::<TomlValue>().ok()?;
    let packages = toml.get("package").and_then(TomlValue::as_array)?;
    Some(
        packages
            .iter()
            .filter_map(|package| package.get("source"))
            .filter_map(uv_git_source)
            .collect(),
    )
}

fn uv_git_source(source: &TomlValue) -> Option<String> {
    match source {
        TomlValue::Table(table) => table
            .get("git")
            .and_then(TomlValue::as_str)
            .and_then(remote_dependency_source_match_value),
        TomlValue::String(source) => {
            let lower = source.trim().to_ascii_lowercase();
            if lower.starts_with(GIT_SOURCE_PREFIX) {
                remote_dependency_source_match_value(source)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn remote_dependency_source_match_value(source: &str) -> Option<String> {
    let trimmed = source.trim();
    let lower = trimmed.to_ascii_lowercase();
    let transport = lower
        .strip_prefix(GIT_SOURCE_PREFIX)
        .unwrap_or(lower.as_str());
    if transport.starts_with(FILE_SOURCE_PREFIX) {
        return None;
    }
    if REMOTE_HTTP_SOURCE_PREFIXES
        .iter()
        .any(|prefix| transport.starts_with(prefix))
    {
        return extract_http_urls(trimmed).into_iter().next();
    }
    if is_scp_like_git_source(transport) {
        return Some(trimmed.to_string());
    }
    REMOTE_NON_HTTP_GIT_SOURCE_PREFIXES
        .iter()
        .any(|prefix| transport.starts_with(prefix))
        .then(|| trimmed.to_string())
}

fn is_scp_like_git_source(value: &str) -> bool {
    let Some((user_host, remote_path)) = value.split_once(':') else {
        return false;
    };
    if user_host.contains('/') || remote_path.trim().is_empty() {
        return false;
    }
    let Some((user, host)) = user_host.split_once('@') else {
        return false;
    };
    !user.is_empty()
        && !host.is_empty()
        && user.bytes().all(is_scp_user_host_byte)
        && host.bytes().all(is_scp_user_host_byte)
}

fn is_scp_user_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn lockfile_mentions_remote_source(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || REMOTE_NON_HTTP_GIT_SOURCE_PREFIXES
            .iter()
            .any(|prefix| lower.contains(prefix))
        || content.split(is_lockfile_source_delimiter).any(|token| {
            let lower_token = token.trim().to_ascii_lowercase();
            let transport = lower_token
                .strip_prefix(GIT_SOURCE_PREFIX)
                .unwrap_or(lower_token.as_str());
            is_scp_like_git_source(transport)
        })
}

fn is_lockfile_source_delimiter(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '{' | '}' | '[' | ']' | '(' | ')')
}

fn remote_urls_for_json_key(content: &str, key: &str) -> Vec<String> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    collect_remote_urls_for_json_key(&json, key, &mut urls);
    urls
}

fn collect_remote_urls_for_json_key(value: &Value, key: &str, urls: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (entry_key, entry_value) in map {
                if entry_key == key {
                    if let Some(text) = entry_value.as_str() {
                        urls.extend(extract_http_urls(text));
                    }
                }
                collect_remote_urls_for_json_key(entry_value, key, urls);
            }
        }
        Value::Array(values) => {
            for entry in values {
                collect_remote_urls_for_json_key(entry, key, urls);
            }
        }
        _ => {}
    }
}

fn pipfile_lock_sources(content: &str) -> Vec<String> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let mut sources = Vec::new();
    collect_remote_sources_for_json_keys(&json, &["url", "git"], &mut sources);
    sources
}

fn collect_remote_sources_for_json_keys(value: &Value, keys: &[&str], sources: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (entry_key, entry_value) in map {
                if keys.contains(&entry_key.as_str()) {
                    if let Some(text) = entry_value.as_str() {
                        if let Some(source) = remote_dependency_source_match_value(text) {
                            sources.push(source);
                        }
                    }
                }
                collect_remote_sources_for_json_keys(entry_value, keys, sources);
            }
        }
        Value::Array(values) => {
            for entry in values {
                collect_remote_sources_for_json_keys(entry, keys, sources);
            }
        }
        _ => {}
    }
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

    fn rule_ids(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect()
    }

    /// # Contract
    ///
    /// Cargo git sources can be pinned through SSH remotes; those are
    /// still remote dependency sources even though they are not HTTP URLs.
    #[test]
    fn analyze_cargo_lock_detects_git_ssh_sources() {
        let content = r#"
version = 4

[[package]]
name = "pkg"
version = "0.1.0"
source = "git+ssh://git@github.com/example/pkg.git?rev=main#0123456789abcdef0123456789abcdef01234567"
"#;

        let findings = analyze_cargo_lock(Path::new("Cargo.lock"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_CARGO_GIT_SOURCE"]);
        assert_eq!(
            findings[0].match_value,
            "git+ssh://git@github.com/example/pkg.git?rev=main#0123456789abcdef0123456789abcdef01234567"
        );
    }

    /// # Contract
    ///
    /// HTTP Cargo git sources expose the extracted URL match value while
    /// structured parsing also supports non-HTTP transports.
    #[test]
    fn analyze_cargo_lock_keeps_https_git_source_match_value() {
        let content = r#"
version = 4

[[package]]
name = "pkg"
version = "0.1.0"
source = "git+HTTPS://packages.attacker.example/pkg.git#0123456789abcdef0123456789abcdef01234567"
"#;

        let findings = analyze_cargo_lock(Path::new("Cargo.lock"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_CARGO_GIT_SOURCE"]);
        assert_eq!(
            findings[0].match_value,
            "HTTPS://packages.attacker.example/pkg.git#0123456789abcdef0123456789abcdef01234567"
        );
    }

    /// # Contract (negative)
    ///
    /// A local file-backed Cargo git source is not a remote dependency
    /// source and must not emit the remote-source lockfile finding.
    #[test]
    fn analyze_cargo_lock_skips_local_git_file_sources() {
        let content = r#"
version = 4

[[package]]
name = "pkg"
version = "0.1.0"
source = "git+file:///tmp/pkg.git#0123456789abcdef0123456789abcdef01234567"
"#;

        let findings = analyze_cargo_lock(Path::new("Cargo.lock"), content);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// # Contract
    ///
    /// uv Git sources are stored in the lockfile as `source = { git = ... }`,
    /// not only as PEP 508 `git+https://...` requirement strings.
    #[test]
    fn analyze_uv_lock_detects_inline_table_git_sources() {
        let content = r#"
version = 1
revision = 3

[[package]]
name = "pkg"
version = "0.1.0"
source = { git = "https://packages.attacker.example/pkg.git#0123456789abcdef0123456789abcdef01234567" }
"#;

        let findings = analyze_uv_lock(Path::new("uv.lock"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_UV_GIT_SOURCE"]);
        assert_eq!(
            findings[0].match_value,
            "https://packages.attacker.example/pkg.git#0123456789abcdef0123456789abcdef01234567"
        );
    }

    /// # Contract
    ///
    /// URL schemes in uv Git sources are case-insensitive all the way through
    /// extraction and non-standard-source classification.
    #[test]
    fn analyze_uv_lock_detects_case_variant_inline_table_git_sources() {
        let content = r#"
version = 1
revision = 3

[[package]]
name = "pkg"
version = "0.1.0"
source = { git = "HTTPS://packages.attacker.example/pkg.git#0123456789abcdef0123456789abcdef01234567" }
"#;

        let findings = analyze_uv_lock(Path::new("uv.lock"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_UV_GIT_SOURCE"]);
    }

    /// # Contract
    ///
    /// uv Git sources can be pinned through SSH remotes; those are still
    /// remote dependency sources even though they are not HTTP URLs.
    #[test]
    fn analyze_uv_lock_detects_ssh_inline_table_git_sources() {
        let content = r#"
version = 1
revision = 3

[[package]]
name = "pkg"
version = "0.1.0"
source = { git = "ssh://git@github.com/example/pkg.git#0123456789abcdef0123456789abcdef01234567" }
"#;

        let findings = analyze_uv_lock(Path::new("uv.lock"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_UV_GIT_SOURCE"]);
        assert_eq!(
            findings[0].match_value,
            "ssh://git@github.com/example/pkg.git#0123456789abcdef0123456789abcdef01234567"
        );
    }

    /// # Contract (negative)
    ///
    /// A local file-backed uv Git source is not a remote dependency
    /// source and must not emit the remote-source lockfile finding.
    #[test]
    fn analyze_uv_lock_skips_local_git_file_sources() {
        let content = r#"
version = 1
revision = 3

[[package]]
name = "pkg"
version = "0.1.0"
source = { git = "file:///tmp/pkg.git#0123456789abcdef0123456789abcdef01234567" }
"#;

        let findings = analyze_uv_lock(Path::new("uv.lock"), content);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// # Contract
    ///
    /// Poetry source tables can pin Git dependencies through SSH remotes;
    /// those are still remote dependency sources even though they are not
    /// HTTP URLs.
    #[test]
    fn analyze_poetry_lock_detects_git_ssh_source_table() {
        let content = r#"
[[package]]
name = "pkg"
version = "0.1.0"

[package.source]
type = "git"
url = "ssh://git@github.com/example/pkg.git"
reference = "main"
resolved_reference = "0123456789abcdef0123456789abcdef01234567"
"#;

        let findings = analyze_poetry_lock(Path::new("poetry.lock"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_POETRY_URL_SOURCE"]);
        assert_eq!(
            findings[0].match_value,
            "ssh://git@github.com/example/pkg.git"
        );
    }

    /// # Contract (negative)
    ///
    /// A local file-backed Poetry source table is not a remote dependency
    /// source and must not emit the remote-source lockfile finding.
    #[test]
    fn analyze_poetry_lock_skips_local_file_source_table() {
        let content = r#"
[[package]]
name = "pkg"
version = "0.1.0"

[package.source]
type = "directory"
url = "file:///tmp/pkg"
"#;

        let findings = analyze_poetry_lock(Path::new("poetry.lock"), content);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// # Contract
    ///
    /// Lockfile remote-source triggers honor case-insensitive URL schemes
    /// before classifying the extracted URL.
    #[test]
    fn lockfile_analyzers_detect_case_variant_remote_url_sources() {
        let cases = [
            (
                "package-lock.json",
                analyze_package_lock as fn(&Path, &str) -> Vec<Finding>,
                r#"{"packages":{"node_modules/pkg":{"resolved":"HTTPS://packages.attacker.example/pkg.tgz"}}}"#,
                "LOCKFILE_PACKAGE_REMOTE_TARBALL",
            ),
            (
                "poetry.lock",
                analyze_poetry_lock,
                r#"
[[package]]
name = "pkg"
version = "0.1.0"
url = "HTTPS://packages.attacker.example/pkg.tar.gz"
"#,
                "LOCKFILE_POETRY_URL_SOURCE",
            ),
            (
                "yarn.lock",
                analyze_yarn_lock,
                r#"
"pkg@npm:1.0.0":
  resolved "HTTPS://packages.attacker.example/pkg.tgz"
"#,
                "LOCKFILE_YARN_REMOTE_TARBALL",
            ),
            (
                "pnpm-lock.yaml",
                analyze_pnpm_lock,
                r#"
packages:
  /pkg@1.0.0:
    resolution:
      tarball: HTTPS://packages.attacker.example/pkg.tgz
"#,
                "LOCKFILE_PNPM_REMOTE_TARBALL",
            ),
        ];

        for (path, analyzer, content, expected_rule) in cases {
            let findings = analyzer(Path::new(path), content);

            assert_eq!(rule_ids(&findings), vec![expected_rule], "{path}");
        }
    }

    /// # Contract (negative)
    ///
    /// Case-insensitive URL-scheme matching must not treat non-HTTP scheme
    /// lookalikes as remote lockfile sources.
    #[test]
    fn lockfile_analyzers_reject_non_http_scheme_lookalikes() {
        let cases = [
            (
                "package-lock.json",
                analyze_package_lock as fn(&Path, &str) -> Vec<Finding>,
                r#"{"packages":{"node_modules/pkg":{"resolved":"HTXP://packages.attacker.example/pkg.tgz"}}}"#,
            ),
            (
                "poetry.lock",
                analyze_poetry_lock,
                r#"
[[package]]
name = "pkg"
version = "0.1.0"
url = "HTXP://packages.attacker.example/pkg.tar.gz"
"#,
            ),
            (
                "yarn.lock",
                analyze_yarn_lock,
                r#"
"pkg@npm:1.0.0":
  resolved "HTXP://packages.attacker.example/pkg.tgz"
"#,
            ),
            (
                "pnpm-lock.yaml",
                analyze_pnpm_lock,
                r#"
packages:
  /pkg@1.0.0:
    resolution:
      tarball: HTXP://packages.attacker.example/pkg.tgz
"#,
            ),
        ];

        for (path, analyzer, content) in cases {
            let findings = analyzer(Path::new(path), content);

            assert!(findings.is_empty(), "{path}: unexpected {findings:?}");
        }
    }

    /// # Contract
    ///
    /// `package-lock.json` analysis only considers the exact `resolved`
    /// string value, not unrelated URL-bearing metadata in the same file.
    #[test]
    fn analyze_package_lock_ignores_unrelated_urls_when_resolved_is_local() {
        let content = r#"{
  "packages": {
    "node_modules/pkg": {
      "version": "1.0.0",
      "resolved": "file:../vendor/pkg-1.0.0.tgz",
      "homepage": "https://packages.attacker.example/pkg"
    }
  }
}"#;

        let findings = analyze_package_lock(Path::new("package-lock.json"), content);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// # Contract
    ///
    /// `resolved` matching is key-exact. Substring keys such as
    /// `unresolved` are not package source resolutions.
    #[test]
    fn analyze_package_lock_rejects_resolved_key_substrings() {
        let content = r#"{
  "packages": {
    "node_modules/pkg": {
      "version": "1.0.0",
      "unresolved": "https://packages.attacker.example/pkg-1.0.0.tgz"
    }
  }
}"#;

        let findings = analyze_package_lock(Path::new("package-lock.json"), content);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// # Contract
    ///
    /// The common-registry allowlist applies to the resolved URL host,
    /// not to known registry hostnames embedded in a remote path.
    #[test]
    fn analyze_package_lock_detects_known_registry_host_in_path() {
        let content = r#"{
  "packages": {
    "node_modules/pkg": {
      "version": "1.0.0",
      "resolved": "https://packages.attacker.example/@registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
    }
  }
}"#;

        let findings = analyze_package_lock(Path::new("package-lock.json"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_PACKAGE_REMOTE_TARBALL"]);
        assert_eq!(
            findings[0].match_value,
            "https://packages.attacker.example/@registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
        );
    }

    /// # Contract
    ///
    /// Pipfile.lock JSON source entries with non-default indexes are
    /// remote dependency sources.
    #[test]
    fn analyze_pipfile_lock_detects_nonstandard_index_source() {
        let content = r#"{
  "_meta": {
    "sources": [
      {
        "name": "internal",
        "url": "https://packages.attacker.example/simple",
        "verify_ssl": true
      }
    ]
  },
  "default": {}
}"#;

        let findings = analyze_pipfile_lock(Path::new("Pipfile.lock"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_PIPFILE_REMOTE_SOURCE"]);
        assert_eq!(
            findings[0].match_value,
            "https://packages.attacker.example/simple"
        );
    }

    /// # Contract (negative)
    ///
    /// The default PyPI index is a common lockfile source and must not
    /// emit the Pipfile remote-source finding.
    #[test]
    fn analyze_pipfile_lock_skips_default_pypi_source() {
        let content = r#"{
  "_meta": {
    "sources": [
      {
        "name": "pypi",
        "url": "https://pypi.org/simple",
        "verify_ssl": true
      }
    ]
  },
  "default": {}
}"#;

        let findings = analyze_pipfile_lock(Path::new("Pipfile.lock"), content);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// # Contract
    ///
    /// Pipfile.lock package entries can pin Git dependencies through SSH
    /// remotes; those are remote dependency sources even though they are
    /// not HTTP URLs.
    #[test]
    fn analyze_pipfile_lock_detects_git_ssh_package_source() {
        let content = r#"{
  "_meta": {
    "sources": [
      {
        "name": "pypi",
        "url": "https://pypi.org/simple",
        "verify_ssl": true
      }
    ]
  },
  "default": {
    "pkg": {
      "git": "ssh://git@github.com/example/pkg.git",
      "ref": "0123456789abcdef0123456789abcdef01234567"
    }
  }
}"#;

        let findings = analyze_pipfile_lock(Path::new("Pipfile.lock"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_PIPFILE_REMOTE_SOURCE"]);
        assert_eq!(
            findings[0].match_value,
            "ssh://git@github.com/example/pkg.git"
        );
    }

    /// # Contract
    ///
    /// Pipfile.lock package entries can also use SCP-like Git SSH
    /// syntax, which is remote even though it has no URL scheme.
    #[test]
    fn analyze_pipfile_lock_detects_scp_like_git_package_source() {
        let content = r#"{
  "_meta": {
    "sources": [
      {
        "name": "pypi",
        "url": "https://pypi.org/simple",
        "verify_ssl": true
      }
    ]
  },
  "default": {
    "pkg": {
      "git": "git@github.com:example/pkg.git",
      "ref": "0123456789abcdef0123456789abcdef01234567"
    }
  }
}"#;

        let findings = analyze_pipfile_lock(Path::new("Pipfile.lock"), content);

        assert_eq!(rule_ids(&findings), vec!["LOCKFILE_PIPFILE_REMOTE_SOURCE"]);
        assert_eq!(findings[0].match_value, "git@github.com:example/pkg.git");
    }

    /// # Contract (negative)
    ///
    /// SCP-like Git source detection requires the remote path separator;
    /// an `@` alone in a Git field is not enough to infer a remote source.
    #[test]
    fn analyze_pipfile_lock_rejects_git_value_without_scp_path() {
        let content = r#"{
  "_meta": {
    "sources": [
      {
        "name": "pypi",
        "url": "https://pypi.org/simple",
        "verify_ssl": true
      }
    ]
  },
  "default": {
    "pkg": {
      "git": "git@github.com",
      "ref": "0123456789abcdef0123456789abcdef01234567"
    }
  }
}"#;

        let findings = analyze_pipfile_lock(Path::new("Pipfile.lock"), content);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// # Contract (negative)
    ///
    /// Local file-backed Pipfile Git sources are not remote dependency
    /// sources and must not emit the remote-source lockfile finding.
    #[test]
    fn analyze_pipfile_lock_skips_local_git_package_source() {
        let content = r#"{
  "_meta": {
    "sources": [
      {
        "name": "pypi",
        "url": "https://pypi.org/simple",
        "verify_ssl": true
      }
    ]
  },
  "default": {
    "pkg": {
      "git": "file:///tmp/pkg",
      "ref": "0123456789abcdef0123456789abcdef01234567"
    }
  }
}"#;

        let findings = analyze_pipfile_lock(Path::new("Pipfile.lock"), content);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// # Contract
    ///
    /// A local tarball reference is not a network edge.
    #[test]
    fn lockfile_graph_inference_rejects_local_tarball_entries() {
        let content = r#"
packages:
  /pkg@1.0.0:
    resolution:
      tarball: file:../vendor/pkg-1.0.0.tgz
"#;

        let caps = lockfile_capabilities(content);
        let links = lockfile_relations(content);

        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
        assert!(!relation_target_present(&links, "registry"));
    }

    /// # Contract
    ///
    /// HTTP(S) URLs in lockfiles still produce the registry network edge.
    #[test]
    fn lockfile_graph_inference_accepts_remote_urls() {
        let content = r#"
packages:
  /pkg@1.0.0:
    resolution:
      tarball: HTTPS://packages.attacker.example/pkg-1.0.0.tgz
"#;

        let caps = lockfile_capabilities(content);
        let links = lockfile_relations(content);

        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
        assert!(relation_target_present(&links, "registry"));
    }

    /// # Contract
    ///
    /// Cargo SSH git sources in lockfiles are remote dependency sources
    /// and produce the same network graph facts as HTTP lockfile sources.
    #[test]
    fn lockfile_graph_inference_accepts_cargo_git_ssh_sources() {
        let content = r#"
version = 4

[[package]]
name = "pkg"
version = "0.1.0"
source = "git+ssh://git@github.com/example/pkg.git?rev=main#0123456789abcdef0123456789abcdef01234567"
"#;

        let caps = lockfile_capabilities(content);
        let links = lockfile_relations(content);

        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
        assert!(relation_target_present(&links, "registry"));
    }

    /// # Contract (negative)
    ///
    /// Local file-backed Cargo git sources are lockfile pins, not network
    /// sources, and must not add network graph facts.
    #[test]
    fn lockfile_graph_inference_rejects_local_cargo_git_file_sources() {
        let content = r#"
version = 4

[[package]]
name = "pkg"
version = "0.1.0"
source = "git+file:///tmp/pkg.git#0123456789abcdef0123456789abcdef01234567"
"#;

        let caps = lockfile_capabilities(content);
        let links = lockfile_relations(content);

        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
        assert!(!relation_target_present(&links, "registry"));
    }

    /// # Contract
    ///
    /// SCP-like Git sources in lockfiles are remote dependency sources
    /// and produce the same network graph facts as URL-form remotes.
    #[test]
    fn lockfile_graph_inference_accepts_scp_like_git_sources() {
        let content = r#"{
  "default": {
    "pkg": {
      "git": "git@github.com:example/pkg.git",
      "ref": "0123456789abcdef0123456789abcdef01234567"
    }
  }
}"#;

        let caps = lockfile_capabilities(content);
        let links = lockfile_relations(content);

        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
        assert!(relation_target_present(&links, "registry"));
    }

    /// # Contract (negative)
    ///
    /// Email-like metadata without an SCP remote path does not create
    /// lockfile network graph facts.
    #[test]
    fn lockfile_graph_inference_rejects_email_like_metadata() {
        let content = r#"{
  "metadata": {
    "maintainer": "dev@example.com"
  }
}"#;

        let caps = lockfile_capabilities(content);
        let links = lockfile_relations(content);

        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
        assert!(!relation_target_present(&links, "registry"));
    }

    /// # Contract (negative)
    ///
    /// A registry-only uv lockfile source should not emit the Git-source
    /// supply-chain finding merely because the lockfile has an HTTPS URL.
    #[test]
    fn analyze_uv_lock_skips_registry_sources_without_git_key() {
        let content = r#"
version = 1
revision = 3

[[package]]
name = "pkg"
version = "0.1.0"
source = { registry = "https://packages.attacker.example/simple" }
"#;

        let findings = analyze_uv_lock(Path::new("uv.lock"), content);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }
}
