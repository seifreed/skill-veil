use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::lazy_pattern;
use crate::services::artifact_orchestration::network::{
    extract_http_urls, is_common_lockfile_source,
};
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};
use std::path::Path;

lazy_pattern!(RE_CARGO_GIT_SOURCE, r#"(?i)\bsource\s*=\s*"git\+"#);
lazy_pattern!(RE_POETRY_URL_SOURCE, r#"(?i)\burl\s*=\s*"https?://"#);
lazy_pattern!(
    RE_UV_GIT_SOURCE,
    r#"(?i)(?:\bgit\s*=\s*"https?://|git\+https?://)"#
);
lazy_pattern!(RE_YARN_REMOTE_TARBALL, r#"(?i)\bresolved\s+"https?://"#);
lazy_pattern!(RE_PNPM_REMOTE_TARBALL, r"(?i)\btarball:\s*https?://");

pub(crate) fn analyze_package_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile(
        path,
        content,
        "LOCKFILE_PACKAGE_REMOTE_TARBALL",
        LockfilePattern::JsonKey("resolved"),
        "package-lock resolves dependencies from remote tarballs",
    )
}

pub(crate) fn analyze_cargo_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile(
        path,
        content,
        "LOCKFILE_CARGO_GIT_SOURCE",
        LockfilePattern::Regex(&RE_CARGO_GIT_SOURCE),
        "Cargo.lock references git-based dependency sources",
    )
}

pub(crate) fn analyze_poetry_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile(
        path,
        content,
        "LOCKFILE_POETRY_URL_SOURCE",
        LockfilePattern::Regex(&RE_POETRY_URL_SOURCE),
        "poetry.lock references URL-based dependency sources",
    )
}

pub(crate) fn analyze_uv_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile(
        path,
        content,
        "LOCKFILE_UV_GIT_SOURCE",
        LockfilePattern::Regex(&RE_UV_GIT_SOURCE),
        "uv.lock references git-based dependency sources",
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
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("http://") || lower.contains("https://") || lower.contains("tarball:") {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    capabilities
}

pub(crate) fn lockfile_relations(content: &str) -> Vec<ArtifactLink> {
    let lower = content.to_ascii_lowercase();
    let mut links = Vec::new();
    if lower.contains("http://") || lower.contains("https://") || lower.contains("tarball:") {
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
    let artifact_path = path.display().to_string();
    let pattern_matches = match &pattern {
        LockfilePattern::JsonKey(key) => {
            let lower_content = content.to_ascii_lowercase();
            content.contains(key)
                && (lower_content.contains("http://") || lower_content.contains("https://"))
        }
        LockfilePattern::Regex(regex) => regex.is_match(content),
    };
    if !pattern_matches {
        return Vec::new();
    }
    let urls = extract_http_urls(content);
    let suspicious_urls: Vec<_> = urls
        .into_iter()
        .filter(|url| !is_common_lockfile_source(url))
        .collect();
    if suspicious_urls.is_empty() {
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
        .match_value(suspicious_urls[0].clone())
        .reason(format!("{reason} from a non-standard remote source"))
        .build()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_ids(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect()
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
