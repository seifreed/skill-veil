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

lazy_pattern!(RE_CARGO_GIT_SOURCE, r#"source\s*=\s*"git\+"#);
lazy_pattern!(RE_POETRY_URL_SOURCE, r#"url\s*=\s*"https?://"#);
lazy_pattern!(RE_UV_GIT_SOURCE, r"git\+https?://");
lazy_pattern!(RE_YARN_REMOTE_TARBALL, r#"resolved\s+"https?://"#);
lazy_pattern!(RE_PNPM_REMOTE_TARBALL, r"tarball:\s*https?://");

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
            content.contains(key) && (content.contains("http://") || content.contains("https://"))
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
