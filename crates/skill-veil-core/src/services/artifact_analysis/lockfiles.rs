use super::{extract_http_urls, is_common_lockfile_source, ArtifactAnalysisService, ArtifactLink};
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity,
    ThreatCategory,
};
use regex::Regex;
use std::path::Path;

pub(super) fn analyze_package_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile_json(
        path,
        content,
        "LOCKFILE_PACKAGE_REMOTE_TARBALL",
        "resolved",
        "package-lock resolves dependencies from remote tarballs",
    )
}

pub(super) fn analyze_cargo_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile_text(
        path,
        content,
        "LOCKFILE_CARGO_GIT_SOURCE",
        r#"source\s*=\s*"git\+"#,
        "Cargo.lock references git-based dependency sources",
    )
}

pub(super) fn analyze_poetry_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile_text(
        path,
        content,
        "LOCKFILE_POETRY_URL_SOURCE",
        r#"url\s*=\s*"https?://"#,
        "poetry.lock references URL-based dependency sources",
    )
}

pub(super) fn analyze_uv_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile_text(
        path,
        content,
        "LOCKFILE_UV_GIT_SOURCE",
        r#"git\+https?://"#,
        "uv.lock references git-based dependency sources",
    )
}

pub(super) fn analyze_yarn_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile_text(
        path,
        content,
        "LOCKFILE_YARN_REMOTE_TARBALL",
        r#"resolved\s+"https?://"#,
        "yarn.lock resolves dependencies from remote tarballs",
    )
}

pub(super) fn analyze_pnpm_lock(path: &Path, content: &str) -> Vec<Finding> {
    analyze_lockfile_text(
        path,
        content,
        "LOCKFILE_PNPM_REMOTE_TARBALL",
        r#"tarball:\s*https?://"#,
        "pnpm lockfile references remote tarballs",
    )
}

pub(super) fn lockfile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();
    if lower.contains("http://") || lower.contains("https://") || lower.contains("tarball:") {
        capabilities.push(ArtifactAnalysisService::declared_capability(ArtifactCapability::NetworkAccess));
    }
    capabilities
}

pub(super) fn lockfile_relations(content: &str) -> Vec<ArtifactLink> {
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

fn analyze_lockfile_json(
    path: &Path,
    content: &str,
    rule_id: &str,
    key: &str,
    reason: &str,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    if !content.contains(key) || !(content.contains("http://") || content.contains("https://")) {
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

fn analyze_lockfile_text(
    path: &Path,
    content: &str,
    rule_id: &str,
    pattern: &str,
    reason: &str,
) -> Vec<Finding> {
    let regex = Regex::new(pattern).expect("valid regex");
    let artifact_path = path.display().to_string();
    let urls = extract_http_urls(content);
    let suspicious_urls: Vec<_> = urls
        .into_iter()
        .filter(|url| !is_common_lockfile_source(url))
        .collect();
    if suspicious_urls.is_empty() {
        return Vec::new();
    }
    regex.find(content).map_or_else(Vec::new, |_| {
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
    })
}
