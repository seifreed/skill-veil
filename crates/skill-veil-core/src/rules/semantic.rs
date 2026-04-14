use std::path::PathBuf;

use crate::artifact_graph::{ArtifactGraph, ArtifactRelation};
use crate::domain_types::ProvenanceTrustLevel;

pub(super) fn semantic_target_paths(
    graph: &ArtifactGraph,
    current_artifact_path: Option<&str>,
    anywhere_in_package: bool,
) -> Vec<String> {
    if anywhere_in_package || current_artifact_path.is_none() {
        return graph.nodes.iter().map(|node| node.path.clone()).collect();
    }

    vec![current_artifact_path.expect("checked is_some").to_string()]
}

pub(super) fn infer_provenance_trust(graph: &ArtifactGraph) -> ProvenanceTrustLevel {
    let mut domains = Vec::new();
    for edge in &graph.edges {
        if edge.relation != ArtifactRelation::ConnectsTo {
            continue;
        }
        if let Some(domain) = remote_domain(&edge.to) {
            domains.push(domain);
        }
    }

    if domains.is_empty() {
        return ProvenanceTrustLevel::Review;
    }

    if domains.iter().any(|domain| {
        domain.ends_with("ngrok.io")
            || domain.ends_with("trycloudflare.com")
            || domain.parse::<std::net::IpAddr>().is_ok()
    }) {
        return ProvenanceTrustLevel::Untrusted;
    }

    if domains.iter().all(|domain| {
        matches!(
            domain.as_str(),
            "registry.npmjs.org" | "pypi.org" | "github.com" | "raw.githubusercontent.com"
        )
    }) {
        ProvenanceTrustLevel::Trusted
    } else {
        ProvenanceTrustLevel::Review
    }
}

fn remote_domain(target: &str) -> Option<String> {
    let normalized = target.trim().trim_matches('"');
    if let Some(rest) = normalized
        .strip_prefix("https://")
        .or_else(|| normalized.strip_prefix("http://"))
    {
        let host = rest
            .split('/')
            .next()
            .unwrap_or_default()
            .split('@')
            .next_back()
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .trim();
        if !host.is_empty() {
            return Some(host.to_ascii_lowercase());
        }
    }

    if target.starts_with('/') || PathBuf::from(target).components().count() > 1 {
        return None;
    }

    let normalized = normalized.to_ascii_lowercase();
    // Only treat as domain if it looks like one (has dot-separated structure, no spaces)
    if normalized.contains('.') && !normalized.contains(' ') {
        Some(normalized)
    } else {
        None
    }
}
