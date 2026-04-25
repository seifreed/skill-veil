//! Graph construction utilities for artifact dependency analysis.
//!
//! Provides [`build_artifact_graph`] which assembles an [`ArtifactGraph`] from
//! discovered files, classifies artifact kinds, infers cross-artifact
//! relationships, and identifies sibling package manifests and lockfiles.

use crate::artifact_graph::{ArtifactCapabilityFact, ArtifactGraph, ArtifactRelation};
use crate::findings::ArtifactKind;
use crate::ports::FileSystemProvider;
use crate::services::{ArtifactAnalysisService, FileDiscoveryService};
use crate::SkillDocument;
use std::path::{Path, PathBuf};

pub(crate) fn build_artifact_graph<F: FileSystemProvider>(
    artifact_analysis: &ArtifactAnalysisService,
    fs_provider: &F,
    doc: &SkillDocument,
) -> ArtifactGraph {
    let mut graph = ArtifactGraph::new();
    let root_path = doc.path.display().to_string();
    graph.add_node_with_capabilities(
        root_path.clone(),
        artifact_kind_for_path::<F>(&doc.path),
        artifact_capabilities(artifact_analysis, fs_provider, &doc.path),
    );
    add_inferred_relations(
        &mut graph,
        artifact_analysis,
        fs_provider,
        &doc.path,
        &root_path,
    );

    if let Some(parent_dir) = doc.path.parent() {
        for manifest in sibling_package_manifests(fs_provider, parent_dir) {
            if manifest == doc.path {
                continue;
            }

            let manifest_path = manifest.display().to_string();
            let manifest_kind = artifact_kind_for_path::<F>(&manifest);
            graph.add_node_with_capabilities(
                manifest_path.clone(),
                manifest_kind,
                artifact_capabilities(artifact_analysis, fs_provider, &manifest),
            );
            graph.add_edge(
                root_path.clone(),
                manifest_path.clone(),
                ArtifactRelation::Contains,
            );
            add_inferred_relations(
                &mut graph,
                artifact_analysis,
                fs_provider,
                &manifest,
                &manifest_path,
            );

            for lockfile in sibling_expected_lockfiles_for_manifest(
                artifact_analysis,
                fs_provider,
                &manifest,
                parent_dir,
            ) {
                let lockfile_path = lockfile.display().to_string();
                graph.add_node_with_capabilities(
                    lockfile_path.clone(),
                    ArtifactKind::Lockfile,
                    artifact_capabilities(artifact_analysis, fs_provider, &lockfile),
                );
                graph.add_edge(
                    manifest_path.clone(),
                    lockfile_path,
                    ArtifactRelation::Locks,
                );
                add_inferred_relations(
                    &mut graph,
                    artifact_analysis,
                    fs_provider,
                    &lockfile,
                    &lockfile.display().to_string(),
                );
            }
        }
    }

    for referenced_file in &doc.referenced_files {
        let referenced_path = referenced_file.display().to_string();
        graph.add_node_with_capabilities(
            referenced_path.clone(),
            artifact_kind_for_path::<F>(referenced_file),
            artifact_capabilities(artifact_analysis, fs_provider, referenced_file),
        );
        graph.add_edge(
            root_path.clone(),
            referenced_path,
            ArtifactRelation::References,
        );
        add_inferred_relations(
            &mut graph,
            artifact_analysis,
            fs_provider,
            referenced_file,
            &referenced_file.display().to_string(),
        );
    }

    graph
}

pub fn artifact_kind_for_path<F: FileSystemProvider>(path: &Path) -> ArtifactKind {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_ascii_lowercase);

    match file_name.as_deref() {
        Some("mcp.json" | "mcp.yaml" | "mcp.yml") => ArtifactKind::McpServerManifest,
        Some(
            "cargo.lock"
            | "poetry.lock"
            | "uv.lock"
            | "pipfile.lock"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "npm-shrinkwrap.json"
            | "package-lock.json",
        ) => ArtifactKind::Lockfile,
        Some(
            "package.json"
            | "requirements.txt"
            | "pyproject.toml"
            | "cargo.toml"
            | "dockerfile"
            | "docker-compose.yml"
            | "docker-compose.yaml"
            | "makefile"
            | ".npmrc"
            | "pip.conf",
        ) => ArtifactKind::PackageManifest,
        Some("agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md") => {
            ArtifactKind::AgentInstruction
        }
        Some(name) if name.ends_with(".prompt.md") => ArtifactKind::PromptPackDocument,
        _ if path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("prompts")) =>
        {
            ArtifactKind::PromptPackDocument
        }
        _ if FileDiscoveryService::<F>::is_explicit_skill_file(path) => ArtifactKind::SkillDocument,
        _ => ArtifactKind::ReferencedArtifact,
    }
}

pub(crate) fn sibling_files<F: FileSystemProvider>(fs_provider: &F, path: &Path) -> Vec<PathBuf> {
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    const RELEVANT_NAMES: &[&str] = &[
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "requirements.txt",
        "pyproject.toml",
        "cargo.toml",
        "cargo.lock",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "makefile",
        ".npmrc",
        "pip.conf",
        "mcp.json",
        "mcp.yaml",
        "mcp.yml",
        "yarn.lock",
        "pnpm-lock.yaml",
    ];

    fs_provider
        .list_files(parent, "*", false)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| {
            let file_name = p
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_ascii_lowercase);
            let extension = p
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase);
            file_name
                .as_deref()
                .is_some_and(|name| RELEVANT_NAMES.contains(&name))
                || matches!(
                    extension.as_deref(),
                    Some("sh" | "bash" | "zsh" | "py" | "js" | "ts" | "ps1")
                )
        })
        .collect()
}

/// Recover a SHA-256 package id from any ancestor directory name.
///
/// # Identity contract
///
/// SHA-256 hex digests in this codebase are always **lowercase**.
/// `is_ascii_hexdigit()` accepts uppercase too, which would let a path
/// segment like `AAAA...` (64 uppercase chars) qualify as a package id.
/// Two copies of the same package whose path differs only in casing
/// would then receive distinct ids and evade case-sensitive baseline /
/// waiver matching. The check below is intentionally stricter than
/// `is_ascii_hexdigit()` to keep ids canonical.
///
/// Kept in sync with `is_sha256_hex` in `crates/skill-veil-cli/src/vt/cross_check.rs`.
pub fn derive_package_id(path: &Path) -> Option<String> {
    path.ancestors()
        .filter_map(|ancestor| ancestor.file_name().and_then(|name| name.to_str()))
        .find(|segment| segment.len() == 64 && segment.bytes().all(is_lower_hex_byte))
        .map(ToOwned::to_owned)
}

#[inline]
fn is_lower_hex_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

fn artifact_capabilities<F: FileSystemProvider>(
    artifact_analysis: &ArtifactAnalysisService,
    fs_provider: &F,
    path: &Path,
) -> Vec<ArtifactCapabilityFact> {
    let Ok(fc) = fs_provider.read_file_bytes(path) else {
        return Vec::new();
    };
    let content = fc.decode_utf8_lossy().text;
    artifact_analysis.infer_capabilities(path, &content)
}

fn add_inferred_relations<F: FileSystemProvider>(
    graph: &mut ArtifactGraph,
    artifact_analysis: &ArtifactAnalysisService,
    fs_provider: &F,
    path: &Path,
    source_path: &str,
) {
    let Ok(fc) = fs_provider.read_file_bytes(path) else {
        return;
    };
    let content = fc.decode_utf8_lossy().text;
    for link in artifact_analysis.infer_relations(path, &content) {
        graph.add_node(link.target.clone(), ArtifactKind::GenericArtifact);
        graph.add_edge(source_path.to_string(), link.target, link.relation);
    }
}

fn sibling_package_manifests<F: FileSystemProvider>(fs_provider: &F, path: &Path) -> Vec<PathBuf> {
    const MANIFEST_NAMES: &[&str] = &[
        "package.json",
        "mcp.json",
        "mcp.yaml",
        "mcp.yml",
        "requirements.txt",
        "pyproject.toml",
        "cargo.toml",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "makefile",
        ".npmrc",
        "pip.conf",
    ];

    fs_provider
        .list_files(path, "*", false)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| MANIFEST_NAMES.contains(&name.to_ascii_lowercase().as_str()))
        })
        .collect()
}

fn sibling_expected_lockfiles_for_manifest<F: FileSystemProvider>(
    artifact_analysis: &ArtifactAnalysisService,
    fs_provider: &F,
    manifest: &Path,
    parent_dir: &Path,
) -> Vec<PathBuf> {
    let Ok(fc) = fs_provider.read_file_bytes(manifest) else {
        return Vec::new();
    };
    let content = fc.decode_utf8_lossy().text;
    artifact_analysis
        .expected_lockfiles(manifest, &content)
        .into_iter()
        .map(|name| parent_dir.join(name))
        .filter(|path| fs_provider.exists(path))
        .collect()
}

#[cfg(test)]
mod derive_package_id_tests {
    use super::derive_package_id;
    use std::path::PathBuf;

    #[test]
    fn accepts_lowercase_hex_64() {
        let sha = "a".repeat(64);
        let p = PathBuf::from(format!("/tmp/{sha}/SKILL.md"));
        assert_eq!(derive_package_id(&p), Some(sha));
    }

    /// Contract: uppercase hex MUST be rejected. SHA-256 outputs from the
    /// project's hashing path are always lowercase; aborting on uppercase
    /// keeps package_id values canonical and case-sensitive baseline
    /// matching consistent.
    #[test]
    fn rejects_uppercase_hex_64() {
        let upper = "A".repeat(64);
        let p = PathBuf::from(format!("/tmp/{upper}/SKILL.md"));
        assert!(derive_package_id(&p).is_none());
    }

    #[test]
    fn rejects_mixed_case_hex_64() {
        let mut s = String::with_capacity(64);
        for i in 0..64 {
            s.push(if i % 2 == 0 { 'a' } else { 'B' });
        }
        let p = PathBuf::from(format!("/tmp/{s}/SKILL.md"));
        assert!(derive_package_id(&p).is_none());
    }

    #[test]
    fn rejects_short_hex() {
        let p = PathBuf::from("/tmp/abcdef/SKILL.md");
        assert!(derive_package_id(&p).is_none());
    }
}
