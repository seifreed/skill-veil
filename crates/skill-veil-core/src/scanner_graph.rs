//! Graph construction utilities for artifact dependency analysis.
//!
//! Provides [`build_artifact_graph`] which assembles an [`ArtifactGraph`] from
//! discovered files, classifies artifact kinds, infers cross-artifact
//! relationships, and identifies sibling package manifests and lockfiles.

use crate::artifact_graph::{ArtifactCapabilityFact, ArtifactGraph, ArtifactRelation};
use crate::findings::ArtifactKind;
use crate::path_safety::path_resolves_within_base;
use crate::ports::FileSystemProvider;
use crate::services::{ArtifactOrchestratorService, FileDiscoveryService};
use crate::SkillDocument;
use std::path::{Path, PathBuf};

pub(crate) fn build_artifact_graph<F: FileSystemProvider>(
    artifact_orchestration: &ArtifactOrchestratorService,
    fs_provider: &F,
    doc: &SkillDocument,
) -> ArtifactGraph {
    let mut graph = ArtifactGraph::new();
    let root_path = doc.path.display().to_string();
    graph.add_node_with_capabilities(
        root_path.clone(),
        artifact_kind_for_path::<F>(&doc.path),
        artifact_capabilities(artifact_orchestration, fs_provider, &doc.path),
    );
    add_inferred_relations(
        &mut graph,
        artifact_orchestration,
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
                artifact_capabilities(artifact_orchestration, fs_provider, &manifest),
            );
            graph.add_edge(
                root_path.clone(),
                manifest_path.clone(),
                ArtifactRelation::Contains,
            );
            add_inferred_relations(
                &mut graph,
                artifact_orchestration,
                fs_provider,
                &manifest,
                &manifest_path,
            );

            for lockfile in sibling_expected_lockfiles_for_manifest(
                artifact_orchestration,
                fs_provider,
                &manifest,
                parent_dir,
            ) {
                let lockfile_path = lockfile.display().to_string();
                graph.add_node_with_capabilities(
                    lockfile_path.clone(),
                    ArtifactKind::Lockfile,
                    artifact_capabilities(artifact_orchestration, fs_provider, &lockfile),
                );
                graph.add_edge(
                    manifest_path.clone(),
                    lockfile_path,
                    ArtifactRelation::Locks,
                );
                add_inferred_relations(
                    &mut graph,
                    artifact_orchestration,
                    fs_provider,
                    &lockfile,
                    &lockfile.display().to_string(),
                );
            }
        }
    }

    let referenced_base_dir = doc.path.parent().unwrap_or_else(|| Path::new("."));
    for referenced_file in &doc.referenced_files {
        if !path_resolves_within_base(fs_provider, referenced_file, referenced_base_dir) {
            tracing::warn!(
                "skipping graph node for referenced artifact outside package root after symlink resolution: {}",
                referenced_file.display()
            );
            continue;
        }
        let referenced_path = referenced_file.display().to_string();
        graph.add_node_with_capabilities(
            referenced_path.clone(),
            artifact_kind_for_path::<F>(referenced_file),
            artifact_capabilities(artifact_orchestration, fs_provider, referenced_file),
        );
        graph.add_edge(
            root_path.clone(),
            referenced_path,
            ArtifactRelation::References,
        );
        add_inferred_relations(
            &mut graph,
            artifact_orchestration,
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
            | "gnumakefile"
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
        "gnumakefile",
        ".npmrc",
        "pip.conf",
        "mcp.json",
        "mcp.yaml",
        "mcp.yml",
        "yarn.lock",
        "pnpm-lock.yaml",
    ];

    let mut siblings = fs_provider
        .list_files(parent, "*", false)
        .unwrap_or_else(|e| {
            tracing::warn!(
                "I/O error listing files in {}: {e}; sibling detection skipped",
                parent.display()
            );
            Vec::new()
        })
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
                    Some(
                        "sh" | "bash"
                            | "zsh"
                            | "ksh"
                            | "fish"
                            | "ps1"
                            | "py"
                            | "js"
                            | "ts"
                            | "mjs"
                            | "cjs"
                            | "mts"
                            | "cts"
                            | "rb"
                            | "pl"
                            | "rs"
                            | "go"
                            | "php",
                    )
                )
        })
        .collect::<Vec<_>>();
    siblings.sort();
    debug_assert!(
        siblings.windows(2).all(|pair| pair[0] <= pair[1]),
        "sibling artifact paths must be sorted"
    );
    siblings
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
        .find(|segment| segment.len() == SHA256_HEX_LEN && segment.bytes().all(is_lower_hex_byte))
        .map(ToOwned::to_owned)
}

/// Length, in characters, of a SHA-256 digest rendered in lowercase hex
/// (32 raw bytes × 2 hex chars). Anchors `derive_package_id` so it can
/// recognise the canonical hex layout without a magic literal.
const SHA256_HEX_LEN: usize = 64;

#[inline]
fn is_lower_hex_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

fn artifact_capabilities<F: FileSystemProvider>(
    artifact_orchestration: &ArtifactOrchestratorService,
    fs_provider: &F,
    path: &Path,
) -> Vec<ArtifactCapabilityFact> {
    let Ok(fc) = fs_provider.read_file_bytes(path) else {
        return Vec::new();
    };
    let decoded = fc.decode_utf8_lossy();
    if decoded.decode_warning {
        // The primary scanner pipeline emits a `decode_warning_finding`
        // for the artifact itself; this trace is the audit trail for the
        // graph-derived capability inference path, which would otherwise
        // analyze a likely-binary file as though it were valid text and
        // silently propagate noisy capabilities.
        tracing::warn!(
            path = %path.display(),
            "graph capability inference using lossy UTF-8 decode (likely binary content)"
        );
    }
    artifact_orchestration.infer_capabilities(path, &decoded.text)
}

fn add_inferred_relations<F: FileSystemProvider>(
    graph: &mut ArtifactGraph,
    artifact_orchestration: &ArtifactOrchestratorService,
    fs_provider: &F,
    path: &Path,
    source_path: &str,
) {
    let Ok(fc) = fs_provider.read_file_bytes(path) else {
        return;
    };
    let decoded = fc.decode_utf8_lossy();
    if decoded.decode_warning {
        tracing::warn!(
            path = %path.display(),
            "graph relation inference using lossy UTF-8 decode (likely binary content)"
        );
    }
    for link in artifact_orchestration.infer_relations(path, &decoded.text) {
        // Classify the inferred target by its path before inserting it
        // into the graph. Pre-fix every inferred target was registered
        // as `ArtifactKind::GenericArtifact`; if the target was, say,
        // an `mcp.json` discovered only through a relation (not as a
        // sibling manifest), the graph never recorded it as
        // `McpServerManifest` and downstream taint rules / blast-radius
        // rules that key on `ArtifactKind` were silently skipped.
        // `add_node_with_capabilities`'s specificity-promotion rule
        // means a later, better-typed insertion can still upgrade the
        // node, but for inferred-only targets that never get a second
        // insertion, this is the only chance to classify them correctly.
        let target_path = std::path::PathBuf::from(&link.target);
        let target_kind = artifact_kind_for_path::<F>(&target_path);
        graph.add_node(link.target.clone(), target_kind);
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
        "gnumakefile",
        ".npmrc",
        "pip.conf",
    ];

    let mut manifests = fs_provider
        .list_files(path, "*", false)
        .unwrap_or_else(|e| {
            tracing::warn!(
                "I/O error listing files in {}: {e}; manifest detection skipped",
                path.display()
            );
            Vec::new()
        })
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| MANIFEST_NAMES.contains(&name.to_ascii_lowercase().as_str()))
        })
        .collect::<Vec<_>>();
    manifests.sort();
    debug_assert!(
        manifests.windows(2).all(|pair| pair[0] <= pair[1]),
        "sibling package manifest paths must be sorted"
    );
    manifests
}

fn sibling_expected_lockfiles_for_manifest<F: FileSystemProvider>(
    artifact_orchestration: &ArtifactOrchestratorService,
    fs_provider: &F,
    manifest: &Path,
    parent_dir: &Path,
) -> Vec<PathBuf> {
    let Ok(fc) = fs_provider.read_file_bytes(manifest) else {
        return Vec::new();
    };
    let content = fc.decode_utf8_lossy().text;
    artifact_orchestration
        .expected_lockfiles(manifest, &content)
        .into_iter()
        .map(|name| parent_dir.join(name))
        .filter(|path| fs_provider.exists(path))
        .collect()
}

#[cfg(test)]
mod derive_package_id_tests {
    use super::{derive_package_id, sibling_files, sibling_package_manifests};
    use crate::ports::{FileContent, FileSystemError, FileSystemProvider};
    use std::path::PathBuf;

    struct UnsortedSiblingFs {
        listed: Vec<PathBuf>,
    }

    impl FileSystemProvider for UnsortedSiblingFs {
        fn read_file_bytes(&self, path: &std::path::Path) -> Result<FileContent, FileSystemError> {
            Err(FileSystemError::PathNotFound(path.to_path_buf()))
        }

        fn list_files(
            &self,
            _path: &std::path::Path,
            pattern: &str,
            _recursive: bool,
        ) -> Result<Vec<PathBuf>, FileSystemError> {
            if pattern == "*" {
                Ok(self.listed.clone())
            } else {
                Ok(Vec::new())
            }
        }

        fn exists(&self, _path: &std::path::Path) -> bool {
            true
        }
    }

    /// Contract: sibling artifact discovery sorts paths returned by the
    /// filesystem provider before handing them to artifact analysis.
    #[test]
    fn sibling_files_sorts_unsorted_provider_paths() {
        let first = PathBuf::from("/pkg/a.sh");
        let second = PathBuf::from("/pkg/z.py");
        let fs = UnsortedSiblingFs {
            listed: vec![second.clone(), first.clone()],
        };

        let siblings = sibling_files(&fs, &PathBuf::from("/pkg/SKILL.md"));

        assert_eq!(siblings, vec![first, second]);
    }

    /// Contract: sibling package manifest discovery sorts matching
    /// paths so artifact graph node order does not depend on directory
    /// traversal order.
    #[test]
    fn sibling_package_manifests_sorts_unsorted_provider_paths() {
        let first = PathBuf::from("/pkg/package.json");
        let second = PathBuf::from("/pkg/pyproject.toml");
        let fs = UnsortedSiblingFs {
            listed: vec![second.clone(), first.clone()],
        };

        let manifests = sibling_package_manifests(&fs, &PathBuf::from("/pkg"));

        assert_eq!(manifests, vec![first, second]);
    }

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
