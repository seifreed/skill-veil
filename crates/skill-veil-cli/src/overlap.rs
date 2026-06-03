//! Cross-skill artifact overlap detection (`--check-overlap`).
//!
//! When a scan covers more than one skill, a byte-identical artifact
//! present in several of them is a useful signal: a shared payload copied
//! across skills, a cloned template, or one compromised helper fanned out
//! to many entrypoints. This is advisory and CLI-local — it walks each
//! scanned package's root directory, hashes the files, and reports the
//! cross-package duplicates. It never changes a verdict.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use skill_veil_core::PackageScanResult;

use crate::util::terminal_safe::sanitise_for_terminal;

/// Leading hex chars of a content hash shown in the report.
const HASH_DISPLAY_CHARS: usize = 12;
/// Bounds on the per-package walk so the advisory pass never becomes the
/// expensive part of a scan.
const MAX_WALK_DEPTH: usize = 4;
const MAX_FILES_PER_PACKAGE: usize = 200;
const MAX_HASH_FILE_BYTES: u64 = 5 * 1024 * 1024;
/// Directories never worth hashing for overlap (caches, VCS, vendored deps).
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "__pycache__",
    "target",
    ".venv",
    "dist",
];

/// One content hash shared by two or more distinct packages.
struct OverlapGroup {
    hash: String,
    /// `(package_label, artifact_path)`, one entry per sharing package.
    occurrences: Vec<(String, String)>,
}

/// Group `(path, hash)` pairs by content hash, keeping only hashes that
/// appear in two or more DISTINCT packages. Distinctness is keyed on the
/// package label, so two identical files inside one package never count as
/// cross-skill overlap. Pure — the caller does the file I/O.
fn find_overlaps(packages: &[(String, Vec<(String, String)>)]) -> Vec<OverlapGroup> {
    let mut by_hash: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (label, files) in packages {
        for (path, hash) in files {
            by_hash
                .entry(hash.clone())
                .or_default()
                .entry(label.clone())
                .or_insert_with(|| path.clone());
        }
    }
    by_hash
        .into_iter()
        .filter(|(_, pkgs)| pkgs.len() >= 2)
        .map(|(hash, pkgs)| OverlapGroup {
            hash,
            occurrences: pkgs.into_iter().collect(),
        })
        .collect()
}

fn hash_file(path: &Path) -> Option<String> {
    crate::util::hash::sha256_file_with_cap(path, MAX_HASH_FILE_BYTES)
        .ok()
        .flatten()
}

/// Bounded recursive walk of a package root, returning `(path, hash)` for
/// each regular file. Skips symlinks (no traversal), oversized files,
/// and cache/VCS/vendor directories; capped at [`MAX_FILES_PER_PACKAGE`].
fn collect_package_files(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if files.len() >= MAX_FILES_PER_PACKAGE {
                return files;
            }
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                let skip = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| SKIP_DIRS.contains(&n));
                if !skip && depth < MAX_WALK_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if meta.is_file() && meta.len() <= MAX_HASH_FILE_BYTES {
                if let Some(hash) = hash_file(&path) {
                    files.push((path.display().to_string(), hash));
                }
            }
        }
    }
    files
}

fn basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
}

fn render(groups: &[OverlapGroup]) -> String {
    let mut out = String::from("\n--- Cross-skill artifact overlap (advisory) ---\n");
    let _ = writeln!(
        out,
        "{} artifact(s) are byte-identical across multiple skills:",
        groups.len()
    );
    for group in groups {
        let short: String = group.hash.chars().take(HASH_DISPLAY_CHARS).collect();
        let _ = writeln!(
            out,
            "  [{short}] shared by {} skills:",
            group.occurrences.len()
        );
        for (label, path) in &group.occurrences {
            let _ = writeln!(
                out,
                "    - {}: {}",
                sanitise_for_terminal(label),
                sanitise_for_terminal(basename(path)),
            );
        }
    }
    out.push_str("This report never changes the skill-veil verdict.\n");
    out
}

/// Root directory of one scanned package: the parent of its entrypoint,
/// falling back to the entrypoint path itself when it has no parent.
fn package_root(result: &skill_veil_core::ScanResult) -> PathBuf {
    result
        .metadata
        .path
        .parent()
        .map_or_else(|| result.metadata.path.clone(), Path::to_path_buf)
}

/// Detect artifacts shared byte-for-byte across two or more scanned
/// skills. Returns `None` when disabled, fewer than two DISTINCT package
/// roots were scanned, or nothing overlaps. Walks each package root and
/// hashes its files (CLI-local) — never mutates the scan result.
pub(crate) fn try_check_overlap(
    scan_result: &PackageScanResult,
    enabled: bool,
    _quiet: bool,
) -> Option<String> {
    if !enabled || scan_result.results.len() < 2 {
        return None;
    }

    // Dedup by root so two entrypoints sharing a directory count as one
    // package — otherwise every file in that directory would look shared.
    let mut roots: BTreeSet<PathBuf> = BTreeSet::new();
    let mut packages: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for result in &scan_result.results {
        let root = package_root(result);
        if !roots.insert(root.clone()) {
            continue;
        }
        let files = collect_package_files(&root);
        packages.push((root.display().to_string(), files));
    }
    if packages.len() < 2 {
        return None;
    }

    let groups = find_overlaps(&packages);
    if groups.is_empty() {
        return None;
    }
    Some(render(&groups))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(label: &str, files: &[(&str, &str)]) -> (String, Vec<(String, String)>) {
        (
            label.to_string(),
            files
                .iter()
                .map(|(p, h)| ((*p).to_string(), (*h).to_string()))
                .collect(),
        )
    }

    #[test]
    fn shared_hash_across_two_packages_is_an_overlap() {
        let packages = [
            pkg("a/SKILL.md", &[("a/evil.py", "deadbeef")]),
            pkg("b/SKILL.md", &[("b/evil.py", "deadbeef")]),
        ];
        let groups = find_overlaps(&packages);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].hash, "deadbeef");
        assert_eq!(groups[0].occurrences.len(), 2);
    }

    #[test]
    fn duplicate_within_one_package_is_not_overlap() {
        let packages = [pkg(
            "a/SKILL.md",
            &[("a/x.py", "deadbeef"), ("a/y.py", "deadbeef")],
        )];
        assert!(find_overlaps(&packages).is_empty());
    }

    #[test]
    fn distinct_hashes_do_not_overlap() {
        let packages = [
            pkg("a/SKILL.md", &[("a/x.py", "aaaa")]),
            pkg("b/SKILL.md", &[("b/y.py", "bbbb")]),
        ];
        assert!(find_overlaps(&packages).is_empty());
    }

    #[test]
    fn render_states_advisory_and_lists_packages() {
        let groups = find_overlaps(&[
            pkg("alpha/SKILL.md", &[("alpha/p.py", "c0ffee1234567890")]),
            pkg("beta/SKILL.md", &[("beta/p.py", "c0ffee1234567890")]),
        ]);
        let text = render(&groups);
        assert!(text.contains("Cross-skill artifact overlap"));
        assert!(text.contains("never changes the skill-veil verdict"));
        assert!(text.contains("c0ffee123456"));
        assert!(text.contains("alpha/SKILL.md"));
    }

    #[test]
    fn basename_extracts_file_name() {
        assert_eq!(basename("a/b/c.py"), "c.py");
        assert_eq!(basename("plain"), "plain");
    }
}
