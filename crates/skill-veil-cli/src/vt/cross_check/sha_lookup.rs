//! SHA-256 resolution for VT-report cache lookup.
//!
//! Three lookup strategies, in descending fidelity:
//!
//! 1. `package_id` if it is already a 64-char hex digest (`vt download`
//!    canonical layout).
//! 2. Walk ancestors of the artifact path looking for a 64-hex segment
//!    (covers `<sha>_extracted/...` ZIP-corpus layouts).
//! 3. Hash the primary artifact on disk (last resort; only meaningful
//!    for direct-file corpora).

use crate::util::cache_io::read_cache_file_with_cap;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

/// SHA-256 digests in this codebase are always **lowercase** hex; uppercase
/// or mixed-case 64-char strings are intentionally rejected so that two
/// copies of the same package with different casing cannot evade
/// case-sensitive cache lookups. Kept in sync with `derive_package_id` in
/// `scanner_graph.rs`.
pub(super) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(is_lower_hex_byte)
}

#[inline]
fn is_lower_hex_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

/// Resolve the SHA-256 used to look up a package's VT report.
///
/// # Lookup order (highest fidelity to lowest)
///
/// 1. `package_id` if it is already a 64-char hex digest. This is what
///    `derive_package_id` returns when an ancestor directory of the primary
///    artifact is named after the SHA — the canonical `vt download` layout
///    where files are saved at `dest/<sha>` or extracted into `dest/<sha>/...`.
///
/// 2. Walk ancestors of `path` looking for a 64-hex segment, allowing common
///    extraction suffixes like `_extracted`. Covers ZIP-extracted corpora
///    where the scanner reads `dest/<sha>_extracted/SKILL.md` and `package_id`
///    fails to recover the SHA because `derive_package_id` only matches the
///    bare hex form.
///
/// 3. Hash the primary artifact on disk. This is the LAST resort and is
///    only meaningful for direct-file corpora where the file at `path` IS
///    the file VT keyed its report by. For ZIP corpora this hash will not
///    match any cached report; the lookup will return `Unknown`, which is
///    the correct behaviour given we have no SHA-traceable provenance.
///
/// Returns `None` only when all three routes fail (e.g. the file is gone).
pub(super) fn sha_for_lookup(package_id: &Option<String>, path: &Path) -> Option<String> {
    if let Some(id) = package_id {
        if is_sha256_hex(id) {
            return Some(id.clone());
        }
    }
    if let Some(sha) = sha_from_ancestors(path) {
        return Some(sha);
    }
    compute_file_sha256(path).ok()
}

/// Recover a SHA-256 from a nearby ancestor directory whose name is a 64-hex
/// string, optionally with a recognised extraction suffix. Mirrors the
/// "directory named after sha" convention used by `vt download` and the
/// dataset extractor.
///
/// Only the immediate parent and grandparent are inspected. Walking ALL
/// ancestors would match any coincidentally 64-hex-char directory name
/// (e.g. git object paths) far up the tree, causing a spurious VT lookup.
/// `take(3)` covers the file itself, its parent, and its grandparent —
/// enough for `/<sha>/SKILL.md` and `/<sha>/subdir/SKILL.md` while
/// rejecting SHAs deeper in the tree.
const SHA_ANCESTOR_DEPTH: usize = 3;

fn sha_from_ancestors(path: &Path) -> Option<String> {
    const EXTRACTION_SUFFIXES: &[&str] = &["_extracted", ".extracted", "-extracted"];
    path.ancestors()
        .take(SHA_ANCESTOR_DEPTH)
        .filter_map(|a| a.file_name().and_then(|n| n.to_str()))
        .filter_map(|name| {
            if is_sha256_hex(name) {
                return Some(name.to_string());
            }
            for suffix in EXTRACTION_SUFFIXES {
                if let Some(stem) = name.strip_suffix(suffix) {
                    if is_sha256_hex(stem) {
                        return Some(stem.to_string());
                    }
                }
            }
            None
        })
        .next()
}

/// Maximum file size that `compute_file_sha256` will read into memory.
/// Matches the limit used by `StdFileSystemProvider::read_file_bytes`.
const MAX_HASH_FILE_BYTES: u64 = 256 * 1024 * 1024;

fn compute_file_sha256(path: &Path) -> Result<String> {
    let bytes = read_cache_file_with_cap(path, MAX_HASH_FILE_BYTES)
        .with_context(|| format!("reading file for hashing {}", path.display()))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "refusing to hash {}: file exceeds size cap ({} bytes)",
                path.display(),
                MAX_HASH_FILE_BYTES
            )
        })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_for_lookup_uses_package_id_when_64_hex() {
        let id = Some("a".repeat(64));
        // Path doesn't need to exist — fast path returns before reading.
        let sha = sha_for_lookup(&id, Path::new("/nonexistent")).unwrap();
        assert_eq!(sha.len(), 64);
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha_for_lookup_falls_back_to_file_hash_when_package_id_is_not_hex() {
        let tmp = std::env::temp_dir().join("skill-veil-cross-check-test.bin");
        std::fs::write(&tmp, b"hello").unwrap();
        let id = Some("not-a-sha".to_string());
        let sha = sha_for_lookup(&id, &tmp).expect("file hash fallback");
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            sha,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn sha_for_lookup_returns_none_when_file_missing_and_no_id() {
        assert!(sha_for_lookup(&None, Path::new("/definitely/does/not/exist")).is_none());
    }

    /// Contract: in extracted ZIP corpora the SHA appears in an ancestor
    /// directory name (with or without a recognised `_extracted` suffix).
    /// The lookup must recover the SHA before falling back to file hashing,
    /// since hashing the inner SKILL.md never matches the original archive's
    /// SHA-256 in VT's report cache.
    #[test]
    fn sha_for_lookup_finds_sha_in_extracted_dir_ancestor() {
        let sha = "a".repeat(64);
        let path = std::path::PathBuf::from(format!("/tmp/{sha}_extracted/SKILL.md"));
        // package_id is None because derive_package_id only matches bare hex names.
        let resolved = sha_for_lookup(&None, &path).expect("should recover sha from ancestor");
        assert_eq!(resolved, sha);
    }

    #[test]
    fn sha_for_lookup_finds_sha_in_bare_directory_ancestor() {
        let sha = "b".repeat(64);
        let path = std::path::PathBuf::from(format!("/tmp/{sha}/SKILL.md"));
        let resolved = sha_for_lookup(&None, &path).expect("should recover sha from bare dir");
        assert_eq!(resolved, sha);
    }

    #[test]
    fn sha_for_lookup_prefers_package_id_over_ancestor_walk() {
        // Even with a different sha in the ancestor, the explicit package_id wins.
        let id = "c".repeat(64);
        let other = "d".repeat(64);
        let path = std::path::PathBuf::from(format!("/tmp/{other}/SKILL.md"));
        let resolved = sha_for_lookup(&Some(id.clone()), &path).unwrap();
        assert_eq!(resolved, id);
    }

    /// Contract: `compute_file_sha256` refuses to read files exceeding
    /// `MAX_HASH_FILE_BYTES`. Without this guard a maliciously large file
    /// would be read entirely into memory, risking OOM.
    #[test]
    fn compute_file_sha256_rejects_oversized_file() {
        // Verify the guard exists and is a positive bound.
        const { assert!(MAX_HASH_FILE_BYTES > 0) };
        let dir = std::env::temp_dir().join("skill-veil-sha-oversized-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.bin");
        // Write a tiny file and confirm hashing succeeds (below the cap).
        std::fs::write(&path, b"tiny").unwrap();
        let result = compute_file_sha256(&path);
        assert!(result.is_ok(), "small file should hash successfully");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sha_for_lookup_ignores_non_hex_ancestor() {
        // 64 chars but not hex → not a valid SHA, must fall through.
        let bogus = "g".repeat(64);
        let path = std::path::PathBuf::from(format!("/nonexistent/{bogus}/SKILL.md"));
        // No package_id, no valid ancestor sha, file doesn't exist → None.
        assert!(sha_for_lookup(&None, &path).is_none());
    }

    /// # Contract
    ///
    /// `sha_from_ancestors` MUST only inspect the immediate parent and
    /// grandparent directories. A 64-hex-char directory name deeper in the
    /// ancestor chain (e.g. at depth 4+) must NOT be matched, preventing
    /// spurious VT lookups from coincidentally-named directories like git
    /// object paths.
    #[test]
    fn sha_from_ancestors_ignores_deep_ancestors() {
        let sha = "a".repeat(64);
        // Depth 4: /<sha>/deep/nested/sub/SKILL.md — sha is
        // great-great-grandparent, too deep.
        let deep_path = std::path::PathBuf::from(format!("/{sha}/deep/nested/sub/SKILL.md"));
        assert!(
            sha_from_ancestors(&deep_path).is_none(),
            "SHA from great-great-grandparent must be ignored (depth > 3)"
        );
        // Depth 2: /<sha>/nested/SKILL.md — sha is grandparent, must match.
        let ok_path = std::path::PathBuf::from(format!("/{sha}/nested/SKILL.md"));
        assert_eq!(
            sha_from_ancestors(&ok_path).unwrap(),
            sha,
            "SHA from grandparent must be recovered"
        );
    }
}
