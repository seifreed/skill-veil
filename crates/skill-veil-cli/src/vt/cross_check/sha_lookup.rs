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

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
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
    match compute_file_sha256(path) {
        Ok(sha) => Some(sha),
        Err(e) => {
            tracing::warn!(
                "sha_for_lookup: failed to compute SHA-256 for {}: {e}",
                path.display()
            );
            None
        }
    }
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

/// Maximum file size that `compute_file_sha256` will read. Files exceeding
/// this cap are rejected with an error rather than hashed as a truncated
/// prefix. The streaming reader enforces the cap after open, so concurrent
/// file growth cannot produce a digest for only the first capped bytes.
const MAX_HASH_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Stream SHA-256 of `path` in 64 KiB chunks, rejecting files that exceed
/// `MAX_HASH_FILE_BYTES`.
fn compute_file_sha256(path: &Path) -> Result<String> {
    compute_file_sha256_with_cap(path, MAX_HASH_FILE_BYTES)
}

fn compute_file_sha256_with_cap(path: &Path, cap: u64) -> Result<String> {
    use std::io::Read;
    let path_meta = regular_hash_file_metadata(path)?;
    let file =
        File::open(path).with_context(|| format!("opening {} for hashing", path.display()))?;
    let opened_meta = file
        .metadata()
        .with_context(|| format!("stat opened hash file {}", path.display()))?;
    if !opened_file_matches_path(&opened_meta, &path_meta) {
        anyhow::bail!(
            "refusing to hash {}: path changed while opening",
            path.display()
        );
    }
    if opened_meta.len() > cap {
        anyhow::bail!(
            "refusing to hash {}: file exceeds cap ({} bytes)",
            path.display(),
            cap
        );
    }
    let mut reader = std::io::BufReader::new(file).take(cap.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total_read = 0_u64;
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total_read = total_read
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("hash read byte count overflow"))?;
        if total_read > cap {
            anyhow::bail!(
                "refusing to hash {}: file exceeds cap ({} bytes)",
                path.display(),
                cap
            );
        }
        hasher.update(&buf[..read]);
    }
    debug_assert!(
        total_read <= cap,
        "hash reader must reject streams over the cap"
    );
    Ok(format!("{:x}", hasher.finalize()))
}

fn regular_hash_file_metadata(path: &Path) -> Result<Metadata> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat hash file {}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        anyhow::bail!("refusing to hash {}: not a regular file", path.display())
    }
    if !has_single_hardlink(&meta) {
        anyhow::bail!(
            "refusing to hash {}: file has multiple hard links",
            path.display()
        )
    }
    Ok(meta)
}

#[cfg(unix)]
fn has_single_hardlink(meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.nlink() == 1
}

#[cfg(not(unix))]
fn has_single_hardlink(_meta: &Metadata) -> bool {
    true
}

#[cfg(unix)]
fn opened_file_matches_path(opened: &Metadata, path_meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    opened.dev() == path_meta.dev() && opened.ino() == path_meta.ino()
}

#[cfg(not(unix))]
fn opened_file_matches_path(_opened: &Metadata, _path_meta: &Metadata) -> bool {
    true
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
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("cross-check-test.bin");
        std::fs::write(&path, b"hello").unwrap();
        let id = Some("not-a-sha".to_string());
        let sha = sha_for_lookup(&id, &path).expect("file hash fallback");
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            sha,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
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

    /// Contract: `compute_file_sha256` hashes files under the default cap.
    #[test]
    fn compute_file_sha256_accepts_file_under_default_cap() {
        // Verify the guard exists and is a positive bound.
        const { assert!(MAX_HASH_FILE_BYTES > 0) };
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("small.bin");
        std::fs::write(&path, b"tiny").unwrap();
        let result = compute_file_sha256(&path);
        assert!(result.is_ok(), "small file should hash successfully");
    }

    /// Contract: files over the hash cap are rejected instead of hashed
    /// as a capped prefix.
    #[test]
    fn compute_file_sha256_rejects_file_over_cap() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("over-cap.bin");
        std::fs::write(&path, b"abcd").unwrap();

        let err = compute_file_sha256_with_cap(&path, 3).expect_err("over-cap file must fail");

        assert!(format!("{err:#}").contains("exceeds cap"));
    }

    /// # Contract
    ///
    /// File-hash fallback accepts only regular files. A symlinked
    /// artifact is rejected instead of hashing its target.
    #[cfg(unix)]
    #[test]
    fn compute_file_sha256_rejects_symlinked_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("target.bin");
        let link = dir.path().join("artifact.bin");
        std::fs::write(&target, b"hello").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = compute_file_sha256(&link).expect_err("symlink must be rejected");

        assert!(format!("{err:#}").contains("not a regular file"));
    }

    /// # Contract
    ///
    /// File-hash fallback accepts only files with a single directory
    /// entry. A hardlinked artifact is rejected instead of hashing an
    /// inode whose provenance is outside the corpus path.
    #[cfg(unix)]
    #[test]
    fn compute_file_sha256_rejects_hardlinked_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("target.bin");
        let link = dir.path().join("artifact.bin");
        std::fs::write(&target, b"hello").unwrap();
        std::fs::hard_link(&target, &link).unwrap();

        let err = compute_file_sha256(&link).expect_err("hardlink must be rejected");

        assert!(format!("{err:#}").contains("multiple hard links"));
    }

    /// # Contract
    ///
    /// `compute_file_sha256` MUST produce a correct SHA-256 digest using
    /// streaming reads. This test pins that the streaming hash matches the
    /// all-at-once hash for a file larger than a single chunk.
    #[test]
    fn compute_file_sha256_streams_correct_hash() {
        use sha2::Digest;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("streaming.bin");
        // 256 KiB — larger than one 64 KiB chunk, exercises the loop.
        let payload = vec![0xABu8; 256 * 1024];
        std::fs::write(&path, &payload).unwrap();

        let result = compute_file_sha256(&path).expect("streaming hash must succeed");

        let expected = format!("{:x}", sha2::Sha256::digest(&payload));
        assert_eq!(
            result, expected,
            "streaming hash must match all-at-once hash"
        );
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
