//! Internal helpers for the `walkdir`-backed file-system adapter.
//!
//! Two pure functions used by the recursive directory walks in
//! [`super::std_filesystem`]:
//!
//! - [`is_skipped_dir`]: prunes vendored/generated trees up front so
//!   the walker never pays for them on adversarial inputs.
//! - [`lossy_filename_with_warning`]: converts `OsStr` filenames to
//!   `str` lossily while emitting a `tracing::warn!` so operators can
//!   spot non-UTF-8 evasion attempts.
//!
//! Lives outside `std_filesystem.rs` to keep the port-implementation
//! file focused on the trait methods themselves.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::Path;

/// Filter helper: prune a directory subtree if its name matches one of
/// `skip_dirs`. Mirrors the exclusion list used by file-discovery so
/// the walker doesn't pay for vendored / generated trees on adversarial
/// inputs.
///
/// The match is performed against a lossy UTF-8 view of the directory
/// name. A pure `to_str()` check would silently descend into a
/// directory whose name contains invalid UTF-8 bytes — closing the same
/// evasion vector that [`lossy_filename_with_warning`] guards against
/// for files. A tarball can ship a `node_modules` rendering with a
/// stray non-UTF-8 byte; without lossy matching the walker would
/// recurse into it instead of pruning.
///
/// The comparison is **case-insensitive** (ASCII): on case-sensitive
/// filesystems (Linux ext4, the canonical CI target) a malicious package
/// shipping `Node_Modules/` or `VENV/` would otherwise bypass the prune
/// list verbatim and have its contents scanned. macOS HFS+/APFS folds
/// case in the filesystem itself, so the gap was Linux-only — exactly
/// where adversarial scans run.
pub(super) fn is_skipped_dir(entry: &walkdir::DirEntry, skip_dirs: &[&str]) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    skip_dirs.iter().any(|skip| name.eq_ignore_ascii_case(skip))
}

/// Match the entry's filename against the discovery pattern using a
/// lossy `&str` view of its `OsStr`. Emits a `tracing::warn!` whenever
/// the filename is not valid UTF-8 so operators can spot evasion
/// attempts. Returning `Cow::Borrowed` for the common UTF-8 case keeps
/// the hot path allocation-free.
pub(super) fn lossy_filename_with_warning<'a>(
    filename: &'a OsStr,
    full_path: &Path,
) -> Cow<'a, str> {
    match filename.to_str() {
        Some(s) => Cow::Borrowed(s),
        None => {
            tracing::warn!(
                "non-UTF-8 filename in {}; matched with lossy conversion (possible evasion attempt in untrusted package)",
                full_path.display(),
            );
            filename.to_string_lossy()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// # Contract
    ///
    /// `is_skipped_dir` MUST be case-insensitive (ASCII). On Linux ext4
    /// — the canonical CI target — directory names are case-sensitive,
    /// so a malicious package shipping `Node_Modules/` or `VENV/`
    /// would otherwise bypass the prune list verbatim. The comparison
    /// must therefore fold case before matching against the registered
    /// skip-list entries.
    #[test]
    fn is_skipped_dir_matches_skip_list_entries_case_insensitively() {
        let dir = tempdir().expect("tempdir");
        for name in ["Node_Modules", "VENV", ".GIT", "Target", "DiSt"] {
            let path = dir.path().join(name);
            fs::create_dir_all(&path).expect("create dir");
        }
        let skip_dirs = &["node_modules", "venv", ".git", "target", "dist"];
        let walker = walkdir::WalkDir::new(dir.path()).min_depth(1).max_depth(1);
        for entry in walker.into_iter().filter_map(Result::ok) {
            assert!(
                is_skipped_dir(&entry, skip_dirs),
                "{} must be pruned (case-insensitive); skip_dirs={skip_dirs:?}",
                entry.file_name().to_string_lossy()
            );
        }
    }

    /// # Contract (negative)
    ///
    /// `is_skipped_dir` MUST NOT prune directories whose names are
    /// unrelated to the skip-list. Pins the tightening so a future
    /// regression that over-broadens the comparison (e.g. substring
    /// match instead of equality) gets caught here.
    #[test]
    fn is_skipped_dir_does_not_prune_unrelated_directories() {
        let dir = tempdir().expect("tempdir");
        for name in ["src", "scripts", "tests", "docs", "node_modules_backup"] {
            fs::create_dir_all(dir.path().join(name)).expect("create dir");
        }
        let skip_dirs = &["node_modules", "venv", ".git", "target", "dist"];
        let walker = walkdir::WalkDir::new(dir.path()).min_depth(1).max_depth(1);
        for entry in walker.into_iter().filter_map(Result::ok) {
            assert!(
                !is_skipped_dir(&entry, skip_dirs),
                "{} must NOT be pruned; skip_dirs={skip_dirs:?}",
                entry.file_name().to_string_lossy()
            );
        }
    }
}
