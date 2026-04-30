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
pub(super) fn is_skipped_dir(entry: &walkdir::DirEntry, skip_dirs: &[&str]) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    skip_dirs.contains(&name.as_ref())
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
