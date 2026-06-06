//! Bounded reads for the LLM and VT caches.
//!
//! The LLM and VT caches store JSON envelopes whose realistic size is
//! tens of KB at most (a single LLM analysis or VT report). The cache
//! directory is created with `0o700` permissions, so under the normal
//! threat model only the owning UID can write to it. A defensive cap is
//! still warranted: a stale process, a panic-induced truncation, or an
//! attacker who has compromised the same UID could otherwise stuff a
//! multi-gigabyte file into the cache and OOM the next scan when
//! `serde_json::from_slice` allocates a parse buffer over the whole
//! body.
//!
//! `MAX_CACHE_FILE_BYTES` is the hard cap. Files at or under the cap
//! load normally; oversized files are treated as a *cache miss* (the
//! caller falls back to fetching a fresh result) rather than as an
//! error, so a poisoned cache entry never breaks user-visible
//! enrichment — it just costs one extra round-trip while the corrupt
//! file gets overwritten on success.

use crate::util::bounded_read::{has_single_hardlink, opened_file_matches_path};
use anyhow::{anyhow, Context, Result};
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::path::Path;

/// Promote a fully-written `tmp` sibling to `dest` via `rename(2)`.
///
/// Use this for any cache or download artefact that must not appear at
/// `dest` until it is complete — readers (cross-process and same-process
/// re-reads) only ever observe the post-rename byte sequence. Pre-fix the
/// VT enrichment cache and the VT file downloader called `std::fs::write`
/// directly: a crash, kill, or concurrent run between truncate and the
/// final write left a zero-byte or partial JSON envelope at `dest`, which
/// `load_fresh` then treated as a cache miss and overwrote with a fresh
/// fetch. The atomic-rename pattern guarantees `dest` is either the old
/// content or the complete new content, never the in-between state.
///
/// Returns a typed `io::Result` so the VT client can map the failure into
/// `VtError::Io` via `?` and the enrichment cache can attach context with
/// `.with_context(...)` — keeping the I/O boundary explicit on each side.
///
/// # Failure handling
///
/// On rename failure (cross-mount `EXDEV`, parent dir disappeared after
/// the caller's `create_dir_secure` check, permissions revoked mid-flight),
/// best-effort delete the `tmp` so it does not accumulate in the cache;
/// pre-fix the tmp file leaked into the directory and required manual
/// cleanup. The original I/O error is preserved for the caller; cleanup
/// failures are intentionally silenced — they would mask the real failure
/// and there is no recovery action from this layer.
pub(crate) fn finalize_atomic_write(tmp: &Path, dest: &Path) -> io::Result<()> {
    if let Err(err) = std::fs::rename(tmp, dest) {
        let _ = std::fs::remove_file(tmp);
        return Err(err);
    }
    Ok(())
}

pub(crate) fn write_cache_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    crate::util::secure_fs::create_dir_secure(parent)
        .with_context(|| format!("creating {}", parent.display()))?;
    ensure_real_cache_dir(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temp file under {}", parent.display()))?;
    tmp.write_all(bytes)
        .with_context(|| format!("writing temp file under {}", parent.display()))?;
    tmp.as_file_mut()
        .sync_all()
        .with_context(|| format!("syncing temp file under {}", parent.display()))?;
    let temp_path = tmp.into_temp_path();
    finalize_atomic_write(temp_path.as_ref(), path)
        .with_context(|| format!("renaming temp file to {}", path.display()))?;
    Ok(())
}

/// Hard ceiling for a single cache file. 16 MiB leaves three orders of
/// magnitude of headroom over realistic envelopes (LLM analysis ~few
/// KB, VT report ~few hundred KB) while ensuring `from_slice`
/// allocations stay bounded on memory-constrained CI runners.
pub(crate) const MAX_CACHE_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Read at most `MAX_CACHE_FILE_BYTES` from `path`.
///
/// Returns `Ok(Some(bytes))` on success, `Ok(None)` if the file is
/// missing OR exceeds the cap (treated as a cache miss; the caller
/// re-fetches). All other I/O errors propagate via `anyhow::Result`
/// with the path attached as context, so operators can diagnose disk
/// issues without losing the offending filename.
pub(crate) fn read_cache_file_bounded(path: &Path) -> Result<Option<Vec<u8>>> {
    read_cache_file_with_cap(path, MAX_CACHE_FILE_BYTES)
}

/// Cap-injected variant for tests.
pub(crate) fn read_cache_file_with_cap(path: &Path, cap: u64) -> Result<Option<Vec<u8>>> {
    let Some(path_meta) = regular_cache_file_metadata(path)? else {
        return Ok(None);
    };
    let file = match File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("opening cache file {}", path.display()));
        }
    };
    let meta = file
        .metadata()
        .with_context(|| format!("stat cache file {}", path.display()))?;
    let len = meta.len();
    if !opened_file_matches_path(&meta, &path_meta) {
        tracing::warn!(
            "ignoring cache file {} (path changed while opening); will refetch",
            path.display(),
        );
        return Ok(None);
    }
    if len > cap {
        tracing::warn!(
            "ignoring cache file {} ({} bytes > cap {}); will refetch",
            path.display(),
            len,
            cap,
        );
        return Ok(None);
    }
    read_cache_reader_with_cap(file, path, len, cap)
}

fn regular_cache_file_metadata(path: &Path) -> Result<Option<Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
            tracing::warn!(
                "ignoring cache file {} (not a regular file); will refetch",
                path.display(),
            );
            Ok(None)
        }
        Ok(meta) if !has_single_hardlink(&meta) => {
            tracing::warn!(
                "ignoring cache file {} (multiple hard links); will refetch",
                path.display(),
            );
            Ok(None)
        }
        Ok(meta) => Ok(Some(meta)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("stat cache file {}", path.display())),
    }
}

fn ensure_real_cache_dir(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat cache directory {}", path.display()))?;
    if meta.is_dir() && !meta.file_type().is_symlink() {
        Ok(())
    } else {
        anyhow::bail!("{} is not a real cache directory", path.display())
    }
}

fn read_cache_reader_with_cap(
    mut reader: impl Read,
    path: &Path,
    len: u64,
    cap: u64,
) -> Result<Option<Vec<u8>>> {
    let alloc_cap = usize::try_from(len.min(cap)).unwrap_or(0);
    let mut buf = Vec::with_capacity(alloc_cap);
    reader
        .by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .with_context(|| format!("reading cache file {}", path.display()))?;
    if buf.len() as u64 > cap {
        tracing::warn!(
            "ignoring cache file {} (stream exceeded cap {}); will refetch",
            path.display(),
            cap,
        );
        return Ok(None);
    }
    debug_assert!(
        buf.len() as u64 <= cap,
        "cache reader must reject streams over the cap"
    );
    Ok(Some(buf))
}

/// Resolve the on-disk base directory for a skill-veil cache: the explicit
/// `override_dir` if given, otherwise `<platform cache dir>/skill-veil`.
/// Returns `None` when no platform cache directory can be resolved — callers
/// then run uncached rather than failing.
pub(crate) fn cache_base_dir(override_dir: Option<&Path>) -> Option<std::path::PathBuf> {
    Some(match override_dir {
        Some(path) => path.to_path_buf(),
        None => dirs::cache_dir()?.join("skill-veil"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// # Contract
    ///
    /// A missing cache file MUST return `Ok(None)` (cache miss), not
    /// an error. Cache loaders use this to short-circuit and re-fetch
    /// without surfacing a confusing "file not found" diagnostic to
    /// the user during normal first-run cold-cache flow.
    #[test]
    fn read_cache_file_bounded_returns_none_for_missing_file() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope.json");

        let result = read_cache_file_bounded(&missing).unwrap();
        assert!(
            result.is_none(),
            "missing file must be a cache miss, got {result:?}"
        );
    }

    /// # Contract
    ///
    /// A cache file at or under the cap MUST be returned verbatim.
    #[test]
    fn read_cache_file_bounded_returns_bytes_when_under_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("small.json");
        let payload = br#"{"hello":"world"}"#;
        std::fs::write(&path, payload).unwrap();

        let bytes = read_cache_file_bounded(&path).unwrap().unwrap();
        assert_eq!(bytes, payload);
    }

    /// # Contract
    ///
    /// Cache reads treat symlink entries as cache misses. A cache entry
    /// must never cause callers to ingest the symlink target.
    #[cfg(unix)]
    #[test]
    fn read_cache_file_with_cap_returns_none_for_symlinked_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.json");
        let link = dir.path().join("cache.json");
        std::fs::write(&target, br#"{"cached":true}"#).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = read_cache_file_with_cap(&link, MAX_CACHE_FILE_BYTES).unwrap();

        assert!(result.is_none());
    }

    /// # Contract
    ///
    /// Cache reads treat hardlinked entries as cache misses. A cache
    /// file must be owned by the cache tree, not a second directory
    /// entry for an inode created elsewhere.
    #[cfg(unix)]
    #[test]
    fn read_cache_file_with_cap_returns_none_for_hardlinked_file() {
        let dir = TempDir::new().unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir(&cache_dir).unwrap();
        let outside = dir.path().join("outside.json");
        let linked = cache_dir.join("cache.json");
        std::fs::write(&outside, br#"{"cached":true}"#).unwrap();
        std::fs::hard_link(&outside, &linked).unwrap();

        let result = read_cache_file_with_cap(&linked, MAX_CACHE_FILE_BYTES).unwrap();

        assert!(result.is_none());
    }

    /// # Contract
    ///
    /// A cache file ABOVE the cap MUST be reported as a cache miss
    /// (`Ok(None)`), not slurped into memory. Pre-fix the loader used
    /// `std::fs::read` with no bound and would OOM on a poisoned cache
    /// entry. The negative case (under-cap → bytes returned) is pinned
    /// by `read_cache_file_bounded_returns_bytes_when_under_cap`.
    #[test]
    fn read_cache_file_with_cap_returns_none_when_over_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("oversized.json");
        std::fs::write(&path, vec![0u8; 1024]).unwrap();

        // Cap below file size — should be reported as cache miss.
        let result = read_cache_file_with_cap(&path, 512).unwrap();
        assert!(
            result.is_none(),
            "over-cap cache file must be a cache miss, got {} bytes",
            result.map_or(0, |v| v.len()),
        );
    }

    /// # Contract
    ///
    /// If a cache stream exceeds the cap after the metadata check, the
    /// reader MUST return a cache miss instead of a truncated prefix.
    #[test]
    fn read_cache_reader_with_cap_returns_none_when_stream_exceeds_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("racy.json");
        let reader = std::io::Cursor::new(b"abcde".to_vec());

        let result = read_cache_reader_with_cap(reader, &path, 4, 4).unwrap();

        assert!(result.is_none(), "over-cap stream must be a cache miss");
    }

    /// # Contract
    ///
    /// A cache stream exactly at the cap is complete and must be
    /// returned unchanged.
    #[test]
    fn read_cache_reader_with_cap_accepts_stream_at_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("boundary.json");
        let reader = std::io::Cursor::new(b"abcd".to_vec());

        let result = read_cache_reader_with_cap(reader, &path, 4, 4)
            .unwrap()
            .unwrap();

        assert_eq!(result, b"abcd");
    }

    /// # Contract (positive)
    ///
    /// `finalize_atomic_write` MUST move `tmp` to `dest` on success and
    /// leave no residue at the `tmp` path.
    #[test]
    fn finalize_atomic_write_renames_tmp_to_dest_on_success() {
        let dir = TempDir::new().expect("tempdir");
        let tmp = dir.path().join("payload.tmp");
        let dest = dir.path().join("payload.bin");
        std::fs::write(&tmp, b"hello").expect("seed tmp");

        finalize_atomic_write(&tmp, &dest).expect("rename must succeed");

        assert!(!tmp.exists(), "tmp must be gone after rename");
        assert!(dest.exists(), "dest must exist after rename");
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
    }

    /// # Contract (negative)
    ///
    /// On rename failure, `finalize_atomic_write` MUST best-effort
    /// remove the `tmp` file and propagate the error. Pre-fix
    /// `download_file` used the `?` operator on `rename`, so when
    /// `rename` returned `Err` the `tmp` leaked into the cache
    /// directory until the user manually swept it. Reproduced here by
    /// renaming into a non-existent parent directory, which all
    /// platforms reject.
    #[test]
    fn finalize_atomic_write_cleans_up_tmp_on_rename_failure() {
        let dir = TempDir::new().expect("tempdir");
        let tmp = dir.path().join("payload.tmp");
        let dest = dir.path().join("absent-subdir").join("payload.bin");
        std::fs::write(&tmp, b"hello").expect("seed tmp");

        let result = finalize_atomic_write(&tmp, &dest);

        assert!(
            result.is_err(),
            "rename into a non-existent parent dir must fail"
        );
        assert!(
            !tmp.exists(),
            "tmp file MUST be cleaned up after rename failure"
        );
    }

    /// # Contract
    ///
    /// `finalize_atomic_write` MUST overwrite an existing destination
    /// atomically: readers see either the old or the new bytes, never an
    /// empty or truncated file. POSIX `rename(2)` is atomic for
    /// same-mount sources; this test pins the success-path overwrite.
    #[test]
    fn finalize_atomic_write_overwrites_existing_dest_atomically() {
        let dir = TempDir::new().expect("tempdir");
        let dest = dir.path().join("payload.bin");
        std::fs::write(&dest, b"OLD").expect("seed dest");

        let tmp = dir.path().join("payload.tmp");
        std::fs::write(&tmp, b"NEW-and-longer").expect("seed tmp");

        finalize_atomic_write(&tmp, &dest).expect("overwrite rename must succeed");

        assert!(!tmp.exists(), "tmp must be gone after overwrite");
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW-and-longer");
    }

    /// # Contract
    ///
    /// `write_cache_file_atomic` writes complete bytes at the
    /// destination and creates missing cache parents with the secure
    /// directory policy used by cache callers.
    #[test]
    fn write_cache_file_atomic_writes_bytes_to_dest() {
        let dir = TempDir::new().expect("tempdir");
        let dest = dir.path().join("nested").join("payload.json");

        write_cache_file_atomic(&dest, b"{\"ok\":true}").unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), br#"{"ok":true}"#);
    }

    /// # Contract
    ///
    /// `write_cache_file_atomic` replaces a symlinked cache entry
    /// without following it and overwriting the target.
    #[cfg(unix)]
    #[test]
    fn write_cache_file_atomic_replaces_symlink_without_touching_target() {
        let dir = TempDir::new().expect("tempdir");
        let target = dir.path().join("target.json");
        let dest = dir.path().join("payload.json");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &dest).unwrap();

        write_cache_file_atomic(&dest, b"fresh").unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        assert!(!std::fs::symlink_metadata(&dest)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "fresh");
    }

    /// # Contract
    ///
    /// The buffer pre-allocation in `read_cache_file_with_cap` MUST be
    /// capped at `min(len, cap)` rather than `len` alone. Without this
    /// cap, a file that grew between the `metadata().len()` check and
    /// the actual read could cause a pre-allocation far exceeding the
    /// intended bound, even though the post-stat stream cap rejects the
    /// oversized content.
    #[test]
    fn read_cache_file_with_cap_pre_allocation_is_capped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("boundary.json");
        // Write a 16-byte file.
        std::fs::write(&path, vec![0u8; 16]).unwrap();

        // With a cap of 8, the file is over cap and should return None.
        let result = read_cache_file_with_cap(&path, 8).unwrap();
        assert!(result.is_none(), "over-cap file must be a cache miss");

        // With a cap of 32, the file is under cap and should be read fully.
        let result = read_cache_file_with_cap(&path, 32).unwrap().unwrap();
        assert_eq!(result.len(), 16, "under-cap file must be read in full");
    }
}
