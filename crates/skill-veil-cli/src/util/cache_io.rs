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

use anyhow::{Context, Result};
use std::io;
use std::io::Read;
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
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("opening cache file {}", path.display()));
        }
    };
    let len = file
        .metadata()
        .with_context(|| format!("stat cache file {}", path.display()))?
        .len();
    if len > cap {
        tracing::warn!(
            "ignoring cache file {} ({} bytes > cap {}); will refetch",
            path.display(),
            len,
            cap,
        );
        return Ok(None);
    }
    // `metadata().len()` is racy with concurrent writers, so still cap
    // the read with `take(cap)` to bound memory even if the file grew
    // between the stat and the read.
    let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.by_ref()
        .take(cap)
        .read_to_end(&mut buf)
        .with_context(|| format!("reading cache file {}", path.display()))?;
    Ok(Some(buf))
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
}
