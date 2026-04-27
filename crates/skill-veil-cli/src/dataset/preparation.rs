use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub(super) struct DatasetPreparation {
    pub(super) package_roots: Vec<PathBuf>,
    pub(super) skipped_archives: usize,
}

pub(super) fn prepare_dataset_packages(root: &Path) -> Result<DatasetPreparation> {
    let immediate_subdirs: Vec<_> = fs::read_dir(root)
        .with_context(|| format!("Failed to read dataset root {}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let hidden = name.to_str().is_some_and(|name| name.starts_with('.'));
            entry
                .file_type()
                .ok()
                .filter(|ft| ft.is_dir() && !hidden)
                .map(|_| entry.path())
        })
        .collect();
    if !immediate_subdirs.is_empty() {
        return Ok(DatasetPreparation {
            package_roots: immediate_subdirs,
            skipped_archives: 0,
        });
    }

    let archive_files: Vec<_> = fs::read_dir(root)
        .with_context(|| format!("Failed to read dataset root {}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if !entry.file_type().ok().is_some_and(|ft| ft.is_file()) {
                return None;
            }
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
                || is_zip_archive(&path)
            {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    if !archive_files.is_empty() {
        let cache_root = root.join(".skill-veil-cache").join("extracted");
        fs::create_dir_all(&cache_root)
            .with_context(|| format!("Failed to create {}", cache_root.display()))?;

        let extraction_results: Vec<_> = archive_files
            .par_iter()
            .map(|zip_path| extract_zip_package_cached(zip_path, &cache_root))
            .collect();

        let mut skipped_archives = 0_usize;
        for result in extraction_results {
            match result {
                Ok(()) => {}
                Err(err) => {
                    skipped_archives += 1;
                    tracing::warn!("{err:#}");
                }
            }
        }

        let extracted_roots: Vec<_> = fs::read_dir(&cache_root)
            .with_context(|| format!("Failed to read {}", cache_root.display()))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(|ft| ft.is_dir())
                    .map(|_| entry.path())
            })
            .collect();
        return Ok(DatasetPreparation {
            package_roots: extracted_roots,
            skipped_archives,
        });
    }

    let mut packages = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
    {
        if entry
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("SKILL.md"))
        {
            if let Some(parent) = entry.path().parent() {
                packages.insert(parent.to_path_buf());
            }
        }
    }
    Ok(DatasetPreparation {
        package_roots: packages.into_iter().collect(),
        skipped_archives: 0,
    })
}

fn is_zip_archive(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    zip::ZipArchive::new(file).is_ok()
}

fn extract_zip_package(zip_path: &Path, output_dir: &Path) -> Result<()> {
    let file = fs::File::open(zip_path)
        .with_context(|| format!("Failed to open {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("Invalid zip {}", zip_path.display()))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("Failed to read zip entry {}", zip_path.display()))?;
        let Some(relative_path) = entry.enclosed_name().map(|path| path.to_path_buf()) else {
            continue;
        };
        let destination = output_dir.join(&relative_path);
        // Zip-slip defence in depth: even when `enclosed_name` rejects the
        // obvious `../` cases, a malicious archive built around symlinks or
        // an exotic path encoding could still produce a destination outside
        // `output_dir` after `Path::join`. Compare lexically so the check
        // applies before the file is created.
        if !skill_veil_core::path_safety::path_stays_within_base(&destination, output_dir) {
            tracing::warn!(
                zip = %zip_path.display(),
                entry = %relative_path.display(),
                "skipping zip entry that would escape output_dir (zip-slip)"
            );
            continue;
        }
        if entry.is_dir() {
            fs::create_dir_all(&destination)
                .with_context(|| format!("Failed to create {}", destination.display()))?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let mut outfile = fs::File::create(&destination)
            .with_context(|| format!("Failed to create {}", destination.display()))?;
        std::io::copy(&mut entry, &mut outfile)
            .with_context(|| format!("Failed to extract {}", destination.display()))?;
    }
    Ok(())
}

/// Maximum time `extract_zip_package_cached` waits for a competing
/// process to finish extracting the same zip before giving up. 60s
/// covers reasonable archive sizes (hundreds of MB extracted to disk);
/// beyond that the lock is treated as stale and the extraction proceeds
/// after taking it over. Larger corpora that legitimately exceed this
/// budget should be split into smaller datasets.
const EXTRACTION_LOCK_TIMEOUT: Duration = Duration::from_secs(60);

/// Polling interval while waiting on a peer extraction to finish. Kept
/// short enough that the second-arriver returns promptly when the first
/// finishes, but not so short that contention burns CPU.
const EXTRACTION_LOCK_POLL: Duration = Duration::from_millis(100);

/// RAII lockfile sentinel: holds the lock for its lifetime and removes
/// the path on drop. Used by `extract_zip_package_cached` to prevent two
/// concurrent invocations (typically from parallel `scan-dataset` runs
/// or rayon worker threads) from racing on the same `output_dir`.
struct ExtractionLock {
    path: PathBuf,
}

impl Drop for ExtractionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Try to acquire the extraction lockfile via `O_EXCL` semantics
/// (`create_new`). Returns the RAII guard on success, `None` on
/// contention. Cross-platform safe — `OpenOptions::create_new` maps to
/// `O_EXCL` on Unix and `CREATE_NEW` on Windows.
fn try_acquire_extraction_lock(lock_path: &Path) -> Result<Option<ExtractionLock>> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock_path)
    {
        Ok(_file) => Ok(Some(ExtractionLock {
            path: lock_path.to_path_buf(),
        })),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(err) => Err(err)
            .with_context(|| format!("Failed to acquire extraction lock {}", lock_path.display())),
    }
}

/// Wait for a competing extraction to finish or for the lock to be
/// considered stale (`EXTRACTION_LOCK_TIMEOUT`). After acquiring the
/// stale lock, the caller proceeds with extraction.
fn wait_for_peer_or_take_lock(
    lock_path: &Path,
    output_dir: &Path,
    marker_path: &Path,
    source_signature: &str,
) -> Result<Option<ExtractionLock>> {
    let started = Instant::now();
    while started.elapsed() < EXTRACTION_LOCK_TIMEOUT {
        thread::sleep(EXTRACTION_LOCK_POLL);
        // Peer may have completed: check cache hit conditions again.
        if output_dir.is_dir()
            && marker_path.exists()
            && fs::read_to_string(marker_path).ok().as_deref() == Some(source_signature)
        {
            return Ok(None);
        }
        if let Some(lock) = try_acquire_extraction_lock(lock_path)? {
            return Ok(Some(lock));
        }
    }
    // Stale lock: forcibly remove and retry once.
    let _ = fs::remove_file(lock_path);
    try_acquire_extraction_lock(lock_path)?
        .map(Some)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Extraction lock {} remained held beyond timeout {:?}",
                lock_path.display(),
                EXTRACTION_LOCK_TIMEOUT
            )
        })
}

fn extract_zip_package_cached(zip_path: &Path, cache_root: &Path) -> Result<()> {
    let package_name = zip_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("package");
    let output_dir = cache_root.join(package_name);
    let marker_path = output_dir.join(".skill-veil-source");
    let source_signature = zip_source_signature(zip_path)?;

    if output_dir.is_dir()
        && marker_path.exists()
        && fs::read_to_string(&marker_path).ok().as_deref() == Some(source_signature.as_str())
    {
        return Ok(());
    }

    // Cross-process / cross-thread serialization: only one extractor
    // operates on `output_dir` at a time. Without this, two parallel
    // `scan-dataset` runs (or rayon workers within one run) could
    // simultaneously `remove_dir_all(&output_dir)` and `rename(...)`,
    // leaving the cache in a half-written state. Round-5 audit Bug 2.5.
    let lock_path = cache_root.join(format!(".{}.lock", package_name));
    let _lock = match try_acquire_extraction_lock(&lock_path)? {
        Some(lock) => lock,
        None => {
            // Peer extracting: wait for it to publish the cache or take
            // over after the timeout window.
            match wait_for_peer_or_take_lock(
                &lock_path,
                &output_dir,
                &marker_path,
                &source_signature,
            )? {
                Some(lock) => lock,
                // Peer published a valid cache while we waited.
                None => return Ok(()),
            }
        }
    };

    // Re-check cache hit after acquiring the lock — the peer may have
    // populated the cache between our pre-lock probe and the lock grab.
    if output_dir.is_dir()
        && marker_path.exists()
        && fs::read_to_string(&marker_path).ok().as_deref() == Some(source_signature.as_str())
    {
        return Ok(());
    }

    let staging_dir = cache_root.join(format!(".{}.tmp", package_name));
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("Failed to clean {}", staging_dir.display()))?;
    }
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("Failed to create {}", staging_dir.display()))?;
    extract_zip_package(zip_path, &staging_dir)?;
    fs::write(staging_dir.join(".skill-veil-source"), &source_signature)
        .with_context(|| format!("Failed to write marker for {}", zip_path.display()))?;

    if output_dir.exists() {
        fs::remove_dir_all(&output_dir)
            .with_context(|| format!("Failed to replace {}", output_dir.display()))?;
    }
    finalize_extraction(&staging_dir, &output_dir).with_context(|| {
        format!(
            "Failed to finalize cached extraction for {}",
            zip_path.display()
        )
    })?;
    Ok(())
}

/// Best-effort cleanup guard: drops `staging_dir` whenever the guard goes
/// out of scope, including on early-return via `?`. Pre-fix the cleanup
/// was a trailing `fs::remove_dir_all(&staging_dir)` after the per-entry
/// rename loop, so any inner `?` failure (cross-mount partial failure,
/// permission error mid-loop) bypassed cleanup and left the staging
/// directory on disk indefinitely.
struct StagingGuard<'a> {
    path: &'a Path,
    armed: bool,
}

impl<'a> StagingGuard<'a> {
    fn arm(path: &'a Path) -> Self {
        Self { path, armed: true }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard<'_> {
    fn drop(&mut self) {
        if self.armed && self.path.exists() {
            let _ = fs::remove_dir_all(self.path);
        }
    }
}

/// Promote `staging_dir` to `output_dir`, falling back to per-entry rename
/// when the source and destination live on different filesystems (`rename`
/// returns `EXDEV`). The `StagingGuard` ensures `staging_dir` is removed
/// even when the fallback loop errors midway.
fn finalize_extraction(staging_dir: &Path, output_dir: &Path) -> Result<()> {
    let guard = StagingGuard::arm(staging_dir);
    if fs::rename(staging_dir, output_dir).is_ok() {
        // `rename` consumed the source; nothing left to clean.
        guard.disarm();
        return Ok(());
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;
    for entry in fs::read_dir(staging_dir)
        .with_context(|| format!("Failed to read {}", staging_dir.display()))?
    {
        let entry = entry?;
        let source = entry.path();
        let destination = output_dir.join(entry.file_name());
        fs::rename(&source, &destination).with_context(|| {
            format!(
                "Failed to move {} to {}",
                source.display(),
                destination.display()
            )
        })?;
    }
    fs::remove_dir_all(staging_dir)
        .with_context(|| format!("Failed to remove {}", staging_dir.display()))?;
    guard.disarm();
    Ok(())
}

/// Content-addressed signature: SHA-256 of the zip bytes. Stable across
/// renames and identical-content copies at different paths, unlike the
/// previous `path:len:mtime` triple which forced re-extraction whenever
/// the file moved. Trade-off: one full read of the archive on every
/// signature computation; the extraction cost would dominate this anyway.
fn zip_source_signature(zip_path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(zip_path)
        .with_context(|| format!("Failed to read {} for signature", zip_path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    /// Contract: malicious ZIP entries that would escape `output_dir` MUST
    /// be skipped, never written. Defence in depth on top of `zip` crate's
    /// `enclosed_name` sanitisation. See `path_safety::path_stays_within_base`.
    #[test]
    fn extract_zip_package_rejects_zip_slip_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("evil.zip");
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&output_dir).unwrap();
        // The "outside" directory is a sibling of output_dir; if zip-slip
        // succeeded, the entry would be written to escape.txt under it.
        let outside_dir = tmp.path().join("outside");
        std::fs::create_dir_all(&outside_dir).unwrap();

        // Build a zip that intentionally tries to escape via `../`.
        // `enclosed_name()` in modern `zip` crate filters obvious `../`
        // entries, so we exercise the defence-in-depth path by injecting
        // an absolute-style entry name. If the zip crate accepts it, our
        // post-join `path_stays_within_base` check must reject it.
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            // Many zip crate versions accept this and `enclosed_name` filters
            // the leading `..` — we still want the helper as the last guard.
            writer
                .start_file("../outside/escape.txt", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"OWNED").unwrap();
            writer.finish().unwrap();
        }

        let _ = extract_zip_package(&zip_path, &output_dir);

        // The escape file MUST NOT exist anywhere outside `output_dir`.
        let escape_target = outside_dir.join("escape.txt");
        assert!(
            !escape_target.exists(),
            "zip-slip defence failed: {} was written outside output_dir",
            escape_target.display()
        );
        // Sanity: nothing under the parent of output_dir got an `escape.txt`.
        let walked: Vec<_> = walkdir::WalkDir::new(tmp.path())
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() == "escape.txt")
            .collect();
        assert!(
            walked.is_empty() || walked.iter().all(|e| e.path().starts_with(&output_dir)),
            "escape.txt must only ever live inside output_dir; found at: {:?}",
            walked
                .iter()
                .map(|e| e.path().to_path_buf())
                .collect::<Vec<_>>()
        );
    }

    /// # Contract
    ///
    /// `finalize_extraction` MUST remove `staging_dir` even when the
    /// per-entry fallback fails midway. Pre-fix the cleanup lived as a
    /// trailing statement after the `for` loop; any inner `?` (cross-mount
    /// rename failing partway, EACCES, etc.) bypassed it and left a stale
    /// `.<pkg>.tmp/` on disk indefinitely. The `StagingGuard` now drops
    /// the directory on every failure path.
    #[test]
    fn cross_mount_fallback_cleans_staging_on_inner_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let staging_dir = tmp.path().join(".pkg.tmp");
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&staging_dir).unwrap();
        std::fs::write(staging_dir.join("a.txt"), b"a").unwrap();
        std::fs::write(staging_dir.join("b.txt"), b"b").unwrap();

        // Force the primary `fs::rename` path to fail by making `output_dir`
        // an existing non-empty directory. On most platforms this still
        // succeeds for `rename(dir, dir)` when target is empty but errors
        // when the target dir contains entries. We pre-populate it to make
        // the primary rename fail and steer execution into the fallback.
        std::fs::create_dir_all(&output_dir).unwrap();
        std::fs::write(output_dir.join("placeholder"), b"x").unwrap();
        // Then sabotage the per-entry fallback: pre-create a read-only
        // directory at the destination of `a.txt` so `fs::rename(source,
        // destination)` fails inside the loop.
        let conflict = output_dir.join("a.txt");
        std::fs::create_dir_all(&conflict).unwrap();
        std::fs::write(conflict.join("blocker"), b"blocker").unwrap();

        let result = finalize_extraction(&staging_dir, &output_dir);
        assert!(
            result.is_err(),
            "fallback must propagate the inner rename failure"
        );
        assert!(
            !staging_dir.exists(),
            "staging_dir must be removed by StagingGuard even on inner failure"
        );
    }

    /// # Contract
    ///
    /// On the happy path, `finalize_extraction` consumes `staging_dir` and
    /// publishes its contents under `output_dir`. The guard must NOT
    /// double-remove an already-renamed directory; observing this
    /// behaviour pins the `disarm()` call on the success path.
    #[test]
    fn finalize_extraction_publishes_then_clears_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let staging_dir = tmp.path().join(".pkg.tmp");
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&staging_dir).unwrap();
        std::fs::write(staging_dir.join("file.txt"), b"hello").unwrap();

        finalize_extraction(&staging_dir, &output_dir).unwrap();
        assert!(!staging_dir.exists(), "staging_dir must be gone");
        assert_eq!(
            std::fs::read_to_string(output_dir.join("file.txt")).unwrap(),
            "hello"
        );
    }
}
