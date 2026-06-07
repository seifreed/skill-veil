use crate::util::secure_fs::{ensure_real_dir, is_real_dir};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
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
        ensure_existing_cache_path_stays_in_dataset(root, &root.join(".skill-veil-cache"))?;
        // `create_dir_secure` (owner-only `0o700` on Unix) instead of
        // `create_dir_all` so the extracted-package cache is not
        // world-readable on shared workstations / CI runners. The cache
        // contains fully-extracted skill packages — possibly proprietary
        // content of the package being scanned. The VT and LLM caches
        // already use this helper; the dataset cache falls into the
        // same threat model.
        crate::util::secure_fs::create_dir_secure(&cache_root)
            .with_context(|| format!("Failed to create {}", cache_root.display()))?;
        ensure_cache_root_stays_in_dataset(root, &cache_root)?;

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

/// Per-entry hard cap on decompressed bytes. A malicious "zip-bomb" is a
/// few-KB archive containing a single entry that decompresses to many
/// gigabytes; without a cap, `std::io::copy` would happily fill the disk
/// before the dataset prep ever returns. 512 MiB covers any realistic
/// skill-package supporting artifact (typical agent bundles are under a
/// few MB) while bounding the worst case from a hostile archive.
const MAX_ZIP_ENTRY_BYTES: u64 = 512 * 1024 * 1024;

/// Aggregate cap across all entries in a single zip. Defends against the
/// "many small bombs" variant where each entry stays under
/// [`MAX_ZIP_ENTRY_BYTES`] but the archive carries thousands of them.
/// 4 GiB matches the typical free-space slack on CI runners.
const MAX_ZIP_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn extract_zip_package(zip_path: &Path, output_dir: &Path) -> Result<()> {
    extract_zip_package_with_caps(
        zip_path,
        output_dir,
        MAX_ZIP_ENTRY_BYTES,
        MAX_ZIP_TOTAL_BYTES,
    )
}

/// Cap-injected variant for tests. Production callers go through
/// [`extract_zip_package`], which pins the production caps.
fn extract_zip_package_with_caps(
    zip_path: &Path,
    output_dir: &Path,
    max_entry_bytes: u64,
    max_total_bytes: u64,
) -> Result<()> {
    let file = fs::File::open(zip_path)
        .with_context(|| format!("Failed to open {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("Invalid zip {}", zip_path.display()))?;
    let mut total_bytes_written: u64 = 0;
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
        if !skill_veil_core::path_stays_within_base(&destination, output_dir) {
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
        // Header-declared size is advisory — a malicious producer can lie —
        // so we still enforce the cap during the streaming copy below.
        // The pre-check is a cheap fast-path that rejects honest bombs
        // without ever writing partial output to disk.
        if entry.size() > max_entry_bytes {
            tracing::warn!(
                zip = %zip_path.display(),
                entry = %relative_path.display(),
                declared_size = entry.size(),
                cap = max_entry_bytes,
                "skipping zip entry whose declared decompressed size exceeds the per-entry cap (possible zip-bomb)"
            );
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let mut outfile = fs::File::create(&destination)
            .with_context(|| format!("Failed to create {}", destination.display()))?;
        // `take(cap + 1)`: if `copy` returns more than `cap`, we know the
        // entry tried to exceed the cap (a bomb that lied in its header).
        // Capping at exactly `cap` would be ambiguous between "entry is
        // exactly at the limit" and "entry is over the limit".
        let probe_limit = max_entry_bytes.saturating_add(1);
        let mut limited = (&mut entry).take(probe_limit);
        let written = std::io::copy(&mut limited, &mut outfile)
            .with_context(|| format!("Failed to extract {}", destination.display()))?;
        if written > max_entry_bytes {
            drop(outfile);
            let _ = fs::remove_file(&destination);
            anyhow::bail!(
                "zip entry {} exceeded per-entry decompression cap of {} bytes (possible zip-bomb in {})",
                relative_path.display(),
                max_entry_bytes,
                zip_path.display(),
            );
        }
        total_bytes_written = total_bytes_written.saturating_add(written);
        if total_bytes_written > max_total_bytes {
            drop(outfile);
            let _ = fs::remove_file(&destination);
            anyhow::bail!(
                "zip {} exceeded aggregate decompression cap of {} bytes (possible zip-bomb)",
                zip_path.display(),
                max_total_bytes,
            );
        }
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

/// Fallback package name when a ZIP filename's stem is unsafe to use as a
/// path component (pure-dot names like `..`, components containing path
/// separators on the host platform). See [`sanitize_package_name`].
const FALLBACK_PACKAGE_NAME: &str = "package";

/// Reduce a ZIP filename stem to a path component that is safe to join onto
/// `cache_root`. Returns [`FALLBACK_PACKAGE_NAME`] when the stem is empty,
/// composed entirely of `.` characters (so `Path::join` would resolve to
/// the parent of `cache_root`), or contains a path separator. Without this,
/// a ZIP literally named `...zip` produces `Path::file_stem == ".."` and
/// `cache_root.join("..")` walks above the cache, which then participates
/// in `fs::remove_dir_all`/`fs::rename` on a path the caller never intended.
fn sanitize_package_name(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return FALLBACK_PACKAGE_NAME;
    }
    if trimmed.bytes().all(|b| b == b'.') {
        return FALLBACK_PACKAGE_NAME;
    }
    if trimmed.contains(std::path::MAIN_SEPARATOR)
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return FALLBACK_PACKAGE_NAME;
    }
    trimmed
}

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
        if is_real_dir(output_dir)
            && marker_path.exists()
            && read_marker_bounded(marker_path).as_deref() == Some(source_signature)
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

/// Maximum marker file size to read. Marker files contain short signatures
/// (zip path + mtime), so 4 KiB is generous. Unbounded reads could OOM on
/// a maliciously large marker written by a compromised same-UID process.
const MAX_MARKER_BYTES: u64 = 4096;

/// Read the extraction marker file with a size cap, returning `None` if the
/// file is missing or exceeds `MAX_MARKER_BYTES`. Uses bounded I/O to
/// prevent OOM from a maliciously large marker.
fn read_marker_bounded(path: &Path) -> Option<String> {
    use crate::util::cache_io::read_cache_file_with_cap;
    let bytes = read_cache_file_with_cap(path, MAX_MARKER_BYTES).ok()??;
    String::from_utf8(bytes).ok()
}

fn extract_zip_package_cached(zip_path: &Path, cache_root: &Path) -> Result<()> {
    let raw_stem = zip_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(FALLBACK_PACKAGE_NAME);
    let package_name = sanitize_package_name(raw_stem);
    let output_dir = cache_root.join(package_name);
    // Defence in depth: the lexical check guarantees that even if a future
    // refactor weakens `sanitize_package_name`, an output path that escapes
    // `cache_root` cannot be silently used in destructive `remove_dir_all`/
    // `rename` operations below.
    if !skill_veil_core::path_stays_within_base(&output_dir, cache_root) {
        anyhow::bail!(
            "Refusing to extract {}: derived cache path {} escapes cache root {}",
            zip_path.display(),
            output_dir.display(),
            cache_root.display()
        );
    }
    let marker_path = output_dir.join(".skill-veil-source");
    let source_signature = zip_source_signature(zip_path)?;

    if is_real_dir(&output_dir)
        && marker_path.exists()
        && read_marker_bounded(&marker_path).as_deref() == Some(source_signature.as_str())
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
    if is_real_dir(&output_dir)
        && marker_path.exists()
        && read_marker_bounded(&marker_path).as_deref() == Some(source_signature.as_str())
    {
        return Ok(());
    }

    let staging_dir = cache_root.join(format!(".{}.tmp", package_name));
    remove_existing_cache_dir(&staging_dir)
        .with_context(|| format!("Failed to clean {}", staging_dir.display()))?;
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("Failed to create {}", staging_dir.display()))?;
    let staging_guard = StagingGuard::arm(&staging_dir);
    extract_zip_package(zip_path, &staging_dir)?;
    fs::write(staging_dir.join(".skill-veil-source"), &source_signature)
        .with_context(|| format!("Failed to write marker for {}", zip_path.display()))?;

    remove_existing_cache_dir(&output_dir)
        .with_context(|| format!("Failed to replace {}", output_dir.display()))?;
    finalize_extraction(&staging_dir, &output_dir).with_context(|| {
        format!(
            "Failed to finalize cached extraction for {}",
            zip_path.display()
        )
    })?;
    staging_guard.disarm();
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
        if self.armed {
            let _ = remove_existing_cache_dir(self.path);
        }
    }
}

/// Promote `staging_dir` to `output_dir`, falling back to per-entry rename
/// when the source and destination live on different filesystems (`rename`
/// returns `EXDEV`). The `StagingGuard` ensures `staging_dir` is removed
/// even when the fallback loop errors midway.
fn finalize_extraction(staging_dir: &Path, output_dir: &Path) -> Result<()> {
    let guard = StagingGuard::arm(staging_dir);
    match fs::rename(staging_dir, output_dir) {
        Ok(()) => {
            guard.disarm();
            return Ok(());
        }
        Err(err) if err.kind() == std::io::ErrorKind::CrossesDevices => {}
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "Failed to rename {} to {}",
                    staging_dir.display(),
                    output_dir.display()
                )
            });
        }
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;
    ensure_real_dir(output_dir)?;
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
    debug_assert!(
        !staging_dir.exists(),
        "cross-device extraction fallback must consume the staging directory"
    );
    guard.disarm();
    Ok(())
}

fn ensure_existing_cache_path_stays_in_dataset(dataset_root: &Path, path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound) {
        return Ok(());
    }
    let dataset_root = dataset_root
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize {}", dataset_root.display()))?;
    let cache_path = path
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize {}", path.display()))?;
    if !cache_path.starts_with(&dataset_root) {
        anyhow::bail!(
            "Refusing to use extraction cache {} because it resolves outside dataset root {}",
            cache_path.display(),
            dataset_root.display()
        );
    }
    Ok(())
}

fn ensure_cache_root_stays_in_dataset(dataset_root: &Path, cache_root: &Path) -> Result<()> {
    ensure_real_dir(cache_root)?;
    let dataset_root = dataset_root
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize {}", dataset_root.display()))?;
    let cache_root = cache_root
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize {}", cache_root.display()))?;
    if !cache_root.starts_with(&dataset_root) {
        anyhow::bail!(
            "Refusing to use extraction cache {} because it resolves outside dataset root {}",
            cache_root.display(),
            dataset_root.display()
        );
    }
    Ok(())
}

fn remove_existing_cache_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!(
                "refusing to replace symlinked cache path {}",
                path.display()
            )
        }
        Ok(meta) if meta.is_dir() => {
            fs::remove_dir_all(path).with_context(|| format!("Failed to remove {}", path.display()))
        }
        Ok(_) => anyhow::bail!(
            "refusing to replace non-directory cache path {}",
            path.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("Failed to stat {}", path.display())),
    }
}

/// Content-addressed signature: SHA-256 of the zip bytes. Stable across
/// renames and identical-content copies at different paths, unlike the
/// previous `path:len:mtime` triple which forced re-extraction whenever
/// the file moved.
///
/// Streams the file in 64 KiB chunks instead of loading the entire archive
/// into memory. Pre-fix this used `fs::read`, which allocates the full file
/// size — a 10 GB archive would OOM the process before the hash was ever
/// computed. The streaming approach keeps peak memory bounded regardless of
/// archive size.
fn zip_source_signature(zip_path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let file = fs::File::open(zip_path)
        .with_context(|| format!("Failed to open {} for signature", zip_path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        for (name, body) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
    }

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
    /// `finalize_extraction` MUST NOT enter the per-entry fallback for
    /// ordinary rename failures such as an already-existing output
    /// directory. The fallback is only valid for `EXDEV`; using it for
    /// `DirectoryNotEmpty` would merge a fresh extraction into stale
    /// cache contents.
    #[test]
    fn finalize_extraction_rejects_non_cross_device_rename_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let staging_dir = tmp.path().join(".pkg.tmp");
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&staging_dir).unwrap();
        std::fs::write(staging_dir.join("a.txt"), b"a").unwrap();
        std::fs::write(staging_dir.join("b.txt"), b"b").unwrap();
        std::fs::create_dir_all(&output_dir).unwrap();
        std::fs::write(output_dir.join("placeholder"), b"x").unwrap();

        let result = finalize_extraction(&staging_dir, &output_dir);

        assert!(
            result.is_err(),
            "non-EXDEV rename failure must propagate instead of entering fallback"
        );
        assert!(
            !staging_dir.exists(),
            "staging_dir must be removed by StagingGuard on publish failure"
        );
        assert!(
            !output_dir.join("a.txt").exists(),
            "fallback must not merge staging entries into an existing output dir"
        );
        assert_eq!(
            std::fs::read_to_string(output_dir.join("placeholder")).unwrap(),
            "x"
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

    /// # Contract
    ///
    /// `sanitize_package_name` MUST replace pure-dot stems (`.`, `..`,
    /// `...`, …) with [`FALLBACK_PACKAGE_NAME`]. Without this, a ZIP literally
    /// named `...zip` produces `Path::file_stem == ".."`; joining `..` onto
    /// the cache root resolves to the cache root's *parent*, which then
    /// participates in `fs::remove_dir_all` and `fs::rename` inside
    /// `extract_zip_package_cached`. That is a path-traversal vector that
    /// deletes data outside the cache.
    #[test]
    fn sanitize_package_name_replaces_pure_dot_stems() {
        assert_eq!(sanitize_package_name(".."), FALLBACK_PACKAGE_NAME);
        assert_eq!(sanitize_package_name("..."), FALLBACK_PACKAGE_NAME);
        assert_eq!(sanitize_package_name("....."), FALLBACK_PACKAGE_NAME);
        assert_eq!(sanitize_package_name("."), FALLBACK_PACKAGE_NAME);
        assert_eq!(sanitize_package_name(""), FALLBACK_PACKAGE_NAME);
        assert_eq!(sanitize_package_name("   "), FALLBACK_PACKAGE_NAME);
    }

    /// # Contract
    ///
    /// `sanitize_package_name` MUST replace any stem containing a path
    /// separator (`/` or platform-native `\`) with the fallback. This blocks
    /// the secondary path-injection vector where an attacker uses creative
    /// encoding to smuggle a separator through `Path::file_stem`.
    #[test]
    fn sanitize_package_name_replaces_stems_with_separators() {
        assert_eq!(sanitize_package_name("evil/payload"), FALLBACK_PACKAGE_NAME);
        assert_eq!(
            sanitize_package_name("evil\\payload"),
            FALLBACK_PACKAGE_NAME
        );
    }

    /// # Contract
    ///
    /// Benign stems pass through unchanged. This pins the negative case so a
    /// future tightening of `sanitize_package_name` cannot accidentally
    /// rewrite legitimate package names.
    #[test]
    fn sanitize_package_name_passes_through_benign_stems() {
        assert_eq!(sanitize_package_name("normal"), "normal");
        assert_eq!(sanitize_package_name("with-dash"), "with-dash");
        assert_eq!(sanitize_package_name("with.dots"), "with.dots");
        assert_eq!(sanitize_package_name(".hidden"), ".hidden");
        assert_eq!(sanitize_package_name("v1.2.3"), "v1.2.3");
    }

    /// # Contract
    ///
    /// `extract_zip_package_cached` MUST refuse to operate on a ZIP whose
    /// derived `output_dir` escapes the cache root. The `path_stays_within_base`
    /// guard is defence in depth on top of `sanitize_package_name`. This test
    /// uses a real `...zip` filename — the most direct path-traversal
    /// trigger — and asserts the function errors out before any destructive
    /// I/O hits the cache root's parent.
    #[test]
    fn extract_zip_package_cached_rejects_dotted_filenames() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_root).unwrap();
        // Sentinel sibling: would be deleted by `remove_dir_all(cache/..)`
        // if the traversal succeeded.
        let sibling = tmp.path().join("sibling");
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("keep.txt"), b"do not delete").unwrap();

        let zip_path = tmp.path().join("...zip");
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            writer
                .start_file("payload.txt", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"OWNED").unwrap();
            writer.finish().unwrap();
        }

        // Sanity: `Path::file_stem` actually does return ".." for "...zip"
        // on this platform — without this, the test would pass for the
        // wrong reason.
        assert_eq!(
            zip_path.file_stem().and_then(|s| s.to_str()),
            Some(".."),
            "test premise broken: file_stem of ...zip should be .."
        );

        // With the sanitizer in place the call falls back to the safe name
        // and extracts under cache_root/package, so it succeeds; without the
        // sanitizer it would have called `remove_dir_all(cache_root/..)` and
        // `rename(staging, cache_root/..)`, escaping the cache.
        extract_zip_package_cached(&zip_path, &cache_root).unwrap();
        assert!(
            sibling.join("keep.txt").exists(),
            "cache_root sibling must not be touched by extraction"
        );
        assert!(
            cache_root.join(FALLBACK_PACKAGE_NAME).is_dir(),
            "extraction must materialise under the sanitized fallback name"
        );
    }

    /// # Contract
    ///
    /// The dataset extraction cache must resolve inside the dataset root.
    /// A corpus-controlled `.skill-veil-cache` symlink must not redirect
    /// extracted ZIP contents to an attacker-chosen directory.
    #[cfg(unix)]
    #[test]
    fn prepare_dataset_packages_rejects_symlinked_extraction_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let dataset = tmp.path().join("dataset");
        let outside_cache = tmp.path().join("outside-cache");
        std::fs::create_dir(&dataset).unwrap();
        std::fs::create_dir(&outside_cache).unwrap();
        std::os::unix::fs::symlink(&outside_cache, dataset.join(".skill-veil-cache")).unwrap();
        write_zip(&dataset.join("sample.zip"), &[("SKILL.md", b"# Skill\n")]);

        let err = match prepare_dataset_packages(&dataset) {
            Ok(_) => panic!("symlinked cache must fail"),
            Err(err) => err,
        };

        assert!(format!("{err:#}").contains("outside dataset root"));
        assert!(
            !outside_cache
                .join("extracted")
                .join("sample")
                .join("SKILL.md")
                .exists(),
            "zip contents must not be written through the cache symlink"
        );
    }

    /// # Contract
    ///
    /// A pre-existing package cache path that is a symlink must not be
    /// replaced or traversed during cached extraction.
    #[cfg(unix)]
    #[test]
    fn extract_zip_package_cached_rejects_symlinked_output_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&cache_root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let zip_path = tmp.path().join("sample.zip");
        write_zip(&zip_path, &[("SKILL.md", b"# Skill\n")]);
        std::os::unix::fs::symlink(&outside, cache_root.join("sample")).unwrap();

        let err =
            extract_zip_package_cached(&zip_path, &cache_root).expect_err("symlink must fail");

        assert!(format!("{err:#}").contains("symlinked cache path"));
        assert!(!outside.join("SKILL.md").exists());
        assert!(!cache_root.join(".sample.tmp").exists());
    }

    /// # Contract
    ///
    /// A pre-existing staging cache path that is a symlink must be
    /// rejected before ZIP extraction writes any entry bytes.
    #[cfg(unix)]
    #[test]
    fn extract_zip_package_cached_rejects_symlinked_staging_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&cache_root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let zip_path = tmp.path().join("sample.zip");
        write_zip(&zip_path, &[("SKILL.md", b"# Skill\n")]);
        std::os::unix::fs::symlink(&outside, cache_root.join(".sample.tmp")).unwrap();

        let err =
            extract_zip_package_cached(&zip_path, &cache_root).expect_err("symlink must fail");

        assert!(format!("{err:#}").contains("symlinked cache path"));
        assert!(!outside.join("SKILL.md").exists());
        assert!(!cache_root.join("sample").exists());
    }

    /// # Contract
    ///
    /// The aggregate cap defends against the "many small bombs" variant
    /// where each individual entry stays under the per-entry cap but the
    /// archive carries enough of them to still exhaust disk. After the
    /// total exceeds [`MAX_ZIP_TOTAL_BYTES`], extraction MUST abort and
    /// remove the entry that pushed it over the threshold.
    #[test]
    fn extract_zip_package_enforces_aggregate_cap_across_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("many.zip");
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&output_dir).unwrap();

        let payload = vec![b'A'; 4 * 1024];
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            for i in 0..8 {
                writer
                    .start_file(format!("file_{i}.bin"), SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(&payload).unwrap();
            }
            writer.finish().unwrap();
        }

        // Per-entry cap is generous (8 KiB), so each individual entry
        // passes; the aggregate cap of 16 KiB caps total at 4 entries.
        let result = extract_zip_package_with_caps(&zip_path, &output_dir, 8 * 1024, 16 * 1024);
        assert!(
            result.is_err(),
            "expected aggregate cap to abort the extraction; got {result:?}"
        );
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("aggregate decompression cap"),
            "error must explain the aggregate cap; got: {err_msg}"
        );
    }

    /// # Contract
    ///
    /// A header-declared decompressed size that already exceeds the cap
    /// MUST be rejected without ever opening `dest`. This is the cheap
    /// fast-path: before allocating I/O, `entry.size()` lets us refuse
    /// the entry entirely so a partial file is never observable on disk.
    #[test]
    fn extract_zip_package_rejects_oversized_declared_size_without_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("declared.zip");
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&output_dir).unwrap();

        // Build a stored (uncompressed) entry of 8 KiB so the header's
        // declared size is honest and large enough to trip a 1 KiB cap.
        let payload = vec![0u8; 8 * 1024];
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            writer
                .start_file(
                    "declared.bin",
                    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
                )
                .unwrap();
            writer.write_all(&payload).unwrap();
            writer.finish().unwrap();
        }

        // 1 KiB per-entry cap: the 8 KiB declared size trips the
        // pre-check, so the entry is skipped without touching disk.
        let result = extract_zip_package_with_caps(&zip_path, &output_dir, 1024, u64::MAX);
        assert!(
            result.is_ok(),
            "skip-on-declared-oversize should NOT abort the whole archive"
        );
        assert!(
            !output_dir.join("declared.bin").exists(),
            "no partial file must be written when the declared size exceeds the cap"
        );
    }

    /// # Contract
    ///
    /// The happy path remains unchanged for honest, in-bound archives.
    /// Pins that the new caps are NOT triggering false positives on the
    /// realistic dataset packages skill-veil already supports.
    #[test]
    fn extract_zip_package_preserves_honest_archives() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("ok.zip");
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&output_dir).unwrap();

        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            writer
                .start_file("README.md", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"# skill\n").unwrap();
            writer
                .start_file("script.sh", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"#!/bin/sh\necho ok\n").unwrap();
            writer.finish().unwrap();
        }

        extract_zip_package(&zip_path, &output_dir).expect("honest zip must extract");
        assert_eq!(
            std::fs::read_to_string(output_dir.join("README.md")).unwrap(),
            "# skill\n"
        );
        assert!(output_dir.join("script.sh").exists());
    }

    /// # Contract
    ///
    /// `zip_source_signature` MUST produce a stable SHA-256 hex digest without
    /// loading the entire file into memory. Pre-fix the function used `fs::read`
    /// which allocated the full archive size — a 10 GB archive would OOM before
    /// the hash was ever computed. The streaming approach reads in 64 KiB chunks
    /// and keeps peak memory bounded. This test pins that the streaming hash
    /// matches the all-at-once hash for a realistic zip archive.
    #[test]
    fn zip_source_signature_streams_stable_hash() {
        use sha2::Digest;
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("sig_test.zip");
        let payload = b"skill-veil signature streaming test payload";
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            writer
                .start_file("data.bin", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(payload).unwrap();
            writer.finish().unwrap();
        }

        let sig = zip_source_signature(&zip_path).expect("streaming hash must succeed");

        // Verify against all-at-once hash to confirm the streaming
        // implementation produces identical output.
        let bytes = fs::read(&zip_path).unwrap();
        let expected = format!("{:x}", sha2::Sha256::digest(&bytes));
        assert_eq!(sig, expected, "streaming hash must match all-at-once hash");
        assert_eq!(sig.len(), 64, "signature must be 64-char hex SHA-256");
    }
}
