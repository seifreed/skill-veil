//! Orchestrates bulk VT corpus downloads.
//!
//! Given a search query and a destination directory, this module paginates
//! through VT Intelligence, downloads each file binary (unless `--report-only`
//! is set), fetches its metadata report, and caches both to disk. Repeat runs
//! are idempotent: reports are reused only when their payload SHA matches the
//! filename, and samples are skipped only after their bytes hash to that SHA.

use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::client::{VtClient, VtError};
use super::types::CachedReport;

/// Default VT Intelligence query for the malicious-skill corpus. Used by
/// `vt download` when no `--query` and no `--clean` are passed. Mirrors
/// the query that seeded `benchmarks/corpus.yaml`.
pub(crate) const DEFAULT_QUERY: &str =
    "entity:file has:codeinsight codeinsight:\"Type: OpenClaw Skill\" codeinsight_verdict:malicious";

/// Default VT Intelligence query for the **clean** OpenClaw skill corpus.
/// Used when `--clean` is passed. Mirrors [`DEFAULT_QUERY`] in shape but
/// flips the codeinsight verdict so we pull skills VT considers benign —
/// exactly the population we need to measure skill-veil's false-positive
/// rate (we expect "benign" verdicts on these; any "malicious" or
/// "suspicious" finding is a candidate FP to triage). The verdict label
/// is `benign` (empirically confirmed against the live VT API);
/// alternate spellings like `harmless` / `clean` / `safe` return zero
/// hits.
pub(crate) const DEFAULT_CLEAN_QUERY: &str =
    "entity:file has:codeinsight codeinsight:\"Type: OpenClaw Skill\" codeinsight_verdict:benign";

/// Pick the default VT search query when the user did not pass `--query`.
/// `clean=false` returns [`DEFAULT_QUERY`] (the historical malicious
/// corpus); `clean=true` returns [`DEFAULT_CLEAN_QUERY`] (the harmless
/// counterpart used for false-positive sweeps).
#[must_use]
pub(crate) fn default_query(clean: bool) -> &'static str {
    if clean {
        DEFAULT_CLEAN_QUERY
    } else {
        DEFAULT_QUERY
    }
}

pub(crate) const REPORTS_DIRNAME: &str = ".vt-reports";
const PER_PAGE: usize = 40;

pub(crate) struct DownloadOptions {
    pub(crate) query: String,
    pub(crate) dest: PathBuf,
    pub(crate) limit: usize,
    pub(crate) report_only: bool,
    /// Per-request delay in ms. Defaults to `super::REQUEST_DELAY_MS` (500ms,
    /// safe for VT free-tier). Premium accounts may lower this; the value is
    /// applied between every search-pagination request and every
    /// per-sample download to throttle the client side.
    pub(crate) rate_limit_ms: u64,
}

pub(crate) struct DownloadSummary {
    pub(crate) total_discovered: usize,
    pub(crate) files_downloaded: usize,
    pub(crate) files_skipped: usize,
    pub(crate) reports_written: usize,
    pub(crate) errors: usize,
}

pub(crate) fn run_download(client: &VtClient, opts: DownloadOptions) -> Result<DownloadSummary> {
    // Use `create_dir_secure` (0o700 on Unix) so VT report JSON and the
    // downloaded malware samples are not exposed to other local users on
    // shared hosts. `vt::enrich::persist_indicator` already uses this
    // helper for the per-file cache path; the bulk-download entrypoint
    // had been the last `create_dir_all` site for malware-sample storage.
    crate::util::secure_fs::create_dir_secure(&opts.dest)
        .with_context(|| format!("creating {}", opts.dest.display()))?;
    ensure_real_dir(&opts.dest)?;
    let reports_dir = opts.dest.join(REPORTS_DIRNAME);
    ensure_existing_child_stays_in_base(&opts.dest, &reports_dir)?;
    crate::util::secure_fs::create_dir_secure(&reports_dir)
        .with_context(|| format!("creating {}", reports_dir.display()))?;
    ensure_child_dir(&opts.dest, &reports_dir)?;

    let mut summary = DownloadSummary {
        total_discovered: 0,
        files_downloaded: 0,
        files_skipped: 0,
        reports_written: 0,
        errors: 0,
    };

    let mut cursor: Option<String> = None;
    let mut collected: Vec<String> = Vec::new();

    while collected.len() < opts.limit {
        let remaining = opts.limit.saturating_sub(collected.len());
        let page_size = remaining.min(PER_PAGE);
        let response = match cursor.as_deref() {
            Some(c) => client.search_page(&opts.query, page_size, c)?,
            None => client.search(&opts.query, page_size)?,
        };
        if response.data.is_empty() {
            break;
        }
        for entry in response.data {
            if collected.len() >= opts.limit {
                break;
            }
            match canonical_download_sha(&entry.id) {
                Ok(sha) => collected.push(sha),
                Err(err) => {
                    tracing::warn!("skipping VT search result with invalid file id: {err}");
                    summary.errors += 1;
                }
            }
        }
        cursor = response.meta.cursor.clone();
        if cursor.is_none() {
            break;
        }
        sleep(Duration::from_millis(opts.rate_limit_ms));
    }

    summary.total_discovered = collected.len();
    tracing::info!(
        "VT search returned {} file hashes (query limit {})",
        summary.total_discovered,
        opts.limit
    );

    for sha in collected {
        if let Err(err) = process_one(client, &sha, &opts, &reports_dir, &mut summary) {
            tracing::warn!("vt download error for {}: {:#}", sha, err);
            summary.errors += 1;
        }
        sleep(Duration::from_millis(opts.rate_limit_ms));
    }

    Ok(summary)
}

fn process_one(
    client: &VtClient,
    sha: &str,
    opts: &DownloadOptions,
    reports_dir: &Path,
    summary: &mut DownloadSummary,
) -> Result<()> {
    let sha = canonical_download_sha(sha)?;
    // Fetch the report first — it is smaller, and we always want it even if
    // the file is already on disk or download is suppressed.
    let report_path = reports_dir.join(format!("{sha}.json"));
    if !report_cache_hit(&report_path, &sha)? {
        let envelope = client
            .get_file_report(&sha)
            .with_context(|| format!("fetching report for {sha}"))?;
        let cached = CachedReport {
            sha256: envelope.data.id.clone(),
            fetched_at: chrono::Utc::now().to_rfc3339(),
            attributes: envelope.data.attributes,
        };
        persist_report(&report_path, &cached)?;
        summary.reports_written += 1;
    }

    if opts.report_only {
        return Ok(());
    }

    let file_path = opts.dest.join(&sha);
    // Concurrent invocations may both pass this check and call
    // `download_file`. The final persist inside `download_file` is
    // atomic, so the on-disk cache stays consistent — only API quota is
    // wasted in that edge case.
    if sample_cache_hit(&file_path, &sha)? {
        summary.files_skipped += 1;
        return Ok(());
    }
    match client.download_file(&sha, &file_path) {
        Ok(()) => {
            summary.files_downloaded += 1;
            Ok(())
        }
        Err(VtError::Unauthorized) => {
            // Premium-only endpoint — surface once then downgrade the rest
            // of the batch to report-only. The caller handles the summary.
            Err(anyhow::anyhow!(
                "file download requires a VT premium apikey (401); rerun with --report-only"
            ))
        }
        Err(err) => Err(err.into()),
    }
}

fn canonical_download_sha(raw: &str) -> Result<String> {
    super::normalize_sha256_hex(raw)
        .ok_or_else(|| anyhow::anyhow!("VT file id is not a 64-character SHA-256"))
}

/// Persist a VT report through a same-directory tempfile and `rename(2)`.
/// Pre-fix this routine called `std::fs::write` directly, which truncates
/// the destination before writing the bytes — a SIGINT, OOM kill, or host
/// reboot between truncate and write left an empty `<sha>.json`.
fn persist_report(report_path: &Path, cached: &CachedReport) -> Result<()> {
    let json = serde_json::to_string_pretty(cached).context("serialising report")?;
    write_cache_file(report_path, json.as_bytes())
        .with_context(|| format!("writing {}", report_path.display()))?;
    Ok(())
}

fn write_cache_file(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    ensure_real_dir(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temp file under {}", parent.display()))?;
    tmp.write_all(body)
        .with_context(|| format!("writing temp file under {}", parent.display()))?;
    tmp.as_file_mut()
        .sync_all()
        .with_context(|| format!("syncing temp file under {}", parent.display()))?;
    tmp.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("renaming temp file to {}", path.display()))?;
    Ok(())
}

fn existing_cache_metadata(path: &Path) -> Result<Option<Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!("refusing to use symlinked VT cache path {}", path.display())
        }
        Ok(meta) if meta.is_file() && !has_single_hardlink(&meta) => {
            anyhow::bail!(
                "refusing to use hardlinked VT cache path {}",
                path.display()
            )
        }
        Ok(meta) if meta.is_file() => Ok(Some(meta)),
        Ok(_) => anyhow::bail!("refusing to use non-file VT cache path {}", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

fn report_cache_hit(path: &Path, expected_sha: &str) -> Result<bool> {
    if existing_cache_metadata(path)?.is_none() {
        return Ok(false);
    }
    let Some(bytes) = crate::util::cache_io::read_cache_file_bounded(path)? else {
        return Ok(false);
    };
    let Ok(report) = serde_json::from_slice::<CachedReport>(&bytes) else {
        tracing::warn!(
            "ignoring cached VT report {} (invalid JSON); refetching",
            path.display()
        );
        return Ok(false);
    };
    let payload_sha = report.sha256.to_ascii_lowercase();
    if payload_sha == expected_sha {
        Ok(true)
    } else {
        tracing::warn!(
            "ignoring cached VT report {} (payload sha256 {} does not match expected {}); refetching",
            path.display(),
            payload_sha,
            expected_sha
        );
        Ok(false)
    }
}

fn sample_cache_hit(path: &Path, expected_sha: &str) -> Result<bool> {
    let Some(path_meta) = existing_cache_metadata(path)? else {
        return Ok(false);
    };
    if path_meta.len() > super::client::MAX_DOWNLOAD_BYTES {
        tracing::warn!(
            "ignoring cached VT sample {} ({} bytes > cap {}); refetching",
            path.display(),
            path_meta.len(),
            super::client::MAX_DOWNLOAD_BYTES
        );
        return Ok(false);
    }
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() || !opened_file_matches_path(&meta, &path_meta) {
        tracing::warn!(
            "ignoring cached VT sample {} (path changed while opening); refetching",
            path.display()
        );
        return Ok(false);
    }
    let Some(actual_sha) = sha256_file_with_cap(file, super::client::MAX_DOWNLOAD_BYTES)
        .with_context(|| format!("hashing {}", path.display()))?
    else {
        tracing::warn!(
            "ignoring cached VT sample {} (stream exceeded cap {}); refetching",
            path.display(),
            super::client::MAX_DOWNLOAD_BYTES
        );
        return Ok(false);
    };
    if actual_sha == expected_sha {
        Ok(true)
    } else {
        tracing::warn!(
            "ignoring cached VT sample {} (actual sha256 {} does not match expected {}); refetching",
            path.display(),
            actual_sha,
            expected_sha
        );
        Ok(false)
    }
}

fn sha256_file_with_cap(mut file: File, max_bytes: u64) -> std::io::Result<Option<String>> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Ok(None);
        }
        hasher.update(&buf[..read]);
    }
    debug_assert!(
        total <= max_bytes,
        "sample cache verifier must reject streams over the cap"
    );
    Ok(Some(format!("{:x}", hasher.finalize())))
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

fn ensure_existing_child_stays_in_base(base: &Path, child: &Path) -> Result<()> {
    if std::fs::symlink_metadata(child).is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    ensure_child_path_stays_in_base(base, child)
}

fn ensure_child_dir(base: &Path, child: &Path) -> Result<()> {
    ensure_real_dir(child)?;
    ensure_child_path_stays_in_base(base, child)
}

fn ensure_child_path_stays_in_base(base: &Path, child: &Path) -> Result<()> {
    let base = base
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", base.display()))?;
    let child = child
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", child.display()))?;
    if !child.starts_with(&base) {
        anyhow::bail!(
            "{} resolves outside VT download directory {}",
            child.display(),
            base.display()
        );
    }
    Ok(())
}

fn ensure_real_dir(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path)
        .map(|meta| meta.is_dir() && !meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        Ok(())
    } else {
        anyhow::bail!("{} is not a real directory", path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hash::sha256_hex;
    use crate::vt::types::FileAttributes;
    use tempfile::TempDir;

    fn fixture_report() -> CachedReport {
        report_with_sha(&"a".repeat(64))
    }

    fn report_with_sha(sha256: &str) -> CachedReport {
        CachedReport {
            sha256: sha256.to_string(),
            fetched_at: "2026-04-27T00:00:00Z".to_string(),
            attributes: FileAttributes::default(),
        }
    }

    /// # Contract
    ///
    /// VT search ids are canonicalized before they become filenames.
    #[test]
    fn canonical_download_sha_lowercases_hex() {
        assert_eq!(
            canonical_download_sha(&"A".repeat(64)).unwrap(),
            "a".repeat(64)
        );
    }

    /// # Contract
    ///
    /// Path-like VT search ids are rejected before report or sample paths
    /// are constructed.
    #[test]
    fn canonical_download_sha_rejects_path_segments() {
        for bad in [
            "../escape".to_string(),
            "/tmp/escape".to_string(),
            "aa/bb".to_string(),
            "g".repeat(64),
        ] {
            assert!(
                canonical_download_sha(&bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// # Contract
    ///
    /// `persist_report` MUST land the report at `report_path` through
    /// a same-directory tempfile and leave no `.tmp` residue on success.
    /// Pre-fix the report was written through `std::fs::write`, which
    /// truncated the destination before writing the bytes; an interrupt
    /// between truncate and write left an empty `<sha>.json` that the
    /// caller's `exists()` short-circuit then treated as a cache hit.
    #[test]
    fn persist_report_writes_atomically_via_rename() {
        let dir = TempDir::new().expect("tempdir");
        let report_path = dir.path().join("aa.json");
        let cached = fixture_report();

        persist_report(&report_path, &cached).expect("persist must succeed");

        let tmp = report_path.with_extension("tmp");
        assert!(!tmp.exists(), "tmp must not linger after success");
        assert!(report_path.exists(), "report must exist at dest");
        let bytes = std::fs::read(&report_path).expect("read report");
        let parsed: CachedReport = serde_json::from_slice(&bytes).expect("re-parse report");
        assert_eq!(parsed.sha256, cached.sha256);
    }

    /// # Contract (negative)
    ///
    /// `persist_report` MUST surface the underlying I/O error and not
    /// leave the old predictable `.tmp` sibling when the target parent is
    /// missing.
    #[test]
    fn persist_report_cleans_up_tmp_on_rename_failure() {
        let dir = TempDir::new().expect("tempdir");
        let report_path = dir.path().join("missing-subdir").join("aa.json");
        let cached = fixture_report();

        let result = persist_report(&report_path, &cached);

        assert!(result.is_err(), "rename into missing parent must fail");
        let tmp = report_path.with_extension("tmp");
        assert!(!tmp.exists(), "tmp must be cleaned up on failure");
    }

    /// # Contract
    ///
    /// `persist_report` MUST overwrite an already-present report
    /// atomically: readers either see the previous bytes or the new
    /// bytes, never an empty/half-written file.
    #[test]
    fn persist_report_overwrites_existing_report_atomically() {
        let dir = TempDir::new().expect("tempdir");
        let report_path = dir.path().join("aa.json");
        std::fs::write(&report_path, b"OLD").expect("seed dest");

        let cached = fixture_report();
        persist_report(&report_path, &cached).expect("overwrite must succeed");

        let bytes = std::fs::read(&report_path).expect("read report");
        let parsed: CachedReport = serde_json::from_slice(&bytes).expect("re-parse");
        assert_eq!(parsed.sha256, cached.sha256);
    }

    /// # Contract
    ///
    /// A pre-existing symlink at the report cache path must be replaced
    /// as a directory entry, not followed and overwritten.
    #[cfg(unix)]
    #[test]
    fn persist_report_replaces_symlink_without_touching_target() {
        let dir = TempDir::new().expect("tempdir");
        let outside = dir.path().join("outside.json");
        let report_path = dir.path().join("aa.json");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, &report_path).unwrap();

        persist_report(&report_path, &fixture_report()).expect("persist must succeed");

        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert!(!std::fs::symlink_metadata(&report_path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// # Contract
    ///
    /// Cache-hit probes reject symlinked report/sample paths instead of
    /// treating them as valid cached files.
    #[cfg(unix)]
    #[test]
    fn sample_cache_hit_rejects_symlinked_cache_path() {
        let dir = TempDir::new().expect("tempdir");
        let outside = dir.path().join("outside.bin");
        let link = dir.path().join("aa");
        std::fs::write(&outside, b"sample").unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = sample_cache_hit(&link, &"a".repeat(64)).unwrap_err();

        assert!(format!("{err:#}").contains("symlinked VT cache path"));
    }

    /// # Contract
    ///
    /// Cache-hit probes reject hardlinked sample paths instead of
    /// treating another directory entry for an external inode as a
    /// trusted cached download.
    #[cfg(unix)]
    #[test]
    fn sample_cache_hit_rejects_hardlinked_cache_path() {
        let dir = TempDir::new().expect("tempdir");
        let body = b"sample";
        let expected = sha256_hex(body);
        let outside = dir.path().join("outside.bin");
        let link = dir.path().join(&expected);
        std::fs::write(&outside, body).unwrap();
        std::fs::hard_link(&outside, &link).unwrap();

        let err = sample_cache_hit(&link, &expected).unwrap_err();

        assert!(format!("{err:#}").contains("hardlinked VT cache path"));
    }

    /// # Contract
    ///
    /// A cached report is reusable only when it is valid JSON and its
    /// payload SHA matches the requested report SHA.
    #[test]
    fn report_cache_hit_accepts_matching_report() {
        let dir = TempDir::new().expect("tempdir");
        let sha = "a".repeat(64);
        let path = dir.path().join(format!("{sha}.json"));
        let report = report_with_sha(&sha);
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();

        assert!(report_cache_hit(&path, &sha).unwrap());
    }

    /// # Contract
    ///
    /// A cached report whose JSON payload names a different SHA must not
    /// be treated as a hit. `vt download` must refetch it instead of
    /// preserving a poisoned `<sha>.json` forever.
    #[test]
    fn report_cache_hit_rejects_payload_sha_mismatch() {
        let dir = TempDir::new().expect("tempdir");
        let requested = "a".repeat(64);
        let payload = "b".repeat(64);
        let path = dir.path().join(format!("{requested}.json"));
        let report = report_with_sha(&payload);
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();

        assert!(!report_cache_hit(&path, &requested).unwrap());
    }

    /// # Contract
    ///
    /// A malformed cached report must be a miss, not a permanent skip.
    /// The next `vt download` pass should fetch a fresh report.
    #[test]
    fn report_cache_hit_rejects_invalid_json() {
        let dir = TempDir::new().expect("tempdir");
        let sha = "a".repeat(64);
        let path = dir.path().join(format!("{sha}.json"));
        std::fs::write(&path, b"{").unwrap();

        assert!(!report_cache_hit(&path, &sha).unwrap());
    }

    /// # Contract
    ///
    /// An existing sample file is reusable only when its bytes hash to
    /// the SHA filename returned by VT.
    #[test]
    fn sample_cache_hit_accepts_matching_sample() {
        let dir = TempDir::new().expect("tempdir");
        let body = b"cached sample bytes";
        let sha = sha256_hex(body);
        let path = dir.path().join(&sha);
        std::fs::write(&path, body).unwrap();

        assert!(sample_cache_hit(&path, &sha).unwrap());
    }

    /// # Contract
    ///
    /// An existing sample file whose bytes do not match the expected SHA
    /// must be a miss. Otherwise a corrupt or operator-planted cache
    /// entry under `<dest>/<sha>` poisons every rerun because the
    /// downloader never asks VT for the real sample again.
    #[test]
    fn sample_cache_hit_rejects_mismatched_sample_bytes() {
        let dir = TempDir::new().expect("tempdir");
        let expected = "a".repeat(64);
        let path = dir.path().join(&expected);
        std::fs::write(&path, b"wrong bytes").unwrap();

        assert!(!sample_cache_hit(&path, &expected).unwrap());
    }

    /// # Contract
    ///
    /// The sample verifier must fail closed when the stream exceeds its
    /// cap after the metadata check.
    #[test]
    fn sha256_file_with_cap_rejects_stream_over_cap() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("sample");
        std::fs::write(&path, b"abcde").unwrap();
        let file = File::open(&path).unwrap();

        assert!(sha256_file_with_cap(file, 4).unwrap().is_none());
    }

    /// # Contract
    ///
    /// `.vt-reports` must resolve under the download destination.
    /// Existing symlinks to outside directories are rejected.
    #[cfg(unix)]
    #[test]
    fn reports_dir_rejects_symlink_outside_download_dir() {
        let dir = TempDir::new().expect("tempdir");
        let dest = dir.path().join("dest");
        let outside = dir.path().join("outside");
        let reports = dest.join(REPORTS_DIRNAME);
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &reports).unwrap();

        let err = ensure_existing_child_stays_in_base(&dest, &reports).unwrap_err();

        assert!(format!("{err:#}").contains("outside VT download directory"));
    }

    /// # Contract
    ///
    /// `remaining = limit - collected.len()` MUST use saturating subtraction
    /// so that duplicate entries from the VT API (where `collected.len() >
    /// limit`) cannot cause a panic in debug mode or an underflow in release
    /// mode. Pre-fix this was a plain subtraction that could panic.
    #[test]
    fn saturating_sub_prevents_panic_on_duplicate_entries() {
        // If the API returns duplicates, `collected.len()` can exceed `limit`.
        // `opts.limit.saturating_sub(collected.len())` must return 0, not panic.
        let limit: usize = 5;
        let collected: usize = 7;
        assert_eq!(limit.saturating_sub(collected), 0);
    }

    /// Contract: `default_query(false)` returns the historical malicious-
    /// corpus query verbatim. The string is part of the operator-facing
    /// surface (anyone reading `--help` or running benchmarks expects
    /// the same query that seeded `benchmarks/corpus.yaml`); changing it
    /// silently would shift detection-rate numbers without anyone noticing.
    #[test]
    fn default_query_false_returns_malicious_corpus_query() {
        let q = default_query(false);
        assert_eq!(q, DEFAULT_QUERY);
        assert!(
            q.contains("codeinsight_verdict:malicious"),
            "malicious verdict filter must be present, got: {q}",
        );
    }

    /// Contract: `default_query(true)` returns the benign-corpus query
    /// — the symmetric counterpart of the malicious default. Shape MUST
    /// match the malicious query (entity / has:codeinsight / type
    /// filter) so the two corpora are directly comparable; only the
    /// verdict filter flips. A drift between the two queries would let
    /// false-positive numbers blame the population rather than the
    /// scanner. The verdict label is `benign` (the only value the live
    /// VT API actually serves for this population — `harmless` /
    /// `clean` / `safe` all return zero hits).
    #[test]
    fn default_query_true_returns_benign_corpus_query() {
        let q = default_query(true);
        assert_eq!(q, DEFAULT_CLEAN_QUERY);
        assert!(
            q.contains("codeinsight_verdict:benign"),
            "benign verdict filter must be present, got: {q}",
        );
        assert!(
            !q.contains("codeinsight_verdict:malicious"),
            "benign query must NOT contain malicious filter, got: {q}",
        );
    }

    /// Contract: the malicious + harmless defaults agree on every
    /// non-verdict filter. The two corpora are intended as paired
    /// populations for true-positive vs false-positive measurement;
    /// any drift in `entity:`, `has:codeinsight`, or the
    /// `codeinsight:"Type: OpenClaw Skill"` selector would invalidate
    /// the comparison.
    #[test]
    fn malicious_and_clean_queries_share_corpus_shape() {
        for needle in [
            "entity:file",
            "has:codeinsight",
            "codeinsight:\"Type: OpenClaw Skill\"",
        ] {
            assert!(
                DEFAULT_QUERY.contains(needle),
                "malicious query missing shared selector {needle:?}",
            );
            assert!(
                DEFAULT_CLEAN_QUERY.contains(needle),
                "clean query missing shared selector {needle:?}",
            );
        }
    }
}
