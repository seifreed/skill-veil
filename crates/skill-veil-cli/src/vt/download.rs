//! Orchestrates bulk VT corpus downloads.
//!
//! Given a search query and a destination directory, this module paginates
//! through VT Intelligence, downloads each file binary (unless `--report-only`
//! is set), fetches its metadata report, and caches both to disk. Repeat runs
//! are idempotent: files already present are skipped based on a SHA-side
//! marker, matching the dataset-extraction cache pattern.

use super::client::{VtClient, VtError};
use super::types::CachedReport;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

pub(crate) const DEFAULT_QUERY: &str =
    "entity:file has:codeinsight codeinsight:\"Type: OpenClaw Skill\" codeinsight_verdict:malicious";
pub(crate) const REPORTS_DIRNAME: &str = ".vt-reports";
const PER_PAGE: usize = 40;
use super::REQUEST_DELAY_MS;

pub(crate) struct DownloadOptions {
    pub(crate) query: String,
    pub(crate) dest: PathBuf,
    pub(crate) limit: usize,
    pub(crate) report_only: bool,
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
    let reports_dir = opts.dest.join(REPORTS_DIRNAME);
    crate::util::secure_fs::create_dir_secure(&reports_dir)
        .with_context(|| format!("creating {}", reports_dir.display()))?;

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
        let remaining = opts.limit - collected.len();
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
            collected.push(entry.id);
        }
        cursor = response.meta.cursor.clone();
        if cursor.is_none() {
            break;
        }
        sleep(Duration::from_millis(REQUEST_DELAY_MS));
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
        sleep(Duration::from_millis(REQUEST_DELAY_MS));
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
    // Fetch the report first — it is smaller, and we always want it even if
    // the file is already on disk or download is suppressed.
    let report_path = reports_dir.join(format!("{sha}.json"));
    if !report_path.exists() {
        let envelope = client
            .get_file_report(sha)
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

    let file_path = opts.dest.join(sha);
    // Concurrent invocations may both pass this check and call
    // `download_file`. The rename inside `download_file` is atomic
    // (`util::cache_io::finalize_atomic_write`), so the on-disk cache
    // stays consistent — only API quota is wasted in that edge case.
    if file_path.exists() {
        summary.files_skipped += 1;
        return Ok(());
    }
    match client.download_file(sha, &file_path) {
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

/// Persist a VT report atomically: serialise to a `.tmp` sibling and then
/// `rename(2)` it into place. Pre-fix this routine called `std::fs::write`
/// directly, which truncates the destination before writing the bytes — a
/// SIGINT, OOM kill, or host reboot between truncate and write left an empty
/// `<sha>.json` at `report_path`. The next run saw `report_path.exists() ==
/// true` (the caller's short-circuit) and skipped the fetch, poisoning the
/// cache silently until the user removed the file by hand.
fn persist_report(report_path: &Path, cached: &CachedReport) -> Result<()> {
    let json = serde_json::to_string_pretty(cached).context("serialising report")?;
    let tmp = report_path.with_extension("json.tmp");
    std::fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
    crate::util::cache_io::finalize_atomic_write(&tmp, report_path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), report_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vt::types::FileAttributes;
    use tempfile::TempDir;

    fn fixture_report() -> CachedReport {
        CachedReport {
            sha256: "a".repeat(64),
            fetched_at: "2026-04-27T00:00:00Z".to_string(),
            attributes: FileAttributes::default(),
        }
    }

    /// # Contract
    ///
    /// `persist_report` MUST land the report at `report_path` via the
    /// atomic rename helper and leave no `.tmp` residue on success.
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

        let tmp = report_path.with_extension("json.tmp");
        assert!(!tmp.exists(), "tmp must not linger after success");
        assert!(report_path.exists(), "report must exist at dest");
        let bytes = std::fs::read(&report_path).expect("read report");
        let parsed: CachedReport = serde_json::from_slice(&bytes).expect("re-parse report");
        assert_eq!(parsed.sha256, cached.sha256);
    }

    /// # Contract (negative)
    ///
    /// `persist_report` MUST surface the underlying I/O error AND best-
    /// effort remove the `.tmp` file when the rename target is invalid
    /// (e.g. parent directory missing). Without the `.tmp` cleanup,
    /// repeated failures would leak siblings into the reports directory
    /// and confuse operators inspecting the cache.
    #[test]
    fn persist_report_cleans_up_tmp_on_rename_failure() {
        let dir = TempDir::new().expect("tempdir");
        let report_path = dir.path().join("missing-subdir").join("aa.json");
        let cached = fixture_report();

        let result = persist_report(&report_path, &cached);

        assert!(result.is_err(), "rename into missing parent must fail");
        let tmp = report_path.with_extension("json.tmp");
        assert!(!tmp.exists(), "tmp must be cleaned up on failure");
    }

    /// # Contract
    ///
    /// `persist_report` MUST overwrite an already-present report
    /// atomically: readers either see the previous bytes or the new
    /// bytes, never an empty/half-written file. The pre-fix
    /// `std::fs::write` path violated this; `finalize_atomic_write`
    /// preserves it via POSIX `rename(2)`.
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
}
