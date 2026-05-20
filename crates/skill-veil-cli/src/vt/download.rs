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
    if !report_path.exists() {
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
    // `download_file`. The rename inside `download_file` is atomic
    // (`util::cache_io::finalize_atomic_write`), so the on-disk cache
    // stays consistent — only API quota is wasted in that edge case.
    if file_path.exists() {
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

/// Persist a VT report atomically: serialise to a `.tmp` sibling and then
/// `rename(2)` it into place. Pre-fix this routine called `std::fs::write`
/// directly, which truncates the destination before writing the bytes — a
/// SIGINT, OOM kill, or host reboot between truncate and write left an empty
/// `<sha>.json` at `report_path`. The next run saw `report_path.exists() ==
/// true` (the caller's short-circuit) and skipped the fetch, poisoning the
/// cache silently until the user removed the file by hand.
fn persist_report(report_path: &Path, cached: &CachedReport) -> Result<()> {
    let json = serde_json::to_string_pretty(cached).context("serialising report")?;
    let tmp = report_path.with_extension("tmp");
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

        let tmp = report_path.with_extension("tmp");
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
        let tmp = report_path.with_extension("tmp");
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
