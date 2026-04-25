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
    std::fs::create_dir_all(&opts.dest)
        .with_context(|| format!("creating {}", opts.dest.display()))?;
    let reports_dir = opts.dest.join(REPORTS_DIRNAME);
    std::fs::create_dir_all(&reports_dir)
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
        let json = serde_json::to_string_pretty(&cached).context("serialising report")?;
        std::fs::write(&report_path, json)
            .with_context(|| format!("writing {}", report_path.display()))?;
        summary.reports_written += 1;
    }

    if opts.report_only {
        return Ok(());
    }

    let file_path = opts.dest.join(sha);
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
