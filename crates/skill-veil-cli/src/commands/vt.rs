//! Wiring for the `skill-veil vt …` subcommand family.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::cli_args::{
    VtAction, VtCrossCheckArgs, VtCrossCheckFormat, VtDownloadArgs, VtReportArgs,
};
use crate::util::output_file::write_output_file_atomic;
use crate::util::terminal_safe::{sanitise_for_terminal, terminal_path};
use crate::vt::client::VtClient;
use crate::vt::config::VtConfig;
use crate::vt::cross_check::{self, CrossCheckOptions};
use crate::vt::download::{self, DownloadOptions};
use crate::vt::types::CachedReport;

pub(crate) fn run_vt(action: VtAction) -> Result<()> {
    match action {
        VtAction::Download(args) => run_download(args),
        VtAction::Report(args) => run_report(args),
        VtAction::CrossCheck(args) => run_cross_check(args),
    }
}

fn run_download(args: VtDownloadArgs) -> Result<()> {
    let client = build_client()?;
    // `--query` and `--clean` are mutually exclusive at the clap layer
    // (`conflicts_with`), so this branch is exhaustive: explicit query
    // wins, else `default_query(clean)` picks the historical malicious
    // default or the harmless mirror used for false-positive sweeps.
    let resolved_query = args
        .query
        .clone()
        .unwrap_or_else(|| download::default_query(args.clean).to_string());
    let opts = DownloadOptions {
        query: resolved_query,
        dest: args.dest,
        limit: args.limit.get(),
        report_only: args.report_only,
        rate_limit_ms: args.rate_limit_ms,
    };
    let summary = download::run_download(&client, opts)?;
    println!(
        "VT download complete: discovered={} downloaded={} skipped={} reports_written={} errors={}",
        summary.total_discovered,
        summary.files_downloaded,
        summary.files_skipped,
        summary.reports_written,
        summary.errors,
    );
    Ok(())
}

fn run_report(args: VtReportArgs) -> Result<()> {
    let client = build_client()?;
    // Route through `lookup_file_report` (Ok(None) on HTTP 404) rather
    // than `get_file_report` (errors on 404). A user looking up a
    // legitimate-but-not-yet-published hash should see a clean
    // "not found" message and exit 0, not a confusing
    // `HttpStatus { status: 404 }` error and exit 2.
    let envelope = match client
        .lookup_file_report(&args.sha256)
        .with_context(|| format!("fetching VT report for {}", args.sha256))?
    {
        Some(envelope) => envelope,
        None => {
            eprintln!(
                "VT has no report for {} (404 — file unknown to VirusTotal)",
                sanitise_for_terminal(&args.sha256)
            );
            return Ok(());
        }
    };
    let cached = CachedReport {
        sha256: envelope.data.id.clone(),
        fetched_at: chrono::Utc::now().to_rfc3339(),
        attributes: envelope.data.attributes,
    };
    let json = serde_json::to_string_pretty(&cached)?;
    match args.output {
        Some(path) => {
            write_output_file_atomic(&path, json.as_bytes())
                .with_context(|| format!("writing {}", path.display()))?;
            // Status to stderr so stdout stays clean for piped consumers.
            eprintln!("wrote VT report to {}", terminal_path(&path));
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn run_cross_check(args: VtCrossCheckArgs) -> Result<()> {
    // `vt download` writes raw files to `<dir>/<sha>` and VT reports to
    // `<dir>/.vt-reports/`, while the scanner materialises extracted
    // package roots (each containing `SKILL.md`) under
    // `<dir>/.skill-veil-cache/extracted/<sha>/`. The dataset walker
    // skips dot-directories, so pointing it at `<dir>` finds none of
    // the extracted corpus (the documented `vt cross-check --dir data`
    // returned `total=0/handful`). Scan the extraction cache when it
    // exists; keep `dataset_dir = <dir>` so report resolution
    // (`<dir>/.vt-reports`) and the `<sha>/` package-id → SHA lookup
    // are unaffected.
    let scan_root = cross_check_scan_root(&args.dir);
    let scan_results = crate::dataset::scan_dataset_to_results(
        &scan_root,
        crate::dataset::default_dataset_scan_options(),
    )
    .with_context(|| format!("scanning {}", scan_root.display()))?;
    let opts = CrossCheckOptions {
        dataset_dir: args.dir.clone(),
        only_mismatches: args.only_mismatches,
    };
    let summary = cross_check::build_summary(&scan_results, &opts)?;
    let rendered = match args.format {
        VtCrossCheckFormat::Text => cross_check::render_text(&summary),
        VtCrossCheckFormat::Markdown => cross_check::render_markdown(&summary),
        VtCrossCheckFormat::Json => serde_json::to_string_pretty(&summary)?,
        VtCrossCheckFormat::Baseline => cross_check::render_baseline(&summary),
    };
    match args.output {
        Some(path) => {
            write_output_file_atomic(&path, rendered.as_bytes())
                .with_context(|| format!("writing {}", path.display()))?;
            // Status + summary go to STDERR so STDOUT stays empty when
            // `--output` is set. Pre-fix this `println!` wrote the text
            // summary to STDOUT regardless of the user's chosen
            // `--format`, so a pipeline running
            //   `skill-veil vt cross-check --format json --output out.json`
            // and reading STDOUT (expecting JSON) instead received the
            // text summary, breaking any JSON-parser-based consumer.
            eprintln!("wrote cross-check to {}", terminal_path(&path));
            eprintln!("{}", cross_check::render_text(&summary));
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

fn cross_check_scan_root(dataset_dir: &Path) -> PathBuf {
    let extracted_root = dataset_dir.join(".skill-veil-cache").join("extracted");
    if is_real_dir(&extracted_root) {
        extracted_root
    } else {
        dataset_dir.to_path_buf()
    }
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.is_dir() && !meta.is_symlink())
        .unwrap_or(false)
}

fn build_client() -> Result<VtClient> {
    let config = VtConfig::load()?;
    Ok(VtClient::new(config))
}

#[cfg(test)]
mod tests {
    use super::cross_check_scan_root;

    /// # Contract
    ///
    /// `vt cross-check` should scan the extracted corpus cache when it
    /// is a real directory, preserving the documented `vt download` flow.
    #[test]
    fn cross_check_scan_root_uses_real_extracted_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let extracted = tmp.path().join(".skill-veil-cache").join("extracted");
        std::fs::create_dir_all(&extracted).unwrap();

        let root = cross_check_scan_root(tmp.path());

        assert_eq!(root, extracted);
    }

    /// # Contract
    ///
    /// A symlinked extracted-cache path MUST be ignored. Otherwise an
    /// untrusted dataset can redirect `vt cross-check` to scan an
    /// attacker-chosen directory outside the dataset root.
    #[cfg(unix)]
    #[test]
    fn cross_check_scan_root_rejects_symlinked_extracted_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_parent = tmp.path().join(".skill-veil-cache");
        let outside = tmp.path().join("outside");
        let extracted = cache_parent.join("extracted");
        std::fs::create_dir_all(&cache_parent).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &extracted).unwrap();

        let root = cross_check_scan_root(tmp.path());

        assert_eq!(root, tmp.path());
    }
}
