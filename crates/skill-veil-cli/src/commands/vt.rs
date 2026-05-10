//! Wiring for the `skill-veil vt …` subcommand family.

use crate::cli_args::{
    VtAction, VtCrossCheckArgs, VtCrossCheckFormat, VtDownloadArgs, VtReportArgs,
};
use crate::vt::client::VtClient;
use crate::vt::config::VtConfig;
use crate::vt::cross_check::{self, CrossCheckOptions};
use crate::vt::download::{self, DownloadOptions};
use crate::vt::types::CachedReport;
use anyhow::{Context, Result};

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
                args.sha256
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
            std::fs::write(&path, &json).with_context(|| format!("writing {}", path.display()))?;
            // Status to stderr so stdout stays clean for piped consumers.
            eprintln!("wrote VT report to {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn run_cross_check(args: VtCrossCheckArgs) -> Result<()> {
    let scan_results = crate::dataset::scan_dataset_to_results(
        &args.dir,
        crate::dataset::default_dataset_scan_options(),
    )
    .with_context(|| format!("scanning {}", args.dir.display()))?;
    let opts = CrossCheckOptions {
        dataset_dir: args.dir.clone(),
        only_mismatches: args.only_mismatches,
    };
    let summary = cross_check::build_summary(&scan_results, &opts)?;
    let rendered = match args.format {
        VtCrossCheckFormat::Text => cross_check::render_text(&summary),
        VtCrossCheckFormat::Markdown => cross_check::render_markdown(&summary),
        VtCrossCheckFormat::Json => serde_json::to_string_pretty(&summary)?,
    };
    match args.output {
        Some(path) => {
            std::fs::write(&path, &rendered)
                .with_context(|| format!("writing {}", path.display()))?;
            // Status + summary go to STDERR so STDOUT stays empty when
            // `--output` is set. Pre-fix this `println!` wrote the text
            // summary to STDOUT regardless of the user's chosen
            // `--format`, so a pipeline running
            //   `skill-veil vt cross-check --format json --output out.json`
            // and reading STDOUT (expecting JSON) instead received the
            // text summary, breaking any JSON-parser-based consumer.
            eprintln!("wrote cross-check to {}", path.display());
            eprintln!("{}", cross_check::render_text(&summary));
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

fn build_client() -> Result<VtClient> {
    let config = VtConfig::load()?;
    Ok(VtClient::new(config))
}
