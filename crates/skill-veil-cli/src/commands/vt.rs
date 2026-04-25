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
    let opts = DownloadOptions {
        query: args
            .query
            .unwrap_or_else(|| download::DEFAULT_QUERY.to_string()),
        dest: args.dest,
        limit: args.limit,
        report_only: args.report_only,
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
    let envelope = client
        .get_file_report(&args.sha256)
        .with_context(|| format!("fetching VT report for {}", args.sha256))?;
    let cached = CachedReport {
        sha256: envelope.data.id.clone(),
        fetched_at: chrono::Utc::now().to_rfc3339(),
        attributes: envelope.data.attributes,
    };
    let json = serde_json::to_string_pretty(&cached)?;
    match args.output {
        Some(path) => {
            std::fs::write(&path, &json).with_context(|| format!("writing {}", path.display()))?;
            println!("wrote VT report to {}", path.display());
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
            eprintln!("wrote cross-check to {}", path.display());
            // Always also print the one-line summary for quick feedback.
            println!("{}", cross_check::render_text(&summary));
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

fn build_client() -> Result<VtClient> {
    let config = VtConfig::load()?;
    Ok(VtClient::new(config))
}
