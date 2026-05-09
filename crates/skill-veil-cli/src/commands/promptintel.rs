//! Wiring for the `skill-veil promptintel …` subcommand family.
//!
//! Mirrors `commands::vt`: build a client from the resolved
//! `PromptIntelConfig`, dispatch on the action, and surface a concise
//! summary back to the operator.

use crate::cli_args::{
    PromptIntelAction, PromptIntelCrossCheckArgs, PromptIntelCrossCheckFormat,
    PromptIntelDownloadArgs,
};
use crate::promptintel::client::PromptIntelClient;
use crate::promptintel::config::PromptIntelConfig;
use crate::promptintel::corpus::{self, DownloadOptions};
use crate::promptintel::cross_check::{self, CrossCheckOptions};
use anyhow::{Context, Result};

pub(crate) fn run_promptintel(action: PromptIntelAction) -> Result<()> {
    match action {
        PromptIntelAction::Download(args) => run_download(args),
        PromptIntelAction::CrossCheck(args) => run_cross_check(args),
    }
}

fn run_download(args: PromptIntelDownloadArgs) -> Result<()> {
    let client = build_client()?;
    let opts = DownloadOptions {
        dest: args.dest,
        page_size: args.page_size,
        rate_limit_ms: args.rate_limit_ms,
        limit: args.limit.map(std::num::NonZeroUsize::get),
    };
    let summary = corpus::run_download(&client, opts)?;
    println!(
        "PromptIntel download complete: discovered={} written={} skipped={} errors={}",
        summary.total_discovered, summary.prompts_written, summary.prompts_skipped, summary.errors,
    );
    Ok(())
}

fn run_cross_check(args: PromptIntelCrossCheckArgs) -> Result<()> {
    let opts = CrossCheckOptions {
        corpus_dir: args.dir.clone(),
        only_misses: args.only_misses,
    };
    let summary = cross_check::build_summary(&opts)
        .with_context(|| format!("cross-check against {}", args.dir.display()))?;
    let rendered = match args.format {
        PromptIntelCrossCheckFormat::Text => cross_check::render_text(&summary),
        PromptIntelCrossCheckFormat::Json => serde_json::to_string_pretty(&summary)?,
    };
    match args.output {
        Some(path) => {
            std::fs::write(&path, &rendered)
                .with_context(|| format!("writing {}", path.display()))?;
            // Status to stderr so stdout stays empty when `--output` is
            // set — mirrors `vt cross-check` so pipelines that consume
            // JSON via stdout don't get a stray text summary.
            eprintln!("wrote PromptIntel cross-check to {}", path.display());
            eprintln!("{}", cross_check::render_text(&summary));
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

fn build_client() -> Result<PromptIntelClient> {
    let config = PromptIntelConfig::load()?;
    Ok(PromptIntelClient::new(config))
}
