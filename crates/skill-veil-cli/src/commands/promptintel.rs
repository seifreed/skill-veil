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

/// Returns `Ok(true)` when the action ran successfully but a CI gate
/// (e.g. `cross-check --fail-below`) was tripped, `Ok(false)` otherwise.
/// `main` maps `Ok(true)` to `EXIT_FINDINGS_OVER_THRESHOLD` so callers
/// can distinguish "regressed below threshold" from "crashed".
pub(crate) fn run_promptintel(action: PromptIntelAction) -> Result<bool> {
    match action {
        PromptIntelAction::Download(args) => run_download(args).map(|()| false),
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

fn run_cross_check(args: PromptIntelCrossCheckArgs) -> Result<bool> {
    let opts = CrossCheckOptions {
        corpus_dir: args.dir.clone(),
        only_misses: args.only_misses,
        rules_dir: None,
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
    Ok(detection_below_gate(&summary, args.fail_below))
}

/// # Contract
/// - `total - errors == 0` never trips: empty/all-errored corpora
///   are already surfaced via `summary.errors`; a doubled CI failure
///   would mask the real "bad path" diagnostic.
/// - Errored prompts are excluded from the denominator:
///   `detected / (total - errors) < threshold`.
/// - Boundary is strict-less-than: `rate == threshold` passes.
///   Matches `scan-package --fail-on`.
fn detection_below_gate(summary: &cross_check::CrossCheckSummary, threshold: Option<f64>) -> bool {
    let Some(threshold) = threshold else {
        return false;
    };
    let denom = summary.total.saturating_sub(summary.errors);
    if denom == 0 {
        return false;
    }
    #[allow(clippy::cast_precision_loss)]
    let rate = (summary.detected as f64) / (denom as f64);
    rate < threshold
}

fn build_client() -> Result<PromptIntelClient> {
    let config = PromptIntelConfig::load()?;
    Ok(PromptIntelClient::new(config))
}

#[cfg(test)]
mod tests {
    use super::detection_below_gate;
    use crate::promptintel::cross_check::CrossCheckSummary;

    fn summary(total: usize, detected: usize, errors: usize) -> CrossCheckSummary {
        CrossCheckSummary {
            total,
            detected,
            missed: total.saturating_sub(detected).saturating_sub(errors),
            errors,
            ..CrossCheckSummary::default()
        }
    }

    #[test]
    fn no_threshold_never_trips() {
        assert!(!detection_below_gate(&summary(50, 0, 0), None));
        assert!(!detection_below_gate(&summary(50, 50, 0), None));
    }

    #[test]
    fn empty_corpus_passes_any_threshold() {
        assert!(!detection_below_gate(&summary(0, 0, 0), Some(0.95)));
        assert!(!detection_below_gate(&summary(0, 0, 0), Some(1.0)));
    }

    #[test]
    fn all_errors_do_not_trip() {
        assert!(!detection_below_gate(&summary(10, 0, 10), Some(0.95)));
    }

    /// 48 detected of 50, with 2 errors → 48/(50-2) = 100%; passes
    /// `--fail-below 0.95` because errors are excluded from the
    /// denominator.
    #[test]
    fn errors_excluded_from_denominator() {
        assert!(!detection_below_gate(&summary(50, 48, 2), Some(0.95)));
    }

    /// `48/50 == 0.96` does NOT trip `--fail-below 0.96`.
    #[test]
    fn boundary_equal_passes() {
        assert!(!detection_below_gate(&summary(50, 48, 0), Some(0.96)));
    }

    /// `47/50 == 0.94 < 0.95` trips.
    #[test]
    fn below_threshold_trips() {
        assert!(detection_below_gate(&summary(50, 47, 0), Some(0.95)));
    }

    #[test]
    fn zero_detections_trips() {
        assert!(detection_below_gate(&summary(50, 0, 0), Some(0.01)));
    }
}
