//! Wiring for the `skill-veil promptintel …` subcommand family.
//!
//! Mirrors `commands::vt`: build a client from the resolved
//! `PromptIntelConfig`, dispatch on the action, and surface a concise
//! summary back to the operator.

use crate::cli_args::{
    PromptIntelAction, PromptIntelCoverageArgs, PromptIntelCrossCheckArgs,
    PromptIntelCrossCheckFormat, PromptIntelDownloadArgs, PromptIntelFeedAction,
    PromptIntelFeedBudgetArgs, PromptIntelFeedListArgs, PromptIntelFeedSyncArgs,
    PromptIntelReportAction, PromptIntelReportListArgs, PromptIntelReportSubmitArgs,
};
use crate::promptintel::client::PromptIntelClient;
use crate::promptintel::config::PromptIntelConfig;
use crate::promptintel::corpus::{self, DownloadOptions};
use crate::promptintel::coverage::{self, CoverageOptions};
use crate::promptintel::cross_check::{self, CrossCheckOptions};
use crate::promptintel::feed::{
    ratelimit::RateLimitState,
    store::FeedStore,
    sync::{self as feed_sync, SyncMode},
};
use crate::promptintel::types::ReportDraft;
use crate::util::terminal_safe::sanitise_for_terminal;
use anyhow::{Context, Result};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAX_PROMPTINTEL_REPORT_DRAFT_BYTES: u64 = 1024 * 1024;

/// Returns `Ok(true)` when the action ran successfully but a CI gate
/// (e.g. `cross-check --fail-below`) was tripped, `Ok(false)` otherwise.
/// `main` maps `Ok(true)` to `EXIT_FINDINGS_OVER_THRESHOLD` so callers
/// can distinguish "regressed below threshold" from "crashed".
pub(crate) fn run_promptintel(action: PromptIntelAction) -> Result<bool> {
    match action {
        PromptIntelAction::Download(args) => run_download(args).map(|()| false),
        PromptIntelAction::CrossCheck(args) => run_cross_check(args),
        PromptIntelAction::Feed(action) => run_feed(action).map(|()| false),
        PromptIntelAction::Report(action) => run_report(action).map(|()| false),
        PromptIntelAction::Coverage(args) => run_coverage(args).map(|()| false),
    }
}

fn run_coverage(args: PromptIntelCoverageArgs) -> Result<()> {
    let opts = CoverageOptions {
        rules_dir: args.rules_dir,
    };
    let report = coverage::build_report(&opts).context("building coverage report")?;
    match args.format {
        PromptIntelCrossCheckFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        PromptIntelCrossCheckFormat::Text => {
            print!("{}", coverage::render_text(&report));
        }
    }
    Ok(())
}

fn run_feed(action: PromptIntelFeedAction) -> Result<()> {
    match action {
        PromptIntelFeedAction::Sync(args) => run_feed_sync(args),
        PromptIntelFeedAction::List(args) => run_feed_list(args),
        PromptIntelFeedAction::Budget(args) => run_feed_budget(args),
    }
}

fn run_feed_sync(args: PromptIntelFeedSyncArgs) -> Result<()> {
    let cache_root = resolve_cache_root(args.cache_dir)?;
    let client = build_client()?;
    let mode = if args.full {
        SyncMode::Full
    } else {
        SyncMode::Incremental
    };
    let summary = feed_sync::run_sync(&client, &cache_root, mode)
        .with_context(|| format!("syncing PromptIntel feed into {}", cache_root.display()))?;
    let mode_label = match summary.mode {
        feed_sync::ResolvedSyncMode::Full => "full",
        feed_sync::ResolvedSyncMode::Incremental => "incremental",
        feed_sync::ResolvedSyncMode::IncrementalUpgradedToFull => {
            "incremental → upgraded to full (no prior cache)"
        }
    };
    println!(
        "PromptIntel feed sync complete ({mode}): pulled={pulled} merged={merged} previous={prev}\nCache: {cache}",
        mode = mode_label,
        pulled = summary.pulled,
        merged = summary.new_total,
        prev = summary.previous_total,
        cache = terminal_path(&cache_root.join("promptintel-feed")),
    );
    Ok(())
}

fn run_feed_budget(args: PromptIntelFeedBudgetArgs) -> Result<()> {
    let cache_root = resolve_cache_root(args.cache_dir)?;
    let state = RateLimitState::load(&cache_root).with_context(|| {
        format!(
            "loading PromptIntel rate-limit state from {}",
            cache_root.display()
        )
    })?;
    println!("{}", state.render_summary());
    Ok(())
}

fn run_report(action: PromptIntelReportAction) -> Result<()> {
    match action {
        PromptIntelReportAction::Submit(args) => run_report_submit(args),
        PromptIntelReportAction::List(args) => run_report_list(args),
    }
}

fn run_report_submit(args: PromptIntelReportSubmitArgs) -> Result<()> {
    let cache_root = resolve_cache_root(args.cache_dir.clone())?;

    let draft = read_report_draft(&args.file)?;

    let validation = draft.validate();
    if !validation.is_empty() {
        for err in &validation {
            eprintln!("  - {err}");
        }
        anyhow::bail!(
            "report draft has {} client-side validation error(s); fix and retry",
            validation.len()
        );
    }

    let body = serde_json::to_string_pretty(&draft).context("serialising report draft")?;
    if args.dry_run {
        println!("{body}");
        eprintln!("\n--dry-run: not sent to api.promptintel.novahunting.ai");
        return Ok(());
    }

    let mut rate_state = RateLimitState::load(&cache_root)?;
    rate_state
        .check_can_call(crate::promptintel::feed::ratelimit::endpoint::REPORTS_SUBMIT)
        .map_err(|e| anyhow::anyhow!(e))?;

    let client = build_client()?;
    let (response, response_meta) = client
        .submit_report(&body)
        .context("submitting report to api.promptintel.novahunting.ai")?;

    rate_state.record_call(
        crate::promptintel::feed::ratelimit::endpoint::REPORTS_SUBMIT,
        response_meta.ratelimit_remaining,
    );
    rate_state.save(&cache_root)?;

    if !response.success {
        anyhow::bail!(
            "PromptIntel reported success=false. Response body: {}",
            serde_json::to_string(&response.extra).unwrap_or_default()
        );
    }
    println!(
        "Report submitted: id={}",
        response
            .id
            .as_deref()
            .map(terminal_field)
            .unwrap_or_else(|| "(server returned no id)".to_string())
    );
    Ok(())
}

fn run_report_list(args: PromptIntelReportListArgs) -> Result<()> {
    let cache_root = resolve_cache_root(args.cache_dir.clone())?;
    let mut rate_state = RateLimitState::load(&cache_root)?;
    rate_state
        .check_can_call(crate::promptintel::feed::ratelimit::endpoint::REPORTS_MINE)
        .map_err(|e| anyhow::anyhow!(e))?;

    let client = build_client()?;
    let (envelope, response_meta) = client
        .list_my_reports(args.limit.max(1), args.offset)
        .context("fetching agents/reports/mine")?;

    rate_state.record_call(
        crate::promptintel::feed::ratelimit::endpoint::REPORTS_MINE,
        response_meta.ratelimit_remaining,
    );
    rate_state.save(&cache_root)?;

    match args.format {
        PromptIntelCrossCheckFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&envelope.data)?);
        }
        PromptIntelCrossCheckFormat::Text => {
            let total = envelope.pagination.as_ref().map(|p| p.total).unwrap_or(0);
            println!(
                "=== Reports submitted by this agent ({} returned, {} total) ===",
                envelope.data.len(),
                total
            );
            for entry in &envelope.data {
                println!(
                    "[{sev:<8}] {action:<16} {id}  {title}",
                    sev = entry.severity.as_str(),
                    action = format!("{:?}", entry.action).to_lowercase(),
                    id = terminal_field(&entry.id),
                    title = terminal_snippet(&entry.title, 70),
                );
            }
        }
    }
    Ok(())
}

fn run_feed_list(args: PromptIntelFeedListArgs) -> Result<()> {
    let cache_root = resolve_cache_root(args.cache_dir)?;
    let store = FeedStore::load(&cache_root).with_context(|| {
        format!(
            "loading PromptIntel feed cache from {}",
            cache_root.display()
        )
    })?;
    if store.entries.is_empty() {
        println!(
            "PromptIntel feed cache is empty at {}. Run `skill-veil promptintel feed sync` first.",
            terminal_path(&cache_root.join("promptintel-feed"))
        );
        return Ok(());
    }
    match args.format {
        PromptIntelCrossCheckFormat::Json => {
            let body =
                serde_json::to_string_pretty(&store.entries).context("serialising feed entries")?;
            println!("{body}");
        }
        PromptIntelCrossCheckFormat::Text => {
            println!(
                "=== PromptIntel feed cache ({} entries) ===",
                store.entries.len()
            );
            for entry in store.active_entries() {
                println!(
                    "[{sev:<8}] {action:<16} {id}  {title}",
                    sev = entry.severity.as_str(),
                    action = format!("{:?}", entry.action).to_lowercase(),
                    id = terminal_field(&entry.id),
                    title = terminal_snippet(&entry.title, 70),
                );
            }
        }
    }
    Ok(())
}

/// Resolve the on-disk cache root for the PromptIntel feed. Prefers
/// the explicit `--cache-dir` override, then `dirs::cache_dir()`.
fn resolve_cache_root(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    resolve_cache_root_from(override_dir, dirs::cache_dir())
}

fn resolve_cache_root_from(
    override_dir: Option<PathBuf>,
    user_cache: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(dir);
    }
    user_cache
        .map(|d| d.join("skill-veil"))
        .ok_or_else(|| anyhow::anyhow!("could not determine cache directory; pass --cache-dir"))
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
            eprintln!("wrote PromptIntel cross-check to {}", terminal_path(&path));
            eprintln!("{}", cross_check::render_text(&summary));
        }
        None => println!("{rendered}"),
    }
    let detection_gate_tripped = detection_below_gate(&summary, args.fail_below);
    let strict_drift_gate_tripped = args.strict_taxonomy && !summary.taxonomy_drift.is_empty();
    if strict_drift_gate_tripped {
        eprintln!(
            "PromptIntel --strict-taxonomy: {} drift name(s) not in taxonomy::TAXONOMY",
            summary.taxonomy_drift.len()
        );
    }
    Ok(detection_gate_tripped || strict_drift_gate_tripped)
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

fn read_report_draft(path: &Path) -> Result<ReportDraft> {
    read_report_draft_with_cap(path, MAX_PROMPTINTEL_REPORT_DRAFT_BYTES)
}

fn read_report_draft_with_cap(path: &Path, cap: u64) -> Result<ReportDraft> {
    let raw = read_to_string_with_cap(path, cap)
        .with_context(|| format!("reading report draft {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parsing report draft as JSON: {}", path.display()))
}

fn read_to_string_with_cap(path: &Path, cap: u64) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if meta.len() > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size {} exceeds limit {}",
                path.display(),
                meta.len(),
                cap
            ),
        ));
    }

    let mut bytes = Vec::with_capacity(usize::try_from(meta.len().min(cap)).unwrap_or(0));
    let mut limited = file.take(cap.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size exceeds limit {}",
                path.display(),
                cap
            ),
        ));
    }
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn terminal_field(value: &str) -> String {
    sanitise_for_terminal(value)
}

fn terminal_path(path: &Path) -> String {
    terminal_field(&path.display().to_string())
}

fn terminal_snippet(value: &str, max_chars: usize) -> String {
    let truncated = value.chars().take(max_chars).collect::<String>();
    sanitise_for_terminal(&truncated)
}

#[cfg(test)]
mod tests {
    use super::{
        detection_below_gate, read_report_draft_with_cap, resolve_cache_root_from, terminal_field,
        terminal_path, terminal_snippet,
    };
    use crate::promptintel::cross_check::CrossCheckSummary;
    use std::path::PathBuf;
    use tempfile::TempDir;

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

    #[test]
    fn resolve_cache_root_rejects_missing_user_cache_without_override() {
        let err = resolve_cache_root_from(None, None)
            .expect_err("missing cache dir without override must fail");

        assert!(format!("{err:#}").contains("pass --cache-dir"));
    }

    #[test]
    fn resolve_cache_root_accepts_override_without_user_cache() {
        let override_dir = PathBuf::from("/tmp/promptintel-cache");
        let resolved = resolve_cache_root_from(Some(override_dir.clone()), None).unwrap();

        assert_eq!(resolved, override_dir);
    }

    #[test]
    fn terminal_field_removes_promptintel_control_sequences() {
        let cleaned = terminal_field("id-\x1b]8;;https://evil.invalid\x07click");

        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
    }

    #[test]
    fn terminal_path_removes_promptintel_status_control_sequences() {
        let path = PathBuf::from("cache\x1b[2J");
        let cleaned = terminal_path(&path);

        assert!(!cleaned.contains('\x1b'));
        assert!(cleaned.contains("cache?[2J"));
    }

    #[test]
    fn terminal_snippet_removes_layout_controls_after_truncation() {
        let cleaned = terminal_snippet("title\x1b[2J\nfake verdict", 16);

        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\n'));
        assert!(cleaned.contains("title?[2J?"));
    }

    /// # Contract
    ///
    /// A valid PromptIntel report draft under the byte cap MUST parse
    /// normally. The cap is a memory guard, not a schema change.
    #[test]
    fn report_draft_read_accepts_valid_json_under_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("draft.json");
        std::fs::write(
            &path,
            r#"{
                "category": "prompt",
                "severity": "low",
                "confidence": 0.8,
                "fingerprint": "fp-1",
                "title": "Valid draft"
            }"#,
        )
        .unwrap();

        let draft = read_report_draft_with_cap(&path, 1024).unwrap();

        assert_eq!(draft.fingerprint, "fp-1");
        assert_eq!(draft.title, "Valid draft");
    }

    /// # Contract
    ///
    /// PromptIntel report draft reads MUST reject files over the
    /// configured cap before JSON parsing, so a local draft path cannot
    /// force an unbounded allocation.
    #[test]
    fn report_draft_read_rejects_oversized_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("draft.json");
        std::fs::write(&path, vec![b'{'; 32]).unwrap();

        let err = read_report_draft_with_cap(&path, 8).unwrap_err();

        assert!(format!("{err:#}").contains("exceeds limit"));
    }
}
