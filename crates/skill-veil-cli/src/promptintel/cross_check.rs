//! Cross-check skill-veil's verdicts against the curated PromptIntel
//! corpus.
//!
//! For each prompt in `_index.json`, run the local scanner over the
//! corresponding markdown file. A `Benign` verdict counts as "missed"
//! (skill-veil failed to flag a curated malicious prompt); anything
//! else counts as "detected". The summary aggregates counts by
//! severity, category, and threat so the operator can target rule
//! authoring at the highest-leverage gaps.

use super::corpus::IndexEntry;
use super::types::PromptSeverity;
use anyhow::{Context, Result};
use serde::Serialize;
use skill_veil_core::{ScanOptions, ScanTargetMode, Scanner, Verdict};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct CrossCheckOptions {
    /// Corpus directory previously populated via
    /// `skill-veil promptintel download`. Must contain `_index.json`
    /// alongside the `prompts/` directory.
    pub(crate) corpus_dir: PathBuf,
    /// When true, the per-prompt list in the rendered output is filtered
    /// to misses only — handy when authoring rules and scanning hundreds
    /// of prompts.
    pub(crate) only_misses: bool,
    /// Optional explicit rule pack directory. CLI users leave this at
    /// `None` so the scanner's normal cwd-relative discovery picks up
    /// `rules/official/`; the regression test pins this to the
    /// workspace-absolute path so the suite is reproducible from any
    /// working directory and so it tests the canonical pack — not the
    /// pack embedded in the binary at compile time.
    pub(crate) rules_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub(crate) struct CrossCheckSummary {
    pub(crate) total: usize,
    pub(crate) detected: usize,
    pub(crate) missed: usize,
    pub(crate) errors: usize,
    pub(crate) by_severity: BTreeMap<String, BucketCounts>,
    pub(crate) by_category: BTreeMap<String, BucketCounts>,
    pub(crate) by_threat: BTreeMap<String, BucketCounts>,
    /// Sorted by severity (critical → low), then by id.
    pub(crate) prompts: Vec<PromptCrossCheck>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub(crate) struct BucketCounts {
    pub(crate) total: usize,
    pub(crate) detected: usize,
}

impl BucketCounts {
    fn record(&mut self, detected: bool) {
        self.total += 1;
        if detected {
            self.detected += 1;
        }
    }

    /// Detection rate as a percentage rounded to one decimal.
    /// Returns `0.0` for empty buckets so the renderer never has to
    /// guard against division-by-zero.
    pub(crate) fn detection_rate_pct(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        // Round to one decimal place.
        #[allow(clippy::cast_precision_loss)]
        let raw = (self.detected as f64) / (self.total as f64) * 100.0;
        (raw * 10.0).round() / 10.0
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PromptCrossCheck {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) severity: PromptSeverity,
    pub(crate) categories: Vec<String>,
    pub(crate) threats: Vec<String>,
    pub(crate) our_verdict: String,
    pub(crate) our_risk_score: u32,
    pub(crate) detected: bool,
    pub(crate) matched_rules: Vec<String>,
}

/// Build a cross-check summary by scanning every prompt referenced in
/// `_index.json`.
///
/// # Errors
///
/// - The index file is missing or malformed (operator must run
///   `promptintel download` first).
/// - The scanner cannot be constructed (e.g. rule packs fail to load).
///
/// Per-prompt scan failures do NOT abort the whole run — they
/// increment `summary.errors` and the offending prompt is omitted from
/// the per-prompt list. This mirrors the existing `vt cross-check`
/// failure mode and keeps long benchmarks resilient.
pub(crate) fn build_summary(opts: &CrossCheckOptions) -> Result<CrossCheckSummary> {
    let index = load_index(&opts.corpus_dir)?;
    let scanner = Arc::new(
        Scanner::with_std_adapters(scan_options(opts.rules_dir.clone()))
            .context("failed to initialise scanner for cross-check")?,
    );

    let mut summary = CrossCheckSummary::default();

    for entry in index.values() {
        let markdown_path = opts.corpus_dir.join(&entry.markdown_path);
        match scanner.scan_file(&markdown_path) {
            Ok(scan) => {
                let detected = scan.verdict != Verdict::Benign;
                let matched_rules: Vec<String> = scan
                    .findings
                    .iter()
                    .map(|f| f.rule_id.clone())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();

                summary.total += 1;
                if detected {
                    summary.detected += 1;
                } else {
                    summary.missed += 1;
                }
                summary
                    .by_severity
                    .entry(entry.severity.as_str().to_string())
                    .or_default()
                    .record(detected);
                for cat in &entry.categories {
                    summary
                        .by_category
                        .entry(cat.clone())
                        .or_default()
                        .record(detected);
                }
                for threat in &entry.threats {
                    summary
                        .by_threat
                        .entry(threat.clone())
                        .or_default()
                        .record(detected);
                }
                if !opts.only_misses || !detected {
                    summary.prompts.push(PromptCrossCheck {
                        id: entry.id.clone(),
                        title: entry.title.clone(),
                        severity: entry.severity,
                        categories: entry.categories.clone(),
                        threats: entry.threats.clone(),
                        our_verdict: format!("{:?}", scan.verdict).to_lowercase(),
                        our_risk_score: scan.summary.risk_score,
                        detected,
                        matched_rules,
                    });
                }
            }
            Err(err) => {
                tracing::warn!(
                    "cross-check failed to scan PromptIntel entry {}: {}",
                    entry.id,
                    err
                );
                summary.errors += 1;
            }
        }
    }

    summary.prompts.sort_by(|a, b| {
        severity_order(b.severity)
            .cmp(&severity_order(a.severity))
            .then_with(|| a.id.cmp(&b.id))
    });

    Ok(summary)
}

/// Render a human-readable text report. Mirrors the `vt cross-check`
/// renderer in shape: top counters, per-bucket detection rates, then a
/// per-prompt list.
pub(crate) fn render_text(summary: &CrossCheckSummary) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("=== PromptIntel Cross-Check ===\n");
    out.push_str(&format!(
        "total: {}  detected: {}  missed: {}  errors: {}\n",
        summary.total, summary.detected, summary.missed, summary.errors,
    ));
    if summary.total > 0 {
        let rate = (f64::from(u32::try_from(summary.detected).unwrap_or(0))
            / f64::from(u32::try_from(summary.total).unwrap_or(1)))
            * 100.0;
        let rate = (rate * 10.0).round() / 10.0;
        out.push_str(&format!("overall detection rate: {rate}%\n"));
    }

    out.push_str("\n--- by severity ---\n");
    // Iterate in severity order rather than alphabetical so operators
    // see critical → low (highest leverage first).
    for sev in ["critical", "high", "medium", "low"] {
        if let Some(b) = summary.by_severity.get(sev) {
            out.push_str(&format!(
                "  {sev:<8}  {:>3}/{:<3}  ({}%)\n",
                b.detected,
                b.total,
                b.detection_rate_pct()
            ));
        }
    }

    if !summary.by_category.is_empty() {
        out.push_str("\n--- by category ---\n");
        for (cat, b) in &summary.by_category {
            out.push_str(&format!(
                "  {cat:<20}  {:>3}/{:<3}  ({}%)\n",
                b.detected,
                b.total,
                b.detection_rate_pct()
            ));
        }
    }

    if !summary.by_threat.is_empty() {
        out.push_str("\n--- by threat ---\n");
        let mut threats: Vec<_> = summary.by_threat.iter().collect();
        // Sort threats by missed count (descending) so the top gaps for
        // rule authoring appear first.
        threats.sort_by(|a, b| {
            let am = a.1.total - a.1.detected;
            let bm = b.1.total - b.1.detected;
            bm.cmp(&am).then_with(|| a.0.cmp(b.0))
        });
        for (threat, b) in threats {
            out.push_str(&format!(
                "  {threat:<48}  {:>3}/{:<3}  ({}%)\n",
                b.detected,
                b.total,
                b.detection_rate_pct()
            ));
        }
    }

    out.push_str("\n--- per-prompt ---\n");
    for p in &summary.prompts {
        let mark = if p.detected { "OK " } else { "MISS" };
        out.push_str(&format!(
            "[{mark}] {sev:<8} risk={risk:<3} verdict={v:<10}  {id}  {title}\n",
            sev = p.severity.as_str(),
            risk = p.our_risk_score,
            v = p.our_verdict,
            id = p.id,
            title = truncate(&p.title, 80),
        ));
    }

    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// Default scan options for the cross-check pipeline. Single-file
/// markdown mode without policy/profile/baseline so the scanner uses
/// the canonical rule pack and we measure detection of the rules
/// themselves, not of an operator-specific policy.
///
/// `rules_dir` is forwarded into `ScanOptions::rules_dir` when supplied
/// so the regression test can pin the canonical workspace pack
/// independent of the test-runner cwd. CLI users always pass `None`
/// and inherit the scanner's normal cwd-relative discovery.
fn scan_options(rules_dir: Option<PathBuf>) -> ScanOptions {
    ScanOptions {
        recursive: false,
        target_mode: ScanTargetMode::File,
        rules_dir,
        ..Default::default()
    }
}

fn severity_order(s: PromptSeverity) -> u8 {
    match s {
        PromptSeverity::Critical => 4,
        PromptSeverity::High => 3,
        PromptSeverity::Medium => 2,
        PromptSeverity::Low => 1,
    }
}

fn load_index(corpus_dir: &Path) -> Result<BTreeMap<String, IndexEntry>> {
    let path = corpus_dir.join("_index.json");
    let body = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading PromptIntel corpus index at {} (run `skill-veil promptintel download` first)",
            path.display()
        )
    })?;
    let index: BTreeMap<String, IndexEntry> = serde_json::from_str(&body)
        .with_context(|| format!("parsing {} as PromptIntel index JSON", path.display()))?;
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `BucketCounts::detection_rate_pct` MUST return `0.0`
    /// for an empty bucket. The renderer iterates over every severity
    /// label whether or not any prompts populate it; a panic on
    /// division-by-zero in the renderer would break every empty-corpus
    /// run.
    #[test]
    fn detection_rate_is_zero_for_empty_bucket() {
        let b = BucketCounts::default();
        assert!((b.detection_rate_pct() - 0.0).abs() < f64::EPSILON);
    }

    /// Contract: detection rate is rounded to one decimal place. The
    /// renderer prints `12.5%` rather than `12.499999%`; floating-point
    /// drift here would make the report visually noisy.
    #[test]
    fn detection_rate_rounds_to_one_decimal() {
        let mut b = BucketCounts::default();
        for _ in 0..7 {
            b.record(true);
        }
        b.record(false); // 7/8 = 87.5%
        assert!((b.detection_rate_pct() - 87.5).abs() < f64::EPSILON);
    }

    /// Contract: `BucketCounts::record` increments `total` for every
    /// call and increments `detected` only on positive calls. A subtle
    /// off-by-one here would invert the gap report and cause operators
    /// to author rules for already-covered threats.
    #[test]
    fn record_separates_detected_from_total() {
        let mut b = BucketCounts::default();
        b.record(true);
        b.record(false);
        b.record(true);
        assert_eq!(b.total, 3);
        assert_eq!(b.detected, 2);
    }

    /// Contract: severities order critical → low so the rendered
    /// per-prompt section surfaces the highest-leverage misses first.
    /// Pre-design we considered alphabetical, but `critical` > `low`
    /// lexically the wrong way.
    #[test]
    fn severity_order_ranks_critical_above_low() {
        assert!(severity_order(PromptSeverity::Critical) > severity_order(PromptSeverity::High));
        assert!(severity_order(PromptSeverity::High) > severity_order(PromptSeverity::Medium));
        assert!(severity_order(PromptSeverity::Medium) > severity_order(PromptSeverity::Low));
    }

    /// Contract: `truncate` MUST NOT split a multi-byte UTF-8 char and
    /// MUST cap at the requested character (not byte) count. The title
    /// field commonly carries non-ASCII characters from non-English
    /// curators; a byte-count truncation would corrupt the rendered
    /// report and break any downstream UTF-8 parser that re-reads it.
    #[test]
    fn truncate_handles_unicode_titles() {
        let title = "测试一个非ASCII的标题用来检查截断逻辑是否正确";
        let out = truncate(title, 10);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        // 9 original chars + '…' = 10 chars total.
        assert_eq!(out.chars().count(), 10);
        assert!(out.ends_with('…'));
    }

    /// Contract (negative): short strings pass through untouched.
    #[test]
    fn truncate_passes_short_strings_through() {
        assert_eq!(truncate("short", 80), "short".to_string());
    }

    /// Contract: scanning the vendored PromptIntel corpus
    /// (`benchmarks/promptintel-corpus/`) MUST clear the per-severity
    /// regression gates below. The thresholds intentionally allow some
    /// drift (one high miss, five medium misses) so isolated rule
    /// adjustments do not require regenerating the snapshot, but a
    /// cohort-wide regression — e.g. a refactor that breaks regex
    /// compilation in the official pack — fails CI.
    ///
    /// Refresh procedure when the snapshot legitimately moves: see
    /// `benchmarks/promptintel-corpus/README.md`. Do NOT relax the
    /// thresholds without a paired commit that explains the labelling
    /// change.
    #[test]
    fn promptintel_vendored_corpus_meets_baseline() {
        let corpus_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("benchmarks")
            .join("promptintel-corpus");

        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("rules")
            .join("official");

        let summary = build_summary(&CrossCheckOptions {
            corpus_dir,
            only_misses: false,
            rules_dir: Some(rules_dir),
        })
        .expect("vendored PromptIntel corpus must be scannable");

        assert_eq!(
            summary.errors, 0,
            "vendored corpus must scan without per-prompt errors; \
             a non-zero error count means the snapshot is malformed \
             or the scanner cannot read a referenced markdown file"
        );

        // Snapshot shape — pin the per-severity distribution so a
        // future refresh that silently drops `critical` entries cannot
        // satisfy the percentage gates by reducing the denominator.
        let critical = summary
            .by_severity
            .get("critical")
            .expect("critical bucket missing — snapshot shape regressed");
        let high = summary
            .by_severity
            .get("high")
            .expect("high bucket missing — snapshot shape regressed");
        let medium = summary
            .by_severity
            .get("medium")
            .expect("medium bucket missing — snapshot shape regressed");
        assert!(
            critical.total >= 6 && high.total >= 18 && medium.total >= 20,
            "snapshot shape regressed (critical={}, high={}, medium={}); \
             refresh the vendored corpus before adjusting thresholds",
            critical.total,
            high.total,
            medium.total,
        );

        // Per-severity gates. Critical never tolerates a miss — those
        // are the highest-leverage prompts we ship rules for.
        assert_eq!(
            critical.detected,
            critical.total,
            "every critical-severity PromptIntel prompt must be detected; \
             missed = {}",
            critical.total - critical.detected,
        );
        assert!(
            high.detection_rate_pct() >= 94.0,
            "high-severity detection regressed below 94% (got {}%)",
            high.detection_rate_pct(),
        );
        assert!(
            medium.detection_rate_pct() >= 80.0,
            "medium-severity detection regressed below 80% (got {}%)",
            medium.detection_rate_pct(),
        );

        // Overall gate. We currently ship at 100%; allow one miss of
        // headroom (≥ 49/50) so unrelated rule churn does not flake CI,
        // but anything below that is a real regression.
        let overall_pct = (f64::from(u32::try_from(summary.detected).unwrap_or(0))
            / f64::from(u32::try_from(summary.total.max(1)).unwrap_or(1)))
            * 100.0;
        assert!(
            overall_pct >= 98.0,
            "overall PromptIntel detection rate regressed below 98% \
             (got {}/{} = {:.1}%)",
            summary.detected,
            summary.total,
            overall_pct,
        );
    }
}
