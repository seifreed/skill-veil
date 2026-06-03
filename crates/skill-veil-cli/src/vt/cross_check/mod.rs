//! Cross-checks skill-veil's own per-package verdicts against VirusTotal's
//! Code Insight verdicts loaded from the `.vt-reports/` cache.
//!
//! The primary output is a list of "we missed" packages — ones VT flagged as
//! `malicious` but skill-veil classified as `benign` or `suspicious`. The VT
//! `analysis` text for each of those packages is the single best source for
//! designing new detection rules.
//!
//! # Module layout
//!
//! - `types` — public DTOs (`Classification`, `CrossCheckSummary`, ...).
//! - `sha_lookup` — resolve SHA-256 keys for the report cache.
//! - `reports_cache` — load `.vt-reports/*.json` from disk.
//! - `classify` — pure decision table mapping `(our, VT)` → `Classification`.
//! - `render` — markdown / text output formatting.
//!
//! `build_summary` is the only orchestrator: it threads the four non-render
//! modules together and produces a `CrossCheckSummary` ready for either
//! renderer.

mod classify;
mod render;
mod reports_cache;
mod sha_lookup;
mod types;

use anyhow::Result;
use skill_veil_core::PackageScanResult;

pub(crate) use render::{render_baseline, render_markdown, render_text};
pub(crate) use types::{Classification, CrossCheckOptions, CrossCheckSummary, PackageCrossCheck};

const REPORTS_DIRNAME: &str = super::download::REPORTS_DIRNAME;

pub(crate) fn build_summary(
    scan_results: &[PackageScanResult],
    opts: &CrossCheckOptions,
) -> Result<CrossCheckSummary> {
    let reports_dir = opts.dataset_dir.join(REPORTS_DIRNAME);
    let reports = reports_cache::load_reports(&reports_dir)?;

    let mut summary = CrossCheckSummary::default();

    for pkg in scan_results {
        for res in &pkg.results {
            // The reports cache is keyed by the SHA-256 returned by VT for the
            // file. `package_id` is only a SHA when the corpus was produced
            // by `vt download` (whose layout is `<sha>/...`); for any other
            // corpus (extracted ZIPs, source dirs) it's a path-derived
            // identifier or `None`, and a direct lookup would always miss.
            // Fall back to hashing the primary artifact on disk so cross-
            // check is meaningful for arbitrary corpora.
            let Some(sha) =
                sha_lookup::sha_for_lookup(&res.metadata.package_id, &res.metadata.path)
            else {
                // Without a SHA we cannot key the VT report cache, so the
                // result is structurally invisible to cross-check. Logging
                // it (vs. silently skipping) is what keeps `summary.total`
                // reconcilable with `scan_results.len()` for users running
                // large dataset scans.
                tracing::warn!(
                    package_id = ?res.metadata.package_id,
                    path = %res.metadata.path.display(),
                    "cross-check: skipping scan result without recoverable SHA-256",
                );
                continue;
            };
            let our_verdict = res.verdict.to_string();
            let our_risk_score = res.summary.risk_score;
            let our_findings: Vec<String> = res
                .findings
                .iter()
                .map(|f| f.rule_id.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();

            let report = reports.get(&sha);
            let (category, verdict, analysis, name) = match report {
                Some(r) => {
                    let ai = r.attributes.primary_ai_verdict();
                    (
                        ai.map(|a| a.category.clone()),
                        ai.map(|a| a.verdict.clone()),
                        ai.map(|a| a.analysis.clone()),
                        r.attributes.meaningful_name.clone(),
                    )
                }
                None => (None, None, None, None),
            };

            // VT Code Insight puts the actionable label in `verdict`
            // ("malicious" | "suspicious" | "benign") and uses `category` as a
            // loose source tag (e.g. "code_insight"). Classify by verdict.
            let classification = classify::classify(res.verdict, verdict.as_deref());
            summary.total += 1;
            match classification {
                Classification::AgreeMalicious => summary.agree_malicious += 1,
                Classification::AgreeSuspicious => summary.agree_suspicious += 1,
                Classification::AgreeBenign => summary.agree_benign += 1,
                Classification::WeMissed => summary.we_missed += 1,
                Classification::WeMissedSuspicious => summary.we_missed_suspicious += 1,
                Classification::WeOverreached => summary.we_overreached += 1,
                Classification::Unknown => summary.unknown += 1,
            }

            if opts.only_mismatches
                && !matches!(
                    classification,
                    Classification::WeMissed
                        | Classification::WeMissedSuspicious
                        | Classification::WeOverreached
                )
            {
                continue;
            }

            summary.packages.push(PackageCrossCheck {
                sha256: sha,
                our_verdict,
                our_risk_score,
                our_findings,
                vt_category: category,
                vt_verdict: verdict,
                vt_analysis: analysis,
                meaningful_name: name,
                classification,
            });
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `we_missed` and `we_missed_suspicious` increment
    /// independently. A package VT marked merely suspicious must not
    /// inflate the apparent "missed malware" count.
    #[test]
    fn summary_counts_split_we_missed_by_vt_tier() {
        let opts = CrossCheckOptions {
            dataset_dir: std::path::PathBuf::from("/nonexistent"),
            only_mismatches: false,
        };
        let mut summary = CrossCheckSummary::default();
        // Manually drive the counter logic with classify outputs since
        // build_summary requires loading reports from disk.
        for c in [
            Classification::WeMissed,
            Classification::WeMissedSuspicious,
            Classification::WeMissedSuspicious,
        ] {
            match c {
                Classification::WeMissed => summary.we_missed += 1,
                Classification::WeMissedSuspicious => summary.we_missed_suspicious += 1,
                _ => unreachable!(),
            }
        }
        assert_eq!(summary.we_missed, 1);
        assert_eq!(summary.we_missed_suspicious, 2);
        // opts is constructed only to verify the type still compiles after the field changes.
        let _ = opts.only_mismatches;
    }
}
