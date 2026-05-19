//! Markdown and plain-text rendering for `CrossCheckSummary`.
//!
//! Output-only: no decisions, no I/O. The classifier already labelled
//! each package; this module formats those labels for human review.

use super::types::{Classification, CrossCheckSummary};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Emit the per-sample `vt-baseline.json` schema consumed by
/// `scripts/regenerate_baseline.py`.
///
/// `summary.packages` is per-artifact (one row per scanned file);
/// the canonical baseline is per-package, so rows are rolled up by
/// SHA-256 taking the strongest skill-veil verdict
/// (`malicious` > `suspicious` > `benign`) and the max risk score /
/// finding count. `expected` is VT's verdict (the corpus label);
/// `actual` / `verdict` is skill-veil's. Metrics are RAW
/// (pre-override): `regenerate_baseline.py` re-applies the 36
/// mislabel overrides and recomputes, so this only needs to be a
/// valid standalone baseline.
pub(crate) fn render_baseline(summary: &CrossCheckSummary) -> String {
    fn rank(v: &str) -> u8 {
        match v {
            "malicious" => 2,
            "suspicious" => 1,
            _ => 0,
        }
    }
    fn is_positive(v: &str) -> bool {
        v == "malicious" || v == "suspicious"
    }

    struct Roll {
        expected: String,
        actual: String,
        risk: u32,
        findings: usize,
    }
    let mut by_sha: BTreeMap<String, Roll> = BTreeMap::new();
    for pkg in &summary.packages {
        // The corpus is uniformly VT-`malicious`; a report whose
        // primary AI verdict is absent is treated as `malicious`
        // (the query that seeded the corpus guarantees the label).
        let expected = pkg
            .vt_verdict
            .clone()
            .unwrap_or_else(|| "malicious".to_string());
        let entry = by_sha.entry(pkg.sha256.clone()).or_insert_with(|| Roll {
            expected: expected.clone(),
            actual: pkg.our_verdict.clone(),
            risk: pkg.our_risk_score,
            findings: pkg.our_findings.len(),
        });
        if rank(&pkg.our_verdict) > rank(&entry.actual) {
            entry.actual = pkg.our_verdict.clone();
        }
        entry.risk = entry.risk.max(pkg.our_risk_score);
        entry.findings = entry.findings.max(pkg.our_findings.len());
        // A benign override is keyed per-SHA; never let an absent-AI
        // artifact downgrade a sibling's real VT verdict.
        if rank_label(&expected) > rank_label(&entry.expected) {
            entry.expected = expected;
        }
    }

    let (mut tp, mut fp, mut fn_, mut tn) = (0u32, 0u32, 0u32, 0u32);
    let samples: Vec<serde_json::Value> = by_sha
        .iter()
        .map(|(sha, r)| {
            match (
                r.expected.as_str(),
                is_positive(&r.actual),
                r.actual.as_str(),
            ) {
                ("malicious", true, _) => tp += 1,
                ("malicious", false, "benign") => fn_ += 1,
                ("benign", true, _) => fp += 1,
                ("benign", false, "benign") => tn += 1,
                _ => {}
            }
            serde_json::json!({
                "id": &sha[..sha.len().min(12)],
                "sha256": sha,
                "expected": r.expected,
                "actual": r.actual,
                "verdict": r.actual,
                "risk_score": r.risk,
                "finding_count": r.findings,
                "path": format!("benchmarks/../data/.skill-veil-cache/extracted/{sha}"),
            })
        })
        .collect();

    let total = tp + fp + fn_ + tn;
    let f = |n: u32, d: u32| {
        if d == 0 {
            1.0
        } else {
            f64::from(n) / f64::from(d)
        }
    };
    let metrics = serde_json::json!({
        "precision": if tp + fp == 0 { 1.0 } else { f(tp, tp + fp) },
        "recall": if tp + fn_ == 0 { 1.0 } else { f(tp, tp + fn_) },
        "false_positive_rate": if fp + tn == 0 { 0.0 } else { f(fp, fp + tn) },
        "accuracy": if total == 0 { 1.0 } else { f(tp + tn, total) },
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn_,
    });
    let mut by_label: BTreeMap<&str, usize> = BTreeMap::new();
    for s in &samples {
        if let Some(e) = s.get("expected").and_then(|v| v.as_str()) {
            *by_label.entry(e).or_insert(0) += 1;
        }
    }
    let out = serde_json::json!({
        "schema_version": "1.0",
        "overrides_file": "vt-baseline-overrides.yaml",
        "overrides_applied": 0,
        "regenerated_at": "pending-regenerate-baseline",
        "metrics": metrics,
        "coverage": { "total_samples": samples.len(), "by_label": by_label },
        "samples": samples,
    });
    serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
}

fn rank_label(v: &str) -> u8 {
    // `benign` (an override-eligible VT mislabel) outranks `malicious`
    // for the per-SHA expected rollup so a single LLM-validated-benign
    // artifact is not masked by a sibling's raw VT label.
    match v {
        "benign" => 2,
        "suspicious" => 1,
        _ => 0,
    }
}

pub(crate) fn render_markdown(summary: &CrossCheckSummary) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# skill-veil × VirusTotal cross-check\n\n\
        _packages compared_: **{}**\n\n\
        | our verdict / VT | count |\n|---|---|\n\
        | ✅ agree malicious (VT: malicious) | {} |\n\
        | ⚠️ agree suspicious (VT: suspicious) | {} |\n\
        | ✅ agree benign | {} |\n\
        | ❌ we missed (VT: malicious, us: benign) | **{}** |\n\
        | ⚠️ VT flagged as suspicious, us: benign | {} |\n\
        | ⚠️ we overreached (VT: benign, us: malicious/suspicious) | {} |\n\
        | ❓ unknown (no VT report or unrecognized verdict) | {} |\n",
        summary.total,
        summary.agree_malicious,
        summary.agree_suspicious,
        summary.agree_benign,
        summary.we_missed,
        summary.we_missed_suspicious,
        summary.we_overreached,
        summary.unknown,
    );

    render_missed_section(
        &mut out,
        summary,
        Classification::WeMissed,
        "We missed (VT: malicious)",
    );
    render_missed_section(
        &mut out,
        summary,
        Classification::WeMissedSuspicious,
        "VT flagged as suspicious, we said benign",
    );

    let overreached: Vec<_> = summary
        .packages
        .iter()
        .filter(|p| p.classification == Classification::WeOverreached)
        .collect();
    if !overreached.is_empty() {
        let _ = writeln!(out, "\n## We overreached ({})\n", overreached.len());
        for pkg in overreached {
            let _ = writeln!(
                out,
                "- `{}` — our={} risk={}  vt={}  findings={}",
                pkg.sha256,
                pkg.our_verdict,
                pkg.our_risk_score,
                pkg.vt_verdict.as_deref().unwrap_or("?"),
                pkg.our_findings.join(",")
            );
        }
    }

    out
}

pub(crate) fn render_text(summary: &CrossCheckSummary) -> String {
    format!(
        "Cross-check: total={} agree_malicious={} agree_suspicious={} agree_benign={} \
         we_missed={} we_missed_suspicious={} we_overreached={} unknown={}",
        summary.total,
        summary.agree_malicious,
        summary.agree_suspicious,
        summary.agree_benign,
        summary.we_missed,
        summary.we_missed_suspicious,
        summary.we_overreached,
        summary.unknown,
    )
}

/// Render one "we missed" detail section (per-package list with VT analysis
/// text) for a specific `Classification` bucket. Used for both
/// `WeMissed` (VT: malicious) and `WeMissedSuspicious` (VT: suspicious)
/// — the two buckets share output shape but were previously inlined into
/// `render_markdown` for the malicious case only.
fn render_missed_section(
    out: &mut String,
    summary: &CrossCheckSummary,
    classification: Classification,
    heading: &str,
) {
    let pkgs: Vec<_> = summary
        .packages
        .iter()
        .filter(|p| p.classification == classification)
        .collect();
    if pkgs.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n## {} ({})\n", heading, pkgs.len());
    for pkg in pkgs {
        let _ = writeln!(out, "### `{}`", pkg.sha256);
        if let Some(name) = &pkg.meaningful_name {
            let _ = writeln!(out, "- **name**: {name}");
        }
        let _ = writeln!(
            out,
            "- **our verdict**: {} (risk {})",
            pkg.our_verdict, pkg.our_risk_score
        );
        if pkg.our_findings.is_empty() {
            let _ = writeln!(out, "- **our findings**: _(none)_");
        } else {
            let _ = writeln!(out, "- **our findings**: {}", pkg.our_findings.join(", "));
        }
        if let Some(v) = &pkg.vt_verdict {
            let _ = writeln!(out, "- **VT verdict**: {v}");
        }
        if let Some(analysis) = &pkg.vt_analysis {
            let _ = writeln!(out, "\n**VT Code Insight analysis:**\n");
            for line in analysis.lines() {
                let _ = writeln!(out, "> {line}");
            }
            let _ = writeln!(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: the markdown table label for each bucket accurately
    /// reflects the data. The pre-fix markdown said "VT: malicious"
    /// even when the bucket included VT-suspicious entries.
    #[test]
    fn render_markdown_labels_match_classification_buckets() {
        let summary = CrossCheckSummary {
            total: 5,
            agree_malicious: 1,
            agree_suspicious: 1,
            agree_benign: 1,
            we_missed: 1,
            we_missed_suspicious: 1,
            we_overreached: 0,
            unknown: 0,
            packages: Vec::new(),
        };
        let md = render_markdown(&summary);
        assert!(
            md.contains("agree malicious (VT: malicious)"),
            "agree-malicious row must be unambiguously labelled"
        );
        assert!(
            md.contains("agree suspicious (VT: suspicious)"),
            "agree-suspicious row must exist and reference VT's suspicious tier"
        );
        assert!(
            md.contains("we missed (VT: malicious, us: benign)"),
            "we-missed row must NOT mention 'suspicious' — that has its own bucket"
        );
        assert!(
            md.contains("VT flagged as suspicious, us: benign"),
            "we-missed-suspicious row must surface the new bucket"
        );
        // The pre-fix label combined both into "us: benign/suspicious"
        // — guard against regression.
        assert!(
            !md.contains("us: benign/suspicious"),
            "the pre-fix combined label must not reappear; markdown was:\n{md}"
        );
    }
}
