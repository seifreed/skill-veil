//! Markdown and plain-text rendering for `CrossCheckSummary`.
//!
//! Output-only: no decisions, no I/O. The classifier already labelled
//! each package; this module formats those labels for human review.

use super::types::{Classification, CrossCheckSummary};
use crate::util::terminal_safe::sanitise_for_terminal;
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
            let findings = pkg
                .our_findings
                .iter()
                .map(|finding| terminal_text(finding))
                .collect::<Vec<_>>()
                .join(",");
            let _ = writeln!(
                out,
                "- `{}` — our={} risk={}  vt={}  findings={}",
                terminal_text(&pkg.sha256),
                terminal_text(&pkg.our_verdict),
                pkg.our_risk_score,
                pkg.vt_verdict
                    .as_deref()
                    .map(terminal_text)
                    .unwrap_or_else(|| "?".to_string()),
                findings
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
        let _ = writeln!(out, "### `{}`", terminal_text(&pkg.sha256));
        if let Some(name) = &pkg.meaningful_name {
            let _ = writeln!(out, "- **name**: {}", terminal_text(name));
        }
        let _ = writeln!(
            out,
            "- **our verdict**: {} (risk {})",
            terminal_text(&pkg.our_verdict),
            pkg.our_risk_score
        );
        if pkg.our_findings.is_empty() {
            let _ = writeln!(out, "- **our findings**: _(none)_");
        } else {
            let findings = pkg
                .our_findings
                .iter()
                .map(|finding| terminal_text(finding))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "- **our findings**: {findings}");
        }
        if let Some(v) = &pkg.vt_verdict {
            let _ = writeln!(out, "- **VT verdict**: {}", terminal_text(v));
        }
        if let Some(analysis) = &pkg.vt_analysis {
            let _ = writeln!(out, "\n**VT Code Insight analysis:**\n");
            for line in analysis.lines() {
                let _ = writeln!(out, "> {}", terminal_text(line));
            }
            let _ = writeln!(out);
        }
    }
}

fn terminal_text(value: &str) -> String {
    sanitise_for_terminal(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcc(sha: &str, our: &str, vt: &str) -> super::super::types::PackageCrossCheck {
        super::super::types::PackageCrossCheck {
            sha256: sha.to_string(),
            our_verdict: our.to_string(),
            our_risk_score: 10,
            our_findings: vec!["RULE_X".to_string()],
            vt_category: None,
            vt_verdict: Some(vt.to_string()),
            vt_analysis: None,
            meaningful_name: None,
            classification: Classification::Unknown,
        }
    }

    /// # Contract
    ///
    /// `render_baseline` rolls `summary.packages` (per-artifact) up to
    /// one sample per SHA taking the STRONGEST skill-veil verdict
    /// (`malicious` > `suspicious` > `benign`), and computes raw
    /// pre-override metrics with the SAME definition as
    /// `scripts/regenerate_baseline.py`: `suspicious` is a POSITIVE
    /// (caught), so a VT-malicious sample we rate `suspicious` is a
    /// TP, NOT a false negative. Both directions are pinned:
    /// strongest-wins rollup AND suspicious-counts-as-caught.
    #[test]
    fn render_baseline_rolls_up_per_sha_and_counts_suspicious_as_caught() {
        let summary = CrossCheckSummary {
            packages: vec![
                // SHA "aaaa…": two artifacts — benign + malicious.
                // Rollup MUST pick `malicious` (strongest). VT=malicious → TP.
                pcc("aaaaaaaaaaaa0000", "benign", "malicious"),
                pcc("aaaaaaaaaaaa0000", "malicious", "malicious"),
                // VT=malicious, we say benign → the ONLY false-negative case.
                pcc("bbbbbbbbbbbb0000", "benign", "malicious"),
                // VT=benign, we say suspicious → false positive (positive).
                pcc("cccccccccccc0000", "suspicious", "benign"),
                // VT=benign, we say benign → true negative.
                pcc("dddddddddddd0000", "benign", "benign"),
                // VT=malicious, we say suspicious → TP (caught), NOT FN.
                pcc("eeeeeeeeeeee0000", "suspicious", "malicious"),
            ],
            ..Default::default()
        };

        let json: serde_json::Value =
            serde_json::from_str(&render_baseline(&summary)).expect("valid JSON");

        assert_eq!(json["schema_version"], "1.0");
        let samples = json["samples"].as_array().expect("samples array");
        assert_eq!(samples.len(), 5, "5 distinct SHAs → 5 rolled-up samples");

        let a = samples
            .iter()
            .find(|s| s["sha256"] == "aaaaaaaaaaaa0000")
            .expect("sha aaaa present");
        assert_eq!(
            a["actual"], "malicious",
            "per-SHA rollup must take the strongest verdict (benign+malicious → malicious)"
        );
        assert_eq!(a["id"], "aaaaaaaaaaaa", "id is the 12-char SHA prefix");

        let m = &json["metrics"];
        assert_eq!(m["true_positive"], 2, "aaaa (mal) + eeee (susp) are TP");
        assert_eq!(
            m["false_negative"], 1,
            "only bbbb (VT-mal, we-benign) is FN; suspicious is NOT a miss"
        );
        assert_eq!(
            m["false_positive"], 1,
            "cccc (VT-benign, we-suspicious) is FP"
        );
        assert_eq!(m["true_negative"], 1, "dddd (VT-benign, we-benign) is TN");
    }

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

    #[test]
    fn render_markdown_sanitises_vt_control_sequences() {
        let summary = CrossCheckSummary {
            total: 1,
            we_missed: 1,
            packages: vec![super::super::types::PackageCrossCheck {
                sha256: "aaaaaaaaaaaa0000\x1b[2J".to_string(),
                our_verdict: "benign\x1b[2J".to_string(),
                our_risk_score: 0,
                our_findings: vec!["RULE\x1b[2J".to_string()],
                vt_category: None,
                vt_verdict: Some("malicious\x1b[2J".to_string()),
                vt_analysis: Some("analysis\x1b]8;;https://evil.invalid\x07click".to_string()),
                meaningful_name: Some("sample\x1b[2J".to_string()),
                classification: Classification::WeMissed,
            }],
            ..Default::default()
        };

        let md = render_markdown(&summary);

        assert!(!md.contains('\x1b'));
        assert!(!md.contains('\x07'));
    }
}
