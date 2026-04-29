//! Markdown and plain-text rendering for `CrossCheckSummary`.
//!
//! Output-only: no decisions, no I/O. The classifier already labelled
//! each package; this module formats those labels for human review.

use super::types::{Classification, CrossCheckSummary};
use std::fmt::Write as _;

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
