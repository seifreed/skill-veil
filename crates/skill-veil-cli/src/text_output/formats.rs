use anyhow::{Context, Result};
use skill_veil_core::ScanResult;

pub(crate) fn format_json_output(results: &[ScanResult]) -> Result<String> {
    let reports: Vec<_> = results
        .iter()
        .map(|r| r.policy_generator().generate_json())
        .collect();
    serde_json::to_string_pretty(&reports).context("Failed to serialize JSON")
}

pub(crate) fn format_sarif_output(results: &[ScanResult]) -> Result<String> {
    if let Some(first) = results.first() {
        let mut sarif = first.policy_generator().generate_sarif();

        for result in results.iter().skip(1) {
            let other = result.policy_generator().generate_sarif();
            if let Some(run) = sarif.runs.first_mut() {
                if let Some(other_run) = other.runs.first() {
                    run.results.extend(other_run.results.clone());
                    // Pre-fix this snapshotted `run.tool.driver.rules` into a
                    // `HashSet` once before the loop. New rules pushed inside
                    // the loop did not update the snapshot, so an
                    // `other_run` that itself contained the same rule id
                    // twice (or a future caller batching multiple scans
                    // into one merge) produced duplicate rule entries in
                    // `tool.driver.rules`. The SARIF 2.1.0 schema requires
                    // `tool.driver.rules[].id` to be unique within a run;
                    // GitHub Code Scanning rejects the document otherwise.
                    // The .any() check looks at the live Vec so each push
                    // is immediately visible.
                    for rule in &other_run.tool.driver.rules {
                        if !run.tool.driver.rules.iter().any(|r| r.id == rule.id) {
                            run.tool.driver.rules.push(rule.clone());
                        }
                    }
                }
            }
        }

        serde_json::to_string_pretty(&sarif).context("Failed to serialize SARIF")
    } else {
        Ok(
            serde_json::to_string_pretty(&skill_veil_core::empty_sarif_report())
                .context("Failed to serialize empty SARIF")?,
        )
    }
}

pub(crate) fn format_shield_output(results: &[ScanResult]) -> String {
    let mut output = String::new();
    for result in results {
        output.push_str(&result.policy_generator().generate_shield_md());
        output.push_str("\n---\n\n");
    }
    output
}

/// Minimal HTML entity escaping for text interpolated into the report.
/// Covers the five characters that can break out of element text or an
/// attribute context — the report never emits user content into a script
/// or style context, so this set is sufficient.
fn html_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn verdict_rank(verdict: skill_veil_core::Verdict) -> u8 {
    match verdict {
        skill_veil_core::Verdict::Benign => 0,
        skill_veil_core::Verdict::Suspicious => 1,
        skill_veil_core::Verdict::Malicious => 2,
    }
}

fn verdict_css_class(verdict: skill_veil_core::Verdict) -> &'static str {
    match verdict {
        skill_veil_core::Verdict::Malicious => "v-malicious",
        skill_veil_core::Verdict::Suspicious => "v-suspicious",
        skill_veil_core::Verdict::Benign => "v-benign",
    }
}

fn severity_css_class(severity: skill_veil_core::Severity) -> &'static str {
    match severity {
        skill_veil_core::Severity::Critical => "s-critical",
        skill_veil_core::Severity::High => "s-high",
        skill_veil_core::Severity::Medium => "s-medium",
        skill_veil_core::Severity::Low => "s-low",
    }
}

const HTML_STYLE: &str = "\
:root{color-scheme:light dark}\
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:2rem;background:#0f1115;color:#e6e6e6}\
h1{margin:0 0 .25rem}.sub{color:#9aa0a6;margin:0 0 1.5rem}\
.pkg{background:#171a21;border:1px solid #2a2f3a;border-radius:10px;margin:1rem 0;overflow:hidden}\
.pkg>summary{cursor:pointer;padding:1rem;font-size:1.1rem;display:flex;align-items:center;gap:.75rem;list-style:none}\
.pkg>summary::-webkit-details-marker{display:none}\
.badge{font-weight:700;padding:.15rem .6rem;border-radius:999px;font-size:.8rem}\
.v-malicious{background:#5b1620;color:#ff8a9a}.v-suspicious{background:#5b4a16;color:#ffd66b}.v-benign{background:#16452a;color:#7ee2a8}\
.risk{margin-left:auto;color:#9aa0a6;font-variant-numeric:tabular-nums}\
table{width:100%;border-collapse:collapse;font-size:.9rem}\
th,td{text-align:left;padding:.5rem .75rem;border-top:1px solid #2a2f3a;vertical-align:top}\
th{color:#9aa0a6;font-weight:600}\
td.sev{font-weight:700;white-space:nowrap}\
.s-critical{color:#ff6b81}.s-high{color:#ff9e6b}.s-medium{color:#ffd66b}.s-low{color:#8ab4f8}\
code{background:#0f1115;border:1px solid #2a2f3a;border-radius:4px;padding:.05rem .35rem;font-size:.85em}\
.empty{padding:1rem;color:#9aa0a6}";

/// Render a self-contained interactive HTML report: a header summary plus
/// one collapsible `<details>` per package with a severity-coloured
/// findings table. No external assets, no scripts — safe to email or
/// attach to a CI artifact.
pub(crate) fn format_html_output(results: &[ScanResult]) -> String {
    let mut findings_total = 0usize;
    let mut worst = skill_veil_core::Verdict::Benign;
    for r in results {
        findings_total += r.findings.len();
        if verdict_rank(r.verdict) > verdict_rank(worst) {
            worst = r.verdict;
        }
    }

    let mut body = String::new();
    body.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    body.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    body.push_str("<title>skill-veil report</title><style>");
    body.push_str(HTML_STYLE);
    body.push_str("</style></head><body>");
    body.push_str("<h1>skill-veil security report</h1>");
    body.push_str(&format!(
        "<p class=\"sub\">{} package(s) &middot; {} finding(s) &middot; worst verdict \
         <span class=\"badge {}\">{}</span></p>",
        results.len(),
        findings_total,
        verdict_css_class(worst),
        html_escape(&worst.to_string()),
    ));

    for r in results {
        let name = html_escape(&r.metadata.name);
        let path = html_escape(&r.metadata.path.display().to_string());
        let open = if r.verdict == skill_veil_core::Verdict::Benign {
            ""
        } else {
            " open"
        };
        body.push_str(&format!("<details class=\"pkg\"{open}><summary>"));
        body.push_str(&format!(
            "<span class=\"badge {}\">{}</span> <span>{name}</span> \
             <span class=\"risk\">risk {}/100</span></summary>",
            verdict_css_class(r.verdict),
            html_escape(&r.verdict.to_string()),
            r.summary.risk_score,
        ));
        body.push_str(&format!(
            "<div class=\"empty\" style=\"padding-top:0\">{path}</div>"
        ));

        if r.findings.is_empty() {
            body.push_str("<div class=\"empty\">No findings.</div>");
        } else {
            body.push_str(
                "<table><thead><tr><th>Severity</th><th>Rule</th><th>Category</th>\
                 <th>Reason</th><th>Location</th></tr></thead><tbody>",
            );
            for f in &r.findings {
                let loc = f.line_number.map_or_else(
                    || {
                        f.artifact_path
                            .as_deref()
                            .map(html_escape)
                            .unwrap_or_default()
                    },
                    |line| format!("line {line}"),
                );
                body.push_str(&format!(
                    "<tr><td class=\"sev {}\">{}</td><td><code>{}</code></td><td>{}</td>\
                     <td>{}</td><td>{}</td></tr>",
                    severity_css_class(f.severity),
                    html_escape(&f.severity.to_string()),
                    html_escape(&f.rule_id),
                    html_escape(&f.category.to_string()),
                    html_escape(&f.reason),
                    loc,
                ));
            }
            body.push_str("</tbody></table>");
        }
        body.push_str("</details>");
    }

    body.push_str("</body></html>");
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::{Severity, Verdict};

    /// Contract: every HTML-significant character in interpolated text is
    /// entity-escaped so a malicious rule reason or path can never break
    /// out of element text or inject markup into the report.
    #[test]
    fn html_escape_neutralizes_markup() {
        let raw = r#"<script>alert("x&y")</script>'"#;
        let escaped = html_escape(raw);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&quot;x&amp;y&quot;)&lt;/script&gt;&#39;"
        );
    }

    #[test]
    fn html_escape_leaves_plain_text_unchanged() {
        assert_eq!(
            html_escape("OFFICIAL_REMOTE_FETCH_EXEC"),
            "OFFICIAL_REMOTE_FETCH_EXEC"
        );
    }

    #[test]
    fn verdict_rank_orders_benign_below_malicious() {
        assert!(verdict_rank(Verdict::Benign) < verdict_rank(Verdict::Suspicious));
        assert!(verdict_rank(Verdict::Suspicious) < verdict_rank(Verdict::Malicious));
    }

    #[test]
    fn css_classes_are_distinct_per_band() {
        assert_eq!(verdict_css_class(Verdict::Malicious), "v-malicious");
        assert_eq!(severity_css_class(Severity::Critical), "s-critical");
        assert_eq!(severity_css_class(Severity::Low), "s-low");
    }

    #[test]
    fn empty_results_render_valid_html_shell() {
        let html = format_html_output(&[]);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.ends_with("</body></html>"));
        assert!(html.contains("0 package(s)"));
    }
}
