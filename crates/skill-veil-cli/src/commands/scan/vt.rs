use super::cache::cache_root_for;
use super::ERROR_MESSAGE_DISPLAY_CHARS;
use crate::util::terminal_safe::sanitise_for_terminal;
use crate::vt::client::VtClient;
use crate::vt::config::VtConfig;
use crate::vt::enrich::{self, EnrichOptions, EnrichedIndicator, EnrichmentStatus, VtEnrichment};
use anyhow::Result;
use skill_veil_core::PackageScanResult;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub(super) fn try_enrich_with_vt(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    submit_unknown: bool,
    cache_dir_override: Option<&Path>,
    quiet: bool,
) -> Result<Option<String>> {
    // Distinguish "not configured" from "configured but broken". Pre-fix
    // every load failure was collapsed to `Ok(None)` so a malformed
    // `~/.vt.toml`, a `chmod 000` lockdown, an empty `apikey` field, or a
    // bad TOML parse all looked exactly like "no apikey" — operators got
    // zero feedback that their VT enrichment had quietly fallen off. The
    // explicit `vt` subcommand still uses `load()` and surfaces the
    // guidance message; the auto-enrichment path uses `load_optional()`
    // and warns on real errors instead of swallowing them.
    let config = match VtConfig::load_optional() {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return Ok(None),
        Err(err) => {
            if !quiet {
                eprintln!("VT enrichment skipped: {err:#}");
            }
            return Ok(None);
        }
    };
    let cache_root = match cache_root_for(scan_path, cache_dir_override) {
        Ok(root) => root,
        Err(err) => {
            if !quiet {
                eprintln!("VT enrichment skipped: {err:#}");
            }
            return Ok(None);
        }
    };
    let client = VtClient::new(config);
    let opts = EnrichOptions {
        cache_root,
        submit_unknown,
        ..EnrichOptions::new(PathBuf::new())
    };

    // Consolidate IOCs across every scan result before issuing VT lookups.
    // Without this, a URL or domain that appears in N artifacts would
    // produce N redundant API calls (the cache root is per-scan, so the
    // file-backed cache only helps across separate runs, not within one).
    let consolidated =
        super::enrichment::consolidate_iocs(scan_result.results.iter().map(|r| &r.extracted_iocs));
    if consolidated.is_empty() {
        return Ok(None);
    }
    let enrichment = match enrich::enrich_iocs(&client, &consolidated, &opts) {
        Ok(e) => e,
        Err(e) => {
            if !quiet {
                eprintln!("VT enrichment warning: {e:#}");
            }
            return Ok(None);
        }
    };

    let aggregate = VtEnrichment {
        files: dedupe_indicators(enrichment.files),
        domains: dedupe_indicators(enrichment.domains),
        ips: dedupe_indicators(enrichment.ips),
        urls: dedupe_indicators(enrichment.urls),
    };

    if aggregate.files.is_empty()
        && aggregate.domains.is_empty()
        && aggregate.ips.is_empty()
        && aggregate.urls.is_empty()
    {
        return Ok(None);
    }

    Ok(Some(format_vt_enrichment(&aggregate)))
}

fn dedupe_indicators(list: Vec<EnrichedIndicator>) -> Vec<EnrichedIndicator> {
    let mut by_indicator: std::collections::BTreeMap<String, EnrichedIndicator> =
        std::collections::BTreeMap::new();
    for item in list {
        by_indicator.entry(item.indicator.clone()).or_insert(item);
    }
    by_indicator.into_values().collect()
}

fn format_vt_enrichment(agg: &VtEnrichment) -> String {
    let mut out = String::new();
    out.push_str(&super::enrichment::enrichment_banner(
        "VirusTotal Enrichment",
    ));
    let _ = writeln!(
        out,
        "  files={} domains={} ips={} urls={}",
        agg.files.len(),
        agg.domains.len(),
        agg.ips.len(),
        agg.urls.len()
    );

    fn format_kind(label: &str, items: &[EnrichedIndicator], out: &mut String) {
        if items.is_empty() {
            return;
        }
        let _ = writeln!(out, "\n  {label}:");
        for ind in items {
            // `ind.indicator` is a URL/domain/IP/hash extracted from
            // attacker-controlled skill content. The error `message`,
            // VT `ai_verdicts.source` and `verdict` strings come from
            // a remote provider that the operator does not fully
            // control. Both have to pass `sanitise_for_terminal` before
            // hitting the TTY — pre-fix a crafted URL embedding
            // `\x1b[2J\x1b[H` could clear the terminal and repaint a
            // fake verdict, and the same vector reached the operator
            // through `ai_verdicts` from a compromised provider
            // response. The text-output formatter already enforced
            // this for `finding.match_value` / `finding.artifact_path`;
            // VT enrichment was the parallel surface that bypassed it.
            let status = match &ind.status {
                EnrichmentStatus::Found => "found".to_string(),
                EnrichmentStatus::NotFound => "not_found".to_string(),
                EnrichmentStatus::Submitted { .. } => "submitted".to_string(),
                EnrichmentStatus::Error { message } => {
                    format!(
                        "error: {}",
                        sanitise_for_terminal(
                            &message
                                .chars()
                                .take(ERROR_MESSAGE_DISPLAY_CHARS)
                                .collect::<String>()
                        )
                    )
                }
            };
            let summary = ind
                .summary
                .as_ref()
                .map(|s| {
                    let stats = s.last_analysis_stats.clone().unwrap_or_default();
                    let ai = s
                        .ai_verdicts
                        .iter()
                        .map(|a| {
                            format!(
                                "{}={}",
                                sanitise_for_terminal(&a.source),
                                sanitise_for_terminal(&a.verdict),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    let rep = s
                        .reputation
                        .map(|r| format!(" rep={r}"))
                        .unwrap_or_default();
                    format!(
                        " mal={} susp={} harmless={}{}{}",
                        stats.malicious,
                        stats.suspicious,
                        stats.harmless,
                        rep,
                        if ai.is_empty() {
                            "".to_string()
                        } else {
                            format!(" ai=[{ai}]")
                        }
                    )
                })
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "    - {} [{status}]{}",
                sanitise_for_terminal(&ind.indicator),
                summary
            );
        }
    }

    format_kind("Files", &agg.files, &mut out);
    format_kind("Domains", &agg.domains, &mut out);
    format_kind("IPs", &agg.ips, &mut out);
    format_kind("URLs", &agg.urls, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::vt::enrich::VtIndicatorSummary;
    use crate::vt::types::{CrowdsourcedAiResult, LastAnalysisStats};

    fn enriched_url(indicator: &str, message: Option<&str>) -> EnrichedIndicator {
        EnrichedIndicator {
            indicator: indicator.to_string(),
            cache_path: PathBuf::from("/tmp/x"),
            fetched_at: chrono::Utc::now(),
            status: match message {
                Some(m) => EnrichmentStatus::Error {
                    message: m.to_string(),
                },
                None => EnrichmentStatus::Found,
            },
            summary: None,
        }
    }

    /// Contract: `format_vt_enrichment` MUST run every
    /// attacker-controlled string through `sanitise_for_terminal`
    /// before it reaches the operator's TTY. Pre-fix `ind.indicator`,
    /// the truncated error `message`, and the VT-supplied
    /// `ai_verdicts.{source, verdict}` strings were written verbatim,
    /// so a crafted IOC like
    /// `https://evil.invalid/\x1b[2J\x1b[H` would clear the terminal
    /// and let an attacker repaint a fake passing verdict. The
    /// text-output formatter already enforced the boundary for
    /// `finding.match_value` / `finding.artifact_path`; VT enrichment
    /// was the parallel surface that bypassed it.
    #[test]
    fn format_vt_enrichment_strips_ansi_control_bytes_from_indicators() {
        let agg = VtEnrichment {
            files: Vec::new(),
            domains: vec![enriched_url("evil.invalid\x1b[2J\x1b[H", None)],
            ips: Vec::new(),
            urls: vec![enriched_url("https://e\x07vil.invalid/x", None)],
        };
        let rendered = format_vt_enrichment(&agg);
        assert!(
            !rendered.contains('\x1b'),
            "ESC byte must not reach the terminal stream; got: {rendered:?}"
        );
        assert!(
            !rendered.contains('\x07'),
            "BEL byte must not reach the terminal stream; got: {rendered:?}"
        );
        // Visible content is preserved (just neutralised) so the
        // operator still sees the indicator.
        assert!(rendered.contains("evil.invalid"));
    }

    /// Contract: error messages and AI verdicts coming back from VT
    /// (semi-trusted) MUST also pass through the sanitiser. A
    /// compromised provider response embedding control bytes would
    /// otherwise bypass the same protection at a different code
    /// path. Pin the contract here so a future refactor that adds a
    /// new VT-derived display string is forced to route it through
    /// the same boundary.
    #[test]
    fn format_vt_enrichment_strips_control_bytes_from_provider_strings() {
        let stats = LastAnalysisStats {
            malicious: 1,
            ..LastAnalysisStats::default()
        };
        let ai_verdict = CrowdsourcedAiResult {
            source: "src\x1b[H".to_string(),
            verdict: "malicious\x07".to_string(),
            ..CrowdsourcedAiResult::default()
        };
        let summary = VtIndicatorSummary {
            last_analysis_stats: Some(stats),
            reputation: None,
            categories: std::collections::BTreeMap::new(),
            meaningful_name: None,
            type_description: None,
            ai_verdicts: vec![ai_verdict],
            vt_malicious_engine_count: 1,
            vt_suspicious_engine_count: 0,
        };

        let agg = VtEnrichment {
            files: Vec::new(),
            domains: vec![EnrichedIndicator {
                indicator: "evil.invalid".to_string(),
                cache_path: PathBuf::from("/tmp/x"),
                fetched_at: chrono::Utc::now(),
                status: EnrichmentStatus::Error {
                    message: "boom\x1b[31m".to_string(),
                },
                summary: Some(summary),
            }],
            ips: Vec::new(),
            urls: Vec::new(),
        };
        let rendered = format_vt_enrichment(&agg);
        assert!(
            !rendered.contains('\x1b'),
            "ESC bytes from VT response must be sanitised; got: {rendered:?}"
        );
        assert!(
            !rendered.contains('\x07'),
            "BEL bytes from VT response must be sanitised; got: {rendered:?}"
        );
    }
}
