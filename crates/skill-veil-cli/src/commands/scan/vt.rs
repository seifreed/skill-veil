use super::cache::cache_root_for;
use super::ERROR_MESSAGE_DISPLAY_CHARS;
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
    let Ok(config) = VtConfig::load() else {
        return Ok(None); // no apikey configured → silent skip
    };
    let client = VtClient::new(config);
    let cache_root = cache_root_for(scan_path, cache_dir_override);
    let opts = EnrichOptions {
        cache_root,
        submit_unknown,
        ..EnrichOptions::new(PathBuf::new())
    };

    // Consolidate IOCs across every scan result before issuing VT lookups.
    // Without this, a URL or domain that appears in N artifacts would
    // produce N redundant API calls (the cache root is per-scan, so the
    // file-backed cache only helps across separate runs, not within one).
    let consolidated = consolidate_iocs(scan_result.results.iter().map(|r| &r.extracted_iocs));
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

/// Merge multiple `ExtractedIocs` into a single deduplicated bundle. Used
/// before issuing VT lookups so the same indicator (URL/domain/IP/hash)
/// shared by N artifacts triggers a single API call instead of N.
fn consolidate_iocs<'a>(
    sources: impl IntoIterator<Item = &'a skill_veil_core::ExtractedIocs>,
) -> skill_veil_core::ExtractedIocs {
    use skill_veil_core::{ExtractedIocs, FileHash};
    use std::collections::BTreeSet;
    let mut urls = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    // FileHash is Eq but not Hash/Ord; dedupe via sha256 string key.
    let mut file_hashes: std::collections::BTreeMap<String, FileHash> =
        std::collections::BTreeMap::new();
    for iocs in sources {
        urls.extend(iocs.urls.iter().cloned());
        domains.extend(iocs.domains.iter().cloned());
        ipv4.extend(iocs.ipv4.iter().cloned());
        ipv6.extend(iocs.ipv6.iter().cloned());
        for fh in &iocs.file_hashes {
            file_hashes
                .entry(fh.sha256.clone())
                .or_insert_with(|| fh.clone());
        }
    }
    ExtractedIocs {
        urls: urls.into_iter().collect(),
        domains: domains.into_iter().collect(),
        ipv4: ipv4.into_iter().collect(),
        ipv6: ipv6.into_iter().collect(),
        file_hashes: file_hashes.into_values().collect(),
    }
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
    let _ = writeln!(
        out,
        "\n=== VirusTotal Enrichment (informational; does not affect skill-veil verdict) ==="
    );
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
            let status = match &ind.status {
                EnrichmentStatus::Found => "found".to_string(),
                EnrichmentStatus::NotFound => "not_found".to_string(),
                EnrichmentStatus::Submitted { .. } => "submitted".to_string(),
                EnrichmentStatus::Error { message } => {
                    format!(
                        "error: {}",
                        message
                            .chars()
                            .take(ERROR_MESSAGE_DISPLAY_CHARS)
                            .collect::<String>()
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
                        .map(|a| format!("{}={}", a.source, a.verdict))
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
            let _ = writeln!(out, "    - {} [{status}]{}", ind.indicator, summary);
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
    use skill_veil_core::{ExtractedIocs, FileHash};
    use std::path::PathBuf;

    #[test]
    fn consolidate_iocs_deduplicates_across_results() {
        let a = ExtractedIocs {
            urls: vec![
                "https://evil.com/x".to_string(),
                "https://example.org".to_string(),
            ],
            domains: vec!["evil.com".to_string()],
            ipv4: vec!["10.0.0.1".to_string()],
            ipv6: Vec::new(),
            file_hashes: vec![FileHash {
                path: PathBuf::from("a.py"),
                sha256: "deadbeef".to_string(),
            }],
        };
        let b = ExtractedIocs {
            urls: vec!["https://evil.com/x".to_string()], // dup of a
            domains: vec!["evil.com".to_string()],        // dup of a
            ipv4: vec!["10.0.0.2".to_string()],
            ipv6: Vec::new(),
            file_hashes: vec![FileHash {
                path: PathBuf::from("b.py"),
                sha256: "deadbeef".to_string(), // dup sha256 of a
            }],
        };
        let merged = consolidate_iocs([&a, &b]);
        assert_eq!(merged.urls.len(), 2, "duplicate URL must collapse");
        assert_eq!(merged.domains.len(), 1);
        assert_eq!(merged.ipv4.len(), 2);
        assert_eq!(merged.file_hashes.len(), 1, "same sha256 collapses");
    }
}
