//! `scan-package` integration for the local PromptIntel feed cache.
//!
//! Mirrors `commands::scan::vt::try_enrich_with_vt` but works fully
//! offline: the lookup hits the cache populated by
//! `skill-veil promptintel feed sync`, never the live API. Operators
//! who want fresh intel re-run the sync command on whatever cadence
//! their rate-limit budget allows.

use crate::promptintel::feed::enrich::{enrich, PromptIntelEnrichment};
use crate::util::terminal_safe::sanitise_for_terminal;
use anyhow::Result;
use skill_veil_core::PackageScanResult;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub(super) fn try_enrich_with_promptintel(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    cache_dir_override: Option<&Path>,
    quiet: bool,
) -> Result<Option<String>> {
    let cache_root = match resolve_cache_root(cache_dir_override, scan_path) {
        Ok(root) => root,
        Err(err) => {
            if !quiet {
                eprintln!("PromptIntel feed enrichment skipped: {err:#}");
            }
            return Ok(None);
        }
    };
    let consolidated = consolidate_iocs(scan_result.results.iter().map(|r| &r.extracted_iocs));
    let enrichment = enrich(&cache_root, &consolidated);

    match enrichment.cache_total_entries {
        None => {
            // No cache: surface a single-line hint so operators know the
            // enrichment exists and how to enable it. Stderr stays
            // silent so JSON / SARIF pipelines aren't polluted.
            if !quiet {
                eprintln!(
                    "PromptIntel feed enrichment skipped: cache missing. \
                     Run `skill-veil promptintel feed sync`."
                );
            }
            Ok(None)
        }
        Some(_) if enrichment.is_empty() => Ok(None),
        Some(_) => Ok(Some(format_enrichment(&enrichment))),
    }
}

fn resolve_cache_root(override_dir: Option<&Path>, scan_path: &Path) -> Result<PathBuf> {
    resolve_cache_root_from_user_cache(override_dir, scan_path, dirs::cache_dir())
}

fn resolve_cache_root_from_user_cache(
    override_dir: Option<&Path>,
    scan_path: &Path,
    user_cache: Option<PathBuf>,
) -> Result<PathBuf> {
    super::cache::cache_base_dir_from_user_cache(override_dir, scan_path, user_cache)
}

fn consolidate_iocs<'a>(
    sources: impl IntoIterator<Item = &'a skill_veil_core::ExtractedIocs>,
) -> skill_veil_core::ExtractedIocs {
    use skill_veil_core::{ExtractedIocs, FileHash};
    use std::collections::{BTreeMap, BTreeSet};
    let mut urls = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    let mut file_hashes: BTreeMap<String, FileHash> = BTreeMap::new();
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

fn format_enrichment(enrichment: &PromptIntelEnrichment) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n=== PromptIntel Feed Enrichment (informational; does not affect skill-veil verdict) ==="
    );
    let cache_total = enrichment.cache_total_entries.unwrap_or(0);
    let _ = writeln!(
        out,
        "matches: {} / {} cached feed entries",
        enrichment.matches.len(),
        cache_total,
    );
    for m in &enrichment.matches {
        let _ = writeln!(
            out,
            "\n  [{sev}] {action:<16} {id}\n    title       : {title}\n    category    : {category}\n    confidence  : {conf}",
            sev = m.entry.severity.as_str(),
            action = format!("{:?}", m.entry.action).to_lowercase(),
            id = sanitise_for_terminal(&m.entry.id),
            title = sanitise_for_terminal(&m.entry.title),
            category = sanitise_for_terminal(&m.entry.category),
            conf = m
                .entry
                .confidence
                .map_or_else(|| "n/a".to_string(), |c| format!("{c:.2}")),
        );
        if let Some(rec) = &m.entry.recommendation_agent {
            let _ = writeln!(out, "    rec         : {}", sanitise_for_terminal(rec));
        }
        for (kind, values) in &m.matched_indicators {
            let joined = values
                .iter()
                .map(|v| sanitise_for_terminal(v))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "    matched {:<5}: {joined}", kind);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::promptintel::types::PromptSeverity;

    /// # Contract
    ///
    /// PromptIntel scan enrichment must not fall back to the shared
    /// system temp directory when the OS user cache is unavailable.
    #[test]
    fn resolve_cache_root_rejects_missing_user_cache_without_override() {
        let tmp = tempfile::tempdir().unwrap();
        let scan_path = tmp.path().join("scan-target");
        std::fs::create_dir_all(&scan_path).unwrap();

        let err = resolve_cache_root_from_user_cache(None, &scan_path, None).unwrap_err();

        assert!(format!("{err:#}").contains("pass --cache-dir"));
    }

    /// # Contract
    ///
    /// A verified override outside the scan path remains accepted even
    /// when the OS user cache is unavailable.
    #[test]
    fn resolve_cache_root_accepts_override_without_user_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let scan_path = tmp.path().join("scan-target");
        let override_dir = tmp.path().join("promptintel-cache");
        std::fs::create_dir_all(&scan_path).unwrap();
        std::fs::create_dir_all(&override_dir).unwrap();

        let resolved =
            resolve_cache_root_from_user_cache(Some(&override_dir), &scan_path, None).unwrap();

        assert_eq!(resolved, override_dir);
    }

    #[test]
    fn format_enrichment_sanitises_feed_entry_id() {
        let enrichment = PromptIntelEnrichment {
            cache_total_entries: Some(1),
            matches: vec![crate::promptintel::feed::enrich::EnrichmentMatch {
                entry: crate::promptintel::types::FeedEntry {
                    id: "id\x1b]8;;https://evil.invalid\x07click".to_string(),
                    fingerprint: None,
                    category: "credential".to_string(),
                    severity: PromptSeverity::High,
                    confidence: Some(1.0),
                    action: crate::promptintel::types::FeedAction::Block,
                    title: "Title".to_string(),
                    description: None,
                    source: None,
                    source_identifier: None,
                    recommendation_agent: None,
                    iocs: Vec::new(),
                    expires_at: None,
                    revoked_at: None,
                    created_at: None,
                    revoked: false,
                },
                matched_indicators: std::collections::BTreeMap::new(),
            }],
        };

        let rendered = format_enrichment(&enrichment);

        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\x07'));
    }
}
