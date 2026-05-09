//! Match scan-extracted IOCs against the local PromptIntel feed cache.
//!
//! # Architectural invariant — DO NOT BREAK
//!
//! Mirrors the contract from `vt::enrich`: PromptIntel enrichment is
//! strictly additive. It NEVER mutates the scanner's verdict, risk
//! score, or finding set. The `enrich` function takes
//! `&ExtractedIocs` (read-only) and returns a fresh
//! [`PromptIntelEnrichment`]. Callers render both sides separately;
//! threading feed matches back into `ScanResult` would erase both
//! reproducibility (offline runs would diverge from feed-enriched
//! ones) and auditability (the operator could no longer compare
//! local-only verdicts against the upstream feed without re-running
//! the scanner).

use super::store::{FeedStore, IocIndex};
use crate::promptintel::types::FeedEntry;
use serde::Serialize;
use skill_veil_core::ExtractedIocs;
use std::collections::BTreeMap;
use std::path::Path;

/// Aggregated enrichment for one scan: every IOC from the scan that
/// matched at least one feed entry, grouped by entry.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct PromptIntelEnrichment {
    /// Entries the scan IOCs matched. Sorted by severity descending,
    /// then by id, so the rendered block surfaces the highest-leverage
    /// matches first.
    pub(crate) matches: Vec<EnrichmentMatch>,
    /// Total entries in the local cache when this enrichment ran.
    /// `None` when the cache is missing — the operator has not run
    /// `feed sync`.
    pub(crate) cache_total_entries: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EnrichmentMatch {
    pub(crate) entry: FeedEntry,
    /// Which scan-extracted indicator values triggered this match,
    /// keyed by indicator kind (`hash`, `ip`, `domain`, `url`).
    pub(crate) matched_indicators: BTreeMap<String, Vec<String>>,
}

impl PromptIntelEnrichment {
    pub(crate) fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }
}

/// Look up `iocs` against the cached feed. A missing cache returns an
/// empty enrichment with `cache_total_entries: None` so the renderer
/// can prompt the operator to run `feed sync`.
pub(crate) fn enrich(cache_root: &Path, iocs: &ExtractedIocs) -> PromptIntelEnrichment {
    let store = match FeedStore::load(cache_root) {
        Ok(s) if s.entries.is_empty() && s.meta.is_none() => {
            return PromptIntelEnrichment::default();
        }
        Ok(s) => s,
        Err(err) => {
            tracing::warn!("PromptIntel feed cache unreadable: {err}");
            return PromptIntelEnrichment::default();
        }
    };

    let index = store.build_index();
    let mut entry_by_id: std::collections::HashMap<&str, &FeedEntry> =
        store.active_entries().map(|e| (e.id.as_str(), e)).collect();
    let mut hits: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();

    record_matches(&iocs.file_hashes_values(), "hash", &index, &mut hits);
    record_matches(&iocs.ipv4, "ip", &index, &mut hits);
    record_matches(&iocs.ipv6, "ip", &index, &mut hits);
    record_matches(&iocs.domains, "domain", &index, &mut hits);
    record_matches(&iocs.urls, "url", &index, &mut hits);

    let mut matches: Vec<EnrichmentMatch> = hits
        .into_iter()
        .filter_map(|(entry_id, matched)| {
            entry_by_id
                .remove(entry_id.as_str())
                .map(|entry| EnrichmentMatch {
                    entry: entry.clone(),
                    matched_indicators: matched,
                })
        })
        .collect();

    matches.sort_by(|a, b| {
        severity_rank(b.entry.severity)
            .cmp(&severity_rank(a.entry.severity))
            .then_with(|| a.entry.id.cmp(&b.entry.id))
    });

    PromptIntelEnrichment {
        matches,
        cache_total_entries: Some(store.entries.len()),
    }
}

fn record_matches(
    values: &[String],
    kind: &'static str,
    index: &IocIndex,
    hits: &mut BTreeMap<String, BTreeMap<String, Vec<String>>>,
) {
    for v in values {
        let entries: &[String] = match kind {
            "hash" => index.lookup_hash(v),
            "ip" => index.lookup_ip(v),
            "domain" => index.lookup_domain(v),
            "url" => index.lookup_url(v),
            _ => &[],
        };
        for entry_id in entries {
            hits.entry(entry_id.clone())
                .or_default()
                .entry(kind.to_string())
                .or_default()
                .push(v.clone());
        }
    }
}

fn severity_rank(s: crate::promptintel::types::PromptSeverity) -> u8 {
    use crate::promptintel::types::PromptSeverity::*;
    match s {
        Critical => 4,
        High => 3,
        Medium => 2,
        Low => 1,
    }
}

/// Helper that lifts `Vec<FileHash>` to a flat `Vec<String>` of
/// hash hex digests for the IOC matcher.
trait FileHashesValues {
    fn file_hashes_values(&self) -> Vec<String>;
}

impl FileHashesValues for ExtractedIocs {
    fn file_hashes_values(&self) -> Vec<String> {
        self.file_hashes.iter().map(|h| h.sha256.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::promptintel::feed::store::FeedStore;
    use crate::promptintel::types::{FeedAction, FeedIoc, FeedIocKind, PromptSeverity};
    use skill_veil_core::FileHash;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn entry(id: &str, sev: PromptSeverity, iocs: Vec<FeedIoc>) -> FeedEntry {
        FeedEntry {
            id: id.to_string(),
            fingerprint: None,
            category: "test".to_string(),
            severity: sev,
            confidence: Some(1.0),
            action: FeedAction::Block,
            title: id.to_string(),
            description: None,
            source: None,
            source_identifier: None,
            recommendation_agent: None,
            iocs,
            expires_at: None,
            revoked_at: None,
            created_at: None,
            revoked: false,
        }
    }

    fn ioc(kind: FeedIocKind, value: &str) -> FeedIoc {
        FeedIoc {
            kind,
            value: value.to_string(),
        }
    }

    /// Missing cache: enrichment is empty AND `cache_total_entries`
    /// stays `None` so the renderer can prompt the operator to run
    /// `feed sync`.
    #[test]
    fn missing_cache_yields_empty_enrichment_with_none_total() {
        let tmp = tempdir().unwrap();
        let scanned = ExtractedIocs::default();
        let result = enrich(tmp.path(), &scanned);
        assert!(result.matches.is_empty());
        assert_eq!(result.cache_total_entries, None);
    }

    /// A scan that produces no IOCs MUST still consult the cache so
    /// the rendered block can confirm "0 matches across N feed
    /// entries"; an empty match set with a populated cache reads
    /// differently from a missing cache.
    #[test]
    fn empty_scan_iocs_against_populated_cache_returns_zero_matches_with_total() {
        let tmp = tempdir().unwrap();
        FeedStore::save(
            tmp.path(),
            &[entry(
                "a",
                PromptSeverity::High,
                vec![ioc(FeedIocKind::Hash, "deadbeef")],
            )],
        )
        .unwrap();

        let result = enrich(tmp.path(), &ExtractedIocs::default());
        assert!(result.matches.is_empty());
        assert_eq!(result.cache_total_entries, Some(1));
    }

    /// Hash hit: scan emits sha256 lowercase hex; feed stores the
    /// same hash with a `sha256:` prefix and uppercase. The
    /// normalisation in `IocIndex` MUST collapse both into a hit.
    #[test]
    fn hash_match_normalises_prefix_and_case() {
        let tmp = tempdir().unwrap();
        FeedStore::save(
            tmp.path(),
            &[entry(
                "h",
                PromptSeverity::Critical,
                vec![ioc(FeedIocKind::Hash, "sha256:DEADBEEFCAFE")],
            )],
        )
        .unwrap();

        let scanned = ExtractedIocs {
            file_hashes: vec![FileHash {
                path: PathBuf::from("foo.py"),
                sha256: "deadbeefcafe".to_string(),
            }],
            ..ExtractedIocs::default()
        };
        let result = enrich(tmp.path(), &scanned);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].entry.id, "h");
        assert!(result.matches[0]
            .matched_indicators
            .get("hash")
            .is_some_and(|v| v.contains(&"deadbeefcafe".to_string())));
    }

    /// Multiple matches MUST sort by severity descending so the
    /// rendered block surfaces the highest-leverage entry first.
    #[test]
    fn multiple_matches_sort_by_severity_descending() {
        let tmp = tempdir().unwrap();
        FeedStore::save(
            tmp.path(),
            &[
                entry(
                    "low",
                    PromptSeverity::Low,
                    vec![ioc(FeedIocKind::Ip, "1.1.1.1")],
                ),
                entry(
                    "crit",
                    PromptSeverity::Critical,
                    vec![ioc(FeedIocKind::Ip, "2.2.2.2")],
                ),
                entry(
                    "high",
                    PromptSeverity::High,
                    vec![ioc(FeedIocKind::Ip, "3.3.3.3")],
                ),
            ],
        )
        .unwrap();

        let scanned = ExtractedIocs {
            ipv4: vec![
                "1.1.1.1".to_string(),
                "2.2.2.2".to_string(),
                "3.3.3.3".to_string(),
            ],
            ..ExtractedIocs::default()
        };
        let result = enrich(tmp.path(), &scanned);
        let ids: Vec<_> = result.matches.iter().map(|m| m.entry.id.clone()).collect();
        assert_eq!(ids, vec!["crit", "high", "low"]);
    }

    /// A revoked entry MUST never produce a match even if its IOCs
    /// would otherwise hit. Pre-fix this would surface stale C2
    /// addresses as live findings.
    #[test]
    fn revoked_entries_do_not_match() {
        let tmp = tempdir().unwrap();
        let mut revoked = entry(
            "rev",
            PromptSeverity::High,
            vec![ioc(FeedIocKind::Domain, "evil.example")],
        );
        revoked.revoked = true;
        FeedStore::save(tmp.path(), &[revoked]).unwrap();

        let scanned = ExtractedIocs {
            domains: vec!["evil.example".to_string()],
            ..ExtractedIocs::default()
        };
        let result = enrich(tmp.path(), &scanned);
        assert!(result.matches.is_empty());
        assert_eq!(result.cache_total_entries, Some(1));
    }
}
