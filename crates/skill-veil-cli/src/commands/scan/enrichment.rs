//! Shared helpers for the post-scan external-enrichment channels (VT and
//! PromptIntel): IOC consolidation before issuing lookups, and the common
//! output banner that marks a section as informational-only.

use skill_veil_core::{ExtractedIocs, FileHash};
use std::collections::{BTreeMap, BTreeSet};

/// Merge multiple `ExtractedIocs` into a single deduplicated bundle. Used
/// before issuing enrichment lookups so the same indicator
/// (URL/domain/IP/hash) shared by N artifacts triggers a single lookup
/// instead of N.
pub(super) fn consolidate_iocs<'a>(
    sources: impl IntoIterator<Item = &'a ExtractedIocs>,
) -> ExtractedIocs {
    let mut urls = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    // FileHash is Eq but not Hash/Ord; dedupe via sha256 string key.
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

/// Banner line opening an enrichment section. The
/// "(informational; does not affect skill-veil verdict)" disclaimer is
/// single-sourced here: it states a verdict-policy guarantee operators
/// rely on, so every enrichment channel must phrase it identically.
pub(super) fn enrichment_banner(title: &str) -> String {
    format!("\n=== {title} (informational; does not affect skill-veil verdict) ===\n")
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn enrichment_banner_includes_informational_disclaimer() {
        let banner = enrichment_banner("VirusTotal Enrichment");

        assert!(banner.contains("VirusTotal Enrichment"));
        assert!(banner.contains("informational; does not affect skill-veil verdict"));
    }
}
