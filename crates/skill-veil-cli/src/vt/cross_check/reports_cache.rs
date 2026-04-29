//! On-disk loader for the `.vt-reports/` cache.
//!
//! Reads every `*.json` entry, parses it into a `CachedReport`, and keys it
//! by **lowercase** SHA-256 — see `load_reports` invariant comment.

use crate::vt::types::CachedReport;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

pub(super) fn load_reports(reports_dir: &Path) -> Result<BTreeMap<String, CachedReport>> {
    let mut out = BTreeMap::new();
    if !reports_dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(reports_dir)
        .with_context(|| format!("reading {}", reports_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = match crate::util::cache_io::read_cache_file_bounded(&path) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue, // missing or over-cap → treat as no report
            Err(err) => {
                tracing::warn!(
                    "skipping VT report {} (read failed: {})",
                    path.display(),
                    err
                );
                continue;
            }
        };
        let Ok(cached) = serde_json::from_slice::<CachedReport>(&bytes) else {
            tracing::warn!("skipping unreadable VT report {}", path.display());
            continue;
        };
        // Lookup keys (`sha_for_lookup`) are guaranteed lowercase via
        // `is_sha256_hex` (rejects uppercase) and `format!("{:x}")` for
        // on-disk hashing. Cache keys MUST match that contract — a report
        // file with `"sha256": "FF00AA..."` would otherwise be stored
        // verbatim and never matched by the lookup, surfacing as `Unknown`
        // even though the report exists.
        out.insert(cached.sha256.to_ascii_lowercase(), cached);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `load_reports` MUST normalise cached SHA-256 keys to
    /// lowercase. `sha_for_lookup` always returns lowercase (validated by
    /// `is_sha256_hex` and produced by `format!("{:x}")`), so a cached
    /// report whose JSON `sha256` field is uppercase or mixed-case would
    /// never match a lookup — surfacing as `Unknown` even though the
    /// report exists. Pre-fix the insert used `cached.sha256.clone()`
    /// verbatim.
    #[test]
    fn load_reports_normalizes_uppercase_sha_to_lowercase() {
        use crate::vt::types::FileAttributes;

        let tmp = tempfile::tempdir().expect("tempdir");
        let upper = "FF".repeat(32); // 64 uppercase hex chars
        let report = CachedReport {
            sha256: upper.clone(),
            fetched_at: "2026-01-01T00:00:00Z".to_string(),
            attributes: FileAttributes::default(),
        };
        let json = serde_json::to_vec(&report).expect("serialise");
        std::fs::write(tmp.path().join("report.json"), &json).expect("write");

        let loaded = load_reports(tmp.path()).expect("load_reports");
        let lower = upper.to_ascii_lowercase();
        assert!(
            loaded.contains_key(&lower),
            "cache key must be lowercase; got keys: {:?}",
            loaded.keys().collect::<Vec<_>>()
        );
        assert!(
            !loaded.contains_key(&upper),
            "uppercase key must NOT be present; the lookup path normalises to lowercase"
        );
    }
}
