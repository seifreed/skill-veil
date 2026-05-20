//! On-disk loader for the `.vt-reports/` cache.
//!
//! Reads every `*.json` entry, parses it into a `CachedReport`, and keys it
//! by **lowercase** SHA-256 — see `load_reports` invariant comment.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::vt::types::CachedReport;

pub(super) fn load_reports(reports_dir: &Path) -> Result<BTreeMap<String, CachedReport>> {
    let mut out = BTreeMap::new();
    if !is_real_dir(reports_dir) {
        return Ok(out);
    }
    for entry in std::fs::read_dir(reports_dir)
        .with_context(|| format!("reading {}", reports_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            continue;
        }
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

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.is_dir() && !meta.is_symlink())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vt::types::FileAttributes;

    fn write_report(path: &Path, sha256: &str) {
        let report = CachedReport {
            sha256: sha256.to_string(),
            fetched_at: "2026-01-01T00:00:00Z".to_string(),
            attributes: FileAttributes::default(),
        };
        let json = serde_json::to_vec(&report).expect("serialise");
        std::fs::write(path, json).expect("write report");
    }

    /// Contract: `load_reports` MUST normalise cached SHA-256 keys to
    /// lowercase. `sha_for_lookup` always returns lowercase (validated by
    /// `is_sha256_hex` and produced by `format!("{:x}")`), so a cached
    /// report whose JSON `sha256` field is uppercase or mixed-case would
    /// never match a lookup — surfacing as `Unknown` even though the
    /// report exists. Pre-fix the insert used `cached.sha256.clone()`
    /// verbatim.
    #[test]
    fn load_reports_normalizes_uppercase_sha_to_lowercase() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let upper = "FF".repeat(32); // 64 uppercase hex chars
        write_report(&tmp.path().join("report.json"), &upper);

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

    /// # Contract
    ///
    /// A `.vt-reports` path that is itself a symlink MUST be treated as
    /// absent. Cross-check consumes local corpus directories that can be
    /// untrusted; following a cache-dir symlink would let that corpus
    /// point report loading at arbitrary operator files.
    #[cfg(unix)]
    #[test]
    fn load_reports_rejects_symlinked_reports_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real-reports");
        let link = tmp.path().join(".vt-reports");
        std::fs::create_dir(&real).unwrap();
        write_report(&real.join("report.json"), &"a".repeat(64));
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let loaded = load_reports(&link).expect("load_reports");

        assert!(loaded.is_empty());
    }

    /// # Contract
    ///
    /// Symlinked `*.json` entries inside a real reports directory MUST
    /// be skipped. A cache entry is data only when the directory entry
    /// itself is a regular file.
    #[cfg(unix)]
    #[test]
    fn load_reports_skips_symlinked_json_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let reports = tmp.path().join("reports");
        std::fs::create_dir(&reports).unwrap();
        let real = reports.join("real.json");
        let outside = tmp.path().join("outside.json");
        let link = reports.join("link.json");
        write_report(&real, &"a".repeat(64));
        write_report(&outside, &"b".repeat(64));
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let loaded = load_reports(&reports).expect("load_reports");

        assert!(loaded.contains_key(&"a".repeat(64)));
        assert!(!loaded.contains_key(&"b".repeat(64)));
        assert_eq!(loaded.len(), 1);
    }
}
