//! On-disk TTL cache for registry metadata.
//!
//! One record kind under `<cache-root>/abandoned/<hash>.json` keyed by
//! `(ecosystem, name)`. Each record stores its `cached_at`; reads past `ttl`
//! are a miss. A corrupt or oversized entry is treated as a miss, never an
//! error — enrichment is advisory and must never break a scan.

use super::types::PackageMetadata;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use skill_veil_core::Ecosystem;
use std::path::{Path, PathBuf};

use crate::util::cache_io::{read_cache_file_bounded, write_cache_file_atomic};

#[derive(Serialize, Deserialize)]
struct MetadataRecord {
    cached_at: DateTime<Utc>,
    metadata: PackageMetadata,
}

pub(super) struct AbandonedCache {
    dir: PathBuf,
    ttl: Duration,
}

impl AbandonedCache {
    /// Build a cache rooted at
    /// `<cache_dir_override or dirs::cache_dir()>/skill-veil/abandoned`.
    /// Returns `None` when no cache directory can be resolved.
    pub fn new(cache_dir_override: Option<&Path>, ttl_days: i64) -> Option<Self> {
        let base = crate::util::cache_io::cache_base_dir(cache_dir_override)?;
        Some(Self {
            dir: base.join("abandoned"),
            ttl: Duration::days(ttl_days.max(1)),
        })
    }

    pub fn get(&self, eco: Ecosystem, name: &str) -> Option<PackageMetadata> {
        let bytes = read_cache_file_bounded(&self.path(eco, name))
            .ok()
            .flatten()?;
        let record: MetadataRecord = serde_json::from_slice(&bytes).ok()?;
        if Utc::now().signed_duration_since(record.cached_at) > self.ttl {
            return None;
        }
        Some(record.metadata)
    }

    pub fn put(&self, eco: Ecosystem, name: &str, metadata: &PackageMetadata) {
        let record = MetadataRecord {
            cached_at: Utc::now(),
            metadata: metadata.clone(),
        };
        if let Ok(bytes) = serde_json::to_vec(&record) {
            let _ = write_cache_file_atomic(&self.path(eco, name), &bytes);
        }
    }

    fn path(&self, eco: Ecosystem, name: &str) -> PathBuf {
        let key = format!("{}|{}", eco.osv_name(), name);
        self.dir.join(format!(
            "{}.json",
            crate::util::hash::sha256_hex(key.as_bytes())
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn meta() -> PackageMetadata {
        PackageMetadata {
            last_modified: Some(Utc::now()),
            deprecated_reason: Some("use bar".to_string()),
        }
    }

    #[test]
    fn round_trips_within_ttl() {
        let dir = TempDir::new().unwrap();
        let c = AbandonedCache::new(Some(dir.path()), 30).unwrap();
        assert!(c.get(Ecosystem::Npm, "leftpad").is_none());
        c.put(Ecosystem::Npm, "leftpad", &meta());
        let got = c.get(Ecosystem::Npm, "leftpad").unwrap();
        assert_eq!(got.deprecated_reason.as_deref(), Some("use bar"));
    }

    #[test]
    fn distinct_ecosystems_do_not_collide() {
        let dir = TempDir::new().unwrap();
        let c = AbandonedCache::new(Some(dir.path()), 30).unwrap();
        c.put(Ecosystem::Npm, "shared", &meta());
        assert!(c.get(Ecosystem::PyPI, "shared").is_none());
        assert!(c.get(Ecosystem::Npm, "shared").is_some());
    }
}
