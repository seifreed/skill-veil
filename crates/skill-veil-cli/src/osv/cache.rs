//! On-disk cache for OSV.dev results, with a TTL.
//!
//! Two record kinds live under `<cache-root>/osv/`:
//!   - `queries/<hash>.json` — the advisory IDs affecting one
//!     `(ecosystem, name, version)` tuple.
//!   - `details/<hash>.json` — the hydrated [`ResolvedAdvisory`] for one ID.
//!
//! Each record stores its `cached_at` timestamp; reads past `ttl` are a cache
//! miss (the caller re-queries). Writes are atomic and the directory is
//! created `0o700`, reusing the shared cache I/O helpers. A corrupt or
//! oversized entry is treated as a miss, never an error — enrichment is
//! advisory and must never break a scan.

use super::types::ResolvedAdvisory;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use skill_veil_core::Ecosystem;
use std::path::{Path, PathBuf};

use crate::util::cache_io::{read_cache_file_bounded, write_cache_file_atomic};

#[derive(Serialize, Deserialize)]
struct QueryRecord {
    cached_at: DateTime<Utc>,
    advisory_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct DetailsRecord {
    cached_at: DateTime<Utc>,
    advisory: ResolvedAdvisory,
}

pub(super) struct OsvCache {
    queries_dir: PathBuf,
    details_dir: PathBuf,
    ttl: Duration,
}

impl OsvCache {
    /// Build a cache rooted at `<cache_dir_override or dirs::cache_dir()>/skill-veil/osv`.
    /// Returns `None` when no cache directory can be resolved (no override and
    /// no platform cache dir) — the caller then runs uncached.
    pub fn new(cache_dir_override: Option<&Path>, ttl_days: i64) -> Option<Self> {
        let base = match cache_dir_override {
            Some(p) => p.to_path_buf(),
            None => dirs::cache_dir()?.join("skill-veil"),
        };
        let root = base.join("osv");
        Some(Self {
            queries_dir: root.join("queries"),
            details_dir: root.join("details"),
            ttl: Duration::days(ttl_days.max(1)),
        })
    }

    pub fn get_query(&self, eco: Ecosystem, name: &str, version: &str) -> Option<Vec<String>> {
        self.read_fresh::<QueryRecord>(&self.query_path(eco, name, version))
    }

    pub fn put_query(&self, eco: Ecosystem, name: &str, version: &str, ids: &[String]) {
        let record = QueryRecord {
            cached_at: Utc::now(),
            advisory_ids: ids.to_vec(),
        };
        self.write(&self.query_path(eco, name, version), &record);
    }

    pub fn get_details(&self, id: &str) -> Option<ResolvedAdvisory> {
        self.read_fresh::<DetailsRecord>(&self.details_path(id))
    }

    pub fn put_details(&self, id: &str, advisory: &ResolvedAdvisory) {
        let record = DetailsRecord {
            cached_at: Utc::now(),
            advisory: advisory.clone(),
        };
        self.write(&self.details_path(id), &record);
    }

    fn query_path(&self, eco: Ecosystem, name: &str, version: &str) -> PathBuf {
        let key = format!("{}|{}|{}", eco.osv_name(), name, version);
        self.queries_dir.join(format!(
            "{}.json",
            crate::util::hash::sha256_hex(key.as_bytes())
        ))
    }

    fn details_path(&self, id: &str) -> PathBuf {
        self.details_dir.join(format!(
            "{}.json",
            crate::util::hash::sha256_hex(id.as_bytes())
        ))
    }

    /// Read a record and return it only if present, parseable, and within TTL.
    /// Any failure (missing, oversized, corrupt, expired) yields `None`.
    fn read_fresh<R>(&self, path: &Path) -> Option<R::Inner>
    where
        R: for<'de> Deserialize<'de> + RecordTimestamp,
    {
        let bytes = read_cache_file_bounded(path).ok().flatten()?;
        let record: R = serde_json::from_slice(&bytes).ok()?;
        if Utc::now().signed_duration_since(record.cached_at()) > self.ttl {
            return None;
        }
        Some(record.into_inner())
    }

    fn write<T: Serialize>(&self, path: &Path, record: &T) {
        if let Ok(bytes) = serde_json::to_vec(record) {
            // Best-effort: a cache write failure must not abort enrichment.
            let _ = write_cache_file_atomic(path, &bytes);
        }
    }
}

/// Lets `read_fresh` share TTL/extraction logic across the two record types.
trait RecordTimestamp {
    type Inner;
    fn cached_at(&self) -> DateTime<Utc>;
    fn into_inner(self) -> Self::Inner;
}

impl RecordTimestamp for QueryRecord {
    type Inner = Vec<String>;
    fn cached_at(&self) -> DateTime<Utc> {
        self.cached_at
    }
    fn into_inner(self) -> Vec<String> {
        self.advisory_ids
    }
}

impl RecordTimestamp for DetailsRecord {
    type Inner = ResolvedAdvisory;
    fn cached_at(&self) -> DateTime<Utc> {
        self.cached_at
    }
    fn into_inner(self) -> ResolvedAdvisory {
        self.advisory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cache(dir: &TempDir, ttl_days: i64) -> OsvCache {
        OsvCache::new(Some(dir.path()), ttl_days).unwrap()
    }

    #[test]
    fn query_round_trips_within_ttl() {
        let dir = TempDir::new().unwrap();
        let c = cache(&dir, 30);
        assert!(c.get_query(Ecosystem::PyPI, "requests", "2.19.0").is_none());
        c.put_query(
            Ecosystem::PyPI,
            "requests",
            "2.19.0",
            &["GHSA-x".to_string()],
        );
        let got = c.get_query(Ecosystem::PyPI, "requests", "2.19.0").unwrap();
        assert_eq!(got, vec!["GHSA-x".to_string()]);
    }

    #[test]
    fn details_round_trip() {
        let dir = TempDir::new().unwrap();
        let c = cache(&dir, 30);
        let adv = ResolvedAdvisory {
            id: "GHSA-x".to_string(),
            aliases: vec!["CVE-2018-18074".to_string()],
            summary: Some("leak".to_string()),
            severity: Some("CVSS_V3:7.5".to_string()),
        };
        c.put_details("GHSA-x", &adv);
        let got = c.get_details("GHSA-x").unwrap();
        assert_eq!(got.id, "GHSA-x");
        assert_eq!(got.aliases, vec!["CVE-2018-18074".to_string()]);
    }

    #[test]
    fn expired_entry_is_a_miss() {
        // TTL clamps to >=1 day, so simulate expiry by writing a record with an
        // old timestamp directly, then reading with a 1-day TTL.
        let dir = TempDir::new().unwrap();
        let c = cache(&dir, 1);
        let path = c.query_path(Ecosystem::Npm, "lodash", "4.17.20");
        let stale = QueryRecord {
            cached_at: Utc::now() - Duration::days(5),
            advisory_ids: vec!["GHSA-stale".to_string()],
        };
        c.write(&path, &stale);
        assert!(
            c.get_query(Ecosystem::Npm, "lodash", "4.17.20").is_none(),
            "an entry older than the TTL must be treated as a miss"
        );
    }

    #[test]
    fn distinct_keys_do_not_collide() {
        let dir = TempDir::new().unwrap();
        let c = cache(&dir, 30);
        c.put_query(Ecosystem::PyPI, "requests", "2.19.0", &["A".to_string()]);
        c.put_query(Ecosystem::PyPI, "requests", "2.20.0", &["B".to_string()]);
        assert_eq!(
            c.get_query(Ecosystem::PyPI, "requests", "2.19.0").unwrap(),
            vec!["A".to_string()]
        );
        assert_eq!(
            c.get_query(Ecosystem::PyPI, "requests", "2.20.0").unwrap(),
            vec!["B".to_string()]
        );
    }
}
