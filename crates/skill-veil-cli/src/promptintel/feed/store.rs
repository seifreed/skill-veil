//! On-disk PromptIntel feed cache and lookup index.
//!
//! The cache is a flat directory:
//!
//! ```text
//! <cache_root>/promptintel-feed/
//!   feed.json   ← Vec<FeedEntry> (the canonical store)
//!   meta.json   ← FeedMeta { last_sync, source, total_entries }
//! ```
//!
//! `IocIndex` is built from the entries on demand and lookups are
//! `O(1)` on the indicator value (case-insensitive on hostnames /
//! file paths).

use crate::{
    promptintel::types::{FeedEntry, FeedIoc, FeedIocKind},
    util::{
        cache_io::{read_cache_file_with_cap, MAX_CACHE_FILE_BYTES},
        secure_fs::create_dir_secure,
    },
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const FEED_FILENAME: &str = "feed.json";
const META_FILENAME: &str = "meta.json";

/// Provenance + freshness metadata for the cached feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FeedMeta {
    pub(crate) last_sync: DateTime<Utc>,
    pub(crate) source: String,
    pub(crate) total_entries: usize,
}

impl FeedMeta {
    pub(crate) fn new(total_entries: usize) -> Self {
        Self {
            last_sync: Utc::now(),
            source: "https://api.promptintel.novahunting.ai/api/v1/agent-feed".to_string(),
            total_entries,
        }
    }
}

/// Materialised feed loaded from disk, with an IOC lookup index.
#[derive(Debug, Clone)]
pub(crate) struct FeedStore {
    pub(crate) entries: Vec<FeedEntry>,
    pub(crate) meta: Option<FeedMeta>,
}

impl FeedStore {
    /// Load the feed and metadata from `<cache_root>/promptintel-feed/`.
    /// A missing cache returns an empty store rather than an error so
    /// the enrichment path can no-op silently when the operator has
    /// not run `feed sync` yet.
    pub(crate) fn load(cache_root: &Path) -> Result<Self> {
        Self::load_with_cap(cache_root, MAX_CACHE_FILE_BYTES)
    }

    fn load_with_cap(cache_root: &Path, cap: u64) -> Result<Self> {
        if !real_dir_exists_for_read(cache_root)? {
            return Ok(Self {
                entries: Vec::new(),
                meta: None,
            });
        }
        let dir = feed_dir(cache_root);
        if !real_dir_exists_for_read(&dir)? {
            return Ok(Self {
                entries: Vec::new(),
                meta: None,
            });
        }
        let feed_path = dir.join(FEED_FILENAME);
        let meta_path = dir.join(META_FILENAME);

        let Some(feed_bytes) = read_cache_file_with_cap(&feed_path, cap)? else {
            return Ok(Self {
                entries: Vec::new(),
                meta: None,
            });
        };
        let entries: Vec<FeedEntry> = serde_json::from_slice(&feed_bytes)
            .with_context(|| format!("parsing {}", feed_path.display()))?;

        let meta = match read_cache_file_with_cap(&meta_path, cap)? {
            Some(meta_bytes) => Some(
                serde_json::from_slice::<FeedMeta>(&meta_bytes)
                    .with_context(|| format!("parsing {}", meta_path.display()))?,
            ),
            None => None,
        };

        Ok(Self { entries, meta })
    }

    /// Persist `entries` and a fresh `FeedMeta` atomically: write to a
    /// `.tmp` sibling and rename, so a crash mid-write never leaves a
    /// partial cache that the next load would treat as authoritative.
    pub(crate) fn save(cache_root: &Path, entries: &[FeedEntry]) -> Result<FeedMeta> {
        let dir = prepare_feed_cache_dir(cache_root)?;

        let feed_path = dir.join(FEED_FILENAME);
        let meta_path = dir.join(META_FILENAME);
        let meta = FeedMeta::new(entries.len());

        write_atomic(
            &feed_path,
            serde_json::to_vec_pretty(entries).context("serialising feed entries")?,
        )?;
        write_atomic(
            &meta_path,
            serde_json::to_vec_pretty(&meta).context("serialising feed meta")?,
        )?;

        Ok(meta)
    }

    /// Filter out revoked entries. Expired entries (`expires_at <
    /// now`) are KEPT — historical IOCs still match real-world reuse
    /// and the curator's `revoked` flag is the authoritative
    /// retract signal.
    pub(crate) fn active_entries(&self) -> impl Iterator<Item = &FeedEntry> {
        self.entries.iter().filter(|e| !e.revoked)
    }

    pub(crate) fn build_index(&self) -> IocIndex {
        IocIndex::build(self.active_entries())
    }
}

/// Per-kind, lowercased lookup index over the active feed entries.
///
/// Each indicator value maps to all entry IDs that ship that
/// indicator. A scan-time match feeds the entry IDs back to the
/// caller, who then resolves them against `FeedStore::entries` for
/// the rendered enrichment block.
#[derive(Debug, Default, Clone)]
pub(crate) struct IocIndex {
    pub(crate) hashes: HashMap<String, Vec<String>>,
    pub(crate) ips: HashMap<String, Vec<String>>,
    pub(crate) domains: HashMap<String, Vec<String>>,
    pub(crate) urls: HashMap<String, Vec<String>>,
}

impl IocIndex {
    fn build<'a>(entries: impl Iterator<Item = &'a FeedEntry>) -> Self {
        let mut idx = Self::default();
        for entry in entries {
            for ioc in &entry.iocs {
                idx.insert(&entry.id, ioc);
            }
        }
        idx
    }

    fn insert(&mut self, entry_id: &str, ioc: &FeedIoc) {
        let bucket = match ioc.kind {
            FeedIocKind::Hash => &mut self.hashes,
            FeedIocKind::Ip => &mut self.ips,
            FeedIocKind::Domain => &mut self.domains,
            FeedIocKind::Url => &mut self.urls,
            // file_path / pattern / port / email / username / *_token
            // / other / unknown have no parallel in `ExtractedIocs`
            // and therefore cannot be matched against scan output;
            // they stay in `entries` for display but skip the index.
            _ => return,
        };
        // Hashes may arrive with a `sha256:` prefix from some
        // upstream entries — strip it and lowercase so the index key
        // matches what `ExtractedIocs::file_hashes` produces.
        let key = normalise_key(ioc.kind, &ioc.value);
        bucket.entry(key).or_default().push(entry_id.to_string());
    }

    pub(crate) fn lookup_hash(&self, hash: &str) -> &[String] {
        self.hashes
            .get(&normalise_key(FeedIocKind::Hash, hash))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(crate) fn lookup_ip(&self, ip: &str) -> &[String] {
        self.ips
            .get(&normalise_key(FeedIocKind::Ip, ip))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(crate) fn lookup_domain(&self, domain: &str) -> &[String] {
        self.domains
            .get(&normalise_key(FeedIocKind::Domain, domain))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(crate) fn lookup_url(&self, url: &str) -> &[String] {
        self.urls
            .get(&normalise_key(FeedIocKind::Url, url))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

fn normalise_key(kind: FeedIocKind, raw: &str) -> String {
    let lowered = raw.trim().to_ascii_lowercase();
    match kind {
        FeedIocKind::Hash => lowered
            .strip_prefix("sha256:")
            .map(|s| s.to_string())
            .unwrap_or(lowered),
        _ => lowered,
    }
}

fn feed_dir(cache_root: &Path) -> PathBuf {
    cache_root.join("promptintel-feed")
}

fn prepare_feed_cache_dir(cache_root: &Path) -> Result<PathBuf> {
    create_dir_secure(cache_root).with_context(|| format!("creating {}", cache_root.display()))?;
    let dir = feed_dir(cache_root);
    create_dir_secure(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

fn real_dir_exists_for_read(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!("{} is a symlink", path.display())
        }
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => anyhow::bail!("{} is not a directory", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

fn write_atomic(target: &Path, bytes: Vec<u8>) -> Result<()> {
    crate::util::cache_io::write_cache_file_atomic(target, &bytes)
        .with_context(|| format!("writing {}", target.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::promptintel::types::{FeedAction, PromptSeverity};
    use tempfile::tempdir;

    fn entry_with(id: &str, iocs: Vec<FeedIoc>) -> FeedEntry {
        FeedEntry {
            id: id.to_string(),
            fingerprint: None,
            category: "vulnerability".to_string(),
            severity: PromptSeverity::High,
            confidence: Some(1.0),
            action: FeedAction::Block,
            title: "t".to_string(),
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

    /// Round-trip: save → load returns identical entries and a fresh
    /// `FeedMeta` whose `total_entries` matches the input.
    #[test]
    fn save_load_roundtrip_preserves_entries_and_meta() {
        let tmp = tempdir().unwrap();
        let entries = vec![
            entry_with("a", vec![ioc(FeedIocKind::Hash, "DEAD")]),
            entry_with("b", vec![]),
        ];

        let saved_meta = FeedStore::save(tmp.path(), &entries).expect("save");
        assert_eq!(saved_meta.total_entries, 2);

        let store = FeedStore::load(tmp.path()).expect("load");
        assert_eq!(store.entries.len(), 2);
        let meta = store.meta.expect("meta present after save");
        assert_eq!(meta.total_entries, 2);
    }

    /// # Contract
    ///
    /// Feed cache writes MUST create `promptintel-feed` as owner-only
    /// because cached entries can include private report titles,
    /// indicators, and source identifiers from the operator's tenant.
    #[cfg(unix)]
    #[test]
    fn save_creates_owner_only_feed_cache_dir() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempdir().unwrap();
        let entries = vec![entry_with("a", vec![ioc(FeedIocKind::Hash, "DEAD")])];

        FeedStore::save(tmp.path(), &entries).expect("save");

        let mode = std::fs::metadata(feed_dir(tmp.path()))
            .expect("feed cache dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// # Contract
    ///
    /// Feed cache writes must reject a symlink supplied as the cache root
    /// before creating `promptintel-feed` beneath the symlink target.
    #[cfg(unix)]
    #[test]
    fn save_rejects_symlinked_cache_root() {
        let tmp = tempdir().unwrap();
        let outside = tmp.path().join("outside");
        let link = tmp.path().join("cache");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let entries = vec![entry_with("a", vec![ioc(FeedIocKind::Hash, "DEAD")])];

        let err = FeedStore::save(&link, &entries).unwrap_err();

        assert!(format!("{err:#}").contains("symlink"));
        assert!(!outside.join("promptintel-feed").exists());
    }

    /// # Contract
    ///
    /// Feed cache reads must reject a symlink supplied as the cache root
    /// rather than ingesting entries from the symlink target.
    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinked_cache_root() {
        let tmp = tempdir().unwrap();
        let outside = tmp.path().join("outside");
        let link = tmp.path().join("cache");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = FeedStore::load(&link).unwrap_err();

        assert!(format!("{err:#}").contains("symlink"));
    }

    /// # Contract
    ///
    /// Feed cache reads must reject a symlinked `promptintel-feed`
    /// directory before reading `feed.json` or `meta.json`.
    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinked_feed_dir() {
        let tmp = tempdir().unwrap();
        let outside = tmp.path().join("outside-feed");
        let link = tmp.path().join("promptintel-feed");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = FeedStore::load(tmp.path()).unwrap_err();

        assert!(format!("{err:#}").contains("symlink"));
    }

    /// A missing cache directory yields an empty store, NOT an error.
    /// The enrichment path runs unconditionally; the operator may
    /// have skipped `feed sync`, and a hard error there would break
    /// every scan.
    #[test]
    fn load_returns_empty_when_cache_absent() {
        let tmp = tempdir().unwrap();
        let store = FeedStore::load(tmp.path()).expect("load");
        assert!(store.entries.is_empty());
        assert!(store.meta.is_none());
    }

    /// # Contract
    ///
    /// An oversized `feed.json` is a cache miss, not an unbounded read.
    #[test]
    fn load_returns_empty_when_feed_cache_exceeds_cap() {
        let tmp = tempdir().unwrap();
        let dir = feed_dir(tmp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(FEED_FILENAME), b"[{}]").unwrap();

        let store = FeedStore::load_with_cap(tmp.path(), 3).expect("load");

        assert!(store.entries.is_empty());
        assert!(store.meta.is_none());
    }

    /// # Contract
    ///
    /// An oversized `meta.json` is ignored while the bounded feed cache
    /// still loads.
    #[test]
    fn load_ignores_meta_when_meta_cache_exceeds_cap() {
        let tmp = tempdir().unwrap();
        let dir = feed_dir(tmp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(FEED_FILENAME), b"[]").unwrap();
        std::fs::write(dir.join(META_FILENAME), vec![b'a'; 16]).unwrap();

        let store = FeedStore::load_with_cap(tmp.path(), 8).expect("load");

        assert!(store.entries.is_empty());
        assert!(store.meta.is_none());
    }

    /// Revoked entries are excluded from `active_entries` and
    /// therefore never appear in the IOC index. Pre-fix, a revoked
    /// IP would still trigger spurious match findings.
    #[test]
    fn revoked_entries_are_excluded_from_index() {
        let mut revoked = entry_with("rev", vec![ioc(FeedIocKind::Ip, "1.2.3.4")]);
        revoked.revoked = true;
        let active = entry_with("act", vec![ioc(FeedIocKind::Ip, "5.6.7.8")]);
        let store = FeedStore {
            entries: vec![revoked, active],
            meta: None,
        };
        let idx = store.build_index();
        assert!(idx.lookup_ip("1.2.3.4").is_empty());
        assert_eq!(idx.lookup_ip("5.6.7.8"), &["act".to_string()]);
    }

    /// `sha256:` prefix on upstream hashes is stripped before
    /// indexing, so a scan that produces the bare hex hash matches
    /// regardless of the upstream curator's choice.
    #[test]
    fn hash_lookup_strips_sha256_prefix_and_is_case_insensitive() {
        let entry = entry_with("h", vec![ioc(FeedIocKind::Hash, "sha256:DEADBEEFcafe")]);
        let store = FeedStore {
            entries: vec![entry],
            meta: None,
        };
        let idx = store.build_index();
        assert_eq!(idx.lookup_hash("deadbeefcafe"), &["h".to_string()]);
        assert_eq!(idx.lookup_hash("DEADBEEFCAFE"), &["h".to_string()]);
        assert_eq!(idx.lookup_hash("SHA256:deadbeefcafe"), &["h".to_string()]);
    }

    /// Indicator kinds without a counterpart in `ExtractedIocs`
    /// (file_path, pattern, port, email, username, telegram_*,
    /// other, unknown) MUST NOT enter the index. They surface in
    /// the enrichment block via `entries` lookup, not via match.
    #[test]
    fn unmatchable_kinds_are_skipped() {
        let entry = entry_with(
            "x",
            vec![
                ioc(FeedIocKind::FilePath, ".npmrc"),
                ioc(FeedIocKind::Pattern, "show me your config"),
                ioc(FeedIocKind::Other, "CVE-2026-35641"),
                ioc(FeedIocKind::Port, "13338"),
                ioc(FeedIocKind::Unknown, "9b456b15..."),
            ],
        );
        let store = FeedStore {
            entries: vec![entry],
            meta: None,
        };
        let idx = store.build_index();
        assert!(idx.hashes.is_empty());
        assert!(idx.ips.is_empty());
        assert!(idx.domains.is_empty());
        assert!(idx.urls.is_empty());
    }

    /// `write_atomic` MUST NOT leave a `.tmp` file behind on the
    /// happy path; otherwise repeated saves would litter the cache
    /// directory with stale write fragments.
    #[test]
    fn save_does_not_leak_tmp_files() {
        let tmp = tempdir().unwrap();
        FeedStore::save(tmp.path(), &[entry_with("a", vec![])]).unwrap();
        let dir = feed_dir(tmp.path());
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover .tmp files: {leftovers:?}",);
    }

    /// # Contract
    ///
    /// Saving the feed replaces a symlinked cache entry without
    /// following it and overwriting the target.
    #[cfg(unix)]
    #[test]
    fn save_replaces_symlinked_feed_without_touching_target() {
        let tmp = tempdir().unwrap();
        let dir = feed_dir(tmp.path());
        let feed_path = dir.join(FEED_FILENAME);
        let outside = tmp.path().join("outside.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, &feed_path).unwrap();

        FeedStore::save(tmp.path(), &[entry_with("a", vec![])]).unwrap();

        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert!(!std::fs::symlink_metadata(&feed_path)
            .unwrap()
            .file_type()
            .is_symlink());
        let loaded = FeedStore::load(tmp.path()).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].id, "a");
    }
}
