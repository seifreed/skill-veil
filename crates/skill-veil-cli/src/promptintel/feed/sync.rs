//! Pull the PromptIntel agent-feed into the local cache.
//!
//! Two modes:
//!
//! - **Incremental** (default): pass `meta.last_sync` as `?since=` so
//!   only new entries are pulled. Cheaper, but the API does NOT
//!   return revoked / edited entries via `?since=`; revocations
//!   propagate only on a full sync.
//! - **Full**: pull the entire dataset and replace the cache. Run
//!   periodically (e.g. weekly) so revocations land. Operators can
//!   force this with `--full`.

use super::ratelimit::{endpoint, RateLimitState};
use super::store::FeedStore;
use crate::promptintel::client::PromptIntelClient;
use crate::promptintel::types::FeedEntry;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Upper bound on `?limit=`. The current dataset is ~55 entries; 200
/// already returns the full set, but we ask for the full upstream cap
/// (1000) so a future growth doesn't silently truncate the cache.
const FEED_PULL_LIMIT: u32 = 1000;

#[derive(Debug, Clone, Copy)]
pub(crate) enum SyncMode {
    /// Pull only entries newer than `meta.last_sync`. Falls back to a
    /// full pull when the cache is missing.
    Incremental,
    /// Pull every entry and replace the cache atomically.
    Full,
}

/// Result of a single sync pass.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SyncSummary {
    pub(crate) mode: ResolvedSyncMode,
    pub(crate) pulled: usize,
    pub(crate) previous_total: usize,
    pub(crate) new_total: usize,
}

/// Distinguishes "operator asked for incremental and we delivered it"
/// from "operator asked for incremental but the cache was empty so we
/// transparently upgraded to full". Surfaces the upgrade so the CLI
/// can mention it in the rendered summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolvedSyncMode {
    Full,
    Incremental,
    /// Asked-for: incremental. Resolved: full because no prior sync.
    IncrementalUpgradedToFull,
}

/// Pull and merge the feed into the local cache.
pub(crate) fn run_sync(
    client: &PromptIntelClient,
    cache_root: &Path,
    mode: SyncMode,
) -> Result<SyncSummary> {
    let mut rate_state = RateLimitState::load(cache_root)?;
    rate_state
        .check_can_call(endpoint::AGENT_FEED)
        .map_err(|e| anyhow::anyhow!(e))?;

    let existing = FeedStore::load(cache_root)?;
    let previous_total = existing.entries.len();

    let (resolved_mode, since) = match mode {
        SyncMode::Full => (ResolvedSyncMode::Full, None),
        SyncMode::Incremental => existing
            .meta
            .as_ref()
            .map(|m| {
                // Second-precision `...Z` form. The upstream returns
                // HTTP 500 for fractional-second timestamps and for
                // the `+00:00` zone form `to_rfc3339()` produces.
                (
                    ResolvedSyncMode::Incremental,
                    Some(m.last_sync.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                )
            })
            .unwrap_or((ResolvedSyncMode::IncrementalUpgradedToFull, None)),
    };

    let (response, response_meta) = client
        .agent_feed(FEED_PULL_LIMIT, since.as_deref())
        .context("fetching PromptIntel agent-feed")?;

    rate_state.record_call(endpoint::AGENT_FEED, response_meta.ratelimit_remaining);
    rate_state.save(cache_root)?;

    if !response.success {
        anyhow::bail!("PromptIntel agent-feed reported success=false");
    }

    let pulled = response.data.len();
    let merged = match resolved_mode {
        ResolvedSyncMode::Full | ResolvedSyncMode::IncrementalUpgradedToFull => response.data,
        ResolvedSyncMode::Incremental => merge_incremental(existing.entries, response.data),
    };
    let new_total = merged.len();
    FeedStore::save(cache_root, &merged).context("persisting PromptIntel feed cache")?;

    Ok(SyncSummary {
        mode: resolved_mode,
        pulled,
        previous_total,
        new_total,
    })
}

/// Merge new entries into the existing snapshot. New entries with the
/// same `id` overwrite their previous version (fields can be edited
/// upstream); entries the increment didn't touch are preserved.
///
/// # Caveat
/// The upstream `?since=` filter does NOT return entries that were
/// revoked since `last_sync`. A long-running incremental-only loop
/// will therefore retain stale revoked entries indefinitely. Operators
/// who care about revocation propagation must run `feed sync --full`
/// periodically.
fn merge_incremental(existing: Vec<FeedEntry>, additions: Vec<FeedEntry>) -> Vec<FeedEntry> {
    let mut by_id: HashMap<String, FeedEntry> =
        existing.into_iter().map(|e| (e.id.clone(), e)).collect();
    for entry in additions {
        by_id.insert(entry.id.clone(), entry);
    }
    let mut merged: Vec<FeedEntry> = by_id.into_values().collect();
    merged.sort_by(|a, b| a.id.cmp(&b.id));
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::promptintel::types::{FeedAction, FeedEntry, PromptSeverity};

    fn entry(id: &str, title: &str) -> FeedEntry {
        FeedEntry {
            id: id.to_string(),
            fingerprint: None,
            category: "test".to_string(),
            severity: PromptSeverity::Low,
            confidence: Some(1.0),
            action: FeedAction::Log,
            title: title.to_string(),
            description: None,
            source: None,
            source_identifier: None,
            recommendation_agent: None,
            iocs: Vec::new(),
            expires_at: None,
            revoked_at: None,
            created_at: None,
            revoked: false,
        }
    }

    /// Contract: a new entry id MUST extend the existing snapshot.
    #[test]
    fn merge_appends_new_ids() {
        let existing = vec![entry("a", "old-a")];
        let additions = vec![entry("b", "new-b")];
        let merged = merge_incremental(existing, additions);
        assert_eq!(merged.len(), 2);
        let ids: Vec<_> = merged.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    /// Contract: a duplicate id in the increment MUST replace the
    /// existing entry — upstream curators edit titles/severities and
    /// the local mirror must converge to the latest version.
    #[test]
    fn merge_replaces_existing_id_with_increment() {
        let existing = vec![entry("a", "old-title")];
        let additions = vec![entry("a", "new-title")];
        let merged = merge_incremental(existing, additions);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].title, "new-title");
    }

    /// Contract: entries the increment did NOT touch MUST stay in the
    /// merged set. Pre-fix a naive `let merged = additions;` would
    /// silently drop unchanged entries on every incremental sync.
    #[test]
    fn merge_preserves_untouched_entries() {
        let existing = vec![entry("a", "kept"), entry("b", "kept-b")];
        let additions = vec![entry("c", "new")];
        let merged = merge_incremental(existing, additions);
        let ids: Vec<_> = merged.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    /// Contract: merge output is sorted by id so two operators who
    /// sync the same upstream state end up with byte-identical
    /// `feed.json` files.
    #[test]
    fn merge_output_is_sorted_by_id() {
        let existing = vec![entry("z", "z")];
        let additions = vec![entry("m", "m"), entry("a", "a")];
        let merged = merge_incremental(existing, additions);
        let ids: Vec<_> = merged.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["a", "m", "z"]);
    }
}
