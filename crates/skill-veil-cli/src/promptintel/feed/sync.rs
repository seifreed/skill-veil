//! Pull the PromptIntel agent-feed and persist it locally.

use super::store::FeedStore;
use crate::promptintel::client::PromptIntelClient;
use anyhow::{Context, Result};
use std::path::Path;

/// Upper bound on `?limit=`. The current dataset is ~55 entries; 200
/// already returns the full set, but we ask for the full upstream cap
/// (1000) so a future growth doesn't silently truncate the cache.
const FEED_PULL_LIMIT: u32 = 1000;

/// Result of a single sync pass — surfaces both the new total and the
/// previous one so the CLI renderer can show a diff.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SyncSummary {
    pub(crate) total_pulled: usize,
    pub(crate) previous_total: usize,
}

/// Pull the full feed and overwrite the local cache atomically.
///
/// Sync is non-incremental on purpose: the dataset is small (~55
/// entries), the API does not honour `?offset`, and the curator may
/// edit / revoke past entries — a full pull keeps the local mirror
/// consistent with the upstream view in a single round-trip,
/// well within the 120/hour rate limit.
pub(crate) fn run_sync(client: &PromptIntelClient, cache_root: &Path) -> Result<SyncSummary> {
    let previous = FeedStore::load(cache_root)
        .map(|s| s.entries.len())
        .unwrap_or(0);

    let response = client
        .agent_feed(FEED_PULL_LIMIT, None)
        .context("fetching PromptIntel agent-feed")?;

    if !response.success {
        anyhow::bail!("PromptIntel agent-feed reported success=false");
    }

    let total_pulled = response.data.len();
    FeedStore::save(cache_root, &response.data).context("persisting PromptIntel feed cache")?;

    Ok(SyncSummary {
        total_pulled,
        previous_total: previous,
    })
}
