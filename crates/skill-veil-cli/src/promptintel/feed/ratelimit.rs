//! Persistent client-side rate-limit tracker for PromptIntel endpoints.
//!
//! Cached at `<cache_root>/promptintel-feed/ratelimit.json` so a fresh
//! shell still respects the previous shell's spend. Quotas are
//! hardcoded per the upstream documentation (we do NOT rely on the
//! `x-ratelimit-*` response headers because those reflect a global
//! counter and miss the per-endpoint splits).
//!
//! Documented limits (2026-05-09):
//!
//! | Endpoint                  | hourly | daily |
//! |---------------------------|--------|-------|
//! | GET  /agent-feed          | 120    |  -    |
//! | GET  /agents/reports/mine | 60     |  -    |
//! | POST /agents/reports      | 5      | 20    |

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::util::{
    cache_io::{read_cache_file_with_cap, MAX_CACHE_FILE_BYTES},
    secure_fs::{create_dir_secure, real_dir_exists_for_read},
};

const RATELIMIT_FILENAME: &str = "ratelimit.json";

/// Logical endpoint key. Stored as a string in the on-disk state so
/// adding a new endpoint never breaks deserialisation of an existing
/// cache.
pub(crate) mod endpoint {
    pub(crate) const AGENT_FEED: &str = "agent-feed";
    pub(crate) const REPORTS_MINE: &str = "agents/reports/mine";
    pub(crate) const REPORTS_SUBMIT: &str = "agents/reports";
}

/// Per-endpoint quota. `None` for `daily_cap` means no daily ceiling
/// is enforced (the upstream simply doesn't publish one for that
/// endpoint).
#[derive(Debug, Clone, Copy)]
struct Quota {
    hourly_cap: u32,
    daily_cap: Option<u32>,
}

fn quota_for(endpoint: &str) -> Option<Quota> {
    match endpoint {
        endpoint::AGENT_FEED => Some(Quota {
            hourly_cap: 120,
            daily_cap: None,
        }),
        endpoint::REPORTS_MINE => Some(Quota {
            hourly_cap: 60,
            daily_cap: None,
        }),
        endpoint::REPORTS_SUBMIT => Some(Quota {
            hourly_cap: 5,
            daily_cap: Some(20),
        }),
        _ => None,
    }
}

/// One call recorded against the rate-limit budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CallRecord {
    at: DateTime<Utc>,
    /// Last `x-ratelimit-remaining` value the server returned for this
    /// endpoint. Informational; not used for the gating decision.
    server_remaining: Option<u32>,
}

/// Per-endpoint timeline: every recorded call within the longest
/// applicable window. We keep individual call timestamps so the
/// rolling window evicts naturally as time passes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EndpointHistory {
    calls: Vec<CallRecord>,
}

impl EndpointHistory {
    fn count_within(&self, window: Duration, now: DateTime<Utc>) -> u32 {
        self.calls
            .iter()
            .filter(|c| {
                let age = now.signed_duration_since(c.at);
                age >= Duration::zero() && age < window
            })
            .count() as u32
    }

    /// Drop calls older than the longest window (24h) so the on-disk
    /// state cannot grow unbounded across long-running sessions.
    fn evict_older_than(&mut self, max_age: Duration, now: DateTime<Utc>) {
        self.calls.retain(|c| {
            let age = now.signed_duration_since(c.at);
            age >= Duration::zero() && age < max_age
        });
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RateLimitState {
    #[serde(default)]
    endpoints: HashMap<String, EndpointHistory>,
}

impl RateLimitState {
    pub(crate) fn load(cache_root: &Path) -> Result<Self> {
        Self::load_with_cap(cache_root, MAX_CACHE_FILE_BYTES)
    }

    fn load_with_cap(cache_root: &Path, cap: u64) -> Result<Self> {
        if !real_dir_exists_for_read(cache_root)? {
            return Ok(Self::default());
        }
        let dir = cache_root.join("promptintel-feed");
        if !real_dir_exists_for_read(&dir)? {
            return Ok(Self::default());
        }
        let path = state_path(cache_root);
        let Some(bytes) = read_cache_file_with_cap(&path, cap)? else {
            return Ok(Self::default());
        };
        let state: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {}", path.display()))?;
        Ok(state)
    }

    pub(crate) fn save(&self, cache_root: &Path) -> Result<()> {
        prepare_rate_limit_cache_dir(cache_root)?;
        let path = state_path(cache_root);
        let bytes = serde_json::to_vec_pretty(self).context("serialising rate-limit state")?;
        crate::util::cache_io::write_cache_file_atomic(&path, &bytes)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Reject `endpoint` when the operator's recent call history would
    /// exceed the documented hourly or daily cap.
    ///
    /// # Contract
    /// - Endpoints with no entry in [`quota_for`] always pass — the
    ///   tracker is opt-in per endpoint.
    /// - The hourly cap is `< hourly_cap` strictly: at 120 prior
    ///   calls the next one is refused even if exactly 60 minutes
    ///   have not yet elapsed since the oldest.
    /// - Returns the [`RateLimitError`] enum so callers can render a
    ///   user-actionable message including the wait window.
    pub(crate) fn check_can_call(&self, endpoint: &str) -> std::result::Result<(), RateLimitError> {
        self.check_can_call_at(endpoint, Utc::now())
    }

    pub(crate) fn check_can_call_at(
        &self,
        endpoint: &str,
        now: DateTime<Utc>,
    ) -> std::result::Result<(), RateLimitError> {
        let Some(quota) = quota_for(endpoint) else {
            return Ok(());
        };
        let history = self.endpoints.get(endpoint);
        if let Some(history) = history {
            let used_hour = history.count_within(Duration::hours(1), now);
            if used_hour >= quota.hourly_cap {
                return Err(RateLimitError::HourlyExceeded {
                    endpoint: endpoint.to_string(),
                    cap: quota.hourly_cap,
                    used: used_hour,
                });
            }
            if let Some(daily_cap) = quota.daily_cap {
                let used_day = history.count_within(Duration::hours(24), now);
                if used_day >= daily_cap {
                    return Err(RateLimitError::DailyExceeded {
                        endpoint: endpoint.to_string(),
                        cap: daily_cap,
                        used: used_day,
                    });
                }
            }
        }
        Ok(())
    }

    /// Record a successful (or attempted) call. We record on every
    /// call regardless of upstream success — failed calls still spend
    /// quota, and over-counting is safer than under-counting for a
    /// quota meant to back off before saturation.
    pub(crate) fn record_call(&mut self, endpoint: &str, server_remaining: Option<u32>) {
        self.record_call_at(endpoint, server_remaining, Utc::now());
    }

    pub(crate) fn record_call_at(
        &mut self,
        endpoint: &str,
        server_remaining: Option<u32>,
        now: DateTime<Utc>,
    ) {
        let history = self.endpoints.entry(endpoint.to_string()).or_default();
        history.calls.push(CallRecord {
            at: now,
            server_remaining,
        });
        // 24h is the longest documented window; evict older entries
        // so the on-disk state stays bounded.
        history.evict_older_than(Duration::hours(24), now);
    }

    /// Render an operator-facing summary block. Used by the CLI
    /// reporter so users can see remaining budget at a glance.
    pub(crate) fn render_summary(&self) -> String {
        let now = Utc::now();
        let mut lines = vec!["=== PromptIntel rate-limit budget ===".to_string()];
        for endpoint_key in [
            endpoint::AGENT_FEED,
            endpoint::REPORTS_MINE,
            endpoint::REPORTS_SUBMIT,
        ] {
            let quota = quota_for(endpoint_key).expect("known endpoint has quota");
            let history = self
                .endpoints
                .get(endpoint_key)
                .cloned()
                .unwrap_or_default();
            let used_hour = history.count_within(Duration::hours(1), now);
            let mut line = format!(
                "  {:<22} {:>3}/{:<3} per hour",
                endpoint_key, used_hour, quota.hourly_cap
            );
            if let Some(daily_cap) = quota.daily_cap {
                let used_day = history.count_within(Duration::hours(24), now);
                line.push_str(&format!("   {used_day:>3}/{daily_cap:<3} per day"));
            }
            lines.push(line);
        }
        lines.join("\n")
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RateLimitError {
    #[error(
        "PromptIntel hourly rate limit reached for {endpoint}: \
         {used}/{cap} calls in the last hour. Wait before retrying."
    )]
    HourlyExceeded {
        endpoint: String,
        cap: u32,
        used: u32,
    },
    #[error(
        "PromptIntel daily rate limit reached for {endpoint}: \
         {used}/{cap} calls in the last 24 hours. Wait before retrying."
    )]
    DailyExceeded {
        endpoint: String,
        cap: u32,
        used: u32,
    },
}

fn state_path(cache_root: &Path) -> PathBuf {
    cache_root.join("promptintel-feed").join(RATELIMIT_FILENAME)
}

fn prepare_rate_limit_cache_dir(cache_root: &Path) -> Result<PathBuf> {
    create_dir_secure(cache_root).with_context(|| format!("creating {}", cache_root.display()))?;
    let dir = cache_root.join("promptintel-feed");
    create_dir_secure(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    /// Contract: an endpoint with no recorded calls passes
    /// `check_can_call` regardless of quota. Pre-fix, a fresh client
    /// would have been refused by an off-by-one in the bucket
    /// initialiser.
    #[test]
    fn empty_state_allows_first_call() {
        let state = RateLimitState::default();
        assert!(state.check_can_call(endpoint::AGENT_FEED).is_ok());
        assert!(state.check_can_call(endpoint::REPORTS_SUBMIT).is_ok());
    }

    /// Contract: an endpoint not in [`quota_for`] always passes the
    /// gate so a future endpoint that lacks documented limits does
    /// not silently brick callers.
    #[test]
    fn unknown_endpoint_always_passes() {
        let state = RateLimitState::default();
        assert!(state.check_can_call("future/endpoint").is_ok());
    }

    /// # Contract
    ///
    /// Saving rate-limit state must reject a symlink supplied as the cache
    /// root before creating `promptintel-feed` beneath the symlink target.
    #[cfg(unix)]
    #[test]
    fn save_rejects_symlinked_cache_root() {
        let tmp = tempdir().unwrap();
        let outside = tmp.path().join("outside");
        let link = tmp.path().join("cache");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = RateLimitState::default().save(&link).unwrap_err();

        assert!(format!("{err:#}").contains("symlink"));
        assert!(!outside.join("promptintel-feed").exists());
    }

    /// # Contract
    ///
    /// Loading rate-limit state must reject a symlink supplied as the
    /// cache root rather than trusting state from the symlink target.
    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinked_cache_root() {
        let tmp = tempdir().unwrap();
        let outside = tmp.path().join("outside");
        let link = tmp.path().join("cache");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = RateLimitState::load(&link).unwrap_err();

        assert!(format!("{err:#}").contains("symlink"));
    }

    /// # Contract
    ///
    /// Loading rate-limit state must reject a symlinked
    /// `promptintel-feed` directory before reading `ratelimit.json`.
    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinked_feed_dir() {
        let tmp = tempdir().unwrap();
        let outside = tmp.path().join("outside-feed");
        let link = tmp.path().join("promptintel-feed");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = RateLimitState::load(tmp.path()).unwrap_err();

        assert!(format!("{err:#}").contains("symlink"));
    }

    /// Contract: hitting exactly `hourly_cap` calls in a 1-hour
    /// window MUST refuse the next call. The boundary is inclusive
    /// of the cap (≥ refuses, < passes).
    #[test]
    fn hourly_cap_refuses_at_boundary() {
        let mut state = RateLimitState::default();
        let base = at(1_000_000);
        for i in 0..5 {
            state.record_call_at(endpoint::REPORTS_SUBMIT, None, base + Duration::seconds(i));
        }
        let err = state
            .check_can_call_at(endpoint::REPORTS_SUBMIT, base + Duration::seconds(6))
            .expect_err("5/5 must refuse");
        match err {
            RateLimitError::HourlyExceeded { used, cap, .. } => {
                assert_eq!(used, 5);
                assert_eq!(cap, 5);
            }
            other => panic!("expected HourlyExceeded, got {other:?}"),
        }
    }

    /// Contract: calls older than 1 hour MUST drop out of the rolling
    /// window so the budget recovers naturally. Pre-fix, a stale
    /// counter would lock out the operator until manual reset.
    #[test]
    fn calls_outside_window_do_not_count_against_hourly_cap() {
        let mut state = RateLimitState::default();
        let base = at(1_000_000);
        for i in 0..5 {
            state.record_call_at(endpoint::REPORTS_SUBMIT, None, base + Duration::seconds(i));
        }
        // 65 minutes later, none of the 5 calls fall inside the
        // 1-hour window, so the next call must pass.
        let now = base + Duration::minutes(65);
        assert!(state
            .check_can_call_at(endpoint::REPORTS_SUBMIT, now)
            .is_ok());
    }

    /// Contract: future-dated cache records MUST NOT count against the
    /// rolling window. Clock skew or a poisoned `ratelimit.json` must
    /// not freeze PromptIntel calls until the future timestamp elapses.
    #[test]
    fn future_records_do_not_count_against_hourly_cap() {
        let mut state = RateLimitState::default();
        let now = at(1_000_000);
        for i in 0..120 {
            state.record_call_at(
                endpoint::AGENT_FEED,
                None,
                now + Duration::hours(24) + Duration::seconds(i),
            );
        }

        assert!(state.check_can_call_at(endpoint::AGENT_FEED, now).is_ok());
    }

    /// Contract: the daily cap (20 for `agents/reports`) refuses even
    /// when the hourly cap has slack. A long-running operator who
    /// makes 5 reports per hour for 4 hours hits the daily limit on
    /// the 21st call.
    #[test]
    fn daily_cap_refuses_when_hourly_has_slack() {
        let mut state = RateLimitState::default();
        let base = at(1_000_000);
        // Spread 20 calls over the last 12 hours so each rolling
        // hour holds at most 2 calls (well under the 5/h cap).
        for i in 0..20 {
            let t = base + Duration::minutes(i * 30);
            state.record_call_at(endpoint::REPORTS_SUBMIT, None, t);
        }
        // 30 seconds after the last call: 20/24h spent, 0/h
        // remaining (the most recent ~hour holds only 1 call).
        let now = base + Duration::minutes(20 * 30) + Duration::seconds(30);
        let err = state
            .check_can_call_at(endpoint::REPORTS_SUBMIT, now)
            .expect_err("20/20 daily must refuse");
        assert!(matches!(err, RateLimitError::DailyExceeded { .. }));
    }

    /// Contract: `record_call` MUST evict entries older than 24h so
    /// the on-disk state stays bounded across long sessions.
    #[test]
    fn record_call_evicts_entries_older_than_24h() {
        let mut state = RateLimitState::default();
        let base = at(1_000_000);
        state.record_call_at(endpoint::AGENT_FEED, None, base);
        let now = base + Duration::hours(25);
        state.record_call_at(endpoint::AGENT_FEED, None, now);
        let history = state.endpoints.get(endpoint::AGENT_FEED).unwrap();
        assert_eq!(history.calls.len(), 1);
        assert_eq!(history.calls[0].at, now);
    }

    /// Round-trip: save → load preserves the call history and the
    /// timestamps survive the JSON encoding (RFC 3339).
    #[test]
    fn save_load_roundtrip_preserves_history() {
        let tmp = tempdir().unwrap();
        let mut state = RateLimitState::default();
        state.record_call_at(endpoint::AGENT_FEED, Some(199), at(1_000_000));
        state.record_call_at(endpoint::REPORTS_SUBMIT, None, at(1_000_001));
        state.save(tmp.path()).unwrap();

        let loaded = RateLimitState::load(tmp.path()).unwrap();
        assert_eq!(loaded.endpoints.len(), 2);
        let feed = loaded.endpoints.get(endpoint::AGENT_FEED).unwrap();
        assert_eq!(feed.calls.len(), 1);
        assert_eq!(feed.calls[0].server_remaining, Some(199));
    }

    /// # Contract
    ///
    /// Rate-limit state writes MUST create `promptintel-feed` as
    /// owner-only because it exposes which PromptIntel endpoints the
    /// operator used and when.
    #[cfg(unix)]
    #[test]
    fn save_creates_owner_only_feed_cache_dir() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempdir().unwrap();
        let mut state = RateLimitState::default();
        state.record_call_at(endpoint::REPORTS_SUBMIT, None, at(1_000_001));

        state.save(tmp.path()).expect("save");

        let mode = std::fs::metadata(tmp.path().join("promptintel-feed"))
            .expect("rate-limit cache dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// # Contract
    ///
    /// Saving rate-limit state replaces a symlinked state file without
    /// following it and overwriting the target.
    #[cfg(unix)]
    #[test]
    fn save_replaces_symlinked_state_without_touching_target() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("promptintel-feed");
        let state_file = dir.join(RATELIMIT_FILENAME);
        let outside = tmp.path().join("outside.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, &state_file).unwrap();

        let mut state = RateLimitState::default();
        state.record_call_at(endpoint::AGENT_FEED, Some(199), at(1_000_000));
        state.save(tmp.path()).unwrap();

        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert!(!std::fs::symlink_metadata(&state_file)
            .unwrap()
            .file_type()
            .is_symlink());
        let loaded = RateLimitState::load(tmp.path()).unwrap();
        assert_eq!(loaded.endpoints.len(), 1);
    }

    /// A missing state file MUST yield a default-empty state, not an
    /// error: a fresh install must not require running an explicit
    /// "init" command before the first call.
    #[test]
    fn load_returns_empty_when_state_absent() {
        let tmp = tempdir().unwrap();
        let state = RateLimitState::load(tmp.path()).unwrap();
        assert!(state.endpoints.is_empty());
    }

    /// # Contract
    ///
    /// An oversized `ratelimit.json` is a default-empty state, not an
    /// unbounded read.
    #[test]
    fn load_returns_empty_when_state_cache_exceeds_cap() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("promptintel-feed");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(RATELIMIT_FILENAME), b"{}").unwrap();

        let state = RateLimitState::load_with_cap(tmp.path(), 1).unwrap();

        assert!(state.endpoints.is_empty());
    }

    /// `render_summary` MUST surface every documented endpoint, not
    /// just the ones with recent activity, so an operator inspecting
    /// the budget after a fresh install sees the full picture.
    #[test]
    fn render_summary_lists_all_known_endpoints() {
        let state = RateLimitState::default();
        let rendered = state.render_summary();
        assert!(rendered.contains(endpoint::AGENT_FEED));
        assert!(rendered.contains(endpoint::REPORTS_MINE));
        assert!(rendered.contains(endpoint::REPORTS_SUBMIT));
    }
}
