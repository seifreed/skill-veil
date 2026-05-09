//! Synchronous PromptIntel v1 API client.
//!
//! Built on `ureq` to match the existing VT client shape and avoid
//! pulling in an async runtime. Only the endpoints skill-veil benchmarks
//! consume are exposed (paginated `/prompts` listing). 429 / 5xx
//! responses are retried with exponential backoff; other non-2xx
//! statuses surface as typed errors so callers can distinguish auth
//! failures (401) from quota / transient faults.

use super::config::PromptIntelConfig;
use super::types::{FeedResponse, PromptListEnvelope};
use std::io::{self, Read};
use std::time::Duration;
use thiserror::Error;

const BASE_URL: &str = "https://api.promptintel.novahunting.ai/api/v1";
const USER_AGENT: &str = concat!(
    "skill-veil/",
    env!("CARGO_PKG_VERSION"),
    " (+promptintel-integration)"
);
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 60;
/// Total attempts = 1 initial + this many retries. Mirrors the LLM and
/// VT clients so retry semantics stay consistent across HTTP integrations.
const MAX_ADDITIONAL_ATTEMPTS: u32 = 2;
const INITIAL_BACKOFF_MS: u64 = 1_500;

/// Cap on PromptIntel JSON bodies. The `/prompts` endpoint paginates
/// to 100 entries per page (each ≈ a few KB), so 10 MiB is a generous
/// ceiling that still prevents a hostile/misconfigured endpoint from
/// causing OOM by streaming an unbounded body into memory.
const MAX_JSON_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

/// Cap on the bytes from a PromptIntel error body that we keep for
/// embedding in `PromptIntelError::HttpStatus { body }`. Anything beyond
/// this point is truncation noise for diagnostics; capping the slice
/// also prevents a hostile gateway from pushing large blobs into
/// operator logs.
const ERROR_BODY_MAX_BYTES: usize = 512;

#[derive(Debug, Error)]
pub(crate) enum PromptIntelError {
    #[error("PromptIntel HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("PromptIntel transport error: {0}")]
    Transport(String),
    #[error("PromptIntel I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("PromptIntel JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

pub(crate) type Result<T> = std::result::Result<T, PromptIntelError>;

pub(crate) struct PromptIntelClient {
    config: PromptIntelConfig,
    agent: ureq::Agent,
}

impl PromptIntelClient {
    pub(crate) fn new(config: PromptIntelConfig) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
            .build();
        Self { config, agent }
    }

    /// Fetch a single page of the `/prompts` listing. Pages are
    /// 1-indexed to match the upstream API. Callers paginate by
    /// inspecting the returned envelope's `pagination.pages` field.
    pub(crate) fn list_prompts(&self, page: u32, limit: u32) -> Result<PromptListEnvelope> {
        let url = format!("{BASE_URL}/prompts?page={page}&limit={limit}");
        let body = self.get_json(&url)?;
        let envelope: PromptListEnvelope = serde_json::from_str(&body)?;
        Ok(envelope)
    }

    /// Fetch the agent threat-intel feed.
    ///
    /// Rate limit: 120/hour, ~2/min. Callers MUST persist a sync
    /// timestamp and pass it as `since` so re-syncs only pull deltas.
    /// `since` accepts ISO-8601 (e.g. `2026-05-09T12:00:00Z`).
    ///
    /// `limit` is upstream-clamped; passing 200 returns the full
    /// dataset today (≈55 entries), so a single call suffices for an
    /// initial sync.
    pub(crate) fn agent_feed(&self, limit: u32, since: Option<&str>) -> Result<FeedResponse> {
        let mut url = format!("{BASE_URL}/agent-feed?limit={limit}");
        if let Some(s) = since {
            // ureq automatically percent-encodes the value at send time.
            url.push_str("&since=");
            url.push_str(s);
        }
        let body = self.get_json(&url)?;
        let response: FeedResponse = serde_json::from_str(&body)?;
        Ok(response)
    }

    fn get_json(&self, url: &str) -> Result<String> {
        let mut backoff_ms = INITIAL_BACKOFF_MS;
        let mut attempts_remaining = MAX_ADDITIONAL_ATTEMPTS;
        loop {
            let response = self
                .agent
                .get(url)
                .set("Authorization", &format!("Bearer {}", self.config.apikey))
                .set("Accept", "application/json")
                .set("User-Agent", USER_AGENT)
                .call();
            match response {
                Ok(resp) => return bounded_read_response(resp),
                Err(ureq::Error::Status(status, resp)) => {
                    let body = drain_error_body(status, resp);
                    if matches!(status, 429 | 500..=599) && attempts_remaining > 0 {
                        tracing::warn!(
                            "PromptIntel returned HTTP {} — sleeping {}ms before retry",
                            status,
                            backoff_ms
                        );
                        std::thread::sleep(Duration::from_millis(backoff_ms));
                        backoff_ms = backoff_ms.saturating_mul(2);
                        attempts_remaining -= 1;
                        continue;
                    }
                    return Err(PromptIntelError::HttpStatus { status, body });
                }
                Err(ureq::Error::Transport(t)) => {
                    if attempts_remaining > 0 {
                        tracing::warn!(
                            "PromptIntel transport error, sleeping {}ms before retry: {}",
                            backoff_ms,
                            t
                        );
                        std::thread::sleep(Duration::from_millis(backoff_ms));
                        backoff_ms = backoff_ms.saturating_mul(2);
                        attempts_remaining -= 1;
                        continue;
                    }
                    return Err(PromptIntelError::Transport(t.to_string()));
                }
            }
        }
    }
}

/// Drain a response body into a string, capped at
/// [`MAX_JSON_RESPONSE_BYTES`] so a hostile or misconfigured endpoint
/// cannot cause unbounded memory allocation.
fn bounded_read_response(resp: ureq::Response) -> Result<String> {
    let mut buf = Vec::with_capacity(8 * 1024);
    resp.into_reader()
        .take(MAX_JSON_RESPONSE_BYTES)
        .read_to_end(&mut buf)?;
    String::from_utf8(buf).map_err(|e| {
        PromptIntelError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("PromptIntel response is not valid UTF-8: {e}"),
        ))
    })
}

/// Truncate `body` to at most [`ERROR_BODY_MAX_BYTES`] bytes on a UTF-8
/// boundary, appending `"...[truncated]"` when shortened.
fn truncate_error_body(body: String) -> String {
    if body.len() <= ERROR_BODY_MAX_BYTES {
        return body;
    }
    let mut end = ERROR_BODY_MAX_BYTES;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 14);
    out.push_str(&body[..end]);
    out.push_str("...[truncated]");
    out
}

/// Drain `resp` into a string for embedding in an error. Mirrors the
/// shape used by the VT and LLM clients so an operator who has
/// debugged one error format already understands the others.
fn drain_error_body(status: u16, resp: ureq::Response) -> String {
    match bounded_read_response(resp) {
        Ok(body) => truncate_error_body(body),
        Err(err) => {
            tracing::warn!(
                "PromptIntel returned HTTP {} but the response body could not be read: {}",
                status,
                err
            );
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: the truncator MUST NOT split a multi-byte UTF-8 char.
    /// Pre-design check: we use `is_char_boundary` to walk back to a
    /// valid boundary; an off-by-one would corrupt the diagnostic
    /// string and crash any downstream JSON parser that re-reads it.
    #[test]
    fn truncate_error_body_respects_utf8_boundary() {
        // 4-byte UTF-8 char (U+1F600 grinning face) repeated until the
        // body exceeds the cap. Each char is 4 bytes, so the byte cap
        // never falls cleanly on a char boundary at offsets like 511.
        let body = "\u{1F600}".repeat(200);
        assert!(body.len() > ERROR_BODY_MAX_BYTES);
        let truncated = truncate_error_body(body);
        // Round-trip through `from_utf8` to prove validity. If the
        // truncator split a char boundary, this would surface as a
        // parse error rather than a silent corruption.
        let _ = std::str::from_utf8(truncated.as_bytes())
            .expect("truncated body must remain valid UTF-8");
        assert!(truncated.ends_with("...[truncated]"));
        assert!(truncated.len() < ERROR_BODY_MAX_BYTES + 32);
    }

    /// Contract: bodies under the cap are passed through unchanged so
    /// `Display` of `PromptIntelError::HttpStatus` shows the full upstream
    /// message verbatim.
    #[test]
    fn truncate_error_body_passes_short_bodies_through() {
        let short = "short error".to_string();
        assert_eq!(truncate_error_body(short.clone()), short);
    }
}
