//! Synchronous PromptIntel v1 API client.
//!
//! Built on `ureq` to match the existing VT client shape and avoid
//! pulling in an async runtime. Only the endpoints skill-veil benchmarks
//! consume are exposed (paginated `/prompts` listing). 429 / 5xx
//! responses are retried with exponential backoff; other non-2xx
//! statuses surface as typed errors so callers can distinguish auth
//! failures (401) from quota / transient faults.

use super::config::PromptIntelConfig;
use super::types::{
    FeedResponse, PromptListEnvelope, ReportListEnvelope, ReportSubmissionResponse,
};
use crate::util::http_status::is_retryable_status;
use crate::util::terminal_safe::drain_error_body;
use std::io;
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
            .redirects(0)
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
    /// Rate limit: 120/hour, ~2/min. Callers should pass
    /// `since=<RFC3339>` for incremental pulls; without it, the
    /// upstream returns the full dataset.
    pub(crate) fn agent_feed(
        &self,
        limit: u32,
        since: Option<&str>,
    ) -> Result<(FeedResponse, ResponseMeta)> {
        let mut url = format!("{BASE_URL}/agent-feed?limit={limit}");
        if let Some(s) = since {
            url.push_str("&since=");
            url.push_str(s);
        }
        let (body, meta) = self.get_json_with_meta(&url)?;
        let response: FeedResponse = serde_json::from_str(&body)?;
        Ok((response, meta))
    }

    /// List reports the authenticated agent has previously submitted.
    /// Rate limit: 60/hour. Pagination is `?limit=&offset=`.
    pub(crate) fn list_my_reports(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<(ReportListEnvelope, ResponseMeta)> {
        let url = format!("{BASE_URL}/agents/reports/mine?limit={limit}&offset={offset}");
        let (body, meta) = self.get_json_with_meta(&url)?;
        let envelope: ReportListEnvelope = serde_json::from_str(&body)?;
        Ok((envelope, meta))
    }

    /// Submit a new threat-intel report. Rate limit: 5/hour, 20/day.
    ///
    /// `body_json` MUST be a serialised JSON object with at minimum
    /// `category`, `severity`, `confidence`, `fingerprint`, `title`
    /// (validated client-side by [`super::types::ReportDraft`]).
    pub(crate) fn submit_report(
        &self,
        body_json: &str,
    ) -> Result<(ReportSubmissionResponse, ResponseMeta)> {
        let url = format!("{BASE_URL}/agents/reports");
        let (body, meta) = self.post_json_with_meta(&url, body_json)?;
        let response: ReportSubmissionResponse = serde_json::from_str(&body)?;
        Ok((response, meta))
    }

    fn get_json(&self, url: &str) -> Result<String> {
        Ok(self.get_json_with_meta(url)?.0)
    }

    fn get_json_with_meta(&self, url: &str) -> Result<(String, ResponseMeta)> {
        self.execute_with_retry(|| {
            self.agent
                .get(url)
                .set("Authorization", &format!("Bearer {}", self.config.apikey))
                .set("Accept", "application/json")
                .set("User-Agent", USER_AGENT)
                .call()
                .map_err(Box::new)
        })
    }

    fn post_json_with_meta(&self, url: &str, body_json: &str) -> Result<(String, ResponseMeta)> {
        self.execute_with_retry(|| {
            self.agent
                .post(url)
                .set("Authorization", &format!("Bearer {}", self.config.apikey))
                .set("Accept", "application/json")
                .set("Content-Type", "application/json")
                .set("User-Agent", USER_AGENT)
                .send_string(body_json)
                .map_err(Box::new)
        })
    }

    /// Drive `request` to a JSON body + [`ResponseMeta`], retrying 429 and 5xx
    /// with exponential backoff up to [`MAX_ADDITIONAL_ATTEMPTS`] times. Other
    /// 4xx statuses are operator-fixable, so they fail immediately — the same
    /// body would re-trip the same validation. Shared by the GET and POST
    /// helpers, which differ only in how they build the request.
    fn execute_with_retry(
        &self,
        request: impl Fn() -> std::result::Result<ureq::Response, Box<ureq::Error>>,
    ) -> Result<(String, ResponseMeta)> {
        let mut backoff_ms = INITIAL_BACKOFF_MS;
        let mut attempts_remaining = MAX_ADDITIONAL_ATTEMPTS;
        loop {
            match request().map_err(|boxed| *boxed) {
                Ok(resp) => {
                    let status = resp.status();
                    if !(200..300).contains(&status) {
                        let body =
                            drain_error_body("PromptIntel", status, bounded_read_response(resp));
                        return Err(PromptIntelError::HttpStatus { status, body });
                    }
                    let meta = ResponseMeta::from_headers(&resp);
                    return bounded_read_response(resp).map(|body| (body, meta));
                }
                Err(ureq::Error::Status(status, resp)) => {
                    let body = drain_error_body("PromptIntel", status, bounded_read_response(resp));
                    if is_retryable_status(status) && attempts_remaining > 0 {
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

/// Per-response observability fields the rate-limit tracker captures.
/// `ratelimit_remaining` mirrors the upstream `x-ratelimit-remaining`
/// header when present; the value is informational and the gating
/// decision uses our own client-side history regardless.
#[derive(Debug, Clone, Default)]
pub(crate) struct ResponseMeta {
    pub(crate) ratelimit_remaining: Option<u32>,
}

impl ResponseMeta {
    fn from_headers(resp: &ureq::Response) -> Self {
        Self {
            ratelimit_remaining: resp
                .header("x-ratelimit-remaining")
                .and_then(|s| s.parse().ok()),
        }
    }

    /// The server-reported remaining budget to record for a call `result`:
    /// the response value on success, `None` on failure. A failed call still
    /// counts toward the local back-off budget (the rate-limit tracker records
    /// every attempt regardless of upstream success), so callers record this
    /// before propagating any error.
    pub(crate) fn remaining_for<T, E>(
        result: &std::result::Result<(T, ResponseMeta), E>,
    ) -> Option<u32> {
        result
            .as_ref()
            .ok()
            .and_then(|(_, meta)| meta.ratelimit_remaining)
    }
}

/// Drain a response body into a string, capped at
/// [`MAX_JSON_RESPONSE_BYTES`] so a hostile or misconfigured endpoint
/// cannot cause unbounded memory allocation.
fn bounded_read_response(resp: ureq::Response) -> Result<String> {
    crate::util::bounded_read::read_response_with_cap(resp, MAX_JSON_RESPONSE_BYTES)
        .map_err(PromptIntelError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_support::response_with_body;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    /// Contract: a failed call yields `None` (no server header) but is still
    /// recordable, so the rate-limit tracker backs off on a saturating
    /// endpoint instead of only counting successes.
    #[test]
    fn remaining_for_extracts_success_value_and_none_on_failure() {
        let ok: std::result::Result<((), ResponseMeta), String> = Ok((
            (),
            ResponseMeta {
                ratelimit_remaining: Some(4),
            },
        ));
        assert_eq!(ResponseMeta::remaining_for(&ok), Some(4));
        let err: std::result::Result<((), ResponseMeta), String> = Err("boom".to_string());
        assert_eq!(ResponseMeta::remaining_for(&err), None);
    }

    /// Contract: a PromptIntel JSON response under the cap is returned as
    /// the decoded body. The byte-cap rejection itself is pinned in
    /// `util::bounded_read`; here we only pin the PromptIntel wrapper.
    #[test]
    fn bounded_read_response_returns_decoded_body() {
        let body = bounded_read_response(response_with_body("abcd")).unwrap();

        assert_eq!(body, "abcd");
    }

    fn drain_request_headers(stream: &mut std::net::TcpStream) -> String {
        let cloned = stream.try_clone().expect("clone stream");
        let mut reader = BufReader::new(cloned);
        let mut headers = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if line == "\r\n" {
                break;
            }
            headers.push_str(&line);
        }
        headers
    }

    /// Contract: PromptIntel requests must not follow redirects because
    /// every request carries `Authorization: Bearer <apikey>`. A redirect
    /// is surfaced as HTTP 302 and the `Location` target is never contacted.
    #[test]
    fn agent_surfaces_302_as_error_instead_of_following_redirect() {
        let redirect_target = TcpListener::bind("127.0.0.1:0").expect("bind target");
        redirect_target
            .set_nonblocking(true)
            .expect("nonblocking target");
        let target_addr = redirect_target.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let target = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                match redirect_target.accept() {
                    Ok((mut stream, _)) => {
                        let headers = drain_request_headers(&mut stream);
                        let body = "{}";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = tx.send(Some(headers));
                        return;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(None);
        });

        let redirector = TcpListener::bind("127.0.0.1:0").expect("bind redirector");
        let redirector_addr = redirector.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = redirector.accept().expect("accept redirector");
            let _headers = drain_request_headers(&mut stream);
            let body = "redirect";
            let resp = format!(
                "HTTP/1.1 302 Found\r\n\
                 Location: http://{target_addr}/leak\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        });

        let client = PromptIntelClient::new(PromptIntelConfig {
            apikey: "promptintel-secret".to_string(),
        });
        let result = client.get_json_with_meta(&format!("http://{redirector_addr}/start"));

        server.join().expect("redirector thread");
        target.join().expect("target thread");
        match result {
            Err(PromptIntelError::HttpStatus { status: 302, .. }) => {}
            other => panic!("expected HTTP 302 error without following redirect, got {other:?}"),
        }
        let target_headers = rx.recv().expect("target thread must report");
        assert!(
            target_headers.is_none(),
            "redirect target must not be contacted; got headers {target_headers:?}"
        );
    }
}
