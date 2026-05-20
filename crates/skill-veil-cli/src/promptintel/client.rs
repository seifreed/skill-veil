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
                Ok(resp) => {
                    let status = resp.status();
                    if !(200..300).contains(&status) {
                        let body = drain_error_body(status, resp);
                        return Err(PromptIntelError::HttpStatus { status, body });
                    }
                    let meta = ResponseMeta::from_headers(&resp);
                    return bounded_read_response(resp).map(|body| (body, meta));
                }
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

    fn post_json_with_meta(&self, url: &str, body_json: &str) -> Result<(String, ResponseMeta)> {
        let mut backoff_ms = INITIAL_BACKOFF_MS;
        let mut attempts_remaining = MAX_ADDITIONAL_ATTEMPTS;
        loop {
            let response = self
                .agent
                .post(url)
                .set("Authorization", &format!("Bearer {}", self.config.apikey))
                .set("Accept", "application/json")
                .set("Content-Type", "application/json")
                .set("User-Agent", USER_AGENT)
                .send_string(body_json);
            match response {
                Ok(resp) => {
                    let status = resp.status();
                    if !(200..300).contains(&status) {
                        let body = drain_error_body(status, resp);
                        return Err(PromptIntelError::HttpStatus { status, body });
                    }
                    let meta = ResponseMeta::from_headers(&resp);
                    return bounded_read_response(resp).map(|body| (body, meta));
                }
                Err(ureq::Error::Status(status, resp)) => {
                    let body = drain_error_body(status, resp);
                    // 4xx (other than 429) are operator-fixable; do not
                    // retry — the same body would re-trip the same
                    // validation. 429 / 5xx are transient enough to
                    // warrant the existing backoff.
                    if matches!(status, 429 | 500..=599) && attempts_remaining > 0 {
                        tracing::warn!(
                            "PromptIntel POST returned HTTP {} — sleeping {}ms before retry",
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
                            "PromptIntel POST transport error, sleeping {}ms: {}",
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
}

/// Drain a response body into a string, capped at
/// [`MAX_JSON_RESPONSE_BYTES`] so a hostile or misconfigured endpoint
/// cannot cause unbounded memory allocation.
fn bounded_read_response(resp: ureq::Response) -> Result<String> {
    read_response_with_cap(resp, MAX_JSON_RESPONSE_BYTES)
}

fn read_response_with_cap(resp: ureq::Response, cap: u64) -> Result<String> {
    let mut buf = Vec::with_capacity(8 * 1024);
    resp.into_reader()
        .take(cap.saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(PromptIntelError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("response body exceeds {cap} byte limit"),
        )));
    }
    debug_assert!(
        buf.len() as u64 <= cap,
        "bounded response reader must reject bodies over the cap"
    );
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn response_with_body(body: &str) -> ureq::Response {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .parse()
        .expect("synthetic response must parse")
    }

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

    /// Contract: a PromptIntel JSON response exactly at the byte cap is
    /// accepted.
    #[test]
    fn bounded_read_response_accepts_body_at_cap() {
        let body = read_response_with_cap(response_with_body("abcd"), 4).unwrap();

        assert_eq!(body, "abcd");
    }

    /// Contract: a PromptIntel JSON response beyond the cap fails
    /// instead of returning a truncated prefix that could be parsed as
    /// complete JSON by a downstream caller.
    #[test]
    fn bounded_read_response_rejects_body_over_cap() {
        let err = read_response_with_cap(response_with_body("abcde"), 4)
            .expect_err("oversized response must fail");

        assert!(matches!(
            err,
            PromptIntelError::Io(ref io_err) if io_err.kind() == io::ErrorKind::InvalidData
        ));
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
