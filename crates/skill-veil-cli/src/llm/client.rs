//! LLM provider trait and shared HTTP helpers.
//!
//! Each provider implements [`LlmProvider::analyze`] to handle its own
//! request shape (OpenAI chat/completions vs Anthropic messages vs Ollama
//! /api/chat). Shared concerns — ureq agent construction, retry on 429 —
//! live in [`post_json_with_retry`].

use super::types::{LlmError, LlmPrompt, LlmRawResponse};
use std::time::Duration;

const MAX_RETRIES: u32 = 2;
const INITIAL_BACKOFF_MS: u64 = 1_500;

/// Implemented by every concrete provider (OpenAI, Anthropic, Ollama, …).
pub(crate) trait LlmProvider: Send + Sync {
    /// One-shot analysis. Takes the prompt by shared reference to make the
    /// "LLM never mutates caller state" contract compile-enforceable.
    fn analyze(&self, prompt: &LlmPrompt) -> Result<LlmRawResponse, LlmError>;
    fn name(&self) -> &'static str;
    fn model(&self) -> &str;

    /// Best-effort probe of the model's loaded context window in tokens.
    /// Returns `None` if the provider can't introspect the value (e.g.
    /// cloud APIs that don't expose it, or a transport error). The caller
    /// must tolerate `None` and fall back to the static model table.
    fn probe_context_length(&self) -> Option<usize> {
        None
    }
}

pub(crate) fn build_agent(timeout_secs: u64) -> ureq::Agent {
    let user_agent = format!("skill-veil/{} (+llm-enrichment)", env!("CARGO_PKG_VERSION"));
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(&user_agent)
        .build()
}

/// Drains an HTTP error response into a string for diagnostic reporting.
///
/// # Contract
///
/// Returns whatever bytes the provider sent in the body, even partial. If
/// reading the body itself fails (transport error mid-stream, encoding
/// issue), emits a `tracing::warn` describing the I/O error and returns an
/// empty string. The pre-fix code used `unwrap_or_default()`, which silently
/// erased the underlying error and made debugging provider failures (a
/// gateway 502, a malformed body) impossible — operators saw
/// `LlmError::HttpStatus { status, body: "" }` with no clue why the body
/// was missing. The warning preserves that context.
fn drain_error_body(status: u16, resp: ureq::Response) -> String {
    match resp.into_string() {
        Ok(body) => body,
        Err(err) => {
            tracing::warn!(
                "LLM provider returned HTTP {} but the response body could not be read: {}",
                status,
                err
            );
            String::new()
        }
    }
}

/// POST a JSON body with authorization headers, parse the response as a
/// string, and retry on HTTP 429 with exponential backoff. The caller is
/// responsible for extracting the assistant content from the returned text
/// (each provider's envelope differs).
pub(crate) fn post_json_with_retry(
    agent: &ureq::Agent,
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<String, LlmError> {
    let mut attempt = 0u32;
    loop {
        let mut req = agent.post(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let result = req
            .set("content-type", "application/json")
            .send_string(body);
        match result {
            Ok(resp) => {
                return resp
                    .into_string()
                    .map_err(|e| LlmError::Decode(e.to_string()))
            }
            Err(ureq::Error::Status(status, resp)) => {
                if status == 401 || status == 403 {
                    return Err(LlmError::Unauthorized);
                }
                // 429 (rate limited) and 5xx (server error) are both
                // transient: a 503 from a model-overloaded gateway is just
                // as worth retrying as a 429 from quota throttling. 4xx
                // codes other than auth are caller errors and MUST NOT be
                // retried — the request will fail the same way every time.
                let is_retryable = status == 429 || (500..600).contains(&status);
                if is_retryable {
                    if attempt >= MAX_RETRIES {
                        return if status == 429 {
                            Err(LlmError::RateLimited { retries: attempt })
                        } else {
                            let body = drain_error_body(status, resp);
                            Err(LlmError::HttpStatus { status, body })
                        };
                    }
                    let delay = Duration::from_millis(INITIAL_BACKOFF_MS * 2u64.pow(attempt));
                    tracing::warn!(
                        "LLM provider returned status {}, sleeping {:?} (attempt {}/{})",
                        status,
                        delay,
                        attempt + 1,
                        MAX_RETRIES
                    );
                    std::thread::sleep(delay);
                    attempt += 1;
                    continue;
                }
                let body = drain_error_body(status, resp);
                return Err(LlmError::HttpStatus { status, body });
            }
            Err(ureq::Error::Transport(err)) => {
                if attempt >= MAX_RETRIES {
                    return Err(LlmError::Network(err.to_string()));
                }
                let delay = Duration::from_millis(INITIAL_BACKOFF_MS * 2u64.pow(attempt));
                tracing::warn!(
                    "LLM transport error, sleeping {:?} (attempt {}/{})",
                    delay,
                    attempt + 1,
                    MAX_RETRIES
                );
                std::thread::sleep(delay);
                attempt += 1;
            }
        }
    }
}

/// Build the `messages` array used by every OpenAI-compatible provider.
/// Returns a `serde_json::Value` so callers can embed it directly in
/// their request body without round-tripping through a string. The
/// previous string-returning helper forced each provider to do
/// `serde_json::from_str(...).unwrap_or(json!([]))`, where the silent
/// fallback would have produced a request with no messages at all if the
/// re-parse ever failed (model receives system prompt + no user content).
pub(crate) fn openai_compatible_messages_value(prompt: &LlmPrompt) -> serde_json::Value {
    serde_json::json!([
        { "role": "system", "content": prompt.system },
        { "role": "user", "content": prompt.user_json },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a readable error body MUST be returned verbatim so the
    /// provider's actual error message reaches `LlmError::HttpStatus { body }`.
    /// Pre-fix the call site used `unwrap_or_default()` which already returned
    /// the body on success — this test pins the success branch so the
    /// regression-causing change (replacing `unwrap_or_default` with the
    /// helper) cannot drop the body.
    #[test]
    fn drain_error_body_returns_body_string_on_success() {
        let resp: ureq::Response = "HTTP/1.1 503 Service Unavailable\r\n\
             Content-Length: 13\r\n\
             \r\n\
             upstream-down"
            .parse()
            .expect("synthetic response must parse");
        let body = drain_error_body(503, resp);
        assert_eq!(body, "upstream-down");
    }

    /// Contract: a body sent with no Content-Length and EOF still drains to
    /// whatever bytes were received. Confirms the helper does not over-read
    /// or panic on minimal headers (matches what some gateways return).
    #[test]
    fn drain_error_body_handles_response_without_content_length() {
        let resp: ureq::Response = "HTTP/1.1 502 Bad Gateway\r\n\r\nfailure-text"
            .parse()
            .expect("synthetic response must parse");
        let body = drain_error_body(502, resp);
        assert_eq!(body, "failure-text");
    }
}
