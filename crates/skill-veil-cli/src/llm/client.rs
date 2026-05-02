//! LLM provider trait and shared HTTP helpers.
//!
//! Each provider implements [`LlmProvider::analyze`] to handle its own
//! request shape (OpenAI chat/completions vs Anthropic messages vs Ollama
//! /api/chat). Shared concerns — ureq agent construction, retry on 429 —
//! live in [`post_json_with_retry`].

use super::types::{LlmError, LlmPrompt, LlmRawResponse};
use std::time::Duration;

/// Maximum number of *additional* attempts after the initial request
/// fails on a transient error (network, 429, 5xx). Total request count
/// is therefore `MAX_ADDITIONAL_ATTEMPTS + 1` = 3. Pre-fix the constant
/// was named `MAX_RETRIES = 2`, leading operators reading the source
/// to expect exactly 2 total attempts when in fact 3 were issued. The
/// new name matches the loop's `attempt >= MAX_ADDITIONAL_ATTEMPTS`
/// guard semantics.
const MAX_ADDITIONAL_ATTEMPTS: u32 = 2;
const INITIAL_BACKOFF_MS: u64 = 1_500;

/// Maximum response body size (10 MiB). A compromised or misconfigured LLM
/// endpoint can return an arbitrarily large response body. Without a cap, the
/// scanner would allocate unbounded memory before any downstream parsing or
/// truncation occurs. 10 MiB is three orders of magnitude above realistic
/// LLM responses while preventing OOM.
const MAX_RESPONSE_BODY_BYTES: u64 = 10 * 1024 * 1024;

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

    /// Canonical fingerprint of every sampling parameter this provider
    /// bakes into outbound requests (temperature, max_tokens, top_p, …).
    ///
    /// The cache layer hashes this string into the cache key alongside
    /// `(provider, model, system, user_json)`. Without it, two scans
    /// with the same prompt but different `temperature` config would
    /// share a cache key — the second scan would return the first
    /// scan's verdict for the full `CACHE_TTL_DAYS` window, masking the
    /// user's deliberate change to inference behaviour.
    ///
    /// Providers that do not bake any sampling params into the request
    /// (e.g. Ollama, which forwards model defaults) MUST still return a
    /// stable, non-empty token here so the field is always present in
    /// the hashed input — adding a new param later then trivially
    /// changes the fingerprint without needing a separate "is empty?"
    /// branch.
    fn sampling_fingerprint(&self) -> String;
}

pub(crate) fn build_agent(timeout_secs: u64) -> ureq::Agent {
    let user_agent = format!("skill-veil/{} (+llm-enrichment)", env!("CARGO_PKG_VERSION"));
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(&user_agent)
        // Prevent API key leakage through HTTP 3xx redirects. Every LLM
        // provider sends Authorization headers; silently following a redirect
        // would forward those headers to the redirect target. The VT client
        // already guards against this exact attack with redirects(0).
        .redirects(0)
        .build()
}

/// Cap on the bytes from a provider error body that we keep for embedding
/// in `LlmError::HttpStatus { body }`. Provider gateways commonly return
/// multi-kilobyte HTML pages on 5xx, and a hostile MITM can return
/// arbitrarily large bodies. Anything beyond this point is truncation noise
/// for operator diagnostics, so we drop it before it reaches `tracing::warn`
/// log aggregators or operator terminals.
const ERROR_BODY_MAX_BYTES: usize = 512;

/// Truncate `body` to at most [`ERROR_BODY_MAX_BYTES`] bytes, ending on a
/// UTF-8 char boundary, appending `"...[truncated]"` when shortened. Lets
/// the producer (`drain_error_body`) cap once at construction so every
/// downstream consumer (`tracing::warn!`, `eprintln!`, structured-output
/// formatters) inherits the bound for free.
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

/// Drains an HTTP error response into a string for diagnostic reporting.
///
/// # Contract
///
/// Returns whatever bytes the provider sent in the body, even partial,
/// truncated to [`ERROR_BODY_MAX_BYTES`] so a hostile or misbehaving gateway
/// cannot push multi-kilobyte HTML/script payloads into operator logs. If
/// reading the body itself fails (transport error mid-stream, encoding
/// issue), emits a `tracing::warn` describing the I/O error and returns an
/// empty string. The pre-fix code used `unwrap_or_default()`, which silently
/// erased the underlying error and made debugging provider failures (a
/// gateway 502, a malformed body) impossible — operators saw
/// `LlmError::HttpStatus { status, body: "" }` with no clue why the body
/// was missing. The warning preserves that context.
fn drain_error_body(status: u16, resp: ureq::Response) -> String {
    match bounded_read_response(resp) {
        Ok(body) => truncate_error_body(body),
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

/// Read an HTTP response body with a size cap to prevent unbounded memory
/// allocation from a compromised or misconfigured endpoint.
pub(crate) fn bounded_read_response(resp: ureq::Response) -> Result<String, std::io::Error> {
    use std::io::Read;
    let mut buf = String::new();
    resp.into_reader()
        .take(MAX_RESPONSE_BODY_BYTES)
        .read_to_string(&mut buf)?;
    Ok(buf)
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
                return bounded_read_response(resp).map_err(|e| LlmError::Decode(e.to_string()))
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
                    if attempt >= MAX_ADDITIONAL_ATTEMPTS {
                        return if status == 429 {
                            Err(LlmError::RateLimited { retries: attempt })
                        } else {
                            let body = drain_error_body(status, resp);
                            Err(LlmError::HttpStatus { status, body })
                        };
                    }
                    let delay = Duration::from_millis(
                        INITIAL_BACKOFF_MS.saturating_mul(2u64.saturating_pow(attempt)),
                    );
                    tracing::warn!(
                        "LLM provider returned status {}, sleeping {:?} (attempt {}/{})",
                        status,
                        delay,
                        attempt + 1,
                        MAX_ADDITIONAL_ATTEMPTS
                    );
                    std::thread::sleep(delay);
                    attempt += 1;
                    continue;
                }
                let body = drain_error_body(status, resp);
                return Err(LlmError::HttpStatus { status, body });
            }
            Err(ureq::Error::Transport(err)) => {
                if attempt >= MAX_ADDITIONAL_ATTEMPTS {
                    return Err(LlmError::Network(err.to_string()));
                }
                let delay = Duration::from_millis(
                    INITIAL_BACKOFF_MS.saturating_mul(2u64.saturating_pow(attempt)),
                );
                tracing::warn!(
                    "LLM transport error, sleeping {:?} (attempt {}/{})",
                    delay,
                    attempt + 1,
                    MAX_ADDITIONAL_ATTEMPTS
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

    /// Contract: a body shorter than [`ERROR_BODY_MAX_BYTES`] is preserved
    /// verbatim. Pins the no-truncate branch so the cap doesn't silently
    /// shorten ordinary error messages.
    #[test]
    fn truncate_error_body_keeps_short_payloads_intact() {
        let body = "transient gateway timeout".to_string();
        assert_eq!(truncate_error_body(body.clone()), body);
    }

    /// Contract: a body longer than [`ERROR_BODY_MAX_BYTES`] is truncated
    /// and tagged with a visible suffix so log readers know the message
    /// was shortened. Pre-fix `LlmError::HttpStatus` embedded the full
    /// body uncapped, which let a hostile or misbehaving gateway push
    /// multi-kilobyte HTML/script payloads into operator logs.
    #[test]
    fn truncate_error_body_caps_long_payloads_with_suffix() {
        let huge = "X".repeat(ERROR_BODY_MAX_BYTES * 4);
        let truncated = truncate_error_body(huge);
        assert!(
            truncated.len() <= ERROR_BODY_MAX_BYTES + "...[truncated]".len(),
            "truncated body must be capped, got len={}",
            truncated.len()
        );
        assert!(
            truncated.ends_with("...[truncated]"),
            "truncated body must carry the suffix; got tail: {:?}",
            &truncated[truncated.len().saturating_sub(20)..]
        );
    }

    /// Contract: truncation never splits a multi-byte UTF-8 character.
    /// `is_char_boundary` walk-back guards against `String` slicing
    /// panicking when `ERROR_BODY_MAX_BYTES` lands inside a codepoint —
    /// pin that the result is valid UTF-8 (as `String` always is) and
    /// the suffix is intact for a body whose cut point falls in the
    /// middle of a multi-byte char.
    #[test]
    fn truncate_error_body_respects_utf8_char_boundary() {
        let mut body = "a".repeat(ERROR_BODY_MAX_BYTES - 1);
        body.push('é'); // 2 bytes — straddles ERROR_BODY_MAX_BYTES if cut naively
        body.push_str(&"b".repeat(64));
        let truncated = truncate_error_body(body);
        assert!(
            truncated.ends_with("...[truncated]"),
            "must still emit the suffix when truncating"
        );
    }
}
