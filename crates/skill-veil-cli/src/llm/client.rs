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
                            let body = resp.into_string().unwrap_or_default();
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
                let body = resp.into_string().unwrap_or_default();
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

/// Build the `messages` list used by every OpenAI-compatible provider.
/// Kept here so it doesn't need to be redefined in each provider.
pub(crate) fn openai_compatible_messages_json(prompt: &LlmPrompt) -> String {
    serde_json::json!([
        { "role": "system", "content": prompt.system },
        { "role": "user", "content": prompt.user_json },
    ])
    .to_string()
}
