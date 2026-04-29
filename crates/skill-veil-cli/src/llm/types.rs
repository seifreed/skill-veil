//! Shared types across all LLM providers.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The rendered prompt fed to a provider. `system` is the fixed analyst
/// instruction; `user_json` is the skill bundle serialised compactly.
#[derive(Debug, Clone)]
pub(crate) struct LlmPrompt {
    pub system: String,
    pub user_json: String,
}

/// Raw response returned by a provider, before structured parsing.
#[derive(Debug, Clone)]
pub(crate) struct LlmRawResponse {
    pub content: String,
}

/// Parsed structured verdict from the LLM. Mirrors the JSON schema the
/// system prompt mandates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LlmVerdict {
    pub verdict: String,  // "malicious" | "suspicious" | "benign"
    pub confidence: f32,  // 0.0 - 1.0
    pub analysis: String, // narrative
    #[serde(default)]
    pub key_signals: Vec<String>,
    #[serde(default)]
    pub agreement_with_scanner: Option<String>, // "agree" | "disagree" | "partial"
    /// Optional: list of supporting-artifact paths the LLM wants to see in
    /// full before committing to a verdict. Empty = verdict is final.
    /// The orchestrator uses these to trigger a single follow-up turn with
    /// the requested file contents included.
    #[serde(default)]
    pub insufficient_context: Vec<String>,
}

#[derive(Debug, Error)]
pub(crate) enum LlmError {
    #[error("LLM provider not configured")]
    NotConfigured,
    #[error("LLM authentication failed (check your API key)")]
    Unauthorized,
    #[error("LLM provider returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("LLM rate limit exceeded after {retries} retries")]
    RateLimited { retries: u32 },
    #[error("network error talking to LLM provider: {0}")]
    Network(String),
    #[error("failed to decode LLM response: {0}")]
    Decode(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
