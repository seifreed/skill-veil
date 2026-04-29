//! Perplexity provider — `/chat/completions`, OpenAI-compatible shape.
//!
//! Notes:
//! - Base URL has no `/v1` prefix (unlike OpenAI/LMStudio).
//! - `response_format: json_object` is accepted by `sonar*` models; older
//!   ones would reject it, so we keep it. If a downstream error surfaces
//!   we can drop it and lean on the tolerant `parse_verdict_json`.
//! - Perplexity responses include citations; we only consume `content`.

use crate::config::ProviderParams;
use crate::llm::client::{
    build_agent, openai_compatible_messages_value, post_json_with_retry, LlmProvider,
};
use crate::llm::types::{LlmError, LlmPrompt, LlmRawResponse};

const DEFAULT_BASE_URL: &str = "https://api.perplexity.ai";
const DEFAULT_MODEL: &str = "sonar-pro";

pub(crate) struct PerplexityProvider {
    agent: ureq::Agent,
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
}

impl PerplexityProvider {
    pub(crate) fn new(params: ProviderParams, timeout_secs: u64) -> Result<Self, LlmError> {
        let api_key = params.api_key.clone().ok_or(LlmError::NotConfigured)?;
        let base_url = params
            .base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let model = super::resolve_model(&params, DEFAULT_MODEL);
        Ok(Self {
            agent: build_agent(timeout_secs),
            api_key,
            base_url,
            model,
            max_tokens: params.max_tokens.unwrap_or(1024),
            temperature: params.temperature.unwrap_or(0.1),
        })
    }
}

impl LlmProvider for PerplexityProvider {
    fn analyze(&self, prompt: &LlmPrompt) -> Result<LlmRawResponse, LlmError> {
        // Perplexity rejects `response_format: json_object` (it expects
        // `{"type":"text"}` or a `json_schema` with a strict schema). We omit
        // the field and rely on the system prompt to drive JSON output; the
        // tolerant `parse_verdict_json` strips fences if the model adds them.
        let body = serde_json::json!({
            "model": self.model,
            "messages": openai_compatible_messages_value(prompt),
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        })
        .to_string();

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let auth = format!("Bearer {}", self.api_key);
        let text = post_json_with_retry(
            &self.agent,
            &url,
            &[("authorization", auth.as_str())],
            &body,
        )?;
        super::openai::parse_chat_completion(&text)
    }

    fn name(&self) -> &'static str {
        "perplexity"
    }

    fn model(&self) -> &str {
        &self.model
    }
}

#[cfg(test)]
mod tests {
    /// Contract: Perplexity also speaks the OpenAI chat-completion envelope,
    /// so `parse_chat_completion` MUST surface its content unchanged.
    #[test]
    fn parses_perplexity_chat_completion_via_shared_parser() {
        let body = r#"{
            "choices": [{"message": {"content": "{\"verdict\":\"malicious\"}"}}],
            "usage": {"total_tokens": 90}
        }"#;
        let got = super::super::openai::parse_chat_completion(body).unwrap();
        assert!(got.content.contains("verdict"));
    }
}
