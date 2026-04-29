//! Grok (xAI) provider — `/v1/chat/completions`, OpenAI-compatible shape.
//!
//! We keep this as a separate file (rather than parameterising OpenAiProvider)
//! so xAI-specific tweaks stay localised: different `max_tokens` defaults,
//! future support for Grok reasoning tokens, etc.

use crate::config::ProviderParams;
use crate::llm::client::{
    build_agent, openai_compatible_messages_value, post_json_with_retry, LlmProvider,
};
use crate::llm::types::{LlmError, LlmPrompt, LlmRawResponse};

const DEFAULT_BASE_URL: &str = "https://api.x.ai/v1";
const DEFAULT_MODEL: &str = "grok-4-latest";

pub(crate) struct GrokProvider {
    agent: ureq::Agent,
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
}

impl GrokProvider {
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

impl LlmProvider for GrokProvider {
    fn analyze(&self, prompt: &LlmPrompt) -> Result<LlmRawResponse, LlmError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": openai_compatible_messages_value(prompt),
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "response_format": { "type": "json_object" },
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
        "grok"
    }

    fn model(&self) -> &str {
        &self.model
    }
}

#[cfg(test)]
mod tests {
    /// Contract: Grok speaks the OpenAI chat-completion envelope verbatim,
    /// so `parse_chat_completion` MUST surface its `choices[0].message.content`
    /// without provider-specific fixups.
    #[test]
    fn parses_grok_chat_completion_via_shared_parser() {
        let body = r#"{
            "choices": [{"message": {"content": "{\"verdict\":\"benign\"}"}}],
            "usage": {"total_tokens": 120}
        }"#;
        let got = super::super::openai::parse_chat_completion(body).unwrap();
        assert!(got.content.contains("verdict"));
    }
}
