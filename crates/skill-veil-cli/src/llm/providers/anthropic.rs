//! Anthropic `/v1/messages` provider.

use crate::config::ProviderParams;
use crate::llm::client::{build_agent, post_json_with_retry, LlmProvider};
use crate::llm::types::{LlmError, LlmPrompt, LlmRawResponse};

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com/v1";
const DEFAULT_MODEL: &str = "claude-sonnet-4-5";
const ANTHROPIC_VERSION: &str = "2023-06-01";

pub(crate) struct AnthropicProvider {
    agent: ureq::Agent,
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
}

impl AnthropicProvider {
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

impl LlmProvider for AnthropicProvider {
    fn analyze(&self, prompt: &LlmPrompt) -> Result<LlmRawResponse, LlmError> {
        // Anthropic uses top-level `system` + a `messages` array of user/assistant.
        // We pack the whole bundle as one user message (no multi-turn).
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "system": prompt.system,
            "messages": [
                { "role": "user", "content": prompt.user_json }
            ],
        })
        .to_string();

        let url = format!("{}/messages", self.base_url.trim_end_matches('/'));
        let text = post_json_with_retry(
            &self.agent,
            &url,
            &[
                ("x-api-key", self.api_key.as_str()),
                ("anthropic-version", ANTHROPIC_VERSION),
            ],
            &body,
        )?;
        parse_messages_response(&text)
    }

    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn sampling_fingerprint(&self) -> String {
        format!(
            "max_tokens={};temperature={}",
            self.max_tokens, self.temperature
        )
    }
}

pub(crate) fn parse_messages_response(body: &str) -> Result<LlmRawResponse, LlmError> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| LlmError::Decode(e.to_string()))?;
    // content: [{ "type": "text", "text": "..." }, ...] — concatenate text blocks.
    let content_arr = v["content"]
        .as_array()
        .ok_or_else(|| LlmError::Decode("missing content array".into()))?;
    let mut content = String::new();
    for block in content_arr {
        if block["type"] == "text" {
            if let Some(t) = block["text"].as_str() {
                content.push_str(t);
            }
        }
    }
    if content.is_empty() {
        return Err(LlmError::Decode("no text blocks in response".into()));
    }
    Ok(LlmRawResponse { content })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a multi-block Anthropic envelope MUST surface every
    /// `text` block concatenated in order.
    #[test]
    fn parses_messages_envelope() {
        let body = r#"{
            "content": [
                {"type": "text", "text": "first "},
                {"type": "text", "text": "second"}
            ],
            "usage": {"input_tokens": 100, "output_tokens": 50}
        }"#;
        let got = parse_messages_response(body).unwrap();
        assert_eq!(got.content, "first second");
    }

    /// Contract (negative): an envelope without a `content` array MUST
    /// fail rather than emit empty content.
    #[test]
    fn parse_fails_when_content_missing() {
        assert!(parse_messages_response("{}").is_err());
    }
}
