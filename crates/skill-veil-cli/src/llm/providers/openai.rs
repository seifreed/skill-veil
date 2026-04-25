//! OpenAI `/v1/chat/completions` provider.
//!
//! Also serves as the basis for LMStudio (same request/response shape, just
//! a different `base_url` and no auth).

use crate::config::ProviderParams;
use crate::llm::client::{
    build_agent, openai_compatible_messages_json, post_json_with_retry, LlmProvider,
};
use crate::llm::types::{LlmError, LlmPrompt, LlmRawResponse};

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_MODEL: &str = "gpt-4o-mini";

pub(crate) struct OpenAiProvider {
    agent: ureq::Agent,
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
}

impl OpenAiProvider {
    pub(crate) fn new(
        params: ProviderParams,
        timeout_secs: u64,
        base_url_override: Option<String>,
    ) -> Result<Self, LlmError> {
        let api_key = params.api_key.clone().ok_or(LlmError::NotConfigured)?;
        let base_url = base_url_override
            .or(params.base_url.clone())
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

impl LlmProvider for OpenAiProvider {
    fn analyze(&self, prompt: &LlmPrompt) -> Result<LlmRawResponse, LlmError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": serde_json::from_str::<serde_json::Value>(
                &openai_compatible_messages_json(prompt)
            ).unwrap_or(serde_json::json!([])),
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
        parse_chat_completion(&text, "openai", &self.model)
    }

    fn name(&self) -> &'static str {
        "openai"
    }

    fn model(&self) -> &str {
        &self.model
    }
}

/// Shared helper also used by LMStudio. Parses the `choices[0].message.content`
/// shape common to all OpenAI-compatible APIs.
pub(crate) fn parse_chat_completion(
    body: &str,
    provider: &'static str,
    model: &str,
) -> Result<LlmRawResponse, LlmError> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| LlmError::Decode(e.to_string()))?;
    let content = v["choices"]
        .get(0)
        .and_then(|c| c["message"]["content"].as_str())
        .ok_or_else(|| LlmError::Decode("missing choices[0].message.content".into()))?
        .to_string();
    let usage_tokens = v["usage"]["total_tokens"].as_u64().map(|t| t as u32);
    Ok(LlmRawResponse {
        content,
        usage_tokens,
        provider,
        model: model.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chat_completion_envelope() {
        let body = r#"{
            "choices": [{"message": {"content": "hello world"}}],
            "usage": {"total_tokens": 42}
        }"#;
        let got = parse_chat_completion(body, "openai", "gpt-4o-mini").unwrap();
        assert_eq!(got.content, "hello world");
        assert_eq!(got.usage_tokens, Some(42));
    }

    #[test]
    fn parse_chat_completion_errors_on_missing_content() {
        let body = r#"{"choices": []}"#;
        assert!(parse_chat_completion(body, "openai", "x").is_err());
    }
}
