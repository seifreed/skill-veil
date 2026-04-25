//! LMStudio provider — serves an OpenAI-compatible API on a local port.
//! Reuses [`super::openai::parse_chat_completion`] for response parsing.

use crate::config::ProviderParams;
use crate::llm::client::{
    build_agent, openai_compatible_messages_json, post_json_with_retry, LlmProvider,
};
use crate::llm::types::{LlmError, LlmPrompt, LlmRawResponse};

const DEFAULT_BASE_URL: &str = "http://localhost:1234/v1";
const DEFAULT_MODEL: &str = "local-model";

pub(crate) struct LmStudioProvider {
    agent: ureq::Agent,
    base_url: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
}

impl LmStudioProvider {
    pub(crate) fn new(params: ProviderParams, timeout_secs: u64) -> Result<Self, LlmError> {
        let base_url = params
            .base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let model = super::resolve_model(&params, DEFAULT_MODEL);
        Ok(Self {
            agent: build_agent(timeout_secs),
            base_url,
            model,
            max_tokens: params.max_tokens.unwrap_or(1024),
            temperature: params.temperature.unwrap_or(0.1),
        })
    }
}

impl LlmProvider for LmStudioProvider {
    fn analyze(&self, prompt: &LlmPrompt) -> Result<LlmRawResponse, LlmError> {
        // LMStudio rejects OpenAI's `response_format: json_object` and
        // requires either `json_schema` or `text`. Omit the field entirely
        // and rely on the system prompt to drive JSON output; our
        // `parse_verdict_json` tolerates ```json fences and whitespace.
        let body = serde_json::json!({
            "model": self.model,
            "messages": serde_json::from_str::<serde_json::Value>(
                &openai_compatible_messages_json(prompt)
            ).unwrap_or(serde_json::json!([])),
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        })
        .to_string();

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        // LMStudio usually needs no auth, but if the user set one (e.g. they
        // fronted it with a proxy), we honour it as Bearer.
        let headers: Vec<(&str, &str)> = Vec::new();
        let text = post_json_with_retry(&self.agent, &url, &headers, &body)?;
        super::openai::parse_chat_completion(&text, "lmstudio", &self.model)
    }

    fn name(&self) -> &'static str {
        "lmstudio"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn probe_context_length(&self) -> Option<usize> {
        // LMStudio 0.3+ exposes `/api/v0/models` (native API, distinct from
        // the OpenAI-compat `/v1/models`) with `loaded_context_length` per
        // model entry. If the base_url is the OpenAI-compat prefix ending in
        // `/v1`, strip it to reach the native API root.
        let api_root = self
            .base_url
            .trim_end_matches('/')
            .strip_suffix("/v1")
            .unwrap_or_else(|| self.base_url.trim_end_matches('/'));
        let url = format!("{api_root}/api/v0/models");
        let resp = self.agent.get(&url).call().ok()?;
        let text = resp.into_string().ok()?;
        parse_lmstudio_context_length(&text, &self.model)
    }
}

/// Find the `loaded_context_length` (preferred) or `max_context_length` for
/// the given model id in a LMStudio `/api/v0/models` response. Returns `None`
/// on missing/malformed data.
pub(crate) fn parse_lmstudio_context_length(body: &str, model: &str) -> Option<usize> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let data = v.get("data")?.as_array()?;
    for entry in data {
        let id = entry.get("id").and_then(|x| x.as_str()).unwrap_or("");
        if id == model {
            // Prefer the actually-loaded ctx; fall back to max.
            if let Some(n) = entry.get("loaded_context_length").and_then(|x| x.as_u64()) {
                return Some(n as usize);
            }
            if let Some(n) = entry.get("max_context_length").and_then(|x| x.as_u64()) {
                return Some(n as usize);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lmstudio_ctx_prefers_loaded_over_max() {
        let body = r#"{
            "data": [
                {
                    "id": "google/gemma-4-26b-a4b",
                    "type": "llm",
                    "max_context_length": 128000,
                    "loaded_context_length": 8192
                }
            ]
        }"#;
        assert_eq!(
            parse_lmstudio_context_length(body, "google/gemma-4-26b-a4b"),
            Some(8192),
        );
    }

    #[test]
    fn parse_lmstudio_ctx_falls_back_to_max_when_loaded_absent() {
        let body = r#"{
            "data": [{"id": "m", "max_context_length": 4096}]
        }"#;
        assert_eq!(parse_lmstudio_context_length(body, "m"), Some(4096));
    }

    #[test]
    fn parse_lmstudio_ctx_returns_none_for_unknown_model() {
        let body = r#"{"data": [{"id": "other", "loaded_context_length": 8192}]}"#;
        assert_eq!(parse_lmstudio_context_length(body, "missing"), None);
    }

    #[test]
    fn parse_lmstudio_ctx_returns_none_on_malformed_body() {
        assert_eq!(parse_lmstudio_context_length("{}", "m"), None);
        assert_eq!(parse_lmstudio_context_length("not-json", "m"), None);
    }
}
