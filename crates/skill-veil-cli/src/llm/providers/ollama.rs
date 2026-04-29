//! Ollama provider — covers both local (`http://localhost:11434`) and Cloud
//! (`https://ollama.com`). Same wire protocol, differs only in `base_url`
//! and whether a Bearer token is required.

use crate::config::ProviderParams;
use crate::llm::client::{build_agent, post_json_with_retry, LlmProvider};
use crate::llm::types::{LlmError, LlmPrompt, LlmRawResponse};

const DEFAULT_LOCAL_BASE_URL: &str = "http://localhost:11434";
const DEFAULT_CLOUD_BASE_URL: &str = "https://ollama.com";
const DEFAULT_MODEL: &str = "llama3.1:8b";

pub(crate) struct OllamaProvider {
    agent: ureq::Agent,
    api_key: Option<String>,
    base_url: String,
    model: String,
    cloud: bool,
}

impl OllamaProvider {
    pub(crate) fn new(
        params: ProviderParams,
        timeout_secs: u64,
        cloud: bool,
    ) -> Result<Self, LlmError> {
        // Cloud requires api_key; local does not.
        let api_key = if cloud {
            Some(params.api_key.clone().ok_or(LlmError::NotConfigured)?)
        } else {
            params.api_key.clone()
        };
        let base_url = params.base_url.clone().unwrap_or_else(|| {
            if cloud {
                DEFAULT_CLOUD_BASE_URL.to_string()
            } else {
                DEFAULT_LOCAL_BASE_URL.to_string()
            }
        });
        let model = super::resolve_model(&params, DEFAULT_MODEL);
        Ok(Self {
            agent: build_agent(timeout_secs),
            api_key,
            base_url,
            model,
            cloud,
        })
    }
}

impl LlmProvider for OllamaProvider {
    fn analyze(&self, prompt: &LlmPrompt) -> Result<LlmRawResponse, LlmError> {
        let body = serde_json::json!({
            "model": self.model,
            "stream": false,
            "format": "json",
            "messages": [
                { "role": "system", "content": prompt.system },
                { "role": "user", "content": prompt.user_json },
            ],
        })
        .to_string();

        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
        let auth_header;
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(ref k) = self.api_key {
            auth_header = format!("Bearer {k}");
            headers.push(("authorization", auth_header.as_str()));
        }
        let text = post_json_with_retry(&self.agent, &url, &headers, &body)?;
        parse_ollama_response(&text)
    }

    fn name(&self) -> &'static str {
        self.provider_name()
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn probe_context_length(&self) -> Option<usize> {
        // POST /api/show returns model metadata including a `model_info` map
        // with `<family>.context_length` entries (e.g. `llama.context_length`)
        // and a `parameters` string like "num_ctx 8192".
        //
        // The canonical field name today is `model`; older Ollama releases
        // expected `name`. We send both for forward/backward compatibility.
        let body = serde_json::json!({
            "model": self.model,
            "name": self.model,
        })
        .to_string();
        let url = format!("{}/api/show", self.base_url.trim_end_matches('/'));
        let auth_header;
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(ref k) = self.api_key {
            auth_header = format!("Bearer {k}");
            headers.push(("authorization", auth_header.as_str()));
        }
        let text = post_json_with_retry(&self.agent, &url, &headers, &body).ok()?;
        parse_ollama_context_length(&text)
    }
}

impl OllamaProvider {
    fn provider_name(&self) -> &'static str {
        if self.cloud {
            "ollama-cloud"
        } else {
            "ollama"
        }
    }
}

/// Extract the context-window size in tokens from an Ollama `/api/show`
/// response. Prefers the typed `model_info` entries (`<family>.context_length`)
/// and falls back to parsing the `parameters` string (`num_ctx N`). Returns
/// `None` if nothing usable is present.
pub(crate) fn parse_ollama_context_length(body: &str) -> Option<usize> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if let Some(info) = v.get("model_info").and_then(|x| x.as_object()) {
        for (key, value) in info {
            if key.ends_with(".context_length") {
                if let Some(n) = value.as_u64() {
                    return Some(n as usize);
                }
            }
        }
    }
    if let Some(params) = v.get("parameters").and_then(|x| x.as_str()) {
        for line in params.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("num_ctx") {
                if let Some(num) = rest.split_whitespace().next() {
                    if let Ok(n) = num.parse::<usize>() {
                        return Some(n);
                    }
                }
            }
        }
    }
    None
}

pub(crate) fn parse_ollama_response(body: &str) -> Result<LlmRawResponse, LlmError> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| LlmError::Decode(e.to_string()))?;
    let content = v["message"]["content"]
        .as_str()
        .ok_or_else(|| LlmError::Decode("missing message.content".into()))?
        .to_string();
    Ok(LlmRawResponse { content })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a well-formed Ollama chat envelope MUST surface
    /// `message.content` verbatim.
    #[test]
    fn parses_chat_response() {
        let body = r#"{
            "message": {"role": "assistant", "content": "{\"verdict\":\"benign\"}"},
            "eval_count": 25
        }"#;
        let got = parse_ollama_response(body).unwrap();
        assert!(got.content.contains("verdict"));
    }

    /// Contract (negative): an envelope without `message.content` MUST
    /// fail rather than emit empty content.
    #[test]
    fn parse_fails_on_missing_content() {
        assert!(parse_ollama_response("{}").is_err());
    }

    #[test]
    fn probe_parses_model_info_context_length() {
        let body = r#"{
            "modelfile": "...",
            "parameters": "stop \"</s>\"",
            "model_info": { "llama.context_length": 8192, "llama.embedding_length": 4096 }
        }"#;
        assert_eq!(parse_ollama_context_length(body), Some(8192));
    }

    #[test]
    fn probe_falls_back_to_num_ctx_parameter() {
        let body = r#"{
            "parameters": "num_ctx 16384\nstop \"<|endoftext|>\""
        }"#;
        assert_eq!(parse_ollama_context_length(body), Some(16384));
    }

    #[test]
    fn probe_returns_none_when_field_absent() {
        assert_eq!(parse_ollama_context_length("{}"), None);
        assert_eq!(parse_ollama_context_length("not-json"), None);
    }
}
