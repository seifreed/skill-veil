//! LMStudio provider — serves an OpenAI-compatible API on a local port.
//! Reuses [`super::openai::parse_chat_completion`] for response parsing.

use crate::config::ProviderParams;
use crate::llm::client::{
    build_agent, openai_compatible_messages_value, post_json_with_retry, LlmProvider,
};
use crate::llm::types::{LlmError, LlmPrompt, LlmRawResponse};

const DEFAULT_BASE_URL: &str = "http://localhost:1234/v1";
const DEFAULT_MODEL: &str = "local-model";

pub(crate) struct LmStudioProvider {
    agent: ureq::Agent,
    api_key: Option<String>,
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
            api_key: params.api_key.clone(),
            base_url,
            model,
            max_tokens: params.max_tokens.unwrap_or(1024),
            temperature: params.temperature.unwrap_or(0.1),
        })
    }

    /// Build the request headers used by `analyze`.
    ///
    /// LMStudio in its default local configuration needs no auth, but if
    /// the user fronted it with a proxy and set `api_key` in
    /// `~/.skill-veil.toml`, we forward that as a Bearer token. Mirrors
    /// `super::ollama::OllamaProvider`'s pattern. Extracted as a method so
    /// tests can verify the contract without spinning up a mock HTTP
    /// server.
    fn build_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();
        if let Some(ref k) = self.api_key {
            headers.push(("authorization", format!("Bearer {k}")));
        }
        headers
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
            "messages": openai_compatible_messages_value(prompt),
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        })
        .to_string();

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        // LMStudio usually needs no auth, but if the user set one (e.g. they
        // fronted it with a proxy), we honour it as Bearer. Header values
        // are owned `String`s so they outlive the slice borrowed by
        // `post_json_with_retry`.
        let owned_headers = self.build_headers();
        let headers: Vec<(&str, &str)> = owned_headers
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();
        let text = post_json_with_retry(&self.agent, &url, &headers, &body)?;
        super::openai::parse_chat_completion(&text)
    }

    fn name(&self) -> &'static str {
        "lmstudio"
    }

    fn sampling_fingerprint(&self) -> String {
        format!(
            "max_tokens={};temperature={}",
            self.max_tokens, self.temperature
        )
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
        // An entry whose `id` is missing or non-string cannot match any model
        // and must be skipped. The previous `unwrap_or("")` collapsed both
        // cases to the empty string, which would silently match a request
        // for `model = ""` and (more importantly) prevented the loop from
        // continuing to a later valid entry whose id *did* match.
        let Some(id) = entry.get("id").and_then(|x| x.as_str()) else {
            continue;
        };
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

    /// Contract: an entry whose `id` is missing or non-string must be
    /// skipped, never matched. The pre-fix code used `unwrap_or("")`,
    /// which silently coerced a `null` or numeric `id` into the empty
    /// string. Two fall-out symptoms are pinned here:
    ///
    /// 1. A query for `model = ""` would falsely match a typed-wrong entry.
    /// 2. A bad early entry would mask a later, well-typed entry whose
    ///    `id` actually equals the requested model — the loop must keep
    ///    searching past the malformed entry rather than treating it as
    ///    a non-match-with-empty-id.
    #[test]
    fn parse_lmstudio_ctx_skips_entries_with_non_string_id() {
        let body = r#"{
            "data": [
                {"id": null, "loaded_context_length": 1},
                {"id": 42, "loaded_context_length": 2},
                {"id": "real-model", "loaded_context_length": 4096}
            ]
        }"#;
        assert_eq!(
            parse_lmstudio_context_length(body, "real-model"),
            Some(4096),
            "well-typed entry must be reachable past malformed siblings",
        );
        assert_eq!(
            parse_lmstudio_context_length(body, ""),
            None,
            "empty-string model must NOT match an entry whose id was \
             coerced from null/non-string",
        );
    }

    fn provider_with_api_key(api_key: Option<&str>) -> LmStudioProvider {
        LmStudioProvider::new(
            ProviderParams {
                model: "test-model".to_string(),
                api_key: api_key.map(ToString::to_string),
                ..Default::default()
            },
            5,
        )
        .expect("LmStudioProvider::new must accept default params")
    }

    /// Contract: when `params.api_key` is set, the request carries an
    /// `Authorization: Bearer <key>` header. Anchors the bug fix — the
    /// pre-fix code dropped the configured key silently.
    #[test]
    fn lmstudio_request_includes_bearer_when_api_key_set() {
        let provider = provider_with_api_key(Some("secret-key"));
        let headers = provider.build_headers();
        assert_eq!(
            headers.iter().find(|(k, _)| *k == "authorization"),
            Some(&("authorization", "Bearer secret-key".to_string())),
            "Bearer header MUST be present when api_key is configured; got {headers:?}"
        );
    }

    /// Contract: when `params.api_key` is absent, no Authorization header
    /// is sent. LMStudio in its default local configuration rejects
    /// unexpected auth headers, so omitting the header is the safe path.
    #[test]
    fn lmstudio_request_omits_bearer_when_api_key_unset() {
        let provider = provider_with_api_key(None);
        let headers = provider.build_headers();
        assert!(
            headers.iter().all(|(k, _)| *k != "authorization"),
            "Authorization header MUST NOT be present when api_key is unset; got {headers:?}"
        );
    }
}
