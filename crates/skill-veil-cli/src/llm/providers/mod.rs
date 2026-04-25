//! Per-provider implementations of [`super::client::LlmProvider`].

pub(crate) mod anthropic;
pub(crate) mod grok;
pub(crate) mod lmstudio;
pub(crate) mod ollama;
pub(crate) mod openai;
pub(crate) mod perplexity;

use super::client::LlmProvider;
use super::types::LlmError;
use crate::config::{LlmConfigSection, LlmProviderKind, ProviderParams};

/// Factory: given the loaded config, build the active provider instance.
pub(crate) fn build_provider(section: &LlmConfigSection) -> Result<Box<dyn LlmProvider>, LlmError> {
    let kind = section.provider;
    let params = section
        .provider_configs
        .get(&kind)
        .cloned()
        .unwrap_or_default();
    let timeout = section.limits.request_timeout_secs;

    match kind {
        LlmProviderKind::OpenAi => Ok(Box::new(openai::OpenAiProvider::new(
            params, timeout, /*base_url_override=*/ None,
        )?)),
        LlmProviderKind::Anthropic => Ok(Box::new(anthropic::AnthropicProvider::new(
            params, timeout,
        )?)),
        LlmProviderKind::Ollama => Ok(Box::new(ollama::OllamaProvider::new(
            params, timeout, /*cloud=*/ false,
        )?)),
        LlmProviderKind::OllamaCloud => Ok(Box::new(ollama::OllamaProvider::new(
            params, timeout, /*cloud=*/ true,
        )?)),
        LlmProviderKind::LmStudio => {
            Ok(Box::new(lmstudio::LmStudioProvider::new(params, timeout)?))
        }
        LlmProviderKind::Grok => Ok(Box::new(grok::GrokProvider::new(params, timeout)?)),
        LlmProviderKind::Perplexity => Ok(Box::new(perplexity::PerplexityProvider::new(
            params, timeout,
        )?)),
    }
}

/// Utility used by every provider: default model if user didn't set one.
pub(crate) fn resolve_model(params: &ProviderParams, fallback: &str) -> String {
    if params.model.trim().is_empty() {
        fallback.to_string()
    } else {
        params.model.clone()
    }
}
