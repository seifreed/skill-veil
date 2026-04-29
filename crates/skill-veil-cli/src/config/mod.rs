//! Unified skill-veil LLM configuration loader.
//!
//! `~/.skill-veil.toml` carries provider settings for the LLM enrichment
//! engine. VirusTotal credentials live in their own loader at
//! [`crate::vt::config`] (it predates this module and resolves
//! `~/.vt.toml` plus `VT_APIKEY`).
//!
//! # Resolution order (first non-empty wins, per field)
//! 1. Environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
//!    `OLLAMA_CLOUD_API_KEY`, `XAI_API_KEY`/`GROK_API_KEY`,
//!    `PERPLEXITY_API_KEY`/`PERPLEXITY_API`).
//! 2. `~/.skill-veil.toml`.
//!
//! The loader is lossy on purpose: a missing `[llm]` section produces
//! `None` rather than an error, so callers can branch on "is the LLM
//! engine configured?" without handling "config file syntax error but
//! this engine isn't used" edge cases.
//!
//! # Submodule layout
//!
//! - [`providers`] — `LlmProviderKind`, env-var resolution, base-URL validation.
//! - [`limits`] — `LlmLimits` and prompt-budget cascade
//!   (`effective_max_prompt_chars*`).
//! - [`resolution`] — disk loading, TOML parsing, orchestration of
//!   `UnifiedConfig::load`.

mod limits;
mod providers;
mod resolution;

#[cfg(test)]
mod test_support;

pub(crate) use limits::LlmLimits;
pub(crate) use providers::{resolve_llm_provider_override, LlmProviderKind};

use std::collections::BTreeMap;

/// Fully-resolved config, ready for consumers.
#[derive(Debug, Clone, Default)]
pub(crate) struct UnifiedConfig {
    pub llm: Option<LlmConfigSection>,
}

#[derive(Debug, Clone)]
pub(crate) struct LlmConfigSection {
    /// The active provider. Overridable via `--llm-provider` CLI flag.
    pub provider: LlmProviderKind,
    pub provider_configs: BTreeMap<LlmProviderKind, ProviderParams>,
    pub limits: LlmLimits,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ProviderParams {
    pub model: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}
