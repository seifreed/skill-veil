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

/// Per-provider configuration after resolving CLI overrides + config files.
///
/// # Debug-secret-redaction contract
///
/// `api_key` carries provider credentials and MUST NOT appear verbatim in
/// any `Debug`-formatted output. Pre-fix `#[derive(Debug)]` produced a
/// derive that printed `api_key: Some("sk-...")` whenever the struct was
/// formatted with `{:?}`. A single `tracing::debug!("{:?}", config)` in a
/// future refactor was therefore enough to leak the key to the log
/// aggregator. The manual implementation below redacts the key while
/// preserving the rest of the fields for debug-print legitimacy
/// (everything else is benign config data).
#[derive(Clone, Default)]
pub(crate) struct ProviderParams {
    pub model: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

impl std::fmt::Debug for ProviderParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderParams")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_deref().map(|_| "<redacted>"))
            .field("max_tokens", &self.max_tokens)
            .field("temperature", &self.temperature)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    ///
    /// `ProviderParams::Debug` MUST NOT print `api_key` verbatim. The struct
    /// crosses module boundaries (cloned in `enrich.rs`, embedded in
    /// `LlmConfigSection`); a single `tracing::debug!("{:?}", config)` would
    /// otherwise leak the credential to the log aggregator. Pre-fix the
    /// `#[derive(Debug)]` printed `api_key: Some("sk-...")`.
    #[test]
    fn provider_params_debug_redacts_api_key() {
        let params = ProviderParams {
            model: "claude-sonnet-4-5".to_string(),
            base_url: Some("https://api.anthropic.com/v1".to_string()),
            api_key: Some("sk-secret-do-not-leak-1234567890".to_string()),
            max_tokens: Some(1024),
            temperature: Some(0.1),
        };
        let rendered = format!("{params:?}");
        assert!(
            !rendered.contains("sk-secret-do-not-leak-1234567890"),
            "Debug output MUST NOT contain the raw api_key; got {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "Debug output MUST mark redaction explicitly; got {rendered}"
        );
        // Other fields stay visible so logs are still useful.
        assert!(rendered.contains("claude-sonnet-4-5"));
        assert!(rendered.contains("api.anthropic.com"));
    }

    /// # Contract (negative)
    ///
    /// When `api_key` is `None`, the redaction marker MUST NOT appear —
    /// otherwise operators reviewing logs cannot tell apart "no key
    /// configured" from "key redacted".
    #[test]
    fn provider_params_debug_marks_absent_key_distinctly() {
        let params = ProviderParams {
            model: "claude-sonnet-4-5".to_string(),
            base_url: None,
            api_key: None,
            max_tokens: None,
            temperature: None,
        };
        let rendered = format!("{params:?}");
        assert!(
            !rendered.contains("<redacted>"),
            "Debug output for None api_key MUST NOT show redaction marker; got {rendered}"
        );
        assert!(rendered.contains("api_key: None"));
    }
}
