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
#[derive(Clone, Default)]
pub(crate) struct UnifiedConfig {
    pub llm: Option<LlmConfigSection>,
    /// Optional VirusTotal API key sourced from the `[vt]` section of
    /// `~/.skill-veil.toml`. The dedicated `~/.vt.toml` loader
    /// ([`crate::vt::config::VtConfig`]) consults this as a fallback when
    /// the legacy standalone file is absent.
    pub vt_apikey: Option<String>,
    /// Optional PromptIntel API key sourced from the `[promptintel]`
    /// section of `~/.skill-veil.toml`. Mirrors `vt_apikey`: the
    /// `PROMPTINTEL` environment variable wins, then this field, then
    /// "not configured".
    pub promptintel_apikey: Option<String>,
    /// OSV.dev CVE-lookup settings from the `[osv]` section. Defaults to
    /// disabled (opt-in) — the `--osv` flag and `SKILL_VEIL_OSV` env var
    /// override `enable`.
    pub osv: OsvSettings,
    /// Abandoned/unmaintained-package settings from the `[abandoned]` section.
    /// Defaults to disabled (opt-in) — the `--abandoned` flag and
    /// `SKILL_VEIL_ABANDONED` env var override `enable`.
    pub abandoned: AbandonedSettings,
}

/// Settings for the abandoned/unmaintained-package enrichment
/// (`[abandoned]` section).
#[derive(Debug, Clone)]
pub(crate) struct AbandonedSettings {
    /// Run the check. Opt-in: `false` unless `[abandoned] enable = true`, the
    /// `--abandoned` flag, or `SKILL_VEIL_ABANDONED=1`.
    pub enabled: bool,
    /// Days a cached metadata result is reused before re-querying.
    pub cache_ttl_days: i64,
    /// A package with no release newer than this many days is flagged as
    /// unmaintained.
    pub stale_days: i64,
    /// Serve only the on-disk cache; never touch the network.
    pub offline: bool,
}

/// Default "no release in N days → unmaintained" threshold (two years).
pub(crate) const ABANDONED_DEFAULT_STALE_DAYS: i64 = 730;

impl Default for AbandonedSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_ttl_days: OSV_DEFAULT_CACHE_TTL_DAYS,
            stale_days: ABANDONED_DEFAULT_STALE_DAYS,
            offline: false,
        }
    }
}

/// Settings for the OSV.dev CVE-lookup enrichment (`[osv]` section).
#[derive(Debug, Clone)]
pub(crate) struct OsvSettings {
    /// Run the lookup. Opt-in: `false` unless `[osv] enable = true`, the
    /// `--osv` flag, or `SKILL_VEIL_OSV=1`.
    pub enabled: bool,
    /// Days a cached advisory result is reused before re-querying.
    pub cache_ttl_days: i64,
    /// Serve only the on-disk cache; never touch the network.
    pub offline: bool,
}

/// Default cache lifetime for OSV results, matching the LLM/VT cache window.
pub(crate) const OSV_DEFAULT_CACHE_TTL_DAYS: i64 = 30;

impl Default for OsvSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_ttl_days: OSV_DEFAULT_CACHE_TTL_DAYS,
            offline: false,
        }
    }
}

impl std::fmt::Debug for UnifiedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedConfig")
            .field("llm", &self.llm)
            .field(
                "vt_apikey",
                &self.vt_apikey.as_deref().map(|_| "<redacted>"),
            )
            .field(
                "promptintel_apikey",
                &self.promptintel_apikey.as_deref().map(|_| "<redacted>"),
            )
            .field("osv", &self.osv)
            .field("abandoned", &self.abandoned)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LlmConfigSection {
    /// The active provider. Overridable via `--llm-provider` CLI flag.
    pub provider: LlmProviderKind,
    pub provider_configs: BTreeMap<LlmProviderKind, ProviderParams>,
    pub limits: LlmLimits,
}

impl LlmConfigSection {
    /// Apply a `--llm-provider` (or `--nova-llm` provider) override:
    /// switch the active provider AND ensure it has a config entry whose
    /// `api_key` is populated from the environment when no
    /// `[llm.providers.X]` file section supplied one.
    ///
    /// Reassigning `provider` alone is not enough: `build_provider` reads
    /// the per-provider `ProviderParams`, and a provider the user never
    /// gave a file section for has no entry, so it falls back to
    /// `ProviderParams::default()` (no key) and fails `NotConfigured` —
    /// silently skipping enrichment even though the env key was exported.
    /// This mirrors the entry-synthesis `resolve_llm` already performs for
    /// the file-selected provider, so an override honours the documented
    /// env-over-file precedence instead of being strictly worse than the
    /// file selection.
    pub(crate) fn apply_provider_override(&mut self, provider: LlmProviderKind) {
        self.provider = provider;
        self.provider_configs
            .entry(provider)
            .or_insert_with(|| provider_params_from_env(provider));
    }
}

/// Synthesise a `ProviderParams` for a provider with no file section,
/// seeding the API key from the environment when present. Shared by the
/// CLI provider-override path and `resolve_llm`'s active-entry synthesis so
/// both honour the documented env-over-file precedence identically.
pub(crate) fn provider_params_from_env(provider: LlmProviderKind) -> ProviderParams {
    let mut params = ProviderParams::default();
    if let Some(env_key) = provider.resolve_apikey_from_env() {
        params.api_key = Some(env_key);
    }
    params
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
    use crate::config::providers::OPENAI_APIKEY_ENV;
    use crate::config::test_support::ENV_LOCK;

    fn section(provider: LlmProviderKind) -> LlmConfigSection {
        LlmConfigSection {
            provider,
            provider_configs: BTreeMap::new(),
            limits: LlmLimits::default(),
        }
    }

    /// # Contract
    ///
    /// `apply_provider_override` MUST synthesise a `ProviderParams` entry
    /// for an overridden provider that has no `[llm.providers.X]` file
    /// section, populating its `api_key` from the environment. Pre-fix the
    /// override only reassigned `.provider`, leaving `provider_configs`
    /// without an entry, so `build_provider` fell back to
    /// `ProviderParams::default()` and failed `NotConfigured` — silently
    /// skipping enrichment even though the env key was exported.
    #[test]
    fn provider_override_populates_env_key_without_file_section() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(OPENAI_APIKEY_ENV, "env-openai-key-xyz");

        let mut cfg = section(LlmProviderKind::Anthropic);
        cfg.apply_provider_override(LlmProviderKind::OpenAi);

        std::env::remove_var(OPENAI_APIKEY_ENV);

        assert_eq!(cfg.provider, LlmProviderKind::OpenAi);
        assert_eq!(
            cfg.provider_configs
                .get(&LlmProviderKind::OpenAi)
                .and_then(|p| p.api_key.as_deref()),
            Some("env-openai-key-xyz"),
            "override must carry the env api_key onto the synthesised entry",
        );
    }

    /// # Contract (preserve)
    ///
    /// When the overridden provider already has a config entry (a file
    /// section, already env-layered by `resolve_llm`), the override MUST
    /// NOT clobber it.
    #[test]
    fn provider_override_preserves_existing_entry() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(OPENAI_APIKEY_ENV, "env-should-not-win");

        let mut cfg = section(LlmProviderKind::Anthropic);
        cfg.provider_configs.insert(
            LlmProviderKind::OpenAi,
            ProviderParams {
                api_key: Some("file-section-key".to_string()),
                ..ProviderParams::default()
            },
        );
        cfg.apply_provider_override(LlmProviderKind::OpenAi);

        std::env::remove_var(OPENAI_APIKEY_ENV);

        assert_eq!(
            cfg.provider_configs
                .get(&LlmProviderKind::OpenAi)
                .and_then(|p| p.api_key.as_deref()),
            Some("file-section-key"),
            "existing entry must be preserved, not overwritten",
        );
    }

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

    /// # Contract
    ///
    /// `UnifiedConfig::Debug` MUST redact VT and PromptIntel credentials.
    /// Those keys sit beside the LLM section and can be formatted during
    /// config troubleshooting just as easily as per-provider params.
    #[test]
    fn unified_config_debug_redacts_top_level_credentials() {
        let config = UnifiedConfig {
            llm: None,
            vt_apikey: Some("vt-secret-do-not-leak".to_string()),
            promptintel_apikey: Some("promptintel-secret-do-not-leak".to_string()),
            osv: OsvSettings::default(),
            abandoned: AbandonedSettings::default(),
        };

        let rendered = format!("{config:?}");

        assert!(!rendered.contains("vt-secret-do-not-leak"));
        assert!(!rendered.contains("promptintel-secret-do-not-leak"));
        assert!(rendered.contains("<redacted>"));
    }
}
