//! Resolve the `[llm.*]` sub-tables into the runtime
//! [`LlmConfigSection`]: validate provider keys, layer env-var precedence
//! over file-specified API keys, and ensure the active provider always
//! has an entry.
//!
//! `resolve_llm` is the single entry point used by `UnifiedConfig::load`.

use anyhow::{anyhow, Result};
use std::collections::BTreeMap;

use super::file_io::{FileFormat, FileLlmLimits, FileProviderParams};
use crate::config::limits::DEFAULT_REQUEST_TIMEOUT_SECS;
use crate::config::providers::{validate_provider_base_url, LLM_PROVIDER_VALID_VALUES};
use crate::config::{LlmConfigSection, LlmLimits, LlmProviderKind, ProviderParams};

pub(super) fn resolve_llm(unified: Option<&FileFormat>) -> Result<Option<LlmConfigSection>> {
    let Some(llm) = unified.and_then(|f| f.llm.as_ref()) else {
        return Ok(None);
    };
    let Some(provider_raw) = llm.provider.as_deref() else {
        return Ok(None);
    };
    let provider = LlmProviderKind::from_str_ci(provider_raw).ok_or_else(|| {
        anyhow!(
            "[llm].provider = \"{provider_raw}\" is not recognised. Valid values: {LLM_PROVIDER_VALID_VALUES}"
        )
    })?;

    validate_provider_section_keys(&llm.providers)?;
    let mut provider_configs = build_provider_configs(&llm.providers)?;
    ensure_active_provider_entry(&mut provider_configs, provider);
    let limits = resolve_llm_limits(llm.limits.as_ref());

    Ok(Some(LlmConfigSection {
        provider,
        provider_configs,
        limits,
    }))
}

/// Reject sub-keys under `[llm]` that aren't recognised provider names.
/// `FileLlmSection` uses `#[serde(flatten)]` on a
/// `BTreeMap<String, FileProviderParams>`, so any unknown sub-key (e.g.
/// `provder = "openai"` instead of `provider`) is otherwise silently
/// absorbed as a fake provider entry — user typos vanished without trace
/// and the active provider quietly fell back to defaults.
fn validate_provider_section_keys(
    file_sections: &BTreeMap<String, FileProviderParams>,
) -> Result<()> {
    for name in file_sections.keys() {
        if LlmProviderKind::from_str_ci(name).is_none() {
            return Err(anyhow!(
                "[llm].{name} is not a recognised key. Expected a provider \
                 ({LLM_PROVIDER_VALID_VALUES}) or one of: provider, limits"
            ));
        }
    }
    Ok(())
}

/// Build the per-provider configuration map from the parsed file
/// sections, applying base-URL validation and env-var precedence over
/// the file-specified API key.
fn build_provider_configs(
    file_sections: &BTreeMap<String, FileProviderParams>,
) -> Result<BTreeMap<LlmProviderKind, ProviderParams>> {
    let mut provider_configs: BTreeMap<LlmProviderKind, ProviderParams> = BTreeMap::new();
    for (name, params) in file_sections {
        // Invariant: `validate_provider_section_keys` runs first in
        // `resolve_llm`, so every key here parses to a known provider. Skip
        // defensively rather than panic if a future refactor reorders the
        // calls — the validator still owns the user-visible error path.
        let Some(kind) = LlmProviderKind::from_str_ci(name) else {
            debug_assert!(
                false,
                "build_provider_configs called without prior validate_provider_section_keys: {name}"
            );
            continue;
        };
        if let Some(raw_url) = params.base_url.as_deref() {
            validate_provider_base_url(kind, raw_url)?;
        }
        let mut p = ProviderParams {
            model: params.model.clone().unwrap_or_default(),
            base_url: params.base_url.clone(),
            api_key: params.api_key.clone(),
            max_tokens: params.max_tokens,
            temperature: params.temperature,
        };
        // Env vars take precedence over file-specified api_key.
        if let Some(env_key) = kind.resolve_apikey_from_env() {
            p.api_key = Some(env_key);
        }
        provider_configs.insert(kind, p);
    }
    Ok(provider_configs)
}

/// Ensure the active provider has a config entry even if the user
/// omitted its section (e.g. they only want defaults for Anthropic).
/// Env vars still populate the api_key on the synthesised entry.
fn ensure_active_provider_entry(
    configs: &mut BTreeMap<LlmProviderKind, ProviderParams>,
    provider: LlmProviderKind,
) {
    configs.entry(provider).or_insert_with(|| {
        let mut p = ProviderParams::default();
        if let Some(env_key) = provider.resolve_apikey_from_env() {
            p.api_key = Some(env_key);
        }
        p
    });
}

/// Translate the optional `[llm.limits]` block into runtime limits.
/// Preserves user intent: an explicit value in the file becomes
/// `Some(...)`; an omitted field falls back to auto-detection via
/// `effective_max_prompt_chars`.
fn resolve_llm_limits(limits: Option<&FileLlmLimits>) -> LlmLimits {
    limits
        .map(|l| LlmLimits {
            max_prompt_chars: l.max_prompt_chars,
            request_timeout_secs: l
                .request_timeout_secs
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::super::file_io::{FileFormat, FileLlmSection, FileProviderParams};
    use super::*;
    use crate::config::providers::{
        ANTHROPIC_APIKEY_ENV, GROK_APIKEY_ENV_ALIAS, OLLAMA_APIKEY_ENV_ALIAS,
        OLLAMA_CLOUD_APIKEY_ENV, OPENAI_APIKEY_ENV, PERPLEXITY_APIKEY_ENV,
        PERPLEXITY_APIKEY_ENV_ALIAS, XAI_APIKEY_ENV,
    };
    use crate::config::test_support::ENV_LOCK;

    /// # Contract
    ///
    /// `resolve_llm` must reject any unknown sub-table under `[llm]` —
    /// e.g. `[llm.openi]` (typo of `openai`) — with an error naming the
    /// offending key. Pre-fix `FileLlmSection` used `#[serde(flatten)]`
    /// over a `BTreeMap`, so unrecognised sub-tables landed in the map
    /// and the configuration loop silently filtered them out, leaving
    /// users no signal that their typo had been dropped.
    #[test]
    fn unknown_llm_section_key_is_rejected() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var(OPENAI_APIKEY_ENV);
        std::env::remove_var(ANTHROPIC_APIKEY_ENV);
        let src = r#"
[llm]
provider = "openai"

[llm.openi]
model = "gpt-4o-mini"
"#;
        let parsed: FileFormat = toml::from_str(src).expect("parses");
        let err = resolve_llm(Some(&parsed)).expect_err("must reject unknown sub-table");
        let msg = err.to_string();
        assert!(msg.contains("openi"), "error must name the bad key: {msg}");
        assert!(
            msg.contains("provider") || msg.contains("openai"),
            "error must hint at valid keys: {msg}"
        );
    }

    #[test]
    fn resolve_llm_rejects_unknown_provider() {
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("unknown".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified));
        assert!(got.is_err());
    }

    #[test]
    fn resolve_llm_ensures_active_provider_has_entry() {
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("ollama".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        assert_eq!(got.provider, LlmProviderKind::Ollama);
        assert!(got.provider_configs.contains_key(&LlmProviderKind::Ollama));
    }

    #[test]
    fn env_var_overrides_file_api_key() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(ANTHROPIC_APIKEY_ENV, "env-anthropic-key");
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("anthropic".into()),
                providers: {
                    let mut m = BTreeMap::new();
                    m.insert(
                        "anthropic".to_string(),
                        FileProviderParams {
                            api_key: Some("file-key".into()),
                            ..Default::default()
                        },
                    );
                    m
                },
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        let ant = got
            .provider_configs
            .get(&LlmProviderKind::Anthropic)
            .unwrap();
        assert_eq!(ant.api_key.as_deref(), Some("env-anthropic-key"));
        std::env::remove_var(ANTHROPIC_APIKEY_ENV);
    }

    #[test]
    fn ollama_cloud_accepts_ollama_api_key_alias() {
        let _g = ENV_LOCK.lock().unwrap();
        // Primary env var unset, alias set: the alias must populate api_key.
        std::env::remove_var(OLLAMA_CLOUD_APIKEY_ENV);
        std::env::set_var(OLLAMA_APIKEY_ENV_ALIAS, "alias-key");
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("ollama-cloud".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        let oc = got
            .provider_configs
            .get(&LlmProviderKind::OllamaCloud)
            .unwrap();
        assert_eq!(oc.api_key.as_deref(), Some("alias-key"));
        std::env::remove_var(OLLAMA_APIKEY_ENV_ALIAS);
    }

    #[test]
    fn grok_accepts_xai_api_key_primary() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(XAI_APIKEY_ENV, "xai-primary");
        std::env::remove_var(GROK_APIKEY_ENV_ALIAS);
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("grok".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        let g = got.provider_configs.get(&LlmProviderKind::Grok).unwrap();
        assert_eq!(g.api_key.as_deref(), Some("xai-primary"));
        std::env::remove_var(XAI_APIKEY_ENV);
    }

    #[test]
    fn grok_accepts_grok_api_key_alias() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var(XAI_APIKEY_ENV);
        std::env::set_var(GROK_APIKEY_ENV_ALIAS, "grok-alias");
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("xai".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        let g = got.provider_configs.get(&LlmProviderKind::Grok).unwrap();
        assert_eq!(g.api_key.as_deref(), Some("grok-alias"));
        std::env::remove_var(GROK_APIKEY_ENV_ALIAS);
    }

    #[test]
    fn grok_primary_env_wins_over_alias() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(XAI_APIKEY_ENV, "xai-primary");
        std::env::set_var(GROK_APIKEY_ENV_ALIAS, "grok-alias");
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("grok".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        let g = got.provider_configs.get(&LlmProviderKind::Grok).unwrap();
        assert_eq!(g.api_key.as_deref(), Some("xai-primary"));
        std::env::remove_var(XAI_APIKEY_ENV);
        std::env::remove_var(GROK_APIKEY_ENV_ALIAS);
    }

    #[test]
    fn perplexity_accepts_perplexity_api_key_primary() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(PERPLEXITY_APIKEY_ENV, "pplx-primary");
        std::env::remove_var(PERPLEXITY_APIKEY_ENV_ALIAS);
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("perplexity".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        let p = got
            .provider_configs
            .get(&LlmProviderKind::Perplexity)
            .unwrap();
        assert_eq!(p.api_key.as_deref(), Some("pplx-primary"));
        std::env::remove_var(PERPLEXITY_APIKEY_ENV);
    }

    #[test]
    fn perplexity_accepts_perplexity_api_alias() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var(PERPLEXITY_APIKEY_ENV);
        std::env::set_var(PERPLEXITY_APIKEY_ENV_ALIAS, "pplx-alias");
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("pplx".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        let p = got
            .provider_configs
            .get(&LlmProviderKind::Perplexity)
            .unwrap();
        assert_eq!(p.api_key.as_deref(), Some("pplx-alias"));
        std::env::remove_var(PERPLEXITY_APIKEY_ENV_ALIAS);
    }

    #[test]
    fn perplexity_primary_env_wins_over_alias() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(PERPLEXITY_APIKEY_ENV, "primary");
        std::env::set_var(PERPLEXITY_APIKEY_ENV_ALIAS, "alias");
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("perplexity".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        let p = got
            .provider_configs
            .get(&LlmProviderKind::Perplexity)
            .unwrap();
        assert_eq!(p.api_key.as_deref(), Some("primary"));
        std::env::remove_var(PERPLEXITY_APIKEY_ENV);
        std::env::remove_var(PERPLEXITY_APIKEY_ENV_ALIAS);
    }

    #[test]
    fn ollama_cloud_primary_env_wins_over_alias() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(OLLAMA_CLOUD_APIKEY_ENV, "primary");
        std::env::set_var(OLLAMA_APIKEY_ENV_ALIAS, "alias");
        let unified = FileFormat {
            llm: Some(FileLlmSection {
                provider: Some("ollama-cloud".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
            vt: None,
            promptintel: None,
        };
        let got = resolve_llm(Some(&unified)).unwrap().unwrap();
        let oc = got
            .provider_configs
            .get(&LlmProviderKind::OllamaCloud)
            .unwrap();
        assert_eq!(oc.api_key.as_deref(), Some("primary"));
        std::env::remove_var(OLLAMA_CLOUD_APIKEY_ENV);
        std::env::remove_var(OLLAMA_APIKEY_ENV_ALIAS);
    }

    fn config_with_provider_url(provider: &str, base_url: Option<&str>) -> FileFormat {
        let mut providers = BTreeMap::new();
        providers.insert(
            provider.to_string(),
            FileProviderParams {
                base_url: base_url.map(ToOwned::to_owned),
                ..Default::default()
            },
        );
        FileFormat {
            llm: Some(FileLlmSection {
                provider: Some(provider.to_string()),
                providers,
                limits: None,
            }),
            vt: None,
            promptintel: None,
        }
    }

    /// # Contract
    ///
    /// `resolve_llm` MUST reject any `base_url` whose scheme is not
    /// `http` or `https`. A `file://` (or `gopher://`, `ftp://`, …) URL
    /// would either fail at request time with an opaque `ureq` error or,
    /// worse, be silently accepted by a future HTTP client that supports
    /// the scheme — both leaking the bundle off the intended channel.
    /// Pre-fix the loader accepted any string verbatim.
    #[test]
    fn resolve_llm_rejects_non_http_base_url() {
        let unified = config_with_provider_url("anthropic", Some("file:///etc/passwd"));
        let err = resolve_llm(Some(&unified))
            .expect_err("non-http(s) base_url MUST be rejected at config-load time");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("scheme") && msg.contains("http"),
            "error must explain the scheme requirement; got: {msg}"
        );
    }

    /// # Contract
    ///
    /// Remote (cloud) providers MUST require `https://` for non-loopback
    /// hosts. Pre-fix a tampered `~/.skill-veil.toml` could redirect the
    /// Anthropic provider at `http://attacker.example/v1/messages` and
    /// exfiltrate every bundle (which carries SKILL.md, supporting
    /// scripts, IOCs, and the Authorization header).
    #[test]
    fn resolve_llm_rejects_remote_provider_with_http_scheme() {
        let unified = config_with_provider_url("anthropic", Some("http://attacker.example/v1"));
        let err = resolve_llm(Some(&unified))
            .expect_err("http to a non-loopback host MUST be rejected for remote providers");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("https"),
            "error must require https for remote providers; got: {msg}"
        );
    }

    /// # Contract (positive)
    ///
    /// Local providers (Ollama, LMStudio) MUST accept `http://` because
    /// their default endpoints are plain-http loopback URLs
    /// (`http://localhost:11434`, `http://localhost:1234/v1`). A regression
    /// here would break out-of-the-box local-LLM workflows.
    #[test]
    fn resolve_llm_accepts_localhost_http_for_ollama() {
        let unified = config_with_provider_url("ollama", Some("http://localhost:11434"));
        let resolved = resolve_llm(Some(&unified))
            .expect("plain-http loopback MUST be allowed for the Ollama local provider");
        let cfg = resolved.expect("active provider section must resolve");
        let entry = cfg.provider_configs.get(&LlmProviderKind::Ollama).unwrap();
        assert_eq!(
            entry.base_url.as_deref(),
            Some("http://localhost:11434"),
            "base_url must be preserved verbatim after validation"
        );
    }

    /// # Contract (positive)
    ///
    /// The `http://` loopback exception applies to remote providers too,
    /// to support legitimate dev workflows like running a local mitm
    /// proxy in front of Anthropic. The exception is narrow:
    /// `localhost`, `127.0.0.1`, `::1`. Anything else falls back to the
    /// https-only rule from
    /// `resolve_llm_rejects_remote_provider_with_http_scheme`.
    #[test]
    fn resolve_llm_accepts_loopback_http_for_remote_provider_dev_proxy() {
        let unified = config_with_provider_url("anthropic", Some("http://127.0.0.1:8080"));
        resolve_llm(Some(&unified))
            .expect("loopback http MUST be allowed even for remote providers (dev proxy)");
    }

    /// # Contract
    ///
    /// `https://` MUST be accepted for remote providers (the production
    /// path). Pin this so over-strict future validation can't accidentally
    /// reject the canonical case.
    #[test]
    fn resolve_llm_accepts_https_for_remote_provider() {
        let unified = config_with_provider_url("anthropic", Some("https://api.anthropic.com/v1"));
        resolve_llm(Some(&unified))
            .expect("https remote URLs MUST resolve cleanly — this is the canonical path");
    }
}
