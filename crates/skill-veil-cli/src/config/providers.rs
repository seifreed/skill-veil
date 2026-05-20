//! `LlmProviderKind`, env-var resolution, and base-URL validation.

use anyhow::{anyhow, Result};

pub(super) const OPENAI_APIKEY_ENV: &str = "OPENAI_API_KEY";
pub(super) const ANTHROPIC_APIKEY_ENV: &str = "ANTHROPIC_API_KEY";
pub(super) const OLLAMA_CLOUD_APIKEY_ENV: &str = "OLLAMA_CLOUD_API_KEY";
/// Ollama's own CLI uses `OLLAMA_API_KEY`; we accept it as an alias so users
/// don't have to duplicate the secret under two names.
pub(super) const OLLAMA_APIKEY_ENV_ALIAS: &str = "OLLAMA_API_KEY";
/// xAI's official env var is `XAI_API_KEY`; `GROK_API_KEY` is widely used
/// in the community. We accept both, primary first.
pub(super) const XAI_APIKEY_ENV: &str = "XAI_API_KEY";
pub(super) const GROK_APIKEY_ENV_ALIAS: &str = "GROK_API_KEY";
/// Perplexity: `PERPLEXITY_API_KEY` is documented; `PERPLEXITY_API` is a
/// shorter form that occasionally appears in user configs.
pub(super) const PERPLEXITY_APIKEY_ENV: &str = "PERPLEXITY_API_KEY";
pub(super) const PERPLEXITY_APIKEY_ENV_ALIAS: &str = "PERPLEXITY_API";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LlmProviderKind {
    OpenAi,
    Anthropic,
    Ollama,
    OllamaCloud,
    LmStudio,
    Grok,
    Perplexity,
}

impl LlmProviderKind {
    /// Stable wire name, used in output formatting and cache keys.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            LlmProviderKind::OpenAi => "openai",
            LlmProviderKind::Anthropic => "anthropic",
            LlmProviderKind::Ollama => "ollama",
            LlmProviderKind::OllamaCloud => "ollama-cloud",
            LlmProviderKind::LmStudio => "lmstudio",
            LlmProviderKind::Grok => "grok",
            LlmProviderKind::Perplexity => "perplexity",
        }
    }

    pub(crate) fn from_str_ci(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "openai" => Some(Self::OpenAi),
            "anthropic" => Some(Self::Anthropic),
            "ollama" => Some(Self::Ollama),
            "ollama-cloud" | "ollama_cloud" | "ollamacloud" => Some(Self::OllamaCloud),
            "lmstudio" | "lm-studio" | "lm_studio" => Some(Self::LmStudio),
            "grok" | "xai" => Some(Self::Grok),
            "perplexity" | "pplx" => Some(Self::Perplexity),
            _ => None,
        }
    }

    /// Env vars that can carry this provider's API key, in priority order.
    /// The first variable that resolves to a non-empty value wins.
    fn apikey_envs(self) -> &'static [&'static str] {
        match self {
            LlmProviderKind::OpenAi => &[OPENAI_APIKEY_ENV],
            LlmProviderKind::Anthropic => &[ANTHROPIC_APIKEY_ENV],
            LlmProviderKind::OllamaCloud => &[OLLAMA_CLOUD_APIKEY_ENV, OLLAMA_APIKEY_ENV_ALIAS],
            LlmProviderKind::Grok => &[XAI_APIKEY_ENV, GROK_APIKEY_ENV_ALIAS],
            LlmProviderKind::Perplexity => &[PERPLEXITY_APIKEY_ENV, PERPLEXITY_APIKEY_ENV_ALIAS],
            LlmProviderKind::Ollama | LlmProviderKind::LmStudio => &[],
        }
    }

    /// First env var in `apikey_envs()` whose value is non-empty, if any.
    pub(super) fn resolve_apikey_from_env(self) -> Option<String> {
        for name in self.apikey_envs() {
            if let Ok(val) = std::env::var(name) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }
}

/// Canonical provider names listed in user-facing error messages. Kept in
/// sync with `LlmProviderKind::from_str_ci`; aliases (`xai`, `pplx`,
/// `lm-studio`, etc.) are accepted by the parser but omitted here so the
/// hint stays short.
pub(crate) const LLM_PROVIDER_VALID_VALUES: &str =
    "openai, anthropic, ollama, ollama-cloud, lmstudio, grok, perplexity";

/// Resolve the `--llm-provider` CLI flag.
///
/// `None` (flag absent) returns `Ok(None)`. A recognised value returns
/// `Ok(Some(kind))`. An unrecognised value returns an `Err` naming the
/// offending input — the previous `and_then` collapsed unknown values to
/// `None`, silently falling back to whichever provider the config file
/// selected and giving the user no signal that their flag was dropped.
pub(crate) fn resolve_llm_provider_override(raw: Option<&str>) -> Result<Option<LlmProviderKind>> {
    match raw {
        None => Ok(None),
        Some(value) => LlmProviderKind::from_str_ci(value).map(Some).ok_or_else(|| {
            anyhow!(
                "--llm-provider \"{value}\" is not recognised. Valid values: {LLM_PROVIDER_VALID_VALUES}"
            )
        }),
    }
}

/// Validate a provider's `base_url` from `~/.skill-veil.toml` to prevent
/// a tampered or typo'd config from silently exfiltrating skill bundles
/// to an attacker-controlled host. The bundle contains the full SKILL.md,
/// supporting scripts, extracted IOCs, and (for cloud providers) an API
/// key in the Authorization header — leaking it to the wrong endpoint is
/// equivalent to exfiltrating the entire scan target.
///
/// Rules:
/// - Scheme MUST be `http` or `https`. Other schemes (`file://`,
///   `ftp://`, `gopher://`, custom) are rejected outright.
/// - Local providers (Ollama, LMStudio) may use `http://` to any host when
///   they do not send an API key —
///   their typical defaults are `http://localhost:11434` /
///   `http://localhost:1234/v1` and users frequently point them at
///   private LAN hosts.
/// - If any provider sends an API key, plain `http://` is only allowed for
///   loopback hosts.
/// - Remote providers (OpenAI, Anthropic, Ollama-Cloud, Grok, Perplexity)
///   MUST use `https://` UNLESS the host is a loopback address — that
///   exception preserves the legitimate "I'm running a local mitm proxy
///   for debugging" workflow without re-opening the SSRF vector.
pub(super) fn validate_provider_base_url(
    kind: LlmProviderKind,
    raw: &str,
    sends_api_key: bool,
) -> Result<()> {
    let parsed = url::Url::parse(raw).map_err(|err| {
        anyhow!(
            "[llm.providers.{}].base_url is not a valid URL ({raw:?}): {err}",
            kind.as_str(),
        )
    })?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(anyhow!(
            "[llm.providers.{}].base_url scheme must be http or https; got {scheme:?}",
            kind.as_str(),
        ));
    }

    let is_local_provider = matches!(kind, LlmProviderKind::Ollama | LlmProviderKind::LmStudio);
    if sends_api_key && scheme == "http" && !host_is_loopback(&parsed) {
        return Err(anyhow!(
            "[llm.providers.{}].base_url must use https when an api_key is configured; \
             plain http with credentials is only allowed to loopback hosts \
             (localhost / 127.0.0.1 / ::1). Got: {raw}",
            kind.as_str(),
        ));
    }
    if !is_local_provider && scheme == "http" && !host_is_loopback(&parsed) {
        return Err(anyhow!(
            "[llm.providers.{}].base_url must use https for remote providers; \
             plain http is only allowed to loopback hosts (localhost / 127.0.0.1 / ::1). \
             Got: {raw}",
            kind.as_str(),
        ));
    }

    Ok(())
}

/// True iff the parsed URL points at a loopback host. Treats `localhost`
/// (the conventional name) and any loopback IPv4/IPv6 literal as
/// equivalent. Used to carve a narrow `http://` exception for remote
/// providers without opening a generic SSRF vector.
fn host_is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_kind_parsing() {
        assert_eq!(
            LlmProviderKind::from_str_ci("OpenAI"),
            Some(LlmProviderKind::OpenAi)
        );
        assert_eq!(
            LlmProviderKind::from_str_ci("ollama-cloud"),
            Some(LlmProviderKind::OllamaCloud)
        );
        assert_eq!(
            LlmProviderKind::from_str_ci("ollama_cloud"),
            Some(LlmProviderKind::OllamaCloud)
        );
        assert_eq!(
            LlmProviderKind::from_str_ci("LMStudio"),
            Some(LlmProviderKind::LmStudio)
        );
        assert_eq!(
            LlmProviderKind::from_str_ci("Grok"),
            Some(LlmProviderKind::Grok)
        );
        assert_eq!(
            LlmProviderKind::from_str_ci("xai"),
            Some(LlmProviderKind::Grok)
        );
        assert_eq!(
            LlmProviderKind::from_str_ci("Perplexity"),
            Some(LlmProviderKind::Perplexity)
        );
        assert_eq!(
            LlmProviderKind::from_str_ci("pplx"),
            Some(LlmProviderKind::Perplexity)
        );
        assert_eq!(LlmProviderKind::from_str_ci("unknown"), None);
    }

    /// # Contract
    ///
    /// `resolve_llm_provider_override` must:
    /// - return `Ok(None)` when the flag is absent (`None`),
    /// - return `Ok(Some(kind))` for a recognised value (canonical or alias),
    /// - return `Err` whose message names the offending value AND lists the
    ///   canonical provider names, when the value is unknown.
    ///
    /// Pre-fix the resolver lived inline in `commands/scan.rs` as
    /// `args.llm_provider.as_deref().and_then(LlmProviderKind::from_str_ci)`
    /// — the `and_then` collapsed unknown values to `None`, silently falling
    /// back to whichever provider the config file selected. Users had no
    /// signal that their `--llm-provider` flag had been dropped.
    #[test]
    fn resolve_llm_provider_override_rejects_unknown_value() {
        assert!(matches!(resolve_llm_provider_override(None), Ok(None)));
        assert_eq!(
            resolve_llm_provider_override(Some("Anthropic")).unwrap(),
            Some(LlmProviderKind::Anthropic)
        );
        assert_eq!(
            resolve_llm_provider_override(Some("xai")).unwrap(),
            Some(LlmProviderKind::Grok)
        );

        let err =
            resolve_llm_provider_override(Some("foobar")).expect_err("unknown provider must error");
        let msg = err.to_string();
        assert!(
            msg.contains("foobar"),
            "error must name the bad value: {msg}"
        );
        assert!(
            msg.contains("openai"),
            "error must list canonical names: {msg}"
        );
        assert!(
            msg.contains("anthropic"),
            "error must list canonical names: {msg}"
        );
    }
}
