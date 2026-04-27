//! Unified skill-veil configuration loader.
//!
//! A single `~/.skill-veil.toml` consolidates VT and LLM provider settings.
//! The legacy `~/.vt.toml` (single-field `apikey = "…"`) is still accepted as
//! a fallback so users already using the VT-only integration don't have to
//! migrate.
//!
//! # Resolution order (first non-empty wins, per field)
//! 1. Environment variables (`VT_APIKEY`, `OPENAI_API_KEY`,
//!    `ANTHROPIC_API_KEY`, `OLLAMA_CLOUD_API_KEY`).
//! 2. `~/.skill-veil.toml` (preferred).
//! 3. `~/.vt.toml` — legacy, only contributes to `[vt].apikey`.
//!
//! The loader is lossy on purpose: missing sections produce `None` rather
//! than errors, so callers can branch on "is this engine configured?"
//! without handling "config file syntax error but this engine isn't used"
//! edge cases.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const UNIFIED_CONFIG_NAME: &str = ".skill-veil.toml";
const LEGACY_VT_CONFIG_NAME: &str = ".vt.toml";

const VT_APIKEY_ENV: &str = "VT_APIKEY";
const OPENAI_APIKEY_ENV: &str = "OPENAI_API_KEY";
const ANTHROPIC_APIKEY_ENV: &str = "ANTHROPIC_API_KEY";
const OLLAMA_CLOUD_APIKEY_ENV: &str = "OLLAMA_CLOUD_API_KEY";
/// Ollama's own CLI uses `OLLAMA_API_KEY`; we accept it as an alias so users
/// don't have to duplicate the secret under two names.
const OLLAMA_APIKEY_ENV_ALIAS: &str = "OLLAMA_API_KEY";
/// xAI's official env var is `XAI_API_KEY`; `GROK_API_KEY` is widely used
/// in the community. We accept both, primary first.
const XAI_APIKEY_ENV: &str = "XAI_API_KEY";
const GROK_APIKEY_ENV_ALIAS: &str = "GROK_API_KEY";
/// Perplexity: `PERPLEXITY_API_KEY` is documented; `PERPLEXITY_API` is a
/// shorter form that occasionally appears in user configs.
const PERPLEXITY_APIKEY_ENV: &str = "PERPLEXITY_API_KEY";
const PERPLEXITY_APIKEY_ENV_ALIAS: &str = "PERPLEXITY_API";

/// Fully-resolved config, ready for consumers.
#[derive(Debug, Clone, Default)]
pub(crate) struct UnifiedConfig {
    /// Reserved for a future migration where we stop reading `~/.vt.toml`
    /// via `VtConfig::load` and consume this section instead. Kept in the
    /// public struct now so the loader proves the section parses.
    #[allow(dead_code)]
    pub vt: Option<VtConfigSection>,
    pub llm: Option<LlmConfigSection>,
}

#[derive(Debug, Clone)]
pub(crate) struct VtConfigSection {
    #[allow(dead_code)]
    pub apikey: String,
}

#[derive(Debug, Clone)]
pub(crate) struct LlmConfigSection {
    /// The active provider. Overridable via `--llm-provider` CLI flag.
    pub provider: LlmProviderKind,
    pub provider_configs: BTreeMap<LlmProviderKind, ProviderParams>,
    pub limits: LlmLimits,
}

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
    #[allow(dead_code)]
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
    fn resolve_apikey_from_env(self) -> Option<String> {
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

#[derive(Debug, Clone, Default)]
pub(crate) struct ProviderParams {
    pub model: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone)]
pub(crate) struct LlmLimits {
    /// `None` means "let `effective_max_prompt_chars` decide based on the
    /// active model". `Some(n)` is the user's explicit override and wins
    /// over the auto-detected value.
    pub max_prompt_chars: Option<usize>,
    pub request_timeout_secs: u64,
}

impl Default for LlmLimits {
    fn default() -> Self {
        Self {
            max_prompt_chars: None,
            request_timeout_secs: 120,
        }
    }
}

/// Fallback char budget when the model isn't recognised in the context table.
pub(crate) const FALLBACK_MAX_PROMPT_CHARS: usize = 100_000;

/// Extra cap for locally-hosted providers (Ollama, LMStudio). The
/// *architectural* context of a model (e.g. Gemma-4's 128k) is often larger
/// than the context the local server loaded it with (LMStudio defaults to
/// 4-8k). We ship a conservative ceiling so we don't overrun the physical
/// runtime; the user can raise it via `[llm.limits].max_prompt_chars` if
/// they configured their loader with more.
pub(crate) const LOCAL_PROVIDER_CAP_CHARS: usize = 60_000;

/// Fraction of the raw context window we reserve for the prompt (rest is
/// response headroom). ~0.75 gives the model ~25% of its context for the
/// structured JSON reply.
const PROMPT_FRACTION: f64 = 0.75;

/// Approximate chars-per-token multiplier. Token density varies by language
/// (English ~4 chars/tok, CJK ~1) and by tokeniser; 3 is a conservative
/// middle ground that still leaves headroom.
const CHARS_PER_TOKEN: usize = 3;

/// Prefix-matched table of known models → context window in tokens.
/// Matching is case-insensitive and prefix-based so `claude-sonnet-4-5`,
/// `claude-sonnet-4-6` etc. all hit `claude-sonnet-4`. Keep list alphabetised
/// within a family for easy upkeep.
const KNOWN_MODEL_CONTEXT: &[(&str, usize)] = &[
    ("claude-haiku-4", 200_000),
    ("claude-opus-4", 200_000),
    ("claude-sonnet-4", 200_000),
    ("gemini-1.5-pro", 2_000_000),
    ("gemini-2", 1_000_000),
    ("gemma-4", 128_000),
    ("gpt-4-turbo", 128_000),
    ("gpt-4o", 128_000),
    ("grok-4", 256_000),
    ("grok-beta", 128_000),
    ("llama3.1", 128_000),
    ("llama3.3", 128_000),
    ("o1", 128_000),
    ("o3", 200_000),
    ("qwen3", 32_000),
    ("qwq", 32_000),
    ("sonar-pro", 200_000),
    ("sonar-reasoning", 127_000),
];

impl LlmConfigSection {
    /// Resolve the prompt-character budget for this scan, honoring user
    /// override first, then the known-model table, then a safe default.
    /// Returns the char budget to pass to the prompt builder.
    pub(crate) fn effective_max_prompt_chars(&self) -> usize {
        self.effective_max_prompt_chars_with_probe(None)
    }

    /// Resolve the prompt-character budget, accepting a runtime probe of the
    /// model's actually-loaded context window (in tokens) for local providers.
    /// Cascade: user override → probe → model table → fallback, then local cap.
    pub(crate) fn effective_max_prompt_chars_with_probe(
        &self,
        probed_tokens: Option<usize>,
    ) -> usize {
        // 1. Explicit user override wins — even over a successful probe.
        if let Some(user) = self.limits.max_prompt_chars {
            return user;
        }

        let active = self.provider;

        // Cap local providers (Ollama/LMStudio) at LOCAL_PROVIDER_CAP_CHARS
        // regardless of how the budget was derived. A probed or table
        // context window of, say, 500k tokens still bumps up against
        // latency/memory ceilings on a self-hosted server; the cap keeps
        // prompts predictable. Users who really want a bigger budget set
        // `limits.max_prompt_chars` explicitly (handled above).
        let apply_local_cap = |budget: usize| -> usize {
            match active {
                LlmProviderKind::Ollama | LlmProviderKind::LmStudio => {
                    budget.min(LOCAL_PROVIDER_CAP_CHARS)
                }
                _ => budget,
            }
        };

        // 2. Runtime probe for local providers. The probe reflects the
        // actually-loaded ctx, which is often smaller than the model's
        // theoretical max — we trust it over the static table.
        if let Some(tokens) = probed_tokens {
            let budget = (tokens * CHARS_PER_TOKEN) as f64 * PROMPT_FRACTION;
            return apply_local_cap(budget as usize);
        }

        let model = self
            .provider_configs
            .get(&active)
            .map(|p| p.model.as_str())
            .unwrap_or("");

        // 3. Prefix-match the model name.
        let lookup = lookup_model_context(model);
        let budget = match lookup {
            Some(tokens) => (tokens * CHARS_PER_TOKEN) as f64 * PROMPT_FRACTION,
            None => FALLBACK_MAX_PROMPT_CHARS as f64,
        };

        apply_local_cap(budget as usize)
    }
}

fn lookup_model_context(model: &str) -> Option<usize> {
    let lc = model.to_ascii_lowercase();
    KNOWN_MODEL_CONTEXT
        .iter()
        .find(|(prefix, _)| lc.starts_with(prefix))
        .map(|(_, tokens)| *tokens)
}

impl UnifiedConfig {
    pub(crate) fn load() -> Result<Self> {
        let home = dirs::home_dir();

        let file_contents = home.as_ref().and_then(|h| {
            let path = h.join(UNIFIED_CONFIG_NAME);
            read_file_if_exists(&path)
        });

        let legacy_vt = home.as_ref().and_then(|h| {
            let path = h.join(LEGACY_VT_CONFIG_NAME);
            read_file_if_exists(&path)
        });

        let parsed_unified: Option<FileFormat> = file_contents
            .map(|c| {
                toml::from_str(&c).map_err(|e| anyhow!("invalid {}: {}", UNIFIED_CONFIG_NAME, e))
            })
            .transpose()?;

        let parsed_legacy_vt: Option<LegacyVtFormat> = legacy_vt
            .map(|c| {
                toml::from_str(&c).map_err(|e| anyhow!("invalid {}: {}", LEGACY_VT_CONFIG_NAME, e))
            })
            .transpose()?;

        Ok(Self {
            vt: resolve_vt(parsed_unified.as_ref(), parsed_legacy_vt.as_ref()),
            llm: resolve_llm(parsed_unified.as_ref())?,
        })
    }
}

/// Read `path` if it exists, surfacing a `tracing::warn!` if the file is
/// group-/other-readable. Used for `~/.skill-veil.toml` and the legacy
/// `~/.vt.toml`, both of which hold API keys (VT, OpenAI, Anthropic,
/// xAI, Perplexity, Ollama Cloud).
///
/// # Contract
///
/// - `NotFound` ⇒ `None` (silent: file is truly absent).
/// - `EACCES`/other I/O ⇒ `None` PLUS a `tracing::warn!` so the operator
///   can distinguish "no config" from "config exists but is unreadable".
///
/// Pre-fix this function used `path.exists()` followed by `read_to_string`,
/// which both (a) introduced a TOCTOU race between the two syscalls, and
/// (b) silently masked `EACCES` (chmod 000) as `not found`, so an admin
/// who restricted the config without informing the user produced an
/// undebuggable "no API key configured" failure.
fn read_file_if_exists(path: &std::path::Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            crate::util::secure_fs::warn_if_file_world_readable(path);
            Some(contents)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            tracing::warn!(
                "skipping config file {}: {err} (check file permissions)",
                path.display(),
            );
            None
        }
    }
}

fn resolve_vt(
    unified: Option<&FileFormat>,
    legacy: Option<&LegacyVtFormat>,
) -> Option<VtConfigSection> {
    let env_key = std::env::var(VT_APIKEY_ENV).ok();
    let file_key = unified
        .and_then(|f| f.vt.as_ref())
        .and_then(|s| s.apikey.clone());
    let legacy_key = legacy.and_then(|l| l.apikey.clone());

    let apikey = env_key.or(file_key).or(legacy_key)?.trim().to_string();
    if apikey.is_empty() {
        return None;
    }
    Some(VtConfigSection { apikey })
}

fn resolve_llm(unified: Option<&FileFormat>) -> Result<Option<LlmConfigSection>> {
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

    let mut provider_configs: BTreeMap<LlmProviderKind, ProviderParams> = BTreeMap::new();
    let file_sections = &llm.providers;

    // Validate sub-keys eagerly. `FileLlmSection` uses `#[serde(flatten)]` on
    // a `BTreeMap<String, FileProviderParams>`, so any unknown sub-key under
    // `[llm]` (e.g. `provder = "openai"` instead of `provider`) is silently
    // absorbed as a fake provider entry. Pre-fix the loop below filtered
    // unknown names with `if let Some(kind) = ...`, so user typos vanished
    // without trace and the active provider quietly fell back to defaults.
    for name in file_sections.keys() {
        if LlmProviderKind::from_str_ci(name).is_none() {
            return Err(anyhow!(
                "[llm].{name} is not a recognised key. Expected a provider \
                 ({LLM_PROVIDER_VALID_VALUES}) or one of: provider, limits"
            ));
        }
    }

    for (name, params) in file_sections {
        let kind = LlmProviderKind::from_str_ci(name).expect("validated above");
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

    // Ensure the active provider has an entry even if the user omitted its
    // section (e.g. they only want defaults for Anthropic). Env vars still
    // populate the api_key.
    provider_configs.entry(provider).or_insert_with(|| {
        let mut p = ProviderParams::default();
        if let Some(env_key) = provider.resolve_apikey_from_env() {
            p.api_key = Some(env_key);
        }
        p
    });

    let limits = llm
        .limits
        .as_ref()
        .map(|l| LlmLimits {
            // Preserve user intent: explicit value in the file → Some(); if
            // the user left the field out we fall back to auto-detection via
            // `effective_max_prompt_chars`.
            max_prompt_chars: l.max_prompt_chars,
            request_timeout_secs: l.request_timeout_secs.unwrap_or(120),
        })
        .unwrap_or_default();

    Ok(Some(LlmConfigSection {
        provider,
        provider_configs,
        limits,
    }))
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
/// - Local providers (Ollama, LMStudio) may use `http://` to any host —
///   their typical defaults are `http://localhost:11434` /
///   `http://localhost:1234/v1` and users frequently point them at
///   private LAN hosts.
/// - Remote providers (OpenAI, Anthropic, Ollama-Cloud, Grok, Perplexity)
///   MUST use `https://` UNLESS the host is a loopback address — that
///   exception preserves the legitimate "I'm running a local mitm proxy
///   for debugging" workflow without re-opening the SSRF vector.
fn validate_provider_base_url(kind: LlmProviderKind, raw: &str) -> Result<()> {
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

// ---- On-disk format (serde) -------------------------------------------

#[derive(Debug, Deserialize, Serialize, Default)]
struct FileFormat {
    #[serde(default)]
    vt: Option<FileVtSection>,
    #[serde(default)]
    llm: Option<FileLlmSection>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct FileVtSection {
    #[serde(default)]
    apikey: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct FileLlmSection {
    #[serde(default)]
    provider: Option<String>,
    #[serde(flatten)]
    providers: BTreeMap<String, FileProviderParams>,
    #[serde(default)]
    limits: Option<FileLlmLimits>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct FileProviderParams {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    temperature: Option<f32>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct FileLlmLimits {
    #[serde(default)]
    max_prompt_chars: Option<usize>,
    #[serde(default)]
    request_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct LegacyVtFormat {
    #[serde(default)]
    apikey: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-var tests mutate process-global state, so serialise them to keep
    // parallel `cargo test` runs from stepping on each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parses_unified_toml_with_vt_and_llm() {
        let src = r#"
[vt]
apikey = "vt-key"

[llm]
provider = "anthropic"

[llm.anthropic]
model = "claude-sonnet-4-5"
max_tokens = 1024

[llm.openai]
model = "gpt-4o-mini"

[llm.limits]
max_prompt_chars = 80000
request_timeout_secs = 60
"#;
        let f: FileFormat = toml::from_str(src).unwrap();
        assert_eq!(f.vt.as_ref().unwrap().apikey.as_deref(), Some("vt-key"));
        let llm = f.llm.as_ref().unwrap();
        assert_eq!(llm.provider.as_deref(), Some("anthropic"));
        assert_eq!(llm.providers.len(), 2);
        assert!(llm.providers.contains_key("anthropic"));
        assert!(llm.providers.contains_key("openai"));
    }

    #[test]
    fn parses_legacy_vt_toml() {
        let src = r#"apikey = "legacy""#;
        let f: LegacyVtFormat = toml::from_str(src).unwrap();
        assert_eq!(f.apikey.as_deref(), Some("legacy"));
    }

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
    fn resolve_vt_prefers_env_over_file() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(VT_APIKEY_ENV, "env-vt-key");
        let unified = FileFormat {
            vt: Some(FileVtSection {
                apikey: Some("file-vt-key".into()),
            }),
            llm: None,
        };
        let got = resolve_vt(Some(&unified), None);
        assert_eq!(got.unwrap().apikey, "env-vt-key");
        std::env::remove_var(VT_APIKEY_ENV);
    }

    #[test]
    fn resolve_vt_falls_back_to_legacy_when_unified_missing() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var(VT_APIKEY_ENV);
        let legacy = LegacyVtFormat {
            apikey: Some("legacy-vt".into()),
        };
        let got = resolve_vt(None, Some(&legacy));
        assert_eq!(got.unwrap().apikey, "legacy-vt");
    }

    #[test]
    fn resolve_llm_rejects_unknown_provider() {
        let unified = FileFormat {
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("unknown".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
        };
        let got = resolve_llm(Some(&unified));
        assert!(got.is_err());
    }

    #[test]
    fn resolve_llm_ensures_active_provider_has_entry() {
        let unified = FileFormat {
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("ollama".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
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
            vt: None,
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
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("ollama-cloud".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
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
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("grok".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
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
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("xai".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
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
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("grok".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
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
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("perplexity".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
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
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("pplx".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
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
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("perplexity".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
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
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some("ollama-cloud".into()),
                providers: BTreeMap::new(),
                limits: None,
            }),
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

    #[test]
    fn limits_have_sane_defaults() {
        let l = LlmLimits::default();
        // No user override by default — resolution defers to
        // `effective_max_prompt_chars` which consults the model table.
        assert!(l.max_prompt_chars.is_none());
        assert!(l.request_timeout_secs >= 30);
    }

    fn mk_section(
        provider: LlmProviderKind,
        model: &str,
        override_chars: Option<usize>,
    ) -> LlmConfigSection {
        let mut pc = BTreeMap::new();
        pc.insert(
            provider,
            ProviderParams {
                model: model.to_string(),
                ..Default::default()
            },
        );
        LlmConfigSection {
            provider,
            provider_configs: pc,
            limits: LlmLimits {
                max_prompt_chars: override_chars,
                request_timeout_secs: 120,
            },
        }
    }

    #[test]
    fn cloud_provider_uses_model_table() {
        let s = mk_section(LlmProviderKind::Anthropic, "claude-sonnet-4-5", None);
        // 200_000 tokens × 3 × 0.75 = 450_000 chars
        assert_eq!(s.effective_max_prompt_chars(), 450_000);
    }

    #[test]
    fn user_override_always_wins_over_table() {
        let s = mk_section(
            LlmProviderKind::Anthropic,
            "claude-sonnet-4-5",
            Some(20_000),
        );
        assert_eq!(s.effective_max_prompt_chars(), 20_000);
    }

    #[test]
    fn local_provider_caps_at_60k_when_using_table() {
        // gemma-4's architectural ctx is 128k tokens → 288k chars, but
        // local providers are capped because the *loaded* ctx may be
        // smaller than the architectural one.
        let s = mk_section(LlmProviderKind::LmStudio, "google/gemma-4-26b-a4b", None);
        assert_eq!(s.effective_max_prompt_chars(), LOCAL_PROVIDER_CAP_CHARS);
    }

    #[test]
    fn local_provider_override_escapes_cap() {
        // If the user loaded a bigger ctx in LMStudio, they can override
        // the cap by setting max_prompt_chars explicitly.
        let s = mk_section(
            LlmProviderKind::LmStudio,
            "google/gemma-4-26b-a4b",
            Some(200_000),
        );
        assert_eq!(s.effective_max_prompt_chars(), 200_000);
    }

    #[test]
    fn local_provider_cap_applies_to_probed_tokens() {
        // A probed ctx of 500k tokens would yield ~1.125M chars, but the
        // local-provider cap must still apply so prompts stay predictable
        // on self-hosted servers.
        let s = mk_section(LlmProviderKind::LmStudio, "google/gemma-4-26b-a4b", None);
        assert_eq!(
            s.effective_max_prompt_chars_with_probe(Some(500_000)),
            LOCAL_PROVIDER_CAP_CHARS,
        );
    }

    #[test]
    fn cloud_provider_skips_cap_with_probed_tokens() {
        // Cloud providers are not capped: an Anthropic probe of 1M tokens
        // must flow through as the full char budget.
        let s = mk_section(LlmProviderKind::Anthropic, "claude-sonnet-4-5", None);
        let got = s.effective_max_prompt_chars_with_probe(Some(1_000_000));
        // 1_000_000 * 3 chars/tok * 0.75 prompt fraction = 2_250_000
        assert_eq!(got, 2_250_000);
    }

    #[test]
    fn unknown_model_falls_back_to_default() {
        let s = mk_section(LlmProviderKind::OpenAi, "some-custom-fine-tune", None);
        assert_eq!(s.effective_max_prompt_chars(), FALLBACK_MAX_PROMPT_CHARS);
    }

    #[test]
    fn model_lookup_is_case_insensitive_and_prefix_matched() {
        assert_eq!(lookup_model_context("Claude-Sonnet-4-6"), Some(200_000));
        assert_eq!(lookup_model_context("llama3.1:70b"), Some(128_000));
        assert_eq!(lookup_model_context("GPT-4o-mini"), Some(128_000));
        assert_eq!(lookup_model_context("mystery"), None);
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
            vt: None,
            llm: Some(FileLlmSection {
                provider: Some(provider.to_string()),
                providers,
                limits: None,
            }),
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

    /// # Contract
    ///
    /// `read_file_if_exists` MUST return `None` for a path that does
    /// not exist, without panicking. Safe to call speculatively on
    /// every config-search location, which is how `UnifiedConfig::load`
    /// uses it.
    #[test]
    fn read_file_if_exists_returns_none_for_missing_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("does-not-exist.toml");

        let result = read_file_if_exists(&missing);

        assert!(
            result.is_none(),
            "missing config files MUST yield None, not Some(empty)"
        );
    }

    /// # Contract
    ///
    /// `read_file_if_exists` MUST return the file body when the file
    /// exists, regardless of permissions. Pre-fix `~/.skill-veil.toml`
    /// got NO permission warning at all (only the standalone
    /// `~/.vt.toml` loader had one); post-fix the unified loader emits
    /// a tracing warning AND still returns the body so legitimate
    /// scans don't break. This test pins the load-success path so a
    /// future "fail-closed on world-readable config" refactor regresses
    /// here instead of silently disabling every shared-host install.
    #[cfg(unix)]
    #[test]
    fn read_file_if_exists_loads_world_readable_file_with_warning() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, "apikey = \"x\"").expect("seed config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("seed mode 0o644");

        let result = read_file_if_exists(&path);

        assert_eq!(
            result.as_deref(),
            Some("apikey = \"x\""),
            "world-readable config MUST still load — we warn, never block"
        );
    }

    /// # Contract
    ///
    /// A config file that exists on disk but is unreadable by the current
    /// process (e.g. `chmod 0o000` after admin lockdown) MUST NOT be
    /// silently treated as absent. Pre-fix the implementation used
    /// `path.exists() && read_to_string().ok()` so `EACCES` collapsed to
    /// `None` (`exists()` returns `false` on permission-denied stat in
    /// some cases, and `.ok()` discarded the error otherwise) — making
    /// "API key not configured" indistinguishable from "API key file is
    /// locked down". The new contract: still return `None` (callers
    /// remain branch-free), but the function MUST be reachable through
    /// the I/O error arm so callers can rely on the warn diagnostic.
    /// This test cannot capture the warn output portably; it asserts the
    /// reachability and `None` return without panicking.
    #[cfg(unix)]
    #[test]
    fn read_file_if_exists_returns_none_for_unreadable_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("locked.toml");
        std::fs::write(&path, "apikey = \"x\"").expect("seed config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("seed mode 0o000");

        // Skip when running as root — root bypasses DAC permission checks
        // and can read any file regardless of mode.
        if let Ok(uid_str) = std::env::var("UID") {
            if uid_str == "0" {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
                return;
            }
        }

        let result = read_file_if_exists(&path);

        // Restore so tempdir cleanup works even if the assertion fails.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));

        assert!(
            result.is_none(),
            "unreadable config MUST yield None (and produce a warn-level diagnostic, \
             not silently look identical to a missing file)"
        );
    }
}
