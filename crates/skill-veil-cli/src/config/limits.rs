//! `LlmLimits` and effective prompt-character budget resolution.
//!
//! The model-context table and the local-provider cap live here so the
//! prompt budget is computed in one place. `LlmConfigSection`'s
//! `effective_max_prompt_chars*` methods are implemented here too — the
//! struct definition stays in `mod.rs`, but the math that consults the
//! model table belongs next to the table.

use super::{LlmConfigSection, LlmProviderKind};

/// Default HTTP request timeout for LLM provider calls, applied when
/// neither the unified config nor the legacy paths supply one.
pub(crate) const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 120;

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

#[derive(Debug, Clone)]
pub(crate) struct LlmLimits {
    /// `None` means "let `effective_max_prompt_chars` decide based on the
    /// active model". `Some(n)` is the user's explicit override and wins
    /// over the auto-detected value.
    pub max_prompt_chars: Option<usize>,
    pub request_timeout_secs: u64,
    /// Operator override for the LLM-adjudication consensus provider
    /// set. `None` ⇒ the validated trio (openai+grok+ollama-cloud).
    /// Broadening this trades the validated 15.75:1 ADR-0029
    /// calibration — gate any change through
    /// `skill-veil adjudication-eval` first.
    pub consensus_providers: Option<Vec<LlmProviderKind>>,
}

impl Default for LlmLimits {
    fn default() -> Self {
        Self {
            max_prompt_chars: None,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            consensus_providers: None,
        }
    }
}

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
            let budget = (tokens.saturating_mul(CHARS_PER_TOKEN) as f64) * PROMPT_FRACTION;
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
            Some(tokens) => (tokens.saturating_mul(CHARS_PER_TOKEN) as f64) * PROMPT_FRACTION,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderParams;
    use std::collections::BTreeMap;

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
                request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
                consensus_providers: None,
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

    /// # Contract
    ///
    /// Probed tokens that would cause `tokens * CHARS_PER_TOKEN` to overflow
    /// `usize` MUST be saturated instead of wrapping. A malicious or buggy
    /// Ollama `/api/show` response returning `usize::MAX` as the context
    /// length must not panic (debug) or produce a nonsensical budget (release).
    #[test]
    fn probed_tokens_overflow_saturates() {
        let s = mk_section(LlmProviderKind::Ollama, "llama3.1:8b", None);
        let result = s.effective_max_prompt_chars_with_probe(Some(usize::MAX));
        // saturating_mul(3) on usize::MAX = usize::MAX, then as f64 * 0.75
        // The local-provider cap of 60_000 must still apply.
        assert_eq!(result, LOCAL_PROVIDER_CAP_CHARS);
    }

    /// # Contract
    ///
    /// Cloud providers with extremely large probed tokens must produce a
    /// finite budget without panicking or wrapping. Saturating_mul prevents
    /// overflow in the `tokens * CHARS_PER_TOKEN` step.
    #[test]
    fn cloud_provider_large_probe_does_not_panic() {
        let s = mk_section(LlmProviderKind::Anthropic, "claude-sonnet-4-5", None);
        // usize::MAX / 2 * 3 is large but should not panic
        let large = usize::MAX / 2;
        let result = s.effective_max_prompt_chars_with_probe(Some(large));
        // Should produce a finite result without panicking
        assert!(
            result > 0,
            "budget must be positive for large probed tokens"
        );
    }
}
