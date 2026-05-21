//! PromptIntel credential resolution.
//!
//! Resolution order (first non-empty wins):
//!   1. `PROMPTINTEL` environment variable
//!   2. `~/.skill-veil.toml` `[promptintel].apikey`
//!
//! The key is never logged, never surfaced in error messages, and never
//! accepted via a CLI flag (so it doesn't leak into shell history or
//! `ps` output). Mirrors `crate::vt::config::VtConfig` so operators who
//! already understand the VT loader find this familiar.

use anyhow::{anyhow, Result};

const API_KEY_ENV_VAR: &str = "PROMPTINTEL";

/// PromptIntel credentials, ready for the HTTP client to consume.
#[derive(Clone)]
pub(crate) struct PromptIntelConfig {
    pub(crate) apikey: String,
}

impl std::fmt::Debug for PromptIntelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptIntelConfig")
            .field("apikey", &"<redacted>")
            .finish()
    }
}

impl PromptIntelConfig {
    /// Resolve credentials, returning a hard error when none of the
    /// configured sources produce a usable value. Used by interactive
    /// commands (`skill-veil promptintel download`) that cannot proceed
    /// without authentication.
    pub(crate) fn load() -> Result<Self> {
        match Self::load_optional()? {
            Some(cfg) => Ok(cfg),
            None => Err(anyhow!(
                "PromptIntel API key not found.\n  \
                Set the {env} environment variable, or add\n  \
                [promptintel]\n  apikey = \"<your-promptintel-apikey>\"\n  \
                to ~/.skill-veil.toml.",
                env = API_KEY_ENV_VAR,
            )),
        }
    }

    /// Three-state resolver mirroring [`crate::vt::config::VtConfig::load_optional`]:
    /// `Ok(Some(_))` when configured, `Ok(None)` when no source set
    /// credentials, `Err(_)` when the unified config exists but is
    /// malformed in a way that affects PromptIntel resolution.
    pub(crate) fn load_optional() -> Result<Option<Self>> {
        if let Ok(env_key) = std::env::var(API_KEY_ENV_VAR) {
            let trimmed = env_key.trim();
            if !trimmed.is_empty() {
                return Ok(Some(Self {
                    apikey: trimmed.to_string(),
                }));
            }
        }

        // The unified loader is best-effort: a typo'd `[llm]` should
        // not mask "PromptIntel not configured" with a noisy parse
        // error from a different section. `Ok(None)` here means "no
        // unified config" or "unified config exists but no
        // `[promptintel]` apikey resolved", which is exactly the
        // semantics callers want.
        let unified = match crate::config::UnifiedConfig::load() {
            Ok(cfg) => cfg,
            Err(_) => return Ok(None),
        };

        Ok(unified.promptintel_apikey.map(|apikey| Self { apikey }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvRestore {
        prior: Option<OsString>,
    }

    impl EnvRestore {
        fn set(value: &str) -> Self {
            let prior = std::env::var_os(API_KEY_ENV_VAR);
            std::env::set_var(API_KEY_ENV_VAR, value);
            Self { prior }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            if let Some(value) = self.prior.take() {
                std::env::set_var(API_KEY_ENV_VAR, value);
            } else {
                std::env::remove_var(API_KEY_ENV_VAR);
            }
        }
    }

    fn with_promptintel_env<R>(value: &str, run: impl FnOnce() -> R) -> R {
        let _lock = ENV_LOCK.lock().expect("ENV_LOCK poisoned");
        let _restore = EnvRestore::set(value);
        run()
    }

    /// Contract: the `PROMPTINTEL` env var, when set to a non-empty
    /// value, MUST short-circuit `load_optional` ahead of the unified
    /// config. Same precedence as `VT_APIKEY` for the VT loader so
    /// operators only have to learn one rule.
    #[test]
    fn env_var_takes_precedence_over_anything_else() {
        // Use a unique value so this test cannot collide with whatever
        // the ambient unified config contains.
        let token = "test-promptintel-env-9f3c";
        let cfg = with_promptintel_env(token, || {
            PromptIntelConfig::load_optional()
                .expect("env var path must not error")
                .expect("env var path must produce credentials")
        });
        assert_eq!(cfg.apikey, token);
    }

    /// # Contract
    ///
    /// `PromptIntelConfig::Debug` must not print the API key. PromptIntel
    /// commands construct this value before every authenticated request,
    /// making debug-format logging an accidental credential leak path.
    #[test]
    fn promptintel_config_debug_redacts_apikey() {
        let cfg = PromptIntelConfig {
            apikey: "promptintel-secret-do-not-leak".to_string(),
        };

        let rendered = format!("{cfg:?}");

        assert!(!rendered.contains("promptintel-secret-do-not-leak"));
        assert!(rendered.contains("<redacted>"));
    }

    /// Contract: a whitespace-only `PROMPTINTEL` env var MUST NOT be
    /// treated as configured credentials. Otherwise an operator who
    /// accidentally exports `PROMPTINTEL=" "` would see a confusing
    /// 401 instead of a clean "not configured" path. Mirrors the
    /// `VT_APIKEY` empty-string contract.
    #[test]
    fn whitespace_env_var_is_treated_as_unset() {
        let result = with_promptintel_env("   ", || {
            PromptIntelConfig::load_optional().expect("whitespace env var must not error")
        });
        // `result` may be `Some(...)` only if the unified config carries
        // a key; that is fine. We only assert the env var path itself
        // didn't produce a whitespace-credentialed `Some`.
        if let Some(cfg) = result {
            assert!(
                !cfg.apikey.trim().is_empty(),
                "whitespace env var leaked an empty-credential PromptIntelConfig"
            );
        }
    }
}
