//! Disk-side TOML loading and orchestration for `~/.skill-veil.toml`.
//!
//! Public consumers only see `UnifiedConfig::load`. Submodules:
//!
//! - `file_io`: serde DTOs (`FileFormat`, `FileLlmSection`, …) and the
//!   permissions-aware `read_file_if_exists` reader.
//! - `provider_resolution`: `resolve_llm` and the helpers that compose the
//!   per-provider map and apply env-var precedence.

mod file_io;
mod provider_resolution;

use anyhow::{anyhow, Result};

use super::UnifiedConfig;
use file_io::{read_file_if_exists, FileFormat};
use provider_resolution::resolve_llm;

const UNIFIED_CONFIG_NAME: &str = ".skill-veil.toml";

impl UnifiedConfig {
    pub(crate) fn load() -> Result<Self> {
        let home = dirs::home_dir();

        let file_contents = home.as_ref().and_then(|h| {
            let path = h.join(UNIFIED_CONFIG_NAME);
            read_file_if_exists(&path)
        });

        let parsed_unified: Option<FileFormat> = file_contents
            .map(|c| {
                toml::from_str(&c).map_err(|e| anyhow!("invalid {}: {}", UNIFIED_CONFIG_NAME, e))
            })
            .transpose()?;

        let vt_apikey = extract_vt_apikey(parsed_unified.as_ref());
        let promptintel_apikey = extract_promptintel_apikey(parsed_unified.as_ref());
        let osv = extract_osv_settings(parsed_unified.as_ref());

        Ok(Self {
            llm: resolve_llm(parsed_unified.as_ref())?,
            vt_apikey,
            promptintel_apikey,
            osv,
        })
    }
}

/// Resolve the `[osv]` section into [`OsvSettings`]. An absent section or
/// fields fall back to the opt-in defaults (disabled, 30-day cache, online).
/// A non-positive `cache_ttl_days` is clamped to the default so a typo cannot
/// silently disable caching.
fn extract_osv_settings(parsed: Option<&FileFormat>) -> super::OsvSettings {
    let mut settings = super::OsvSettings::default();
    let Some(section) = parsed.and_then(|f| f.osv.as_ref()) else {
        return settings;
    };
    if let Some(enable) = section.enable {
        settings.enabled = enable;
    }
    if let Some(days) = section.cache_ttl_days {
        if days > 0 {
            settings.cache_ttl_days = days;
        }
    }
    if let Some(offline) = section.offline {
        settings.offline = offline;
    }
    settings
}

/// Extract a usable VT API key from the parsed unified config.
///
/// # Contract
///
/// - Returns `Some(trimmed)` only when `[vt].apikey` is present AND
///   non-empty after trimming whitespace. An empty / whitespace-only
///   value yields `None` so the VT loader's "not configured" silent-skip
///   path remains reachable from the unified file (matching the
///   semantics of the legacy `~/.vt.toml` empty-string check).
/// - Returns `None` for an absent `[vt]` section, an absent `apikey`
///   key, or a missing config file altogether.
fn extract_vt_apikey(parsed: Option<&FileFormat>) -> Option<String> {
    parsed
        .and_then(|f| f.vt.as_ref())
        .and_then(|v| v.apikey.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Extract a usable PromptIntel API key from the parsed unified config.
///
/// # Contract
///
/// Same trimmed-and-non-empty semantics as [`extract_vt_apikey`]. The
/// PromptIntel loader treats `None` as "not configured" and silently
/// skips the integration so an operator who only wants VT enrichment
/// is never surprised by a 401 from PromptIntel.
fn extract_promptintel_apikey(parsed: Option<&FileFormat>) -> Option<String> {
    parsed
        .and_then(|f| f.promptintel.as_ref())
        .and_then(|v| v.apikey.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a populated `[vt].apikey` in `~/.skill-veil.toml`
    /// surfaces on `UnifiedConfig::vt_apikey` so the VT loader's
    /// unified-file fallback can resolve credentials without the
    /// legacy `~/.vt.toml`. Pre-fix the `[vt]` section was rejected
    /// outright by the TOML parser.
    #[test]
    fn extract_vt_apikey_returns_trimmed_value_when_present() {
        let parsed: FileFormat = toml::from_str(
            r#"
[vt]
apikey = "  key-with-padding  "
"#,
        )
        .expect("parses");
        let got = extract_vt_apikey(Some(&parsed));
        assert_eq!(got.as_deref(), Some("key-with-padding"));
    }

    /// Contract (negative): a whitespace-only `[vt].apikey` MUST yield
    /// `None`. The VT loader treats an empty value as a configuration
    /// error on the legacy `~/.vt.toml` path; on the unified-file
    /// fallback path we instead silently skip (the user can still
    /// supply credentials via env or `~/.vt.toml`), which is friendlier
    /// while still preventing a blank string from being sent as a
    /// bearer token.
    #[test]
    fn extract_vt_apikey_drops_whitespace_only_value() {
        let parsed: FileFormat = toml::from_str(
            r#"
[vt]
apikey = "   "
"#,
        )
        .expect("parses");
        let got = extract_vt_apikey(Some(&parsed));
        assert!(
            got.is_none(),
            "whitespace-only apikey MUST NOT surface as a usable credential"
        );
    }

    /// Contract (negative): an absent `[vt]` section MUST yield `None`
    /// without panicking, so a user who configures only `[llm]` in the
    /// unified file does not see spurious VT activity.
    #[test]
    fn extract_vt_apikey_returns_none_when_section_absent() {
        let parsed: FileFormat = toml::from_str(
            r#"
[llm]
provider = "lmstudio"
"#,
        )
        .expect("parses");
        assert!(extract_vt_apikey(Some(&parsed)).is_none());
        assert!(extract_vt_apikey(None).is_none());
    }
}
