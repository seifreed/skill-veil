//! VT credential resolution.
//!
//! Resolution order (first non-empty wins):
//!   1. `VT_APIKEY` environment variable
//!   2. `~/.vt.toml` with `apikey = "…"`
//!   3. `~/.skill-veil.toml` `[vt]` section (`apikey = "…"`) — lets users
//!      centralise both LLM and VT credentials in a single file.
//!
//! The key is never logged, never surfaced in error messages, and never
//! accepted via a CLI flag (to keep it out of shell history / `ps` output).

use crate::util::{bounded_read::read_text_file_with_cap, secure_fs::warn_if_file_world_readable};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::io;
use std::path::{Path, PathBuf};

const CONFIG_FILE_NAME: &str = ".vt.toml";
const API_KEY_ENV_VAR: &str = "VT_APIKEY";
const MAX_LEGACY_VT_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct VtConfig {
    pub(crate) apikey: String,
}

impl std::fmt::Debug for VtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VtConfig")
            .field("apikey", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    apikey: Option<String>,
}

impl VtConfig {
    pub(crate) fn load() -> Result<Self> {
        match Self::load_optional()? {
            Some(cfg) => Ok(cfg),
            None => {
                let path = Self::config_path()?;
                Err(anyhow!(
                    "VirusTotal API key not found.\n  \
                    Set the {env} environment variable, or create {path}\n  \
                    with contents: apikey = \"<your-vt-apikey>\"",
                    env = API_KEY_ENV_VAR,
                    path = path.display(),
                ))
            }
        }
    }

    /// Resolve the VT API key, distinguishing "not configured" from
    /// "configured but unreadable / malformed". Used by the auto-enrichment
    /// path inside `scan` so an absent `~/.vt.toml` silently skips VT
    /// (the operator never asked for VT) but a present-but-broken config
    /// still surfaces as an error the caller can warn about.
    ///
    /// Pre-fix the auto-enrichment path collapsed every error variant into
    /// `Ok(None)`, so a `chmod 000 ~/.vt.toml`, a malformed TOML body, or
    /// an empty `apikey` value all looked indistinguishable from "VT not
    /// configured" — operators saw their VT enrichment silently disappear
    /// without a single warning.
    ///
    /// Returns:
    /// - `Ok(Some(cfg))` — credentials were resolved (env var, legacy
    ///   `~/.vt.toml`, or unified `~/.skill-veil.toml` `[vt]` section).
    /// - `Ok(None)` — none of the three sources are present.
    /// - `Err(_)` — the legacy `~/.vt.toml` exists but cannot be used
    ///   (I/O error, parse error, missing or empty `apikey` field).
    pub(crate) fn load_optional() -> Result<Option<Self>> {
        if let Ok(env_key) = std::env::var(API_KEY_ENV_VAR) {
            let trimmed = env_key.trim();
            if !trimmed.is_empty() {
                return Ok(Some(Self {
                    apikey: trimmed.to_string(),
                }));
            }
        }

        if let Some(cfg) = Self::load_from_legacy_file()? {
            return Ok(Some(cfg));
        }

        Ok(Self::load_from_unified_config())
    }

    /// Read the legacy `~/.vt.toml`. `Ok(None)` means the file does not
    /// exist; an `Err` signals a real misconfiguration the caller should
    /// surface (we never want a typo'd `~/.vt.toml` to silently fall
    /// through to a different source and confuse the operator).
    fn load_from_legacy_file() -> Result<Option<Self>> {
        let path = Self::config_path()?;

        // Surface the world-readable warning before materialising the
        // secret in process memory: if the file is group/other-readable
        // the user should see the warning even when a downstream parse
        // error aborts the load. `warn_if_file_world_readable` is a
        // no-op on missing paths, so calling it before the read is safe.
        warn_if_file_world_readable(&path);

        // Read directly instead of `path.exists()` then `read_to_string`:
        // the prior pattern opened a tiny TOCTOU window where a
        // concurrent symlink swap between the existence check and the
        // open could change the file under us. NotFound here means the
        // user simply hasn't created `~/.vt.toml` yet, which is not an
        // error — return `Ok(None)` so the unified-config fallback can
        // run.
        let Some(contents) = read_legacy_config_file(&path)? else {
            return Ok(None);
        };
        let parsed: FileFormat = toml::from_str(&contents)
            .with_context(|| format!("failed to parse {} as TOML", path.display()))?;
        let apikey = parsed
            .apikey
            .ok_or_else(|| anyhow!("{} is missing required `apikey` field", path.display()))?
            .trim()
            .to_string();
        if apikey.is_empty() {
            return Err(anyhow!("{} has an empty `apikey` value", path.display()));
        }
        Ok(Some(Self { apikey }))
    }

    /// Resolve the VT API key from the unified `~/.skill-veil.toml`
    /// `[vt]` section. This is a best-effort fallback: if the unified
    /// loader fails (e.g. unrelated `[llm]` section is malformed), we
    /// silently return `None` rather than masking the legacy
    /// `~/.vt.toml` not-found path with a confusing parse error from a
    /// different file.
    fn load_from_unified_config() -> Option<Self> {
        let unified = crate::config::UnifiedConfig::load().ok()?;
        unified.vt_apikey.map(|apikey| Self { apikey })
    }

    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| {
            anyhow!("could not determine home directory; set {API_KEY_ENV_VAR} instead")
        })?;
        Ok(home.join(CONFIG_FILE_NAME))
    }
}

fn read_legacy_config_file(path: &Path) -> Result<Option<String>> {
    match read_text_file_with_cap(path, MAX_LEGACY_VT_CONFIG_BYTES) {
        Ok(contents) => Ok(Some(contents)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parses_key_from_toml_body() {
        let body = r#"apikey = "abc123""#;
        let parsed: FileFormat = toml::from_str(body).unwrap();
        assert_eq!(parsed.apikey.as_deref(), Some("abc123"));
    }

    /// # Contract
    ///
    /// `VtConfig::Debug` must not print the VirusTotal API key. The
    /// config value crosses command and enrichment boundaries, so debug
    /// formatting is a realistic accidental log path.
    #[test]
    fn vt_config_debug_redacts_apikey() {
        let cfg = VtConfig {
            apikey: "vt-secret-do-not-leak".to_string(),
        };

        let rendered = format!("{cfg:?}");

        assert!(!rendered.contains("vt-secret-do-not-leak"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn rejects_empty_toml_body() {
        let body = "";
        let parsed: FileFormat = toml::from_str(body).unwrap();
        assert!(parsed.apikey.is_none());
    }

    /// # Contract
    ///
    /// `FileFormat` MUST reject unknown fields so that typos like `api_key`
    /// (underscore) or `apikey` (missing 'y') produce a clear error rather
    /// than silently falling back to `apikey: None`, which causes a confusing
    /// "VirusTotal API key not found" message. Pre-fix, `#[serde(deny_unknown_fields)]`
    /// was absent, so `api_key = "sk-..."` was silently accepted with
    /// `apikey` defaulting to `None`.
    #[test]
    fn file_format_rejects_unknown_fields() {
        let body = r#"api_key = "sk-test123""#;
        let result: Result<FileFormat, _> = toml::from_str(body);
        assert!(
            result.is_err(),
            "FileFormat MUST reject unknown field 'api_key'; \
             pre-fix, this was silently accepted and apikey defaulted to None"
        );
    }

    #[test]
    fn env_override_takes_precedence() {
        // Note: this test cannot fully validate load() without mocking the home
        // dir, but the env var path is exercised separately in integration.
        std::env::set_var(API_KEY_ENV_VAR, "env-key");
        let cfg = VtConfig::load().unwrap();
        assert_eq!(cfg.apikey, "env-key");
        std::env::remove_var(API_KEY_ENV_VAR);
    }

    /// # Contract
    ///
    /// An explicitly empty `apikey` value MUST surface as `Err` (not
    /// `Ok(None)`). Pre-fix the auto-enrichment path swallowed every
    /// load failure, so an operator who accidentally wrote `apikey = ""`
    /// to `~/.vt.toml` lost VT enrichment without any warning. The `Err`
    /// lets the caller print a hint pointing at the broken file.
    ///
    /// `load_optional()` itself reads via `Self::config_path()`, which
    /// resolves through the user's HOME directory — global process state
    /// we cannot scope per-test. So this test pins the same parser-level
    /// contract that drives the production check (`apikey.is_empty()`
    /// branch in `load_optional()`).
    #[test]
    fn empty_apikey_in_toml_body_is_treated_as_error_signal() {
        let body = r#"apikey = """#;
        let parsed: FileFormat = toml::from_str(body).unwrap();
        let trimmed = parsed
            .apikey
            .expect("present-but-empty apikey must still parse")
            .trim()
            .to_string();
        assert!(
            trimmed.is_empty(),
            "an empty apikey value must surface as empty for the production check to reject it",
        );
    }

    /// # Contract
    ///
    /// `load_optional` MUST distinguish "not configured" (silent skip) from
    /// "configured but unusable" (caller warns). The auto-enrichment path
    /// in `commands/scan/vt.rs` relies on this tri-state to decide when to
    /// print a warning. This test pins the API shape so a future refactor
    /// cannot collapse the cases back into a single Boolean and re-introduce
    /// the swallowed-error bug.
    #[test]
    fn load_optional_signature_returns_optional_inside_result() {
        // Compile-time pin: `load_optional` returns `Result<Option<Self>>`.
        // Any change to `Result<Self>` would break this assignment and the
        // call site in `commands/scan/vt.rs` simultaneously.
        fn _signature_check() -> Result<Option<VtConfig>> {
            VtConfig::load_optional()
        }
    }

    /// # Contract
    ///
    /// The legacy VT config reader MUST accept normal TOML under the
    /// byte cap so existing `~/.vt.toml` users keep working.
    #[test]
    fn legacy_config_read_accepts_valid_toml_under_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);
        std::fs::write(&path, r#"apikey = "abc123""#).unwrap();

        let body = read_legacy_config_file(&path).unwrap().unwrap();

        assert!(body.contains("abc123"));
    }

    /// # Contract
    ///
    /// The legacy VT config reader MUST reject oversized files before
    /// TOML parsing, so a poisoned config path cannot allocate
    /// unbounded memory while resolving credentials.
    #[test]
    fn legacy_config_read_rejects_oversized_toml() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);
        let oversized_len = usize::try_from(MAX_LEGACY_VT_CONFIG_BYTES).unwrap() + 1;
        std::fs::write(&path, vec![b'a'; oversized_len]).unwrap();

        let err = read_legacy_config_file(&path).unwrap_err();

        assert!(format!("{err:#}").contains("exceeds limit"));
    }
}
