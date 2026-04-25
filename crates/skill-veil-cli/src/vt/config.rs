//! VT credential resolution.
//!
//! Resolution order (first non-empty wins):
//!   1. `VT_APIKEY` environment variable
//!   2. `~/.vt.toml` with `apikey = "…"`
//!
//! The key is never logged, never surfaced in error messages, and never
//! accepted via a CLI flag (to keep it out of shell history / `ps` output).

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

const CONFIG_FILE_NAME: &str = ".vt.toml";
const API_KEY_ENV_VAR: &str = "VT_APIKEY";

#[derive(Debug, Clone)]
pub(crate) struct VtConfig {
    pub(crate) apikey: String,
}

#[derive(Debug, Deserialize)]
struct FileFormat {
    apikey: Option<String>,
}

impl VtConfig {
    pub(crate) fn load() -> Result<Self> {
        if let Ok(env_key) = std::env::var(API_KEY_ENV_VAR) {
            let trimmed = env_key.trim();
            if !trimmed.is_empty() {
                return Ok(Self {
                    apikey: trimmed.to_string(),
                });
            }
        }

        let path = Self::config_path()?;
        if !path.exists() {
            return Err(anyhow!(
                "VirusTotal API key not found.\n  \
                Set the {env} environment variable, or create {path}\n  \
                with contents: apikey = \"<your-vt-apikey>\"",
                env = API_KEY_ENV_VAR,
                path = path.display(),
            ));
        }

        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
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
        warn_if_world_readable(&path);
        Ok(Self { apikey })
    }

    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| {
            anyhow!("could not determine home directory; set {API_KEY_ENV_VAR} instead")
        })?;
        Ok(home.join(CONFIG_FILE_NAME))
    }
}

/// On Unix, warn when the config file is readable by other users. The apikey
/// grants premium VT access; world-readable storage is a common leak vector.
#[cfg(unix)]
fn warn_if_world_readable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                "{} is world- or group-readable (mode {:o}); recommend `chmod 600 {}`",
                path.display(),
                mode,
                path.display(),
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_path: &std::path::Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_from_toml_body() {
        let body = r#"apikey = "abc123""#;
        let parsed: FileFormat = toml::from_str(body).unwrap();
        assert_eq!(parsed.apikey.as_deref(), Some("abc123"));
    }

    #[test]
    fn rejects_empty_toml_body() {
        let body = "";
        let parsed: FileFormat = toml::from_str(body).unwrap();
        assert!(parsed.apikey.is_none());
    }

    #[test]
    fn rejects_missing_apikey_field() {
        let body = r#"other = "x""#;
        let parsed: FileFormat = toml::from_str(body).unwrap();
        assert!(parsed.apikey.is_none());
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
}
