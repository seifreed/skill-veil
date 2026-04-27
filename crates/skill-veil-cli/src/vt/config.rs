//! VT credential resolution.
//!
//! Resolution order (first non-empty wins):
//!   1. `VT_APIKEY` environment variable
//!   2. `~/.vt.toml` with `apikey = "…"`
//!
//! The key is never logged, never surfaced in error messages, and never
//! accepted via a CLI flag (to keep it out of shell history / `ps` output).

use crate::util::secure_fs::warn_if_file_world_readable;
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::io;
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

        // Surface the world-readable warning before materialising the
        // secret in process memory: if the file is group/other-readable
        // the user should see the warning even when a downstream parse
        // error aborts the load. `warn_if_file_world_readable` is a
        // no-op on missing paths, so calling it before the read is safe.
        warn_if_file_world_readable(&path);

        // Read directly instead of `path.exists()` then `read_to_string`:
        // the prior pattern opened a tiny TOCTOU window where a
        // concurrent symlink swap between the existence check and the
        // open could change the file under us. Mapping `NotFound` here
        // also lets us preserve the helpful "set VT_APIKEY or create
        // ~/.vt.toml" guidance message users rely on for first-run
        // onboarding without introducing the race.
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(anyhow!(
                    "VirusTotal API key not found.\n  \
                    Set the {env} environment variable, or create {path}\n  \
                    with contents: apikey = \"<your-vt-apikey>\"",
                    env = API_KEY_ENV_VAR,
                    path = path.display(),
                ));
            }
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", path.display()));
            }
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
        Ok(Self { apikey })
    }

    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| {
            anyhow!("could not determine home directory; set {API_KEY_ENV_VAR} instead")
        })?;
        Ok(home.join(CONFIG_FILE_NAME))
    }
}

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
