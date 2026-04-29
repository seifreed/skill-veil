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

        Ok(Self {
            llm: resolve_llm(parsed_unified.as_ref())?,
        })
    }
}
