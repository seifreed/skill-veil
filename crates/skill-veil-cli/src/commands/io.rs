use anyhow::{Context, Result};
use skill_veil_core::{JsonReport, PolicyFile};
use std::path::{Path, PathBuf};

pub(super) fn write_output_file(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content).context("Failed to write output file")
}

pub(crate) fn load_json_reports(path: &PathBuf) -> Result<Vec<JsonReport>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON report {}", path.display()))
}

pub(super) fn serialize_json_pretty<T>(value: &T, context: &str) -> Result<String>
where
    T: serde::Serialize,
{
    serde_json::to_string_pretty(value).context(context.to_string())
}

pub(super) fn parse_policy_file(path: &Path) -> Result<PolicyFile> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .with_context(|| format!("Failed to parse {}", path.display()))
}
