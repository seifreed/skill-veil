use super::types::{BenchmarkError, CorpusManifest};
use std::path::Path;

pub fn load_manifest(path: &Path) -> Result<CorpusManifest, BenchmarkError> {
    let manifest = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&manifest)?)
}
