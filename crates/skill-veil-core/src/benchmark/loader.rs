use super::types::{BenchmarkError, CorpusManifest};
use crate::ports::{FileSystemError, FileSystemProvider};
use serde::de::DeserializeOwned;
use std::path::Path;

/// Read `path` through the `FileSystemProvider` port and deserialise
/// it from YAML. Shared by the path-based corpus loaders so the
/// read/UTF-8/parse error mapping lives in one place.
pub fn load_yaml<F: FileSystemProvider, T: DeserializeOwned>(
    fs: &F,
    path: &Path,
) -> Result<T, BenchmarkError> {
    let bytes = fs.read_file_bytes(path).map_err(|err| match err {
        FileSystemError::IoError(io) => BenchmarkError::Io(io),
        FileSystemError::PathNotFound(missing) => BenchmarkError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("path not found: {}", missing.display()),
        )),
    })?;
    let text = String::from_utf8(bytes.as_bytes().to_vec()).map_err(|err| {
        BenchmarkError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    })?;
    Ok(serde_yaml::from_str(&text)?)
}

pub fn load_manifest<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<CorpusManifest, BenchmarkError> {
    load_yaml(fs, path)
}
