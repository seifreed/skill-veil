use super::types::{BenchmarkError, CorpusManifest};
use crate::ports::{FileSystemError, FileSystemProvider};
use std::path::Path;

pub fn load_manifest<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<CorpusManifest, BenchmarkError> {
    let bytes = fs.read_file_bytes(path).map_err(|err| match err {
        FileSystemError::IoError(io) => BenchmarkError::Io(io),
        FileSystemError::PathNotFound(missing) => BenchmarkError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("path not found: {}", missing.display()),
        )),
    })?;
    let manifest = String::from_utf8(bytes.as_bytes().to_vec()).map_err(|err| {
        BenchmarkError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    })?;
    Ok(serde_yaml::from_str(&manifest)?)
}
