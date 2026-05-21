use std::fs::Metadata;
use std::io::{self, Read};
use std::path::Path;

use anyhow::{Context, Result};

pub(crate) const MAX_OPERATOR_TEXT_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn read_operator_text_file(path: &Path) -> Result<String> {
    read_text_file_with_cap(path, MAX_OPERATOR_TEXT_FILE_BYTES)
        .with_context(|| format!("reading {}", path.display()))
}

pub(crate) fn read_text_file_with_cap(path: &Path, cap: u64) -> io::Result<String> {
    let path_meta = std::fs::symlink_metadata(path)?;
    if !path_meta.is_file() || path_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to read non-regular text file {}", path.display()),
        ));
    }

    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || !opened_file_matches_path(&meta, &path_meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to read swapped text file {}", path.display()),
        ));
    }
    if meta.len() > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size {} exceeds limit {}",
                path.display(),
                meta.len(),
                cap
            ),
        ));
    }

    let mut bytes = Vec::with_capacity(usize::try_from(meta.len().min(cap)).unwrap_or(0));
    let mut limited = file.take(cap.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size exceeds limit {}",
                path.display(),
                cap
            ),
        ));
    }
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(unix)]
fn opened_file_matches_path(opened: &Metadata, path_meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    opened.dev() == path_meta.dev() && opened.ino() == path_meta.ino()
}

#[cfg(not(unix))]
fn opened_file_matches_path(_opened: &Metadata, _path_meta: &Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// # Contract
    ///
    /// Operator text files under the configured cap MUST read
    /// unchanged. The helper is shared by report/corpus commands whose
    /// formats remain ordinary UTF-8 JSON/YAML/JSONL.
    #[test]
    fn read_text_file_with_cap_accepts_valid_text_under_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.json");
        std::fs::write(&path, "{\"ok\":true}\n").unwrap();

        let body = read_text_file_with_cap(&path, 1024).unwrap();

        assert_eq!(body, "{\"ok\":true}\n");
    }

    /// # Contract
    ///
    /// Operator text reads MUST reject files over the configured cap
    /// before UTF-8 decoding or JSON/YAML parsing.
    #[test]
    fn read_text_file_with_cap_rejects_oversized_text() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.json");
        std::fs::write(&path, vec![b'{'; 32]).unwrap();

        let err = read_text_file_with_cap(&path, 8).unwrap_err();

        assert!(format!("{err:#}").contains("exceeds limit"));
    }

    /// # Contract
    ///
    /// Operator text reads MUST reject non-regular filesystem entries
    /// before opening them. A directory, FIFO, or device path must never
    /// reach the bounded streaming read.
    #[test]
    fn read_text_file_with_cap_rejects_non_regular_text() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report-dir");
        std::fs::create_dir(&path).unwrap();

        let err = read_text_file_with_cap(&path, 1024).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(format!("{err:#}").contains("non-regular text file"));
    }

    /// # Contract
    ///
    /// Operator text reads MUST reject symlink entries instead of reading
    /// the link target. The helper feeds policy, disposition, gold, and
    /// history inputs whose contents affect scanner decisions.
    #[cfg(unix)]
    #[test]
    fn read_text_file_with_cap_rejects_symlinked_text() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.json");
        let link = dir.path().join("report.json");
        std::fs::write(&target, "{\"ok\":true}\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = read_text_file_with_cap(&link, 1024).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(format!("{err:#}").contains("non-regular text file"));
    }
}
