use anyhow::{Context, Result};
use std::io::{self, Read};
use std::path::Path;

pub(crate) const MAX_OPERATOR_TEXT_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn read_operator_text_file(path: &Path) -> Result<String> {
    read_text_file_with_cap(path, MAX_OPERATOR_TEXT_FILE_BYTES)
        .with_context(|| format!("reading {}", path.display()))
}

pub(crate) fn read_text_file_with_cap(path: &Path, cap: u64) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
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
}
