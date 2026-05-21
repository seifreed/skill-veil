//! Atomic writes for operator-requested output files.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Write `body` to `path` through a same-directory temporary file.
///
/// The destination path is replaced by `rename(2)`, so a pre-existing
/// symlink at the final path is replaced as a directory entry instead of
/// being followed and overwritten.
pub(crate) fn write_output_file_atomic(path: &Path, body: &[u8]) -> Result<()> {
    let parent = output_parent(path);
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating output directory {}", parent.display()))?;
    ensure_real_output_dir(parent)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temp output under {}", parent.display()))?;
    tmp.write_all(body)
        .with_context(|| format!("writing temp output under {}", parent.display()))?;
    tmp.as_file_mut()
        .sync_all()
        .with_context(|| format!("syncing temp output under {}", parent.display()))?;
    let temp_path = tmp.into_temp_path();
    crate::util::cache_io::finalize_atomic_write(temp_path.as_ref(), path)
        .with_context(|| format!("renaming temp output to {}", path.display()))?;
    Ok(())
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn ensure_real_output_dir(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat output directory {}", path.display()))?;
    if meta.is_dir() && !meta.file_type().is_symlink() {
        Ok(())
    } else {
        anyhow::bail!("{} is not a real output directory", path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// # Contract
    ///
    /// Output writes MUST create a regular file containing the requested
    /// bytes when the destination does not yet exist.
    #[test]
    fn write_output_file_atomic_creates_regular_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("scan.json");

        write_output_file_atomic(&path, b"{\"ok\":true}\n").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"{\"ok\":true}\n");
    }

    /// # Contract
    ///
    /// Output writes MUST replace a symlink at the final path without
    /// mutating the symlink target.
    #[cfg(unix)]
    #[test]
    fn write_output_file_atomic_replaces_symlink_without_touching_target() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("outside.json");
        let link = dir.path().join("scan.json");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        write_output_file_atomic(&link, b"fresh").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&link).unwrap(), b"fresh");
    }

    /// # Contract
    ///
    /// The parent directory used for the temporary file MUST be a real
    /// directory, not a symlink to a different location.
    #[cfg(unix)]
    #[test]
    fn write_output_file_atomic_rejects_symlinked_parent_dir() {
        let dir = TempDir::new().unwrap();
        let outside = dir.path().join("outside");
        let link_parent = dir.path().join("reports");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link_parent).unwrap();

        let err = write_output_file_atomic(&link_parent.join("scan.json"), b"fresh").unwrap_err();

        assert!(format!("{err:#}").contains("not a real output directory"));
        assert!(!outside.join("scan.json").exists());
    }
}
