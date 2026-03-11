//! File system provider implementation using std::fs

use crate::ports::{FileSystemError, FileSystemProvider};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// File system provider implementation using the standard library
#[derive(Debug, Default, Clone)]
pub struct StdFileSystemProvider;

impl StdFileSystemProvider {
    /// Create a new standard filesystem provider
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check if a filename matches a glob-like pattern
    fn matches_pattern(filename: &str, pattern: &str) -> bool {
        // Simple glob matching: support * as wildcard
        if pattern == "*" {
            return true;
        }

        if let Some(suffix) = pattern.strip_prefix('*') {
            return filename.ends_with(suffix);
        }

        if let Some(prefix) = pattern.strip_suffix('*') {
            return filename.starts_with(prefix);
        }

        filename == pattern
    }
}

impl FileSystemProvider for StdFileSystemProvider {
    fn read_file(&self, path: &Path) -> Result<String, FileSystemError> {
        if !path.exists() {
            return Err(FileSystemError::PathNotFound(path.to_path_buf()));
        }
        std::fs::read_to_string(path).map_err(FileSystemError::IoError)
    }

    fn list_files(
        &self,
        path: &Path,
        pattern: &str,
        recursive: bool,
    ) -> Result<Vec<PathBuf>, FileSystemError> {
        if !path.exists() {
            return Err(FileSystemError::PathNotFound(path.to_path_buf()));
        }

        let mut files = Vec::new();

        if recursive {
            for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
                if entry.file_type().is_file() {
                    if let Some(filename) = entry.path().file_name().and_then(|n| n.to_str()) {
                        if Self::matches_pattern(filename, pattern) {
                            files.push(entry.path().to_path_buf());
                        }
                    }
                }
            }
        } else {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    if let Some(filename) = entry.path().file_name().and_then(|n| n.to_str()) {
                        if Self::matches_pattern(filename, pattern) {
                            files.push(entry.path());
                        }
                    }
                }
            }
        }

        Ok(files)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_read_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let fs = StdFileSystemProvider::new();
        let content = fs.read_file(&file_path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_read_nonexistent_file() {
        let fs = StdFileSystemProvider::new();
        let result = fs.read_file(Path::new("/nonexistent/path/file.txt"));
        assert!(matches!(result, Err(FileSystemError::PathNotFound(_))));
    }

    #[test]
    fn test_list_files_non_recursive() {
        let dir = TempDir::new().unwrap();

        // Create test files
        std::fs::write(dir.path().join("test1.md"), "").unwrap();
        std::fs::write(dir.path().join("test2.md"), "").unwrap();
        std::fs::write(dir.path().join("test.txt"), "").unwrap();

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*.md", false).unwrap();

        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| f.extension().unwrap() == "md"));
    }

    #[test]
    fn test_list_files_recursive() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();

        std::fs::write(dir.path().join("test1.md"), "").unwrap();
        std::fs::write(subdir.join("test2.md"), "").unwrap();

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*.md", true).unwrap();

        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_exists() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("exists.txt");
        std::fs::write(&file_path, "").unwrap();

        let fs = StdFileSystemProvider::new();
        assert!(fs.exists(&file_path));
        assert!(!fs.exists(&dir.path().join("does_not_exist.txt")));
    }

    #[test]
    fn test_pattern_matching() {
        assert!(StdFileSystemProvider::matches_pattern("test.md", "*.md"));
        assert!(StdFileSystemProvider::matches_pattern("test.md", "*"));
        assert!(StdFileSystemProvider::matches_pattern("test.md", "test*"));
        assert!(!StdFileSystemProvider::matches_pattern("test.txt", "*.md"));
    }
}
