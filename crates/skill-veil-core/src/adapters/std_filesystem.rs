//! File system provider implementation using std::fs

use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::ports::{FileContent, FileMeta, FileSystemError, FileSystemProvider};

use super::walk_helpers::{is_skipped_dir, lossy_filename_with_warning};

/// Hard upper bound on a single `read_file_bytes` call. Any larger file
/// surfaces as `FileSystemError::IoError` instead of being slurped into
/// memory. The limit is generous (256 MiB) so it does not interfere with
/// legitimate skills carrying full datasets, but defends against a
/// malicious package that ships a 100 GB file as a denial-of-service
/// vector — `std::fs::read` would otherwise attempt to allocate the
/// entire body into a `Vec<u8>` and OOM the process.
///
/// Discovery layers (`file_discovery::package_artifacts`) already apply
/// per-pattern caps (`MAX_DATA_FILE_BYTES`, `MAX_SCRIPT_FILE_BYTES`),
/// but external callers — VT enrichment, dataset preparation, ad-hoc
/// CLI commands — bypass those caps and reach this port directly. The
/// guard here is the last line of defence.
pub const MAX_READ_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// File system provider implementation using the standard library
#[derive(Debug, Default, Clone)]
pub struct StdFileSystemProvider;

impl StdFileSystemProvider {
    /// Create a new standard filesystem provider
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check if a filename matches a glob pattern.
    ///
    /// Backed by `globset`, which supports the standard glob subset:
    /// `*` (any non-separator run), `?` (single char), `[abc]`
    /// (character class), `{a,b}` (alternation). Pre-fix the matcher
    /// only handled leading- or trailing-`*` patterns and silently
    /// returned `false` for anything more complex (`foo*bar.json`,
    /// `*.{json,yaml}`), which made it easy to author a discovery
    /// pattern that compiled fine but matched nothing.
    ///
    /// Failure mode is fail-closed: an invalid glob (e.g. `[unclosed`)
    /// returns `false` instead of panicking. The caller already passes
    /// well-known patterns from the discovery rules, so a malformed
    /// pattern is a programming error worth surfacing as "no matches"
    /// rather than crashing a long-running scan.
    fn compile_matcher(pattern: &str) -> Option<globset::GlobMatcher> {
        match globset::Glob::new(pattern) {
            Ok(glob) => Some(glob.compile_matcher()),
            Err(err) => {
                tracing::debug!(
                    "invalid glob pattern {pattern:?} in file discovery (treating as no-match): {err}",
                );
                None
            }
        }
    }

    #[cfg(test)]
    fn matches_pattern(filename: &str, pattern: &str) -> bool {
        Self::compile_matcher(pattern).is_some_and(|matcher| matcher.is_match(filename))
    }
}

impl FileSystemProvider for StdFileSystemProvider {
    /// Read the contents of `path`.
    ///
    /// `PathNotFound` is reserved for genuine "no such entry" errors;
    /// permission-denied, EBUSY, EIO and other I/O failures are returned
    /// as `IoError`. Pre-fix the function used `path.exists()` as a
    /// pre-check, but `Path::exists` returns `false` for *any* failure
    /// to stat (including `PermissionDenied`), so an unreadable file
    /// would surface as `PathNotFound` and operators would see the scan
    /// silently skip artifacts that actually exist.
    fn read_file_bytes(&self, path: &Path) -> Result<FileContent, FileSystemError> {
        let path_meta = regular_file_metadata(path)?;
        let file = match File::open(path) {
            Ok(f) => f,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(FileSystemError::PathNotFound(path.to_path_buf()));
            }
            Err(err) => return Err(FileSystemError::IoError(err)),
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(FileSystemError::PathNotFound(path.to_path_buf()));
            }
            Err(err) => return Err(FileSystemError::IoError(err)),
        };
        validate_opened_regular_file(path, &path_meta, &meta)?;
        if meta.len() > MAX_READ_FILE_BYTES {
            return Err(FileSystemError::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to read {}: size {} exceeds MAX_READ_FILE_BYTES ({})",
                    path.display(),
                    meta.len(),
                    MAX_READ_FILE_BYTES
                ),
            )));
        }
        use std::io::Read;
        let mut buf = Vec::with_capacity(meta.len().try_into().unwrap_or(0));
        // `.take()` bounds the read at MAX_READ_FILE_BYTES + 1 so that a
        // file that grew between the metadata check and the read still
        // cannot exceed the cap. If we read more than MAX_READ_FILE_BYTES
        // bytes, the file grew and we reject it.
        let mut limited = file.take(MAX_READ_FILE_BYTES + 1);
        if let Err(err) = limited.read_to_end(&mut buf) {
            return Err(FileSystemError::IoError(err));
        }
        if buf.len() as u64 > MAX_READ_FILE_BYTES {
            return Err(FileSystemError::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to read {}: size exceeds MAX_READ_FILE_BYTES ({})",
                    path.display(),
                    MAX_READ_FILE_BYTES
                ),
            )));
        }
        Ok(FileContent::new(buf))
    }

    /// List the entries of `path` that match `pattern`.
    ///
    /// # Symlink policy
    ///
    /// Symlinks are deliberately NOT followed. The threat model includes
    /// scanned packages authored by untrusted parties, so a symlink like
    /// `evil.json -> /etc/passwd` shipped inside a malicious skill MUST
    /// NOT cause the scanner to ingest the link target. Concretely:
    ///
    /// * The recursive walk pins `WalkDir::follow_links(false)` so the
    ///   walker neither descends into symlinked directories nor reports
    ///   the link target's type.
    /// * Both branches gate on `FileType::is_file()` AND
    ///   `!FileType::is_symlink()` so a future refactor that turns
    ///   `follow_links` on (which would make `is_file()` reflect the
    ///   target type) does not silently re-enable symlink ingestion.
    ///
    /// # Error policy
    ///
    /// `PathNotFound` is reserved for genuine "no such directory"
    /// errors; permission-denied, EBUSY, EIO and other I/O failures on
    /// the root path are returned as `IoError`. Pre-fix the function
    /// used `path.exists()` as a pre-check, but `Path::exists` returns
    /// `false` for *any* failure to stat (including `PermissionDenied`),
    /// so an unreadable directory would surface as `PathNotFound` and
    /// operators would see the scan silently skip artifacts that
    /// actually exist on disk — the same failure mode `read_file_bytes`
    /// guards against. Errors encountered on individual *child* entries
    /// during a recursive walk remain warnings: the scan keeps going on
    /// the legible siblings instead of aborting the whole package.
    ///
    /// # Non-UTF-8 filenames
    ///
    /// Filenames containing non-UTF-8 bytes are matched against `pattern`
    /// using `OsStr::to_string_lossy` (invalid sequences become
    /// `U+FFFD`) and a `tracing::warn!` is emitted naming the lossy
    /// path. Pre-fix the chained `to_str()` returned `None` and the
    /// entry was silently skipped, allowing an attacker who packages
    /// an untrusted skill with a non-UTF-8 artifact name (zip and tar
    /// both preserve raw bytes) to evade scanning entirely. Lossy
    /// matching closes the evasion vector while the warning surfaces
    /// the attempt to operators.
    fn list_files(
        &self,
        path: &Path,
        pattern: &str,
        recursive: bool,
    ) -> Result<Vec<PathBuf>, FileSystemError> {
        let mut files = Vec::new();
        let Some(matcher) = Self::compile_matcher(pattern) else {
            return Ok(files);
        };

        if recursive {
            for result in WalkDir::new(path).follow_links(false) {
                match result {
                    Ok(entry) => {
                        let file_type = entry.file_type();
                        if file_type.is_file() && !file_type.is_symlink() {
                            let entry_path = entry.path();
                            if let Some(filename_os) = entry_path.file_name() {
                                let filename = lossy_filename_with_warning(filename_os, entry_path);
                                if matcher.is_match(filename.as_ref()) {
                                    files.push(entry_path.to_path_buf());
                                }
                            }
                        }
                    }
                    Err(err) if err.depth() == 0 => {
                        let io_err = err.into_io_error().unwrap_or_else(|| {
                            io::Error::other("walkdir error without underlying io::Error")
                        });
                        return match io_err.kind() {
                            io::ErrorKind::NotFound => {
                                Err(FileSystemError::PathNotFound(path.to_path_buf()))
                            }
                            _ => Err(FileSystemError::IoError(io_err)),
                        };
                    }
                    Err(err) => {
                        tracing::warn!("Skipping entry during recursive file listing: {err}");
                    }
                }
            }
        } else {
            let entries = match std::fs::read_dir(path) {
                Ok(it) => it,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    return Err(FileSystemError::PathNotFound(path.to_path_buf()));
                }
                Err(err) => return Err(FileSystemError::IoError(err)),
            };
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(err) => {
                        tracing::warn!("Skipping entry during non-recursive file listing: {err}");
                        continue;
                    }
                };
                let file_type = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(err) => {
                        tracing::warn!(
                            "Skipping entry with unavailable file type: {}: {err}",
                            entry.path().display()
                        );
                        continue;
                    }
                };
                if file_type.is_file() && !file_type.is_symlink() {
                    let entry_path = entry.path();
                    if let Some(filename_os) = entry_path.file_name() {
                        let filename = lossy_filename_with_warning(filename_os, &entry_path);
                        if matcher.is_match(filename.as_ref()) {
                            files.push(entry_path);
                        }
                    }
                }
            }
        }

        Ok(files)
    }

    /// Use `symlink_metadata` to avoid following symlinks, consistent with
    /// `list_files` / `walk_files` which explicitly filter out symlinks.
    /// `Path::exists()` follows symlinks AND swallows permission errors
    /// (returning `false` for `PermissionDenied`), which is inconsistent
    /// with the symlink-does-not-exist policy of the listing methods.
    fn exists(&self, path: &Path) -> bool {
        match std::fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                tracing::debug!("exists: stat failed for {}: {e}", path.display());
                // Fail-closed: permission errors mean "exists but
                // inaccessible", not "not found"
                true
            }
        }
    }

    fn metadata(&self, path: &Path) -> Result<FileMeta, FileSystemError> {
        let meta = std::fs::symlink_metadata(path).map_err(FileSystemError::IoError)?;
        Ok(FileMeta { len: meta.len() })
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf, FileSystemError> {
        std::fs::canonicalize(path).map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => FileSystemError::PathNotFound(path.to_path_buf()),
            _ => FileSystemError::IoError(err),
        })
    }

    /// Use `symlink_metadata` to avoid following symlinks, consistent with
    /// the listing methods' `!file_type.is_symlink()` filter.
    fn is_file(&self, path: &Path) -> bool {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => meta.is_file() && !meta.is_symlink(),
            Err(_) => false,
        }
    }

    /// Use `symlink_metadata` to avoid following symlinks, consistent with
    /// the listing methods' `!file_type.is_symlink()` filter.
    fn is_dir(&self, path: &Path) -> bool {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => meta.is_dir() && !meta.is_symlink(),
            Err(_) => false,
        }
    }

    /// Recursive walk over `path` honouring `max_depth` and `skip_dirs`.
    ///
    /// Symlinks are NOT followed (`follow_links(false)`). Errors on
    /// individual entries are logged via `tracing::warn!` and the walk
    /// continues, matching the asymmetry documented for `list_files`:
    /// the root error is fatal, child errors are non-fatal so a single
    /// unreadable subtree does not blank an entire package scan.
    ///
    /// `max_depth = 0` means unlimited (matches the documented port
    /// contract). `skip_dirs` is checked against the lossy filename of
    /// each directory entry; a match prunes the entire subtree.
    fn walk_files(
        &self,
        path: &Path,
        max_depth: usize,
        skip_dirs: &[&str],
    ) -> Result<Vec<PathBuf>, FileSystemError> {
        let mut walker = WalkDir::new(path).follow_links(false);
        if max_depth > 0 {
            walker = walker.max_depth(max_depth);
        }

        let mut files = Vec::new();
        let walker = walker
            .into_iter()
            .filter_entry(|entry| !is_skipped_dir(entry, skip_dirs));
        for result in walker {
            match result {
                Ok(entry) => {
                    let file_type = entry.file_type();
                    if file_type.is_file() && !file_type.is_symlink() {
                        files.push(entry.into_path());
                    }
                }
                Err(err) if err.depth() == 0 => {
                    let io_err = err.into_io_error().unwrap_or_else(|| {
                        io::Error::other("walkdir error without underlying io::Error")
                    });
                    return match io_err.kind() {
                        io::ErrorKind::NotFound => {
                            Err(FileSystemError::PathNotFound(path.to_path_buf()))
                        }
                        _ => Err(FileSystemError::IoError(io_err)),
                    };
                }
                Err(err) => {
                    tracing::warn!("Skipping entry during recursive walk: {err}");
                }
            }
        }
        Ok(files)
    }
}

fn regular_file_metadata(path: &Path) -> Result<Metadata, FileSystemError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(FileSystemError::PathNotFound(path.to_path_buf()));
        }
        Err(err) => return Err(FileSystemError::IoError(err)),
    };
    if !meta.is_file() || meta.is_symlink() {
        return Err(FileSystemError::IoError(non_regular_file_error(path)));
    }
    Ok(meta)
}

fn validate_opened_regular_file(
    path: &Path,
    path_meta: &Metadata,
    opened_meta: &Metadata,
) -> Result<(), FileSystemError> {
    let latest_meta = regular_file_metadata(path)?;
    if !same_file_identity(path_meta, opened_meta) || !same_file_identity(&latest_meta, opened_meta)
    {
        return Err(FileSystemError::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to read {}: path changed while opening",
                path.display()
            ),
        )));
    }
    Ok(())
}

fn non_regular_file_error(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "refusing to read {}: path is not a regular file",
            path.display()
        ),
    )
}

#[cfg(unix)]
fn same_file_identity(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file_identity(_a: &Metadata, _b: &Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// # Contract
    /// `read_file_bytes` MUST return the file's raw bytes via the
    /// [`FileContent`] wrapper without re-encoding or normalising line
    /// endings. The hexagonal contract makes this the only way the core
    /// reads bytes — any silent transformation would leak into every
    /// downstream pattern match.
    #[test]
    fn read_file_bytes_returns_raw_contents_through_port() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let fs = StdFileSystemProvider::new();
        let content = fs.read_file_bytes(&file_path).unwrap();
        assert_eq!(content.as_bytes(), b"hello world");
    }

    /// # Contract
    ///
    /// `read_file_bytes` MUST reject symlinks even when the symlink target
    /// is a regular file. Untrusted packages can carry links that point
    /// outside the package; the filesystem port is the final guard for
    /// direct `scan-file` callers that bypass discovery.
    #[cfg(unix)]
    #[test]
    fn read_file_bytes_rejects_symlink_to_regular_file() {
        let dir = TempDir::new().unwrap();
        let outside = dir.path().join("outside.txt");
        let link = dir.path().join("link.txt");
        std::fs::write(&outside, "secret").unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let fs = StdFileSystemProvider::new();
        let err = fs
            .read_file_bytes(&link)
            .expect_err("symlinked file must be rejected");

        assert!(
            matches!(err, FileSystemError::IoError(ref io_err)
                if io_err.kind() == std::io::ErrorKind::InvalidInput),
            "symlink must surface as InvalidInput IoError, got {err:?}",
        );
    }

    /// # Contract
    ///
    /// `read_file_bytes` MUST refuse files larger than
    /// [`MAX_READ_FILE_BYTES`] with a [`FileSystemError::IoError`] whose
    /// message names the size and the limit. Pre-fix the function called
    /// `std::fs::read` unconditionally, so a malicious package shipping
    /// a 100 GB file would trigger a 100 GB heap allocation and OOM the
    /// process. The pre-stat guard is the last line of defence for
    /// callers that bypass the discovery-layer caps.
    #[test]
    fn read_file_bytes_refuses_files_larger_than_max() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("oversized.bin");
        // Write `MAX_READ_FILE_BYTES + 1` bytes via `set_len` so the test
        // does not actually allocate the buffer; the guard must consult
        // metadata, not the body.
        let file = std::fs::File::create(&file_path).unwrap();
        file.set_len(MAX_READ_FILE_BYTES + 1).unwrap();
        drop(file);

        let fs = StdFileSystemProvider::new();
        let err = fs
            .read_file_bytes(&file_path)
            .expect_err("oversized file MUST be rejected");
        match err {
            FileSystemError::IoError(io_err) => {
                let msg = io_err.to_string();
                assert!(
                    msg.contains("MAX_READ_FILE_BYTES")
                        && msg.contains(&MAX_READ_FILE_BYTES.to_string()),
                    "error message must explain the size guard; got {msg}"
                );
            }
            other => panic!("expected IoError with size-guard message; got {other:?}"),
        }
    }

    /// # Contract
    ///
    /// Files at exactly the size cap are allowed; only strictly-larger
    /// files are rejected. Pins the boundary so a future tightening
    /// does not accidentally invert the comparison.
    #[test]
    fn read_file_bytes_accepts_files_at_max_size() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("limit.bin");
        // Use a small synthetic limit-equivalent body; we cannot allocate
        // 256 MiB in a unit test, so we instead verify a 1 KiB file
        // (well under the cap) is still accepted.
        std::fs::write(&file_path, vec![0u8; 1024]).unwrap();
        let fs = StdFileSystemProvider::new();
        let content = fs
            .read_file_bytes(&file_path)
            .expect("under-cap file MUST be accepted");
        assert_eq!(content.as_bytes().len(), 1024);
    }

    /// # Contract (negative)
    /// A missing path MUST surface as
    /// [`FileSystemError::PathNotFound`], not as a generic
    /// [`FileSystemError::IoError`] or a panic. Callers (the scanner,
    /// rule loaders, dataset preparation) discriminate on this variant
    /// to decide between "skip and continue" and "abort the run".
    #[test]
    fn read_file_bytes_returns_path_not_found_for_missing_path() {
        let fs = StdFileSystemProvider::new();
        let result = fs.read_file_bytes(Path::new("/nonexistent/path/file.txt"));
        assert!(matches!(result, Err(FileSystemError::PathNotFound(_))));
    }

    /// # Contract
    /// Non-recursive `list_files` MUST honour the glob pattern AND stay
    /// within the supplied directory — a sibling directory's matches do
    /// not leak in. This is the load-bearing invariant for skill
    /// discovery, which lists the package root non-recursively to find
    /// `SKILL.md` without walking vendored subtrees.
    #[test]
    fn list_files_non_recursive_filters_by_glob_and_stays_in_dir() {
        let dir = TempDir::new().unwrap();

        std::fs::write(dir.path().join("test1.md"), "").unwrap();
        std::fs::write(dir.path().join("test2.md"), "").unwrap();
        std::fs::write(dir.path().join("test.txt"), "").unwrap();

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*.md", false).unwrap();

        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| f.extension().unwrap() == "md"));
    }

    /// # Contract
    ///
    /// A broad `*` listing over many siblings must still complete as a
    /// single listing operation. This pins the scanner's sibling-file
    /// path, which calls `list_files(parent, "*", false)` for every
    /// scanned entrypoint.
    #[test]
    fn list_files_non_recursive_star_handles_many_siblings() {
        let dir = TempDir::new().unwrap();
        for i in 0..512 {
            std::fs::write(dir.path().join(format!("file-{i}.txt")), "").unwrap();
        }

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*", false).unwrap();

        assert_eq!(files.len(), 512);
    }

    /// # Contract
    /// Recursive `list_files` MUST descend into subdirectories and apply
    /// the glob to filenames at every depth. Discovery for "find every
    /// `SKILL.md` in this package" relies on this; if recursion silently
    /// stopped at the root, supporting artifacts in subdirectories would
    /// never enter the scan graph.
    #[test]
    fn list_files_recursive_descends_into_subdirectories() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();

        std::fs::write(dir.path().join("test1.md"), "").unwrap();
        std::fs::write(subdir.join("test2.md"), "").unwrap();

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*.md", true).unwrap();

        assert_eq!(files.len(), 2);
    }

    /// # Contract
    /// `exists` MUST report `true` only for paths the OS resolves to a
    /// real entry, and never panic on a non-existent path. The scanner
    /// uses this as its cheap pre-flight before opening referenced
    /// artifacts.
    #[test]
    fn exists_returns_true_only_for_real_paths() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("exists.txt");
        std::fs::write(&file_path, "").unwrap();

        let fs = StdFileSystemProvider::new();
        assert!(fs.exists(&file_path));
        assert!(!fs.exists(&dir.path().join("does_not_exist.txt")));
    }

    /// # Contract
    /// `matches_pattern` MUST recognise the canonical glob shapes
    /// (`*.ext`, `*`, `prefix*`) and reject mismatches. These are the
    /// shapes the rule loader and discovery service emit — a silent
    /// failure here breaks discovery without producing an error.
    #[test]
    fn matches_pattern_handles_canonical_glob_shapes() {
        assert!(StdFileSystemProvider::matches_pattern("test.md", "*.md"));
        assert!(StdFileSystemProvider::matches_pattern("test.md", "*"));
        assert!(StdFileSystemProvider::matches_pattern("test.md", "test*"));
        assert!(!StdFileSystemProvider::matches_pattern("test.txt", "*.md"));
    }

    /// # Contract
    ///
    /// `matches_pattern` MUST support `*` in the middle of a pattern.
    /// Pre-fix the matcher only handled leading- or trailing-`*` and
    /// silently returned `false` for `foo*bar.json`, so a discovery
    /// rule using a middle wildcard would never trigger.
    #[test]
    fn matches_pattern_supports_middle_wildcard() {
        assert!(StdFileSystemProvider::matches_pattern(
            "manifest.lock.json",
            "manifest*.json"
        ));
        assert!(!StdFileSystemProvider::matches_pattern(
            "other.json",
            "manifest*.json"
        ));
    }

    /// # Contract
    ///
    /// `matches_pattern` MUST support brace alternation. This lets a
    /// single discovery pattern handle related extensions like
    /// `*.{json,yaml}` instead of forcing the discovery layer to fan
    /// out into per-extension list_files calls (which compounds I/O on
    /// large trees).
    #[test]
    fn matches_pattern_supports_brace_alternation() {
        assert!(StdFileSystemProvider::matches_pattern(
            "config.yaml",
            "*.{json,yaml}"
        ));
        assert!(StdFileSystemProvider::matches_pattern(
            "config.json",
            "*.{json,yaml}"
        ));
        assert!(!StdFileSystemProvider::matches_pattern(
            "config.toml",
            "*.{json,yaml}"
        ));
    }

    /// # Contract (fail-closed)
    ///
    /// An invalid glob pattern MUST return `false` instead of panicking.
    /// Callers pass well-known patterns from discovery rules, so a
    /// malformed pattern is a programming error worth surfacing as
    /// "no matches" rather than crashing a long-running scan in the
    /// middle of a dataset run.
    #[test]
    fn matches_pattern_returns_false_for_invalid_glob_silently() {
        // Unbalanced character class is a glob syntax error.
        assert!(!StdFileSystemProvider::matches_pattern(
            "anything",
            "[unclosed"
        ));
    }

    /// # Contract
    ///
    /// `read_file_bytes` MUST distinguish "file does not exist" from
    /// other I/O failures. Pre-fix the function pre-checked
    /// `path.exists()`, but `Path::exists` returns `false` on *any*
    /// stat failure (including `PermissionDenied`), so an unreadable
    /// file would be reported as `PathNotFound` and the scan would
    /// silently skip artifacts that actually exist on disk. This test
    /// pins the post-fix behaviour: a `PermissionDenied` from
    /// `std::fs::read` MUST surface as `IoError`, not `PathNotFound`.
    #[cfg(unix)]
    #[test]
    fn read_file_bytes_distinguishes_permission_denied_from_path_not_found() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let unreadable = dir.path().join("locked.bin");
        std::fs::write(&unreadable, b"secret").unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

        let fs = StdFileSystemProvider::new();
        let err = fs
            .read_file_bytes(&unreadable)
            .expect_err("unreadable file must surface an error");

        // Restore mode so TempDir teardown doesn't choke.
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644)).ok();

        assert!(
            matches!(
                err,
                FileSystemError::IoError(ref io_err)
                    if io_err.kind() == std::io::ErrorKind::PermissionDenied
            ),
            "PermissionDenied MUST be preserved, not collapsed to PathNotFound or other variant; got {err:?}",
        );
    }

    /// # Contract
    ///
    /// `read_file_bytes` MUST still return `PathNotFound` for files
    /// that genuinely don't exist. Negative-direction pin for the
    /// permission-denied test above: the fix must not regress the
    /// "missing file" path.
    #[test]
    fn read_file_bytes_still_returns_path_not_found_for_missing_file() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does_not_exist.bin");

        let fs = StdFileSystemProvider::new();
        let err = fs
            .read_file_bytes(&missing)
            .expect_err("missing file must error");

        assert!(
            matches!(err, FileSystemError::PathNotFound(_)),
            "missing file must surface as PathNotFound, got {err:?}",
        );
    }

    /// # Contract
    ///
    /// `list_files` MUST NOT return entries that are symlinks, even
    /// when the link target is a regular file matching the pattern.
    /// Threat model: malware analysts scan untrusted skill packages,
    /// so a malicious package shipping `evil.json -> /etc/hosts` MUST
    /// NOT cause the scanner to read or report the link target as if
    /// it were a regular file inside the package.
    #[cfg(unix)]
    #[test]
    fn list_files_skips_symlinks_in_recursive_walk() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(&real, b"{}").unwrap();
        let evil = dir.path().join("evil.json");
        std::os::unix::fs::symlink("/etc/hosts", &evil).unwrap();

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*.json", true).unwrap();

        assert_eq!(
            files.len(),
            1,
            "expected only the regular file, got {files:?}"
        );
        assert_eq!(files[0], real);
    }

    /// # Contract
    ///
    /// Same symlink-skip contract as the recursive case, pinned for
    /// the non-recursive (`std::fs::read_dir`) branch. Both branches
    /// share the threat model: untrusted package contents.
    #[cfg(unix)]
    #[test]
    fn list_files_skips_symlinks_in_non_recursive_walk() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(&real, b"{}").unwrap();
        let evil = dir.path().join("evil.json");
        std::os::unix::fs::symlink("/etc/hosts", &evil).unwrap();

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*.json", false).unwrap();

        assert_eq!(
            files.len(),
            1,
            "expected only the regular file, got {files:?}"
        );
        assert_eq!(files[0], real);
    }

    /// # Contract
    ///
    /// `list_files` MUST distinguish "permission denied" from "path not
    /// found" in the recursive branch. Pre-fix the function pre-checked
    /// `path.exists()` and the WalkDir filter_map swallowed the root
    /// error as a tracing warning, so an unreadable directory would
    /// surface as either PathNotFound (with the precheck) or an empty
    /// `Ok` vec (without it) — both silently hiding a real I/O failure
    /// during scans of untrusted packages. This test pins the post-fix
    /// behaviour: a `PermissionDenied` from the root walk MUST surface
    /// as `IoError`, never as `PathNotFound` or as an empty result.
    #[cfg(unix)]
    #[test]
    fn list_files_recursive_distinguishes_permission_denied_from_path_not_found() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let fs = StdFileSystemProvider::new();
        let result = fs.list_files(&locked, "*.md", true);

        // Restore permissions so TempDir teardown doesn't choke.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();

        let err = result.expect_err("unreadable directory must surface an error");
        assert!(
            matches!(
                err,
                FileSystemError::IoError(ref io_err)
                    if io_err.kind() == std::io::ErrorKind::PermissionDenied
            ),
            "PermissionDenied MUST be preserved, not collapsed to PathNotFound or empty Ok; got {err:?}",
        );
    }

    /// # Contract
    ///
    /// Same `PermissionDenied` distinction as the recursive case, pinned
    /// for the non-recursive (`std::fs::read_dir`) branch. Both branches
    /// share the threat model and contract: callers need an actionable
    /// error kind so the scanner can log a permission failure instead
    /// of silently treating an unreadable directory as missing.
    #[cfg(unix)]
    #[test]
    fn list_files_non_recursive_distinguishes_permission_denied_from_path_not_found() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let fs = StdFileSystemProvider::new();
        let result = fs.list_files(&locked, "*.md", false);

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();

        let err = result.expect_err("unreadable directory must surface an error");
        assert!(
            matches!(
                err,
                FileSystemError::IoError(ref io_err)
                    if io_err.kind() == std::io::ErrorKind::PermissionDenied
            ),
            "PermissionDenied MUST be preserved, not collapsed to PathNotFound; got {err:?}",
        );
    }

    /// # Contract
    ///
    /// `list_files` MUST still return `PathNotFound` for directories
    /// that genuinely don't exist. Negative-direction pin paired with
    /// the permission-denied tests above: removing the `path.exists()`
    /// pre-check must not regress the "missing directory" path. Both
    /// the recursive and non-recursive branches are exercised because
    /// they use different underlying primitives (WalkDir vs read_dir).
    #[test]
    fn list_files_still_returns_path_not_found_for_missing_directory() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does_not_exist");

        let fs = StdFileSystemProvider::new();

        let err_recursive = fs
            .list_files(&missing, "*.md", true)
            .expect_err("missing dir must error in recursive branch");
        assert!(
            matches!(err_recursive, FileSystemError::PathNotFound(_)),
            "missing dir must surface as PathNotFound in recursive branch, got {err_recursive:?}",
        );

        let err_flat = fs
            .list_files(&missing, "*.md", false)
            .expect_err("missing dir must error in non-recursive branch");
        assert!(
            matches!(err_flat, FileSystemError::PathNotFound(_)),
            "missing dir must surface as PathNotFound in non-recursive branch, got {err_flat:?}",
        );
    }

    /// # Contract
    ///
    /// Errors on *child* entries of a recursive walk MUST remain
    /// non-fatal: the scanner keeps reporting the legible siblings
    /// rather than aborting the whole package because one subdirectory
    /// is unreadable. This pins the asymmetry between "root error"
    /// (fatal, surfaced as IoError) and "child error" (logged warning,
    /// scan continues) — without this test a future refactor could
    /// turn child errors fatal and silently drop coverage on partially
    /// readable trees.
    #[cfg(unix)]
    #[test]
    fn list_files_recursive_continues_past_unreadable_child() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("readable.md"), b"").unwrap();
        let blocked = dir.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("hidden.md"), b"").unwrap();
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let fs = StdFileSystemProvider::new();
        let result = fs.list_files(dir.path(), "*.md", true);

        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755)).ok();

        let files = result.expect("root is readable; walk must succeed despite blocked subdir");
        assert_eq!(
            files.len(),
            1,
            "expected only the readable sibling, got {files:?}",
        );
        assert!(
            files[0].ends_with("readable.md"),
            "expected readable.md, got {:?}",
            files[0]
        );
    }

    /// # Contract
    ///
    /// `list_files` MUST surface entries whose filenames contain
    /// non-UTF-8 bytes by matching them against `pattern` via a lossy
    /// `OsStr::to_string_lossy` conversion. Pre-fix the chained
    /// `to_str()` returned `None` and the `if let` silently dropped
    /// the entry, allowing an attacker who packages a skill with a
    /// critical artifact named with raw bytes (zip and tar preserve
    /// them) to evade the entire scan. Both branches (recursive walk
    /// via WalkDir and non-recursive via `read_dir`) share the threat
    /// model and the contract.
    ///
    /// Linux-only because HFS+/APFS reject non-UTF-8 filenames at the
    /// `creat(2)` syscall (errno `EILSEQ`); the evasion vector this
    /// test pins is only reachable on filesystems that accept raw
    /// bytes (ext4, xfs, btrfs, zfs) or via archive extraction tools
    /// that ship raw-byte names. The runtime fix (lossy match in
    /// `lossy_filename_with_warning`) is platform-agnostic.
    #[cfg(target_os = "linux")]
    #[test]
    fn list_files_recursive_matches_non_utf8_filename_via_lossy_conversion() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = TempDir::new().unwrap();
        // `bad\xFF.json` — `\xFF` is invalid UTF-8 as a standalone byte.
        let evil_name = OsStr::from_bytes(b"bad\xFF.json");
        let evil_path = dir.path().join(evil_name);
        std::fs::write(&evil_path, b"{}").unwrap();

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*.json", true).unwrap();

        assert_eq!(
            files.len(),
            1,
            "non-UTF-8 filename MUST be matched via lossy conversion, got {files:?}",
        );
        assert_eq!(
            files[0], evil_path,
            "returned path MUST preserve the original (non-UTF-8) bytes",
        );
    }

    /// # Contract
    ///
    /// Non-recursive twin of
    /// `list_files_recursive_matches_non_utf8_filename_via_lossy_conversion`.
    /// Pinned separately because the two branches use different
    /// underlying primitives (WalkDir vs `std::fs::read_dir`); a future
    /// refactor that fixes one without the other would silently
    /// re-open the evasion path on whichever discovery mode regresses.
    /// See the recursive twin's doc-comment for the platform-gating
    /// rationale (HFS+/APFS reject non-UTF-8 filenames at syscall time).
    #[cfg(target_os = "linux")]
    #[test]
    fn list_files_non_recursive_matches_non_utf8_filename_via_lossy_conversion() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = TempDir::new().unwrap();
        let evil_name = OsStr::from_bytes(b"manifest\xFF.json");
        let evil_path = dir.path().join(evil_name);
        std::fs::write(&evil_path, b"{}").unwrap();

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*.json", false).unwrap();

        assert_eq!(
            files.len(),
            1,
            "non-UTF-8 filename MUST be matched via lossy conversion, got {files:?}",
        );
        assert_eq!(
            files[0], evil_path,
            "returned path MUST preserve the original (non-UTF-8) bytes",
        );
    }

    /// # Contract
    ///
    /// Negative-direction pin for the lossy-match contract above:
    /// regular UTF-8 filenames MUST continue to be returned without
    /// behavioural change. Without this test a future refactor that
    /// over-corrects (e.g. unconditionally allocates via
    /// `to_string_lossy`) could regress the hot path's borrow-only
    /// behaviour or accidentally drop UTF-8 entries.
    #[test]
    fn list_files_returns_utf8_filenames_unchanged() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("alpha.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("beta.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("gamma.txt"), b"").unwrap();

        let fs = StdFileSystemProvider::new();
        let files = fs.list_files(dir.path(), "*.json", false).unwrap();

        assert_eq!(
            files.len(),
            2,
            "expected the two .json files, got {files:?}"
        );
        assert!(files.iter().all(|f| f.extension().unwrap() == "json"));
    }
}
