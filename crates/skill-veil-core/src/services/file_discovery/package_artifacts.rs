//! Package-artifact branch of [`FileDiscoveryService`]: locates
//! supporting scripts, data files, manifests, and lockfiles co-located
//! with a skill package.
//!
//! Distinct from [`super::skill_discovery`] (which finds canonical
//! entrypoints): this branch is I/O-heavy, applies size and depth
//! quotas, and routes recursive walks through
//! [`FileSystemProvider::walk_files`] so test mocks observe the same
//! code path as production.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::ports::FileSystemProvider;

use super::classification::{
    DATA_FILE_GLOB_PATTERNS, MAX_DATA_FILE_BYTES, MAX_DISCOVERED_DATA_FILES,
    MAX_DISCOVERED_SCRIPTS, SCRIPT_DISCOVERY_SUBDIRS, SCRIPT_GLOB_PATTERNS, SKIP_DISCOVERY_DIRS,
};
use super::{FileDiscoveryService, MAX_DISCOVERY_DEPTH};

/// Filenames recognised as package manifests by
/// [`FileDiscoveryService::discover_package_manifests`]. Lifted to a module-
/// level constant (instead of nested inside the discovery method) so that
/// [`FileDiscoveryService::discover_package_data_files`] can exclude these
/// filenames from data-file results — without the exclusion, files like
/// `docker-compose.yaml` and `mcp.yaml` (which match the data-file glob
/// `*.yaml` AND the manifest name list) appear in BOTH discovery streams,
/// producing duplicate artifact entries in the artifact graph and
/// double-weighting any finding attached to them.
const MANIFEST_NAMES: &[&str] = &[
    "package.json",
    "mcp.json",
    "mcp.yaml",
    "mcp.yml",
    "requirements.txt",
    "pyproject.toml",
    "cargo.toml",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "makefile",
    "gnumakefile",
    ".npmrc",
    "pip.conf",
];

/// Filenames recognised as lockfiles. Same dedup contract as
/// [`MANIFEST_NAMES`]: lifted to module scope so data-file discovery can
/// avoid double-counting `pnpm-lock.yaml` (matches `*.yaml` glob) and
/// similar overlaps.
const LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "cargo.lock",
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
];

/// `true` when `path`'s lowercased filename matches an entry in
/// [`MANIFEST_NAMES`] or [`LOCKFILE_NAMES`]. Used to filter the data-file
/// discovery stream so a single physical file cannot appear under two
/// artifact roles at once.
fn is_manifest_or_lockfile(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    // Use lossy conversion consistent with `list_files` / `walk_files`,
    // which already apply `to_string_lossy` to handle non-UTF-8 filenames.
    // Strict `to_str()` returns `None` for non-UTF-8, silently dropping
    // manifest files with unusual names — a known evasion vector.
    let lowered = name.to_string_lossy().to_ascii_lowercase();
    MANIFEST_NAMES.contains(&lowered.as_str()) || LOCKFILE_NAMES.contains(&lowered.as_str())
}

impl<F: FileSystemProvider> FileDiscoveryService<F> {
    /// Discover executable/script files co-located with a skill package.
    ///
    /// Surfaces supporting artifacts (shell / Python / etc.) that live inside
    /// the package but are not explicitly referenced via resolvable relative
    /// paths in the skill markdown — a common pattern in malicious skills that
    /// use absolute-looking home paths like `~/.openclaw/skills/.../x.sh`.
    ///
    /// Scans only the package root itself (non-recursive) and a small set of
    /// conventional subdirectories (see [`SCRIPT_DISCOVERY_SUBDIRS`]),
    /// non-recursive. This avoids sweeping unrelated files when a caller
    /// points the scanner at a loose markdown document sitting inside a
    /// populated directory (e.g. a temp file under `/var/folders/`). Results
    /// are capped at [`MAX_DISCOVERED_SCRIPTS`].
    pub fn discover_package_scripts(&self, package_root: &Path) -> Vec<PathBuf> {
        self.discover_by_patterns(
            package_root,
            SCRIPT_GLOB_PATTERNS,
            MAX_DISCOVERED_SCRIPTS,
            None,
        )
    }

    /// Discover data-bearing files (`.json`, `.yaml`, `.txt`, …) co-located
    /// with a skill package. These are frequently abused as payload carriers:
    /// embedded credential-exfil URLs in config JSON, `.pyc` bytecode stashed
    /// as `data.txt`, base64-encoded instruction blobs in YAML workflows, etc.
    ///
    /// Uses the same directory scope as [`Self::discover_package_scripts`] and
    /// additionally skips files exceeding [`MAX_DATA_FILE_BYTES`] to avoid
    /// paying parse cost on legitimate bulk datasets.
    ///
    /// Filenames that also match a manifest or lockfile name are excluded
    /// here so they are not double-counted: `docker-compose.yaml` and
    /// `pnpm-lock.yaml` belong to [`Self::discover_package_manifests`] /
    /// [`Self::discover_lockfiles`] and would otherwise produce a second
    /// artifact entry through the `*.yaml` glob path.
    pub fn discover_package_data_files(&self, package_root: &Path) -> Vec<PathBuf> {
        self.discover_by_patterns(
            package_root,
            DATA_FILE_GLOB_PATTERNS,
            MAX_DISCOVERED_DATA_FILES,
            Some(MAX_DATA_FILE_BYTES),
        )
        .into_iter()
        .filter(|path| !is_manifest_or_lockfile(path))
        .collect()
    }

    fn discover_by_patterns(
        &self,
        package_root: &Path,
        patterns: &[&str],
        cap: usize,
        max_bytes: Option<u64>,
    ) -> Vec<PathBuf> {
        let mut results = Vec::new();
        let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
        // Each root has an associated `recursive` flag: the package root is
        // scanned non-recursively (to avoid sweeping unrelated files when the
        // caller pointed us at a loose markdown file), while the conventional
        // subdirs (`scripts/`, `bin/`, …) are scanned recursively because
        // malicious skills routinely hide payloads in nested folders like
        // `scripts/备份文件/` ("backup files") or `tools/internal/`.
        //
        // Recursive subdirectory roots route through `walk_files` with
        // `MAX_DISCOVERY_DEPTH` and `SKIP_DISCOVERY_DIRS` so that deeply
        // nested trees (e.g. `scripts/node_modules/`) are bounded and
        // excluded directories are pruned — matching the same hardening
        // applied by `discover_package_manifests` and `discover_lockfiles`.
        let mut roots: Vec<(PathBuf, bool)> =
            Vec::with_capacity(1 + SCRIPT_DISCOVERY_SUBDIRS.len());
        roots.push((package_root.to_path_buf(), false));
        for subdir in SCRIPT_DISCOVERY_SUBDIRS {
            let candidate = package_root.join(subdir);
            if self.fs_provider.exists(&candidate) {
                roots.push((candidate, true));
            }
        }
        for (root, recursive) in &roots {
            let files = if *recursive {
                match self
                    .fs_provider
                    .walk_files(root, MAX_DISCOVERY_DEPTH, SKIP_DISCOVERY_DIRS)
                {
                    Ok(f) => f,
                    Err(err) => {
                        tracing::warn!(
                            path = %root.display(),
                            error = %err,
                            "discover_by_patterns: walk_files failed"
                        );
                        continue;
                    }
                }
            } else {
                let mut combined = Vec::new();
                for pattern in patterns {
                    match self.fs_provider.list_files(root, pattern, false) {
                        Ok(f) => combined.extend(f),
                        Err(err) => {
                            tracing::warn!(
                                path = %root.display(),
                                pattern = %pattern,
                                error = %err,
                                "discover_by_patterns: list_files failed"
                            );
                        }
                    }
                }
                combined
            };
            let extensions: Vec<&str> = patterns
                .iter()
                .filter_map(|p| p.strip_prefix("*."))
                .collect();
            for file in files {
                if results.len() >= cap {
                    return results;
                }
                // For recursive walks (which return ALL files, not just those
                // matching a glob), filter by extension to respect the caller's
                // pattern list. Non-recursive roots already went through
                // `list_files` with the glob, so no extension filter needed.
                if *recursive && !extensions.is_empty() {
                    let matches_ext = file.extension().is_some_and(|ext| {
                        extensions
                            .iter()
                            .any(|e| e.eq_ignore_ascii_case(&ext.to_string_lossy()))
                    });
                    if !matches_ext {
                        continue;
                    }
                }
                if let Some(limit) = max_bytes {
                    // Fail-safe: when metadata is unavailable (permission
                    // denied, symlink loop, file deleted between listing
                    // and stat) we MUST skip the file rather than fall
                    // through to the include path. Including it would let
                    // an unreadable 50 MB blob bypass `max_bytes` and
                    // pressure the analysis pipeline. Going through the
                    // `fs_provider` port keeps test mocks consistent —
                    // calling `std::fs::metadata` directly would always
                    // miss virtual paths in unit tests.
                    match self.fs_provider.metadata(&file) {
                        Ok(meta) if meta.len > limit => continue,
                        Ok(_) => {}
                        Err(err) => {
                            tracing::debug!(
                                file = %file.display(),
                                error = %err,
                                "file_discovery: skipping file with unavailable metadata"
                            );
                            continue;
                        }
                    }
                }
                if seen.insert(file.clone()) {
                    results.push(file);
                }
            }
        }
        results
    }

    /// Discover package manifests (`package.json`, `pyproject.toml`,
    /// `Dockerfile`, …) anywhere under `path`.
    ///
    /// Routes the recursive walk through the
    /// [`FileSystemProvider::walk_files`] port so test mocks observe
    /// the same code path as production. Pre-fix this lived as a free
    /// function calling `WalkDir` directly, which broke the hexagonal
    /// contract (services MUST depend only on ports, not on concrete
    /// filesystem libraries).
    pub(crate) fn discover_package_manifests(&self, path: &Path) -> Vec<PathBuf> {
        self.discover_files_by_name(path, MANIFEST_NAMES)
    }

    /// Discover lockfiles (`package-lock.json`, `Cargo.lock`, …)
    /// anywhere under `path`. Same port-routed walk as
    /// [`Self::discover_package_manifests`].
    pub(crate) fn discover_lockfiles(&self, path: &Path) -> Vec<PathBuf> {
        self.discover_files_by_name(path, LOCKFILE_NAMES)
    }

    /// Walk `root` recursively through the
    /// [`FileSystemProvider::walk_files`] port, returning entries
    /// whose lowercased filename matches one of `names`.
    ///
    /// `MAX_DISCOVERY_DEPTH` and `SKIP_DISCOVERY_DIRS` are forwarded
    /// to the port so the std adapter can prune vendored / generated
    /// trees and bound descent on adversarial inputs. A failure on
    /// the root path is logged and treated as "no matches" rather
    /// than propagated, mirroring the pre-fix tracing-warning
    /// behaviour of the WalkDir-based implementation.
    fn discover_files_by_name(&self, root: &Path, names: &[&str]) -> Vec<PathBuf> {
        let files =
            match self
                .fs_provider
                .walk_files(root, MAX_DISCOVERY_DEPTH, SKIP_DISCOVERY_DIRS)
            {
                Ok(files) => files,
                Err(err) => {
                    tracing::warn!("Skipping discovery walk in {}: {err}", root.display(),);
                    return Vec::new();
                }
            };

        files
            .into_iter()
            .filter_map(|path| {
                // Use lossy conversion consistent with `list_files` / `walk_files`
                // so non-UTF-8 filenames are still discovered rather than silently
                // dropped (a known evasion vector for malicious packages).
                let file_name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
                names.contains(&file_name.as_str()).then_some(path)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory `FileSystemProvider` that lists exactly one path but always
    /// fails on `metadata`. Used to verify the fail-safe behaviour: when
    /// metadata cannot be obtained the file MUST be skipped, not included.
    /// Without the fix, the `if let Ok(meta) = ...` arm fell through and
    /// the file silently bypassed the size guard.
    struct MetadataFailingFs {
        listed: Vec<PathBuf>,
    }

    impl FileSystemProvider for MetadataFailingFs {
        fn read_file_bytes(
            &self,
            _path: &Path,
        ) -> Result<crate::ports::FileContent, crate::ports::FileSystemError> {
            Err(crate::ports::FileSystemError::PathNotFound(PathBuf::new()))
        }
        fn list_files(
            &self,
            _path: &Path,
            _pattern: &str,
            _recursive: bool,
        ) -> Result<Vec<PathBuf>, crate::ports::FileSystemError> {
            Ok(self.listed.clone())
        }
        fn exists(&self, _path: &Path) -> bool {
            true
        }
        fn metadata(
            &self,
            _path: &Path,
        ) -> Result<crate::ports::FileMeta, crate::ports::FileSystemError> {
            Err(crate::ports::FileSystemError::PathNotFound(PathBuf::new()))
        }
    }

    #[test]
    fn discover_skips_file_when_metadata_unavailable() {
        let listed = PathBuf::from("/virtual/big.yaml");
        let fs = MetadataFailingFs {
            listed: vec![listed.clone()],
        };
        let service = FileDiscoveryService::with_fs_provider(false, fs);
        let results = service.discover_package_data_files(Path::new("/virtual"));
        assert!(
            !results.contains(&listed),
            "file with unavailable metadata MUST be skipped, not included; got {results:?}"
        );
    }

    /// Architectural contract: `discover_by_patterns` MUST go through the
    /// `FileSystemProvider` port for metadata. Calling `std::fs::metadata`
    /// directly breaks the hexagonal contract — test mocks would always
    /// see `Err` and (combined with the previous fall-through bug) every
    /// virtual file would bypass the size guard.
    #[test]
    fn file_discovery_does_not_call_std_fs_metadata_directly() {
        let body = include_str!("package_artifacts.rs");
        // Scan production code only — stop at the test module.
        let production = body.split("#[cfg(test)]").next().unwrap_or(body);
        assert!(
            production.contains("self.fs_provider.metadata("),
            "file_discovery must route metadata through the fs_provider port"
        );
        for (idx, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains("std::fs::metadata("),
                "production line {} still calls std::fs::metadata directly: {line}",
                idx + 1
            );
        }
    }

    /// Architectural contract: `discover_files_by_name` and its public
    /// wrappers (`discover_package_manifests`, `discover_lockfiles`)
    /// MUST route the recursive walk through the
    /// `FileSystemProvider::walk_files` port instead of calling
    /// `WalkDir` (or `std::fs`) directly. The pre-fix free-function
    /// version named `WalkDir` and `entry.file_type().is_file()`
    /// inline, breaking the hexagonal contract: test mocks could not
    /// observe or override discovery I/O. This test pins the post-fix
    /// behaviour by checking the production module's source.
    #[test]
    fn file_discovery_does_not_use_walkdir_or_filetype_directly() {
        let body = include_str!("package_artifacts.rs");
        let production = body.split("#[cfg(test)]").next().unwrap_or(body);
        // Tolerate rustfmt's multi-line method chains: the pattern can
        // be written either as `self.fs_provider.walk_files(...)` on a
        // single line OR with the receiver on its own line followed by
        // `.walk_files(...)`. We only care that the port method is
        // invoked from the production module, not where the linebreak
        // happens to fall.
        let collapsed: String = production.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            collapsed.contains("self.fs_provider .walk_files(")
                || collapsed.contains("self.fs_provider.walk_files(")
                || collapsed.contains("self . fs_provider . walk_files (")
                || collapsed.contains(".fs_provider .walk_files(")
                || collapsed.contains(".fs_provider.walk_files("),
            "discover_files_by_name must route the recursive walk through the fs_provider port",
        );
        for (idx, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains("WalkDir::new("),
                "production line {} still calls WalkDir::new directly: {line}",
                idx + 1
            );
            assert!(
                !trimmed.contains(".file_type().is_file()"),
                "production line {} still inspects file_type via the WalkDir entry: {line}",
                idx + 1
            );
        }
    }

    /// Behavioral contract: `discover_package_manifests` consults the
    /// `FileSystemProvider::walk_files` port. Records every
    /// `walk_files` call against an in-memory adapter and asserts at
    /// least one call lands with `MAX_DISCOVERY_DEPTH` and the
    /// `SKIP_DISCOVERY_DIRS` exclude list — proving both that the
    /// service routes through the port AND that it forwards the
    /// hardening knobs the std adapter relies on.
    #[test]
    fn discover_package_manifests_invokes_walk_files_with_hardening_knobs() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        struct WalkRecordingFs {
            walk_calls: Arc<AtomicUsize>,
            recorded_max_depth: Arc<Mutex<Vec<usize>>>,
            recorded_skip_dirs: Arc<Mutex<Vec<Vec<String>>>>,
        }

        impl FileSystemProvider for WalkRecordingFs {
            fn read_file_bytes(
                &self,
                _path: &Path,
            ) -> Result<crate::ports::FileContent, crate::ports::FileSystemError> {
                Err(crate::ports::FileSystemError::PathNotFound(PathBuf::new()))
            }
            fn list_files(
                &self,
                _path: &Path,
                _pattern: &str,
                _recursive: bool,
            ) -> Result<Vec<PathBuf>, crate::ports::FileSystemError> {
                Ok(Vec::new())
            }
            fn exists(&self, _path: &Path) -> bool {
                true
            }
            fn walk_files(
                &self,
                _path: &Path,
                max_depth: usize,
                skip_dirs: &[&str],
            ) -> Result<Vec<PathBuf>, crate::ports::FileSystemError> {
                self.walk_calls.fetch_add(1, Ordering::SeqCst);
                self.recorded_max_depth
                    .lock()
                    .expect("WalkRecordingFs mutex poisoned")
                    .push(max_depth);
                self.recorded_skip_dirs
                    .lock()
                    .expect("WalkRecordingFs mutex poisoned")
                    .push(skip_dirs.iter().map(|s| (*s).to_string()).collect());
                Ok(Vec::new())
            }
        }

        let fs = WalkRecordingFs {
            walk_calls: Arc::new(AtomicUsize::new(0)),
            recorded_max_depth: Arc::new(Mutex::new(Vec::new())),
            recorded_skip_dirs: Arc::new(Mutex::new(Vec::new())),
        };
        let calls = Arc::clone(&fs.walk_calls);
        let max_depths = Arc::clone(&fs.recorded_max_depth);
        let skip_dirs_log = Arc::clone(&fs.recorded_skip_dirs);

        let service = FileDiscoveryService::with_fs_provider(false, fs);
        let _ = service.discover_package_manifests(Path::new("/virtual/pkg"));
        let _ = service.discover_lockfiles(Path::new("/virtual/pkg"));

        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "manifest + lockfile discovery must invoke walk_files at least twice",
        );

        let depths = max_depths.lock().expect("poisoned");
        assert!(
            depths.iter().all(|d| *d == MAX_DISCOVERY_DEPTH),
            "every walk_files call must forward MAX_DISCOVERY_DEPTH ({MAX_DISCOVERY_DEPTH}); got {depths:?}",
        );
        let skips = skip_dirs_log.lock().expect("poisoned");
        let expected_skip: Vec<String> = SKIP_DISCOVERY_DIRS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(
            skips.iter().all(|recorded| recorded == &expected_skip),
            "every walk_files call must forward SKIP_DISCOVERY_DIRS verbatim; got {skips:?}",
        );
    }

    /// In-memory `FileSystemProvider` that returns a curated file list for
    /// the data-file glob expansion. Used to verify cross-discovery dedup:
    /// `docker-compose.yaml` matches the `*.yaml` glob AND the manifest
    /// name list, and pre-fix appeared in BOTH discovery streams.
    struct FixedListFs {
        per_pattern: Vec<(String, Vec<PathBuf>)>,
    }

    impl FileSystemProvider for FixedListFs {
        fn read_file_bytes(
            &self,
            _path: &Path,
        ) -> Result<crate::ports::FileContent, crate::ports::FileSystemError> {
            Err(crate::ports::FileSystemError::PathNotFound(PathBuf::new()))
        }
        fn list_files(
            &self,
            _path: &Path,
            pattern: &str,
            _recursive: bool,
        ) -> Result<Vec<PathBuf>, crate::ports::FileSystemError> {
            for (registered, files) in &self.per_pattern {
                if registered == pattern {
                    return Ok(files.clone());
                }
            }
            Ok(Vec::new())
        }
        fn exists(&self, _path: &Path) -> bool {
            true
        }
        fn metadata(
            &self,
            _path: &Path,
        ) -> Result<crate::ports::FileMeta, crate::ports::FileSystemError> {
            // Stay well under MAX_DATA_FILE_BYTES so the discovery does
            // not skip the file as oversized.
            Ok(crate::ports::FileMeta { len: 1024 })
        }
    }

    /// # Contract
    ///
    /// `discover_package_data_files` MUST NOT return filenames that are
    /// owned by the manifest or lockfile discovery streams. Pre-fix
    /// `docker-compose.yaml` appeared in BOTH `discover_package_manifests`
    /// (by name match) AND `discover_package_data_files` (by `*.yaml`
    /// glob), producing duplicate artifact-graph entries for a single
    /// physical file. Cross-discovery dedup requires excluding the
    /// manifest/lockfile names from data-file results.
    #[test]
    fn data_file_discovery_excludes_manifest_and_lockfile_names() {
        let pkg_root = PathBuf::from("/virtual/pkg");
        let yaml_files = vec![
            pkg_root.join("docker-compose.yaml"),
            pkg_root.join("pnpm-lock.yaml"),
            pkg_root.join("mcp.yaml"),
            pkg_root.join("benign-data.yaml"),
        ];
        let json_files = vec![
            pkg_root.join("package.json"),
            pkg_root.join("package-lock.json"),
            pkg_root.join("data.json"),
        ];
        let fs = FixedListFs {
            per_pattern: vec![
                ("*.yaml".to_string(), yaml_files.clone()),
                ("*.json".to_string(), json_files.clone()),
            ],
        };
        let service = FileDiscoveryService::with_fs_provider(false, fs);
        let results = service.discover_package_data_files(&pkg_root);

        for excluded in [
            "docker-compose.yaml",
            "pnpm-lock.yaml",
            "mcp.yaml",
            "package.json",
            "package-lock.json",
        ] {
            assert!(
                !results.iter().any(|p| p.file_name().and_then(|n| n.to_str()) == Some(excluded)),
                "data-file discovery must NOT return manifest/lockfile name {excluded}; got {results:?}"
            );
        }
        assert!(
            results
                .iter()
                .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("benign-data.yaml")),
            "data-file discovery must STILL return non-manifest YAML files; got {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("data.json")),
            "data-file discovery must STILL return non-manifest JSON files; got {results:?}"
        );
    }
}
