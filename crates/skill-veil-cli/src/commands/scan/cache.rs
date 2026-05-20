use std::path::{Path, PathBuf};

/// Directory name under `dirs::cache_dir()` that holds all skill-veil
/// caches, isolating us from other tools that share the user cache root.
const CACHE_NAMESPACE: &str = "skill-veil";

/// Return a stable cache key for `scan_path`. The canonical absolute
/// path is hashed with SHA-256 so two distinct projects don't collide
/// and so the on-disk path is filesystem-safe regardless of source
/// path content. Falls back to a hash of the lossy path string when
/// `canonicalize` fails (e.g. the scan path was deleted between args
/// parse and cache lookup) — in that case the cache simply misses,
/// which is the safe failure mode.
///
/// Uses `format!("{:#?}", …)` rather than `to_string_lossy()` to avoid
/// collisions between paths that differ only in non-UTF-8 byte sequences
/// (which `to_string_lossy` replaces with the same U+FFFD replacement
/// character, collapsing distinct paths into the same key).
pub(super) fn cache_key_for(scan_path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let canonical = scan_path
        .canonicalize()
        .unwrap_or_else(|_| scan_path.to_path_buf());
    let mut h = Sha256::new();
    // Lossless encoding: Debug format preserves the full OsStr including
    // non-UTF-8 sequences that to_string_lossy would collapse.
    h.update(format!("{canonical:#?}").as_bytes());
    format!("{:x}", h.finalize())
}

/// Resolve the base directory that holds all skill-veil per-scan
/// caches. Order: explicit `--cache-dir` override → `dirs::cache_dir()`
/// → temporary directory fallback. The cache MUST NEVER live inside
/// the scanned package: an attacker-controlled skill could otherwise
/// ship a forged `.vt-enrichment/files/<sha>.json` or
/// `.llm-cache/<sha>.json` with `fetched_at: now+1d` and a benign
/// verdict to suppress real lookups for the entire cache TTL window
/// (30 days for VT, 90 days for LLM).
pub(super) fn cache_base_dir(override_dir: Option<&Path>, scan_path: &Path) -> PathBuf {
    if let Some(dir) = override_dir {
        // Validate the override does not place the cache inside the
        // scanned package (see the invariant doc-comment above).
        if let (Ok(dir_canon), Ok(scan_canon)) = (dir.canonicalize(), scan_path.canonicalize()) {
            let scan_root = scan_containment_root(&scan_canon);
            if dir_canon.starts_with(scan_root) {
                tracing::warn!(
                    "--cache-dir {} is inside scan path {}; this allows a malicious skill to \
                     forge cache entries and suppress real enrichment. Using default cache location.",
                    dir.display(),
                    scan_path.display(),
                );
                // Fall through to default
            } else {
                return dir.to_path_buf();
            }
        } else {
            // If we can't canonicalize, we cannot verify the override is
            // safe.  Reject it and fall through to the default cache
            // location — a malicious skill could place a symlink that
            // breaks canonicalize to bypass the containment check.
            tracing::warn!(
                "--cache-dir {} or scan path {} could not be canonicalized; \
                 cannot verify the override is not inside the scan path. \
                 Using default cache location.",
                dir.display(),
                scan_path.display(),
            );
        }
    }
    if let Some(user_cache) = dirs::cache_dir() {
        return user_cache.join(CACHE_NAMESPACE);
    }
    // Last-resort fallback when HOME is missing (CI sandboxes, minimal
    // containers). Tracing-logged so the operator knows the cache will
    // not survive a reboot; never silently co-locate with scan_path.
    tracing::warn!(
        "dirs::cache_dir() returned None; using temp directory for skill-veil cache. \
         Cache hits will not survive a reboot. Pass --cache-dir to override."
    );
    std::env::temp_dir().join(CACHE_NAMESPACE)
}

fn scan_containment_root(scan_canon: &Path) -> &Path {
    if scan_canon.is_file() {
        scan_canon.parent().unwrap_or(scan_canon)
    } else {
        scan_canon
    }
}

pub(super) fn cache_root_for(scan_path: &Path, override_dir: Option<&Path>) -> PathBuf {
    cache_base_dir(override_dir, scan_path)
        .join("vt-enrichment")
        .join(cache_key_for(scan_path))
}

pub(super) fn llm_cache_root_for(scan_path: &Path, override_dir: Option<&Path>) -> PathBuf {
    cache_base_dir(override_dir, scan_path)
        .join("llm")
        .join(cache_key_for(scan_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_uncanonicalizable_override_is_rejected(override_dir: &Path, scan_path: &Path) {
        let result = cache_base_dir(Some(override_dir), scan_path);

        assert!(
            !result.starts_with(override_dir),
            "uncanonicalizable cache override MUST be rejected; got {result:?}",
        );
    }

    /// # Contract
    ///
    /// `cache_root_for` and `llm_cache_root_for` MUST NEVER place the
    /// per-scan cache inside the scanned package. Pre-fix the cache
    /// roots were `<scan_path>/.vt-enrichment/` and `<scan_path>/.llm-cache/`,
    /// so a malicious skill could ship a forged JSON entry with a
    /// future `fetched_at` to suppress real VT or LLM lookups for the
    /// entire cache TTL window. Post-fix the cache root is rooted at
    /// `dirs::cache_dir()/skill-veil/<kind>/<key>` (or the
    /// `--cache-dir` override), keyed by SHA-256 of the canonical scan
    /// path.
    #[test]
    fn cache_root_for_never_lives_inside_scan_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scan_path = tmp.path().to_path_buf();

        let vt_root = cache_root_for(&scan_path, None);
        let llm_root = llm_cache_root_for(&scan_path, None);

        // Canonicalise both sides — `dirs::cache_dir()` may live under
        // `/private/var/...` on macOS while the user's tempdir resolves
        // to `/var/...`; we just need to ensure neither cache lives
        // inside the scanned package.
        let scan_canon = scan_path.canonicalize().unwrap_or(scan_path.clone());
        for (kind, root) in [("vt", &vt_root), ("llm", &llm_root)] {
            let root_canon = root
                .ancestors()
                .find_map(|p| p.canonicalize().ok())
                .unwrap_or_else(|| root.clone());
            assert!(
                !root_canon.starts_with(&scan_canon),
                "{kind} cache root MUST NOT be a descendant of scan_path; \
                 got cache_root={root_canon:?}, scan_path={scan_canon:?}",
            );
        }
    }

    /// # Contract
    ///
    /// The `--cache-dir` override takes priority over the user cache
    /// directory. CI and sandboxed runs depend on this so they can
    /// custody the cache themselves (and so tests can use a tempdir
    /// without writing into `~/Library/Caches/skill-veil/`).
    #[test]
    fn cache_root_for_uses_override_when_provided() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scan_path = tmp.path().join("scan-target");
        std::fs::create_dir_all(&scan_path).expect("seed scan dir");
        let override_dir = tmp.path().join("custom-cache");
        // Both directories must exist on disk so that canonicalize()
        // succeeds — the security check rejects overrides when it
        // cannot verify containment.
        std::fs::create_dir_all(&override_dir).expect("seed override dir");

        let vt_root = cache_root_for(&scan_path, Some(&override_dir));
        let llm_root = llm_cache_root_for(&scan_path, Some(&override_dir));

        assert!(
            vt_root.starts_with(&override_dir),
            "vt cache MUST be rooted under override; got {vt_root:?}",
        );
        assert!(
            llm_root.starts_with(&override_dir),
            "llm cache MUST be rooted under override; got {llm_root:?}",
        );
    }

    /// # Contract
    ///
    /// When the scan target is a single file, the scanned package boundary
    /// is that file's parent directory. A cache override under that parent
    /// must be rejected for the same cache-forgery reason as package-dir
    /// targets.
    #[test]
    fn cache_base_dir_rejects_override_inside_scan_file_parent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let package = tmp.path().join("package");
        std::fs::create_dir_all(&package).expect("seed package");
        let scan_file = package.join("SKILL.md");
        std::fs::write(&scan_file, "# skill").expect("seed scan file");
        let override_dir = package.join(".skill-veil-cache");
        std::fs::create_dir_all(&override_dir).expect("seed override dir");

        let result = cache_base_dir(Some(&override_dir), &scan_file);

        assert!(
            !result.starts_with(&override_dir),
            "cache override inside scan-file parent MUST be rejected; got {result:?}",
        );
    }

    /// # Contract
    ///
    /// A scan-file target may still use an explicit cache override outside
    /// the package parent. CI jobs depend on this to put caches in a
    /// workspace-owned directory without writing into the scanned package.
    #[test]
    fn cache_base_dir_accepts_override_outside_scan_file_parent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let package = tmp.path().join("package");
        std::fs::create_dir_all(&package).expect("seed package");
        let scan_file = package.join("SKILL.md");
        std::fs::write(&scan_file, "# skill").expect("seed scan file");
        let override_dir = tmp.path().join("cache");
        std::fs::create_dir_all(&override_dir).expect("seed override dir");

        let result = cache_base_dir(Some(&override_dir), &scan_file);

        assert!(
            result.starts_with(&override_dir),
            "cache override outside scan-file parent MUST be accepted; got {result:?}",
        );
    }

    /// # Contract
    ///
    /// When `--cache-dir` points to a path that cannot be canonicalized,
    /// the override MUST be rejected and the default cache location used
    /// instead. Pre-fix the code trusted the override with a warning,
    /// which allowed a malicious skill to bypass the containment check.
    #[test]
    fn cache_base_dir_rejects_missing_override_when_canonicalize_fails() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scan_path = tmp.path().join("scan-target");
        std::fs::create_dir_all(&scan_path).expect("seed scan dir");
        let missing = tmp.path().join("missing-cache-dir");
        debug_assert!(
            !missing.exists(),
            "fixture invariant: override path must not exist"
        );

        assert_uncanonicalizable_override_is_rejected(&missing, &scan_path);
    }

    /// # Contract
    ///
    /// When `--cache-dir` points to a broken symlink, the override MUST
    /// be rejected and the default cache location used instead. Pre-fix
    /// the code trusted the override with a warning, which allowed a
    /// malicious skill to bypass the containment check by placing a
    /// symlink that breaks canonicalize.
    #[cfg(unix)]
    #[test]
    fn cache_base_dir_rejects_broken_symlink_override_when_canonicalize_fails() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scan_path = tmp.path().join("scan-target");
        std::fs::create_dir_all(&scan_path).expect("seed scan dir");
        let broken = tmp.path().join("broken-cache-link");
        std::os::unix::fs::symlink("/nonexistent/path/that/does/not/exist", &broken)
            .expect("create broken symlink");

        assert_uncanonicalizable_override_is_rejected(&broken, &scan_path);
    }

    /// # Contract
    ///
    /// `cache_key_for` MUST produce the same key for two paths that
    /// resolve to the same canonical location (e.g. via a symlink).
    /// The key is the cache namespace; collapsing equivalent paths
    /// avoids redundant lookups across the same logical project.
    #[test]
    fn cache_key_for_is_canonical_path_dependent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real).expect("seed real");
        let key_real = cache_key_for(&real);

        // Same path twice: same key.
        let key_again = cache_key_for(&real);
        assert_eq!(
            key_real, key_again,
            "same canonical path MUST produce identical cache key"
        );

        // Different path: different key.
        let other = tmp.path().join("other");
        std::fs::create_dir_all(&other).expect("seed other");
        let key_other = cache_key_for(&other);
        assert_ne!(
            key_real, key_other,
            "distinct canonical paths MUST produce distinct cache keys"
        );

        // SHA-256 hex is 64 lowercase hex chars.
        assert_eq!(key_real.len(), 64, "cache key MUST be 64-hex-char SHA-256");
        assert!(
            key_real.chars().all(|c| c.is_ascii_hexdigit()),
            "cache key MUST be filesystem-safe (hex-only)"
        );
    }
}
