//! Filesystem helpers that harden defaults so cache/state directories
//! and config files holding API keys aren't world-readable on shared
//! (multi-user) hosts.
//!
//! Both the LLM enrichment cache and the VT report cache hold material
//! that should not leak to other local users: extracted IOCs, absolute
//! paths into the user's repos, full LLM analyses, and downloaded VT
//! reports that may contain hashes of sensitive private samples. The
//! plain `std::fs::create_dir_all` honours the process umask (typically
//! `022`, yielding `0o755` directories) which is too permissive on
//! shared workstations.
//!
//! `create_dir_secure` creates the directory tree with `0o700` on Unix
//! (owner read/write/execute only) and falls back to platform default
//! semantics on non-Unix targets where POSIX modes don't apply.
//!
//! `warn_if_file_world_readable` and `warn_if_dir_world_readable` are
//! shared helpers used by config loaders and cache initialisers — both
//! emit `tracing::warn!` when permissions allow group/other access, but
//! never mutate existing modes (silent permission changes would fight
//! with intentional setups like shared CI caches).

use std::io;
use std::path::Path;

/// Recursively create `path` with permissions restricted to the owning
/// user (`0o700`) on Unix. On non-Unix platforms this collapses to a
/// plain `create_dir_all` since POSIX modes are not applicable.
///
/// `DirBuilder::recursive(true).create(path)` is itself idempotent:
/// pre-existing directories return `Ok(())` without error and without
/// mutating their mode. We exploit that to avoid a `path.exists()`
/// check-then-use pattern (which opens a tiny TOCTOU window between the
/// check and the directory creation). Pre-existing directories are
/// inspected for over-broad permissions and surface a `tracing::warn!`
/// so the user can re-key or chmod the cache.
pub(crate) fn create_dir_secure(path: &Path) -> io::Result<()> {
    reject_symlink_components(path)?;
    create_dir_secure_inner(path)?;
    reject_symlink_components(path)?;
    warn_if_dir_world_readable(path);
    Ok(())
}

/// `true` when `path` is a directory and not a symlink. Uses
/// `symlink_metadata` so a symlink pointing at a directory is rejected —
/// callers rely on this to refuse following an attacker-planted symlink to
/// a directory outside the intended tree. Any stat error (missing path,
/// permission denied) maps to `false`.
pub(crate) fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| is_real_dir_meta(&meta))
        .unwrap_or(false)
}

/// `true` when already-fetched `meta` describes a directory that is not a
/// symlink. The symlink rejection is load-bearing — callers that have
/// already stat'd a path (to propagate a contextual error or reuse the
/// metadata) refuse to follow an attacker-planted symlink into a tree
/// outside the intended one.
pub(crate) fn is_real_dir_meta(meta: &std::fs::Metadata) -> bool {
    meta.is_dir() && !meta.file_type().is_symlink()
}

/// Error unless `path` is a real directory (see [`is_real_dir`]). Download
/// and corpus writers call this to refuse a symlinked or non-directory
/// destination before streaming bytes into it.
pub(crate) fn ensure_real_dir(path: &Path) -> anyhow::Result<()> {
    if is_real_dir(path) {
        Ok(())
    } else {
        anyhow::bail!("{} is not a real directory", path.display())
    }
}

fn reject_symlink_components(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() && !is_platform_root_alias(ancestor) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{} contains symlink component {}",
                        path.display(),
                        ancestor.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn is_platform_root_alias(path: &Path) -> bool {
    path.parent()
        .is_some_and(|parent| parent.has_root() && parent.parent().is_none())
}

#[cfg(unix)]
fn create_dir_secure_inner(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn create_dir_secure_inner(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

/// Warn (via `tracing::warn!`) if the directory at `path` is
/// group-/other-accessible. Used for cache and state directories whose
/// owner-only contract is `0o700`.
pub(crate) fn warn_if_dir_world_readable(path: &Path) {
    warn_if_world_readable_inner(path, "cache directory", 0o700);
}

/// Warn (via `tracing::warn!`) if the file at `path` is
/// group-/other-readable. Used for config files holding API keys
/// (`~/.skill-veil.toml`, `~/.vt.toml`) whose owner-only contract is
/// `0o600`.
///
/// # Limitations
///
/// The function relies on `std::fs::metadata`. If `metadata` fails
/// (`EACCES` on `chmod 0o000`, `ELOOP` on a symlink loop, missing path,
/// non-Unix platform), the function silently returns without warning —
/// there is no underlying mode to inspect and no way to surface a
/// permission diagnostic from this layer. Callers that need a warning
/// even on unreadable files should additionally check the result of
/// `read_to_string` and log the error themselves (`config.rs`'s
/// `read_file_if_exists` is the canonical example).
pub(crate) fn warn_if_file_world_readable(path: &Path) {
    warn_if_world_readable_inner(path, "config file", 0o600);
}

#[cfg(unix)]
fn warn_if_world_readable_inner(path: &Path, kind: &str, recommended_mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        tracing::warn!(
            "{kind} {} has permissions {mode:o} (group/other accessible); \
             consider `chmod {recommended_mode:o} {}` to restrict to owner",
            path.display(),
            path.display(),
        );
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable_inner(_path: &Path, _kind: &str, _recommended_mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// # Contract
    ///
    /// On Unix, `create_dir_secure` MUST create the new directory with
    /// permissions equal to `0o700` regardless of the process umask.
    /// Pre-fix the LLM and VT cache dirs were created with the default
    /// umask (typically `0o755`) which exposes their contents — extracted
    /// IOCs, absolute repo paths, full LLM analyses, VT reports — to
    /// every local user on a shared host.
    #[cfg(unix)]
    #[test]
    fn create_dir_secure_sets_owner_only_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let parent = TempDir::new().expect("tempdir");
        let target = parent.path().join("cache").join("nested");

        create_dir_secure(&target).expect("create_dir_secure must succeed");

        let mode = std::fs::metadata(&target)
            .expect("metadata on freshly created dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "freshly created directory must be 0o700 (got {mode:o})"
        );
    }

    /// # Contract
    ///
    /// `create_dir_secure` MUST be idempotent: calling it on a directory
    /// that already exists is not an error and does NOT silently widen
    /// or narrow the existing permissions. (We only warn if the existing
    /// directory is world-/group-readable; mutating user-owned state
    /// would surprise legitimate setups like shared CI caches.)
    #[test]
    fn create_dir_secure_is_idempotent_on_existing_dir() {
        let parent = TempDir::new().expect("tempdir");
        let target = parent.path().join("already_here");
        std::fs::create_dir_all(&target).expect("seed pre-existing dir");

        create_dir_secure(&target).expect("idempotent on existing dir");
        create_dir_secure(&target).expect("second call must also succeed");

        assert!(target.exists());
    }

    /// # Contract
    ///
    /// `create_dir_secure` MUST reject a symlink supplied as the target
    /// directory rather than treating the symlink target as trusted cache
    /// storage.
    #[cfg(unix)]
    #[test]
    fn create_dir_secure_rejects_symlinked_target_dir() {
        let parent = TempDir::new().expect("tempdir");
        let outside = parent.path().join("outside");
        let target = parent.path().join("cache");
        std::fs::create_dir(&outside).expect("seed outside dir");
        std::os::unix::fs::symlink(&outside, &target).expect("seed symlink");

        let err = create_dir_secure(&target).expect_err("symlink target must be rejected");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("symlink"));
    }

    /// # Contract
    ///
    /// `create_dir_secure` MUST reject a symlink in any existing
    /// ancestor component before creating missing cache/state
    /// directories beneath it.
    #[cfg(unix)]
    #[test]
    fn create_dir_secure_rejects_symlinked_intermediate_dir() {
        let parent = TempDir::new().expect("tempdir");
        let outside = parent.path().join("outside");
        let link = parent.path().join("cache-link");
        let target = link.join("nested").join("cache");
        std::fs::create_dir(&outside).expect("seed outside dir");
        std::os::unix::fs::symlink(&outside, &link).expect("seed symlink");

        let err = create_dir_secure(&target).expect_err("symlinked ancestor must be rejected");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("symlink"));
        assert!(
            !outside.join("nested").exists(),
            "rejected symlink ancestor must not receive created children"
        );
    }

    /// # Contract
    ///
    /// Real ancestor directories remain valid: `create_dir_secure`
    /// creates the missing descendant tree under them and preserves the
    /// existing ancestors as directories.
    #[test]
    fn create_dir_secure_accepts_real_intermediate_dirs() {
        let parent = TempDir::new().expect("tempdir");
        let real_parent = parent.path().join("real-parent");
        let target = real_parent.join("nested").join("cache");
        std::fs::create_dir(&real_parent).expect("seed real parent");

        create_dir_secure(&target).expect("real ancestors must be accepted");

        assert!(target.is_dir());
        assert!(real_parent.is_dir());
    }

    /// # Contract
    ///
    /// `create_dir_secure` MUST preserve the mode of a pre-existing
    /// directory rather than narrow it. The function only warns about
    /// over-broad permissions; it never mutates them. Pre-fix this was
    /// guaranteed by an explicit `if path.exists() { return Ok(()) }`
    /// short-circuit; post-fix the same guarantee comes from
    /// `DirBuilder::recursive(true).create()` returning `Ok` without
    /// touching mode when the target already exists. This test pins
    /// the post-fix behaviour so a future refactor that swaps to a
    /// permission-mutating call regresses here.
    #[cfg(unix)]
    #[test]
    fn create_dir_secure_does_not_narrow_existing_dir_mode() {
        use std::os::unix::fs::PermissionsExt;

        let parent = TempDir::new().expect("tempdir");
        let target = parent.path().join("preexisting");
        std::fs::create_dir_all(&target).expect("seed pre-existing dir");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("seed mode 0o755");

        create_dir_secure(&target).expect("idempotent on existing dir");

        let mode = std::fs::metadata(&target)
            .expect("metadata on existing dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o755,
            "create_dir_secure MUST NOT mutate the mode of an existing directory"
        );
    }

    /// # Contract
    ///
    /// `warn_if_file_world_readable` is a no-op (no panic, no logs) for
    /// a non-existent path. Config loaders may call it speculatively on
    /// paths that have not been created yet; a panic or log spam in that
    /// case would surprise callers.
    #[test]
    fn warn_if_file_world_readable_handles_missing_path() {
        let parent = TempDir::new().expect("tempdir");
        let missing = parent.path().join("does-not-exist.toml");

        warn_if_file_world_readable(&missing);
    }

    /// # Contract
    ///
    /// On Unix, `warn_if_file_world_readable` SHOULD execute its
    /// permission-check branch when the file mode is group-/other-
    /// readable (`mode & 0o077 != 0`). We can't assert on the tracing
    /// output without a subscriber, but the function MUST NOT panic on
    /// a real file with permissive mode — guarding against future
    /// refactors that swap `mode()` for an unwrap-prone alternative.
    #[cfg(unix)]
    #[test]
    fn warn_if_file_world_readable_runs_on_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let parent = TempDir::new().expect("tempdir");
        let file_path = parent.path().join("config.toml");
        std::fs::write(&file_path, "apikey = \"x\"").expect("seed file");
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o644))
            .expect("seed mode 0o644");

        warn_if_file_world_readable(&file_path);
    }
}
