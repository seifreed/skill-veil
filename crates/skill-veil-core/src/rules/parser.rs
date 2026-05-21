use super::ioc::ioc_feed_to_rules;
use super::schema::{IocFeedFile, Rule, RulePackFile};
use super::{RuleError, RULE_PACK_SCHEMA_VERSION};
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Parse a YAML rule file, attempting three formats in priority order:
/// `RulePackFile` (preferred), `IocFeedFile` (legacy IOC packs), and
/// finally a bare `Vec<Rule>`.
///
/// # Schema validation contract
///
/// When the YAML deserializes to a `RulePackFile` or `IocFeedFile`, the
/// `schema_version` is validated **before** the per-format emptiness
/// check (`pack.rules.is_empty()` / no IOC items). Pre-fix the order was
/// inverted: a pack with `schema_version: invalid-version` and `rules:
/// []` would silently fall through to the next format and ultimately
/// surface as the misleading `"Rule file is empty or contains no valid
/// rules"` instead of the actual schema error. Validating early gives
/// pack authors an actionable error and prevents the scanner from
/// accepting packs that may rely on schema-version-specific semantics
/// the engine does not yet understand.
pub fn parse_rules_file(content: &str) -> Result<Vec<Rule>, RuleError> {
    let mut errors = Vec::new();

    if let Ok(pack) = serde_yaml::from_str::<RulePackFile>(content) {
        if !is_supported_rule_pack_schema(&pack.schema_version) {
            return Err(RuleError::InvalidRule(format!(
                "Unsupported rule pack schema version: {}",
                pack.schema_version
            )));
        }
        if !pack.rules.is_empty() {
            return Ok(pack.rules);
        }
        // Recognised as RulePackFile but empty — push a label so the
        // final error message mentions this format was attempted.
        errors.push("RulePackFile format (empty rules)".to_string());
    } else if !content.trim().is_empty() {
        errors.push("RulePackFile format".to_string());
    }

    if let Ok(feed) = serde_yaml::from_str::<IocFeedFile>(content) {
        if !is_supported_rule_pack_schema(&feed.schema_version) {
            return Err(RuleError::InvalidRule(format!(
                "Unsupported IOC feed schema version: {}",
                feed.schema_version
            )));
        }
        if !(feed.domains.is_empty() && feed.filenames.is_empty() && feed.ips.is_empty()) {
            return ioc_feed_to_rules(&feed);
        }
    } else if !content.trim().is_empty() {
        errors.push("IocFeedFile format".to_string());
    }

    match serde_yaml::from_str::<Vec<Rule>>(content) {
        Ok(rules) => {
            if !rules.is_empty() {
                tracing::warn!(
                    "rule-parser: accepted bare Vec<Rule> format without schema_version — \
                     pack authors should use RulePackFile with schema_version {}",
                    RULE_PACK_SCHEMA_VERSION
                );
            }
            return Ok(rules);
        }
        Err(e) => {
            errors.push(format!("rule list format: {e}"));
        }
    }

    if errors.is_empty() {
        Err(RuleError::InvalidRule(
            "Rule file is empty or contains no valid rules".to_string(),
        ))
    } else {
        Err(RuleError::InvalidRule(format!(
            "Failed to parse rules file. Attempted formats: {}",
            errors.join("; ")
        )))
    }
}

pub fn is_supported_rule_pack_schema(schema_version: &str) -> bool {
    schema_version == RULE_PACK_SCHEMA_VERSION
}

/// Environment variable that overrides the rule discovery search path.
/// Set to a colon-separated list (`:` on unix, `;` on Windows) of
/// directories the engine should treat as external rule overlays. Used
/// by CI runs and by `skill-veil scan --rules-dir` callers who want the
/// override to apply even when the flag is not threaded through.
pub const RULES_DIR_ENV: &str = "SKILL_VEIL_RULES_DIR";

/// Filename of the JSON pointer the CLI's `init` command writes after a
/// successful download. Kept here so the discovery contract is owned by
/// the same module that defines the search order.
const CURRENT_POINTER_FILENAME: &str = "current.json";
const MAX_CURRENT_POINTER_BYTES: u64 = 64 * 1024;

/// # Search order contract
///
/// The engine probes overlay directories in this order, loading from
/// every existing path:
///
/// 1. `$SKILL_VEIL_RULES_DIR` (env var, colon/semicolon-separated list).
///    Honoured first so CI / sandboxed runs can pin an exact path
///    without relying on filesystem lookups elsewhere.
/// 2. `<cache_dir>/skill-veil/rules/<current_version>/official/` —
///    the install populated by `skill-veil init`. The `current_version`
///    is read from `<cache_dir>/skill-veil/rules/current.json`.
/// 3. `./rules/official/` — legacy / dev-mode fallback so `cargo run`
///    against a sibling checkout of `skill-veil-rules` still works.
///
/// Every path that exists is loaded; non-existent paths are skipped
/// silently (matches the `load_runtime_default_rules` contract).
/// Duplicate IDs across overlays are resolved by the engine's
/// `strict_mode` policy — the legacy default is non-strict skip, which
/// preserves embedded canonical rules.
pub fn default_external_rule_dirs() -> Vec<PathBuf> {
    let env_value = std::env::var(RULES_DIR_ENV).ok();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    compose_external_rule_dirs(env_value.as_deref(), current_install_overlay(), &cwd)
}

/// Pure helper — kept separate so the search-order contract can be
/// unit-tested without mutating process-global state (parallel tests
/// in the same crate would otherwise race on `std::env::set_var`).
fn compose_external_rule_dirs(
    env_value: Option<&str>,
    cache_overlay: Option<PathBuf>,
    cwd: &Path,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(raw) = env_value {
        for part in raw.split(env_path_separator()) {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                dirs.push(PathBuf::from(trimmed));
            }
        }
    }
    if let Some(overlay) = cache_overlay {
        dirs.push(overlay);
    }
    dirs.push(cwd.join("rules").join("official"));
    dirs
}

const fn env_path_separator() -> char {
    if cfg!(windows) {
        ';'
    } else {
        ':'
    }
}

/// Resolve `<cache_dir>/skill-veil/rules/<current_version>/official/`
/// by reading the `current.json` pointer the CLI's `init` writes.
/// Returns `None` if no init has run, the pointer is unreadable, or
/// the version directory does not exist on disk.
fn current_install_overlay() -> Option<PathBuf> {
    let cache_root = dirs::cache_dir()?.join("skill-veil");
    let install_root = cache_root.join("rules");
    let pointer_path = install_root.join(CURRENT_POINTER_FILENAME);
    let body = read_current_pointer_file(&pointer_path)?;
    current_install_overlay_from_pointer(&cache_root, &install_root, &body)
}

fn read_current_pointer_file(path: &Path) -> Option<String> {
    let path_meta = regular_pointer_metadata(path)?;
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !opened_file_matches_path(&meta, &path_meta) {
        tracing::warn!(
            "ignoring installed rules pointer {} (path changed while opening)",
            path.display(),
        );
        return None;
    }
    if meta.len() > MAX_CURRENT_POINTER_BYTES {
        tracing::warn!(
            "ignoring installed rules pointer {} ({} bytes > cap {})",
            path.display(),
            meta.len(),
            MAX_CURRENT_POINTER_BYTES,
        );
        return None;
    }

    let mut body = String::new();
    let mut limited = file.take(MAX_CURRENT_POINTER_BYTES.saturating_add(1));
    limited.read_to_string(&mut body).ok()?;
    if body.len() as u64 > MAX_CURRENT_POINTER_BYTES {
        tracing::warn!(
            "ignoring installed rules pointer {} (stream exceeded cap {})",
            path.display(),
            MAX_CURRENT_POINTER_BYTES,
        );
        return None;
    }
    Some(body)
}

fn regular_pointer_metadata(path: &Path) -> Option<Metadata> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        tracing::warn!(
            "ignoring installed rules pointer {} (not a regular file)",
            path.display(),
        );
        return None;
    }
    if !has_single_hardlink(&meta) {
        tracing::warn!(
            "ignoring installed rules pointer {} (multiple hard links)",
            path.display(),
        );
        return None;
    }
    Some(meta)
}

fn current_install_overlay_from_pointer(
    cache_root: &Path,
    install_root: &Path,
    body: &str,
) -> Option<PathBuf> {
    let pointer: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = pointer.get("version")?.as_str()?;
    if !is_safe_release_version(version) {
        return None;
    }
    if !is_real_dir(cache_root) {
        return None;
    }
    if !is_real_dir(install_root) {
        return None;
    }
    let version_dir = install_root.join(version);
    if !is_real_dir(&version_dir) {
        return None;
    }
    let candidate = version_dir.join("official");
    if is_real_dir(&candidate) {
        Some(candidate)
    } else {
        None
    }
}

fn is_safe_release_version(version: &str) -> bool {
    let bytes = version.as_bytes();
    !bytes.is_empty()
        && bytes[0] == b'v'
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.is_dir() && !meta.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(unix)]
fn has_single_hardlink(meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.nlink() == 1
}

#[cfg(not(unix))]
fn has_single_hardlink(_meta: &Metadata) -> bool {
    true
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

    /// Contract: with no env var set and no cache install, the
    /// search path still includes the legacy `./rules/official/` dev
    /// path last. Removing this fallback would break local
    /// `cargo run -- scan ...` against a sibling checkout.
    #[test]
    fn legacy_cwd_fallback_is_always_present() {
        let dirs = compose_external_rule_dirs(None, None, Path::new("/test/cwd"));
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0], PathBuf::from("/test/cwd/rules/official"));
    }

    /// Contract: `$SKILL_VEIL_RULES_DIR` is honoured first and
    /// supports a list. Empty entries are filtered so a stray
    /// trailing colon (`/path/a:`) does not inject the cwd.
    #[test]
    fn env_var_paths_appear_first_and_skip_empties() {
        let sep = env_path_separator();
        let raw = format!("/path/a{sep}{sep}/path/b{sep}");
        let dirs = compose_external_rule_dirs(Some(&raw), None, Path::new("/cwd"));
        assert_eq!(dirs[0], PathBuf::from("/path/a"));
        assert_eq!(dirs[1], PathBuf::from("/path/b"));
        // legacy fallback is still last.
        assert_eq!(dirs[2], PathBuf::from("/cwd/rules/official"));
        assert_eq!(dirs.len(), 3);
    }

    /// Contract: when the cache pointer resolves, the cache overlay
    /// sits between env-var entries and the legacy cwd fallback. This
    /// is the order `skill-veil scan` relies on after a successful
    /// `init`: explicit env wins, then the verified install, then
    /// dev-mode last.
    #[test]
    fn cache_overlay_sits_between_env_and_legacy_fallback() {
        let dirs = compose_external_rule_dirs(
            Some("/from/env"),
            Some(PathBuf::from("/cache/v0.1.0/official")),
            Path::new("/cwd"),
        );
        assert_eq!(dirs[0], PathBuf::from("/from/env"));
        assert_eq!(dirs[1], PathBuf::from("/cache/v0.1.0/official"));
        assert_eq!(dirs[2], PathBuf::from("/cwd/rules/official"));
    }

    /// Contract: a corrupted `current.json` cannot point runtime rule
    /// discovery outside the cache install root.
    #[test]
    fn current_install_overlay_rejects_path_like_version() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_root = tmp.path().join("skill-veil");
        let install_root = cache_root.join("rules");
        let official = install_root.join("v0.1.0").join("official");
        std::fs::create_dir_all(&official).unwrap();

        let good = r#"{"version":"v0.1.0"}"#;
        assert_eq!(
            current_install_overlay_from_pointer(&cache_root, &install_root, good),
            Some(official)
        );

        for bad in [
            r#"{"version":"/tmp/evil"}"#,
            r#"{"version":"v0.1.0/../../evil"}"#,
            r#"{"version":"v0.1.0\\..\\evil"}"#,
            r#"{"version":"0.1.0"}"#,
        ] {
            assert!(
                current_install_overlay_from_pointer(&cache_root, &install_root, bad).is_none(),
                "{bad} must not produce an overlay path"
            );
        }
    }

    /// # Contract
    ///
    /// Runtime rule discovery MUST read a normal installed pointer
    /// without requiring the CLI crate. The core scanner owns this
    /// fallback path when callers use the library directly.
    #[test]
    fn current_pointer_read_accepts_valid_json_under_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pointer_path = tmp.path().join(CURRENT_POINTER_FILENAME);
        std::fs::write(&pointer_path, r#"{"version":"v0.1.0"}"#).unwrap();

        let body = read_current_pointer_file(&pointer_path).unwrap();

        assert!(body.contains("v0.1.0"));
    }

    /// # Contract
    ///
    /// Runtime rule discovery MUST ignore an oversized installed
    /// pointer before parsing so a poisoned cache file cannot allocate
    /// unbounded memory in library callers.
    #[test]
    fn current_pointer_read_rejects_oversized_json() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pointer_path = tmp.path().join(CURRENT_POINTER_FILENAME);
        let oversized_len = usize::try_from(MAX_CURRENT_POINTER_BYTES).unwrap() + 1;
        std::fs::write(&pointer_path, vec![b'{'; oversized_len]).unwrap();

        let body = read_current_pointer_file(&pointer_path);

        assert!(body.is_none());
    }

    /// # Contract
    ///
    /// Runtime rule discovery ignores symlinked installed pointers,
    /// even when the symlink target contains valid JSON.
    #[cfg(unix)]
    #[test]
    fn current_pointer_read_rejects_symlinked_json() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("target.json");
        let pointer_path = tmp.path().join(CURRENT_POINTER_FILENAME);
        std::fs::write(&target, r#"{"version":"v0.1.0"}"#).unwrap();
        std::os::unix::fs::symlink(&target, &pointer_path).unwrap();

        let body = read_current_pointer_file(&pointer_path);

        assert!(body.is_none());
    }

    /// # Contract
    ///
    /// Runtime rule discovery ignores hardlinked installed pointers.
    /// The active rule-pack pointer must be a cache-owned directory
    /// entry, not another name for an inode created elsewhere.
    #[cfg(unix)]
    #[test]
    fn current_pointer_read_rejects_hardlinked_json() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("target.json");
        let pointer_path = tmp.path().join(CURRENT_POINTER_FILENAME);
        std::fs::write(&target, r#"{"version":"v0.1.0"}"#).unwrap();
        std::fs::hard_link(&target, &pointer_path).unwrap();

        let body = read_current_pointer_file(&pointer_path);

        assert!(body.is_none());
    }

    /// # Contract
    ///
    /// Runtime rule discovery ignores a symlinked `skill-veil` cache
    /// root. The cache pointer can only activate rule overlays from the
    /// real cache tree owned by this process.
    #[cfg(unix)]
    #[test]
    fn current_install_overlay_rejects_symlinked_cache_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let outside = tmp.path().join("outside-cache");
        let cache_root = tmp.path().join("skill-veil");
        let install_root = cache_root.join("rules");
        let official = outside.join("rules").join("v0.1.0").join("official");
        std::fs::create_dir_all(&official).unwrap();
        std::os::unix::fs::symlink(&outside, &cache_root).unwrap();

        assert!(current_install_overlay_from_pointer(
            &cache_root,
            &install_root,
            r#"{"version":"v0.1.0"}"#
        )
        .is_none());
    }

    /// # Contract
    ///
    /// Runtime rule discovery loads only real install directories. A
    /// symlinked version directory or `official` directory is ignored.
    #[cfg(unix)]
    #[test]
    fn current_install_overlay_rejects_symlinked_install_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_root = tmp.path().join("skill-veil");
        let install_root = cache_root.join("rules");
        let outside = tmp.path().join("outside");
        let version_dir = install_root.join("v0.1.0");
        let official = version_dir.join("official");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&version_dir).unwrap();
        std::os::unix::fs::symlink(&outside, &official).unwrap();

        assert!(current_install_overlay_from_pointer(
            &cache_root,
            &install_root,
            r#"{"version":"v0.1.0"}"#
        )
        .is_none());

        std::fs::remove_file(&official).unwrap();
        std::fs::remove_dir(&version_dir).unwrap();
        std::os::unix::fs::symlink(&outside, &version_dir).unwrap();

        assert!(current_install_overlay_from_pointer(
            &cache_root,
            &install_root,
            r#"{"version":"v0.1.0"}"#
        )
        .is_none());
    }
}
