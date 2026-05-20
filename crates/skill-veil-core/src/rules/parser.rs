use super::ioc::ioc_feed_to_rules;
use super::schema::{IocFeedFile, Rule, RulePackFile};
use super::{RuleError, RULE_PACK_SCHEMA_VERSION};
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
    let install_root = dirs::cache_dir()?.join("skill-veil").join("rules");
    let pointer_path = install_root.join(CURRENT_POINTER_FILENAME);
    let body = std::fs::read_to_string(&pointer_path).ok()?;
    current_install_overlay_from_pointer(&install_root, &body)
}

fn current_install_overlay_from_pointer(install_root: &Path, body: &str) -> Option<PathBuf> {
    let pointer: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = pointer.get("version")?.as_str()?;
    if !is_safe_release_version(version) {
        return None;
    }
    let candidate = install_root.join(version).join("official");
    if candidate.is_dir() {
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
        let install_root = tmp.path().join("rules");
        let official = install_root.join("v0.1.0").join("official");
        std::fs::create_dir_all(&official).unwrap();

        let good = r#"{"version":"v0.1.0"}"#;
        assert_eq!(
            current_install_overlay_from_pointer(&install_root, good),
            Some(official)
        );

        for bad in [
            r#"{"version":"/tmp/evil"}"#,
            r#"{"version":"v0.1.0/../../evil"}"#,
            r#"{"version":"v0.1.0\\..\\evil"}"#,
            r#"{"version":"0.1.0"}"#,
        ] {
            assert!(
                current_install_overlay_from_pointer(&install_root, bad).is_none(),
                "{bad} must not produce an overlay path"
            );
        }
    }
}
