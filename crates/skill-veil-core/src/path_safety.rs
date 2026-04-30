//! Path-containment helpers for safely resolving attacker-controlled paths.
//!
//! All path-resolution code that processes attacker-controlled input MUST
//! validate the result against [`path_stays_within_base`]. Two attack
//! classes motivate this contract:
//!
//! 1. **Absolute-path injection** — `Path::join(base, attacker)` silently
//!    discards `base` when the attacker side is absolute, producing a
//!    fully attacker-controlled output path.
//! 2. **Parent-traversal (`..`) escape** — even with relative input, `..`
//!    components can lift the resolved path above `base`.
//!
//! The check is **lexical**, not filesystem-based, so it works on paths
//! whose targets do not yet exist (zip extraction, sandbox prepares the
//! destination after the check).
//!
//! Examples of call sites that must use this helper:
//! - `dataset/preparation.rs::extract_zip_package` (zip-slip defence)
//! - `analyzer/references.rs::extract_references` (markdown link sanitisation)

use std::path::{Component, Path};

/// Return `true` when `candidate` resolves inside `base_dir` after walking
/// `..` components lexically. Absolute paths are accepted only when they
/// share the prefix with `base_dir`; otherwise the caller should reject
/// them at an earlier guard (see `extract_references` for the recommended
/// `Path::is_absolute()` pre-check).
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use skill_veil_core::path_stays_within_base;
///
/// let base = Path::new("/pkg");
/// assert!(path_stays_within_base(&base.join("scripts/ok.sh"), base));
/// assert!(!path_stays_within_base(&base.join("../../etc/evil.sh"), base));
/// ```
#[must_use]
pub fn path_stays_within_base(candidate: &Path, base_dir: &Path) -> bool {
    // Strip the common base prefix; if candidate doesn't start with
    // base_dir, fall back to walking the full path (handles relative
    // inputs and absolute inputs that already escaped).
    let suffix = candidate.strip_prefix(base_dir).unwrap_or(candidate);
    let mut depth: i32 = 0;
    for comp in suffix.components() {
        match comp {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            // Absolute root inside the suffix means the original path was
            // built from an absolute leaf; reject defensively. Callers
            // should typically catch this earlier with `Path::is_absolute()`.
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn accepts_simple_relative_descendant() {
        let base = Path::new("/pkg");
        assert!(path_stays_within_base(
            &base.join("scripts/install.sh"),
            base
        ));
    }

    #[test]
    fn accepts_curdir_components() {
        let base = Path::new("/pkg");
        assert!(path_stays_within_base(
            &base.join("./helpers/./util.py"),
            base
        ));
    }

    /// Contract: parent-traversal that escapes the base is rejected even
    /// when the final resolved path appears benign. This is the load-bearing
    /// check for zip-slip defence.
    #[test]
    fn rejects_parent_traversal_escape() {
        let base = Path::new("/pkg");
        let candidate = PathBuf::from("/pkg/../../../etc/evil.sh");
        assert!(!path_stays_within_base(&candidate, base));
    }

    /// Internal `..` that does not escape (cancels a prior `Normal`) is
    /// allowed. The depth counter handles this case.
    #[test]
    fn allows_internal_parent_traversal_within_base() {
        let base = Path::new("/pkg");
        let candidate = PathBuf::from("/pkg/sub/../scripts/ok.sh");
        assert!(path_stays_within_base(&candidate, base));
    }

    #[test]
    fn rejects_absolute_root_inside_suffix() {
        // Synthetic case: a path whose suffix has an embedded RootDir
        // component (rare but possible via PathBuf manipulation).
        let base = Path::new("/pkg");
        let mut candidate = PathBuf::from("/pkg");
        candidate.push("/etc/evil.sh"); // Path::push of an absolute discards the prefix
                                        // After `push`, candidate == /etc/evil.sh, which strip_prefix can't
                                        // strip; the function then walks the full /etc/evil.sh and rejects
                                        // the RootDir component.
        assert!(!path_stays_within_base(&candidate, base));
    }
}
