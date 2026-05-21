use crate::lazy_pattern;
use crate::path_safety::path_stays_within_base;
use crate::patterns::compile_patterns;
use crate::ports::CompiledPattern;
use std::path::{Path, PathBuf};

const SCRIPT_EXT_PATTERN: &str = "sh|py|ps1|js|ts|rb|pl";
const ALL_EXT_PATTERN: &str = "sh|py|ps1|js|ts|rb|pl|exe|bin|dll";

lazy_pattern!(EXEC_REFERENCE_PATTERN, r"(?:chmod\s+\+x\s+|\./)([^\s]+)");

/// Bare-prefix URL schemes that don't use `://` but are still URLs (data
/// URIs, mailto, javascript). Anything else MUST present `scheme://` to
/// be classified as a URL — that filters out Windows drive letters
/// (`C:foo.txt`) and other colon-bearing local paths from being treated
/// as URL references.
const KNOWN_BARE_URL_PREFIXES: &[&str] = &["mailto:", "data:", "javascript:", "tel:"];

/// `true` when `candidate` begins with a URL scheme — either the
/// `scheme://...` form (HTTP/HTTPS, FTP, file URIs, custom `git+ssh://`)
/// or one of the recognised bare-prefix forms in [`KNOWN_BARE_URL_PREFIXES`].
/// Pure: no allocation; checks a leading `[A-Za-z][A-Za-z0-9+.-]*://`
/// rune followed by at least one body byte.
fn has_url_scheme(candidate: &str) -> bool {
    if KNOWN_BARE_URL_PREFIXES
        .iter()
        .any(|prefix| starts_with_bare_url_prefix(candidate, prefix))
    {
        return true;
    }
    let bytes = candidate.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    // Walk the scheme bytes looking for the first non-scheme character.
    let mut idx = 1;
    while idx < bytes.len() {
        let b = bytes[idx];
        if !(b.is_ascii_alphanumeric() || b == b'+' || b == b'.' || b == b'-') {
            // Require `scheme://` followed by at least one body byte for
            // the unambiguously-URL form. This filters `C:foo.txt`
            // (Windows drive) because it has only `:` (no `//`).
            return b == b':'
                && bytes.get(idx + 1).copied() == Some(b'/')
                && bytes.get(idx + 2).copied() == Some(b'/')
                && bytes.len() > idx + 3;
        }
        idx += 1;
    }
    false
}

fn starts_with_bare_url_prefix(candidate: &str, prefix: &str) -> bool {
    candidate.len() > prefix.len()
        && candidate
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Extract paths to supporting artifacts referenced from a markdown skill doc.
///
/// # Security contract
///
/// Returned `PathBuf`s MUST stay within `base_path.parent()`. Two attack
/// classes are explicitly rejected:
///
/// 1. **Absolute paths**: a markdown link like `[script](/etc/shadow.sh)`
///    captured by the regex would, via `Path::join`, silently discard the
///    base directory and resolve to `/etc/shadow.sh`. The scanner would
///    then read attacker-chosen system files.
/// 2. **Parent-traversal**: relative paths whose lexical normalisation
///    escapes `base_dir` (e.g. `../../etc/passwd.sh`) are rejected before
///    any filesystem call. We compare lexical components so the check works
///    even when the target file does not exist yet.
///
/// Violations are skipped silently; the function is best-effort and never
/// surfaces them as findings (the regex would over-flag legitimate edge
/// cases like example references in documentation).
pub(super) fn extract_references(content: &str, base_path: &Path) -> Vec<PathBuf> {
    let mut references = Vec::new();
    let base_dir = base_path.parent().unwrap_or_else(|| {
        tracing::debug!(
            "extract_references: `{}` has no parent; resolving references relative to CWD",
            base_path.display()
        );
        Path::new(".")
    });

    let link_pattern = format!(r#"\[.*?\]\((\.?/?[^\)]+\.({}))\)"#, ALL_EXT_PATTERN);
    let command_pattern = format!(
        r#"(?:source|run|execute|include)\s+[\"']?([^\s\"']+\.({}))"#,
        SCRIPT_EXT_PATTERN
    );

    // The link/command patterns embed runtime-built extension lists
    // (`SCRIPT_EXT_PATTERN`, `ALL_EXT_PATTERN`), so they cannot live
    // inside `lazy_pattern!`. They go through `compile_patterns` —
    // the bulk variant of the same composition seam — which still
    // routes through the `PatternMatcher` port without naming the
    // concrete adapter. The static `EXEC_REFERENCE_PATTERN` uses
    // `lazy_pattern!` because it is a binary literal.
    let dynamic = compile_patterns(&[link_pattern.as_str(), command_pattern.as_str()]);
    let patterns = dynamic
        .iter()
        .chain(std::iter::once::<&CompiledPattern>(&EXEC_REFERENCE_PATTERN));

    for re in patterns {
        for cap in re.captures_iter(content) {
            let Some(m) = cap.get(1) else { continue };
            let raw = m.matched_text.as_str();

            // Reject scheme-prefixed URLs (`http://`, `https://`, `ftp://`,
            // `file://`, `mailto:`, custom schemes). `Path::is_absolute`
            // returns `false` for `https://attacker.com/x.sh` on Unix
            // because the path starts with `h`; without this guard the
            // URL would be `Path::join`-ed onto `base_dir`, producing a
            // bogus local path like `/pkg/https:/attacker.com/x.sh` that
            // gets queued for filesystem reads. The lookup fails with
            // `NotFound`, so this is not a path-traversal exploit, but
            // every URL link in a skill triggered a wasted I/O round-trip
            // and inflated `referenced_files` with phantom entries.
            if has_url_scheme(raw) {
                tracing::debug!(
                    "extract_references: skipping URL reference in {}: {}",
                    base_path.display(),
                    raw
                );
                continue;
            }

            // Reject absolute paths: `Path::join` would discard `base_dir`
            // and produce a path under attacker control. Note: on Unix this
            // catches leading `/`; on Windows it also catches drive prefixes
            // like `C:\`.
            if Path::new(raw).is_absolute() {
                tracing::debug!(
                    "extract_references: skipping absolute path in {}: {}",
                    base_path.display(),
                    raw
                );
                continue;
            }

            let resolved = base_dir.join(raw);

            // Lexical traversal check: count `..` vs normal components.
            // A resolved path that escapes base_dir would have a leading
            // `..` after normalisation. `Path::canonicalize` would do this
            // correctly but requires the file to exist; we want the check
            // to apply pre-existence too.
            if !path_stays_within_base(&resolved, base_dir) {
                tracing::debug!(
                    "extract_references: skipping path that escapes base_dir {}: {}",
                    base_dir.display(),
                    raw
                );
                continue;
            }

            if !references.contains(&resolved) {
                references.push(resolved);
            }
        }
    }

    references
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: an absolute path captured by a markdown link must NEVER
    /// produce a reference. `Path::join` would otherwise discard `base_dir`
    /// and let attacker-controlled markdown make the scanner read system
    /// files like `/etc/shadow`.
    #[test]
    fn extract_references_rejects_absolute_link_targets() {
        let content = "See [the script](/etc/shadow.sh) for details.";
        let base_path = Path::new("/tmp/pkg/SKILL.md");
        let refs = extract_references(content, base_path);
        assert!(
            refs.iter().all(|p| !p.starts_with("/etc")),
            "Absolute /etc/shadow.sh must NOT escape base_dir; got {refs:?}"
        );
    }

    /// Contract: relative paths that traverse out of base_dir (`../../`) are
    /// rejected. Lexical check, no filesystem dependency.
    #[test]
    fn extract_references_rejects_parent_traversal() {
        let content = "Run `[evil](../../etc/passwd.sh)`.";
        let base_path = Path::new("/tmp/pkg/SKILL.md");
        let refs = extract_references(content, base_path);
        assert!(
            refs.is_empty()
                || refs
                    .iter()
                    .all(|p| !p.to_string_lossy().contains("etc/passwd")),
            "Parent-traversal must be rejected; got {refs:?}"
        );
    }

    /// Sanity: legitimate relative references inside the package still resolve.
    #[test]
    fn extract_references_accepts_legitimate_relative_paths() {
        let content = "[install](./scripts/install.sh) and [helper](helpers/util.py)";
        let base_path = Path::new("/tmp/pkg/SKILL.md");
        let refs = extract_references(content, base_path);
        assert!(refs.iter().any(|p| p.ends_with("scripts/install.sh")));
        assert!(refs.iter().any(|p| p.ends_with("helpers/util.py")));
    }

    /// # Contract
    ///
    /// URL link targets — `[install](https://example.com/install.sh)` — MUST
    /// NOT be added to `referenced_files`. Pre-fix `Path::is_absolute`
    /// returned `false` for `https://...` on Unix, so the URL was joined
    /// onto `base_dir` and produced a phantom local path
    /// (`/pkg/https:/example.com/install.sh`) that downstream artifact
    /// scanning then attempted to read. Not a path-traversal exploit but
    /// a real source of phantom entries and wasted I/O.
    #[test]
    fn extract_references_rejects_url_link_targets() {
        let base_path = Path::new("/tmp/pkg/SKILL.md");
        for sample in [
            "[install](https://example.com/install.sh)",
            "[install](MAILTO:security@example.com/install.sh)",
            "[install](http://example.com/install.sh)",
            "[install](ftp://example.com/install.sh)",
            "[install](file:///etc/install.sh)",
        ] {
            let refs = extract_references(sample, base_path);
            assert!(
                refs.is_empty(),
                "URL target must not be resolved: {sample:?} -> {refs:?}"
            );
        }
    }

    /// # Contract (low-level helper)
    ///
    /// `has_url_scheme` MUST recognise canonical URL prefixes and reject
    /// everything else — including paths that happen to contain a colon
    /// (Windows drive letters, scheme-shaped filenames). Pins the
    /// classifier so `Path::join` cannot silently consume a URL that
    /// slipped past via a near-miss.
    #[test]
    fn has_url_scheme_classifies_canonical_inputs() {
        for url in [
            "https://example.com/x.sh",
            "http://example.com",
            "ftp://example.com",
            "file:///etc/passwd",
            "git+ssh://example.com/repo.git",
            "data:text/plain,hello",
            "DATA:text/plain,hello",
            "JavaScript:alert(1)",
            "TEL:+15551234567",
        ] {
            assert!(has_url_scheme(url), "must classify as URL: {url:?}");
        }
        for non_url in [
            "scripts/install.sh",
            "./scripts/install.sh",
            "../helpers/util.py",
            "C:foo.txt",
            "scheme",
            "a:",
            "",
            ":",
        ] {
            assert!(
                !has_url_scheme(non_url),
                "must NOT classify as URL: {non_url:?}"
            );
        }
    }
}
