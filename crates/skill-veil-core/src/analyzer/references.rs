use crate::lazy_pattern;
use crate::path_safety::path_stays_within_base;
use crate::patterns::compile_patterns;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Hard cap on the number of distinct referenced files extracted from a
/// single document. A legitimate skill references a handful of supporting
/// artifacts; an unbounded count is an attacker shaping the input. Without
/// the cap, a `SKILL.md` packed with thousands of distinct `[a](fN.sh)`
/// links would push an unbounded reference set into the artifact graph,
/// whose node/edge insertion is linear-scan — turning the scan
/// super-linear (a denial-of-service on a single `scan-file`).
const MAX_REFERENCED_FILES: usize = 1024;

const SCRIPT_EXTENSIONS: &[&str] = &["sh", "py", "ps1", "js", "ts", "rb", "pl", "bat", "cmd"];
const ALL_EXT_PATTERN: &str = "sh|py|ps1|js|ts|rb|pl|bat|cmd|exe|bin|dll";

/// Trailing characters stripped from a captured reference before
/// resolution: markdown/shell punctuation that the greedy capture
/// classes swallow, plus a sentence-ending `.` (`run bootstrap.py.`).
/// None of these can be the final character of a real referenced file.
const TRAILING_PUNCTUATION: &[char] = &[')', '`', '"', '\'', ',', ';', '>', '.'];

lazy_pattern!(EXEC_REFERENCE_PATTERN, r"(?:chmod\s+\+x\s+|\./)([^\s]+)");

/// Whether `path`'s final extension is one skill-veil treats as a script.
/// The `command_pattern` captures the whole referenced token and defers
/// the extension test here so a compound name (`utils.sh.inc`) is judged
/// by its real trailing extension (`inc`, rejected) rather than letting a
/// greedy regex truncate to an interior `.sh` and queue a phantom path.
fn has_script_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| SCRIPT_EXTENSIONS.contains(&ext))
}

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

    // CommonMark link destinations can carry a title (`(path "t")`), be
    // angle-bracket wrapped (`(<path>)`), or trail a query/fragment
    // (`(path?x=1)`). The destination capture stops at whitespace, `)`,
    // and `>` so none of those trailing forms either defeat the match
    // (referenced file silently never scanned) or get glued onto the
    // captured path. The query/fragment and title are consumed but not
    // captured.
    let link_pattern = format!(
        r#"\[.*?\]\(\s*<?(\.?/?[^\s)>]+\.({}))(?:[?#][^\s)>]*)?>?(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)"#,
        ALL_EXT_PATTERN
    );
    // Capture the whole referenced token, not a `.<scriptext>`-anchored
    // prefix. With the old anchored form the greedy path run backtracked
    // to an *interior* script extension when the real trailing segment
    // was not one — `source utils.sh.inc` captured `utils.sh`, queuing a
    // phantom path that never exists. The extension test now happens in
    // `has_script_extension` after trailing-punctuation stripping, so the
    // token is judged by its real final extension. `link_pattern` keeps
    // its inline extension group: its closing `\)` already anchors the
    // destination so no truncation is possible.
    let command_pattern = r#"(?:source|run|execute|include)\s+[\"']?([^\s\"']+)"#;

    // The link pattern embeds the runtime-built `ALL_EXT_PATTERN`, so it
    // cannot live inside `lazy_pattern!`. Both dynamic patterns go through
    // `compile_patterns` — the bulk variant of the same composition seam —
    // which still routes through the `PatternMatcher` port without naming
    // the concrete adapter. The static `EXEC_REFERENCE_PATTERN` uses
    // `lazy_pattern!` because it is a binary literal.
    let dynamic = compile_patterns(&[link_pattern.as_str(), command_pattern]);
    // `compile_patterns` preserves input order, so `dynamic[0]` is the
    // link pattern and `dynamic[1]` the command pattern. The command
    // pattern captures a bare token and must be filtered to references
    // whose final extension is a script; the link pattern already embeds
    // its extension group and the exec pattern intentionally accepts
    // extension-less targets (`chmod +x payload`).
    let patterns = dynamic
        .iter()
        .zip([false, true])
        .chain(std::iter::once((&*EXEC_REFERENCE_PATTERN, false)));

    // O(1) membership for dedup: a linear `references.contains(..)` per
    // match made the whole pass O(N^2) in the number of distinct
    // references, which an attacker controls via the document body.
    let mut seen: HashSet<PathBuf> = HashSet::new();
    'patterns: for (re, requires_script_ext) in patterns {
        for cap in re.captures_iter(content) {
            if references.len() >= MAX_REFERENCED_FILES {
                tracing::warn!(
                    "extract_references: capping at {} references for {}; \
                     remaining links are ignored",
                    MAX_REFERENCED_FILES,
                    base_path.display()
                );
                break 'patterns;
            }
            let Some(m) = cap.get(1) else { continue };
            // The `chmod +x`/`./` exec pattern uses `[^\s]+`, which greedily
            // swallows trailing markdown/shell punctuation (`./x.sh)` inside a
            // link, `` `./x.sh` `` in prose). Strip it so the resolved path is
            // the real file, not a phantom that fails the read. A leading `./`
            // is normalised away so the same file referenced as `./x` and `x`
            // does not produce two distinct (un-deduplicated) entries.
            let raw = m
                .matched_text
                .as_str()
                .trim_end_matches(TRAILING_PUNCTUATION);
            let raw = raw.strip_prefix("./").unwrap_or(raw);
            if raw.is_empty() {
                continue;
            }

            // The command pattern captures any token after a
            // `source`/`run`/`execute`/`include` directive; keep only
            // those that resolve to a script by their real extension.
            if requires_script_ext && !has_script_extension(raw) {
                continue;
            }

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

            if seen.insert(resolved.clone()) {
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

    /// # Contract
    ///
    /// The reference set is bounded (no unbounded O(N^2) growth on a
    /// crafted document) and de-duplicated. Pre-fix, dedup used a linear
    /// `Vec::contains` per match (O(N^2)) and there was no cap, so a
    /// `SKILL.md` packed with distinct links could hang a scan.
    #[test]
    fn extract_references_caps_and_dedups() {
        let base_path = Path::new("/tmp/pkg/SKILL.md");

        let mut content = String::new();
        for i in 0..(MAX_REFERENCED_FILES + 50) {
            content.push_str(&format!("[a](f{i}.sh)\n"));
        }
        let refs = extract_references(&content, base_path);
        assert_eq!(
            refs.len(),
            MAX_REFERENCED_FILES,
            "distinct references must be capped at MAX_REFERENCED_FILES"
        );

        let dup = "[a](dup.sh)\n".repeat(100);
        let refs = extract_references(&dup, base_path);
        assert_eq!(
            refs.iter().filter(|p| p.ends_with("dup.sh")).count(),
            1,
            "duplicate references must collapse to a single entry"
        );
    }

    /// # Contract
    ///
    /// A CommonMark link with a title, angle brackets, or a trailing
    /// query/fragment MUST still resolve its referenced script. Pre-fix
    /// the regex required the destination to end exactly at `.<ext>)`, so
    /// `[run](payload.sh "Installer")` matched nothing and the referenced
    /// script — potential malware in a non-conventional directory — was
    /// never queued for scanning.
    #[test]
    fn extract_references_handles_link_titles_brackets_and_query() {
        let base_path = Path::new("/tmp/pkg/SKILL.md");
        for sample in [
            r#"[run](assets/payload.sh "Installer")"#,
            "[run](<assets/payload.sh>)",
            "[run](assets/payload.sh?v=1)",
            "[run](assets/payload.sh#top)",
            "[run](./assets/payload.sh 'note')",
        ] {
            let refs = extract_references(sample, base_path);
            assert!(
                refs.iter().any(|p| p.ends_with("assets/payload.sh")),
                "must resolve referenced script for {sample:?}; got {refs:?}"
            );
        }
    }

    /// # Contract
    ///
    /// Trailing markdown/shell punctuation captured by the `./`/`chmod +x`
    /// exec pattern MUST be stripped, and a leading `./` normalised, so a
    /// reference resolves to the real file rather than a phantom path that
    /// fails the read (and is never deduplicated against the clean form).
    #[test]
    fn extract_references_strips_trailing_punctuation_and_normalises_dot_slash() {
        let base_path = Path::new("/tmp/pkg/SKILL.md");
        let refs = extract_references("Run `./payload.sh` to install.", base_path);
        assert!(
            refs.iter().any(|p| p.ends_with("payload.sh")),
            "must resolve payload.sh from backtick-wrapped exec ref; got {refs:?}"
        );
        assert!(
            refs.iter().all(|p| !p.to_string_lossy().contains('`')),
            "no captured reference may retain a backtick; got {refs:?}"
        );
        // `[a](./scripts/x.sh)` must not also yield a phantom `scripts/x.sh)`.
        let refs = extract_references("[a](./scripts/x.sh)", base_path);
        assert!(
            refs.iter().all(|p| !p.to_string_lossy().contains(')')),
            "no captured reference may retain a paren; got {refs:?}"
        );
        assert!(
            refs.iter().any(|p| p.ends_with("scripts/x.sh")),
            "must resolve scripts/x.sh; got {refs:?}"
        );
    }

    /// # Contract
    ///
    /// A `source`/`include`/`run`/`execute` directive whose argument ends
    /// in a non-script segment after a script extension (e.g.
    /// `source utils.sh.inc`) MUST NOT capture the truncated prefix
    /// (`utils.sh`). Pre-fix the unanchored `command_pattern` backtracked
    /// to the earlier `.sh`, queuing a phantom path that never exists.
    #[test]
    fn extract_references_command_directive_does_not_truncate_compound_extension() {
        let base_path = Path::new("/tmp/pkg/SKILL.md");
        for sample in [
            "source utils.sh.inc",
            "include vendor/lib.js.gz",
            "run handler.py.orig",
        ] {
            let refs = extract_references(sample, base_path);
            assert!(
                refs.is_empty(),
                "compound-extension directive must not yield a truncated phantom: \
                 {sample:?} -> {refs:?}"
            );
        }
    }

    /// # Contract
    ///
    /// The boundary added to `command_pattern` must not regress ordinary
    /// `source`/`include` directives: a script referenced via a bare
    /// directive (with or without trailing punctuation, with stacked
    /// script extensions) is still queued.
    #[test]
    fn extract_references_command_directive_resolves_real_scripts() {
        let base_path = Path::new("/tmp/pkg/SKILL.md");
        let cases: &[(&str, &str)] = &[
            ("source scripts/setup.sh", "scripts/setup.sh"),
            ("run install.sh && echo done", "install.sh"),
            ("execute \"deploy.py\"", "deploy.py"),
            ("source stage.sh.py", "stage.sh.py"),
        ];
        for (sample, expected) in cases {
            let refs = extract_references(sample, base_path);
            assert!(
                refs.iter().any(|p| p.ends_with(expected)),
                "must resolve {expected:?} from {sample:?}; got {refs:?}"
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
