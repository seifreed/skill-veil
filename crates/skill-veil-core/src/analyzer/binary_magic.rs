//! Pure byte-level magic-number probe used to catch artifacts that are
//! actually binary archives (ZIP, gzip, PE/EXE, ELF, PNG, BMP) but carry
//! a markdown-style file extension.
//!
//! Lives at the analyzer layer because the byte-loading site is here
//! (see `analyzer/document.rs::from_file_with_provider`). Returning the
//! kind name (rather than a `Finding`) keeps this module dependency-free
//! so callers in other layers can build their own `Finding` shape.
//!
//! Sample `01d1232c` (zuckerbot) — a ZIP archive named `Skill.MD` —
//! motivated the original detector. Today's wiring catches it both at
//! the entrypoint loader and at the referenced-file loader.

use std::path::Path;

const MARKDOWN_EXTENSIONS: &[&str] = &["md", "markdown"];

const BINARY_MAGICS: &[(&[u8], &str)] = &[
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b", "gzip"),
    (b"MZ\x90", "PE/EXE"),
    (b"\x7fELF", "ELF"),
    (b"\x89PNG", "PNG"),
    (b"BM", "BMP"),
];

/// Returns the kind label (e.g. `"ZIP"`) when `path` carries a markdown
/// extension AND `bytes` starts with one of the known binary magic
/// signatures. Returns `None` otherwise.
///
/// # Contract
/// - Extension match is case-insensitive (`.MD` and `.markdown`
///   recognized).
/// - The kind label is a static string — callers can stash it in
///   `SkillDocument` without allocating.
/// - The probe is byte-prefix only; it intentionally does not attempt
///   to fully validate the archive format. False positives are
///   acceptable here because the rule emitted downstream is a high-
///   confidence content-obfuscation signal.
pub(crate) fn detect_binary_disguise_kind(path: &Path, bytes: &[u8]) -> Option<&'static str> {
    if !is_markdown_extension(path) {
        return None;
    }
    BINARY_MAGICS
        .iter()
        .find(|(magic, _)| bytes.starts_with(magic))
        .map(|(_, kind)| *kind)
}

fn is_markdown_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| {
            MARKDOWN_EXTENSIONS
                .iter()
                .any(|known| ext.eq_ignore_ascii_case(known))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Contract: a `.md` artifact whose bytes start with the ZIP local
    /// file header (`PK\x03\x04`) is reported as a `ZIP` disguise.
    /// Anchors the `01d1232c` sample.
    #[test]
    fn detect_binary_disguise_kind_flags_zip_named_md() {
        let bytes = b"PK\x03\x04rest of zip body";
        let kind = detect_binary_disguise_kind(&PathBuf::from("Skill.MD"), bytes);
        assert_eq!(kind, Some("ZIP"));
    }

    /// Contract: identical bytes, but the path has a `.zip` extension —
    /// no disguise (the file is honest about its type), so we return
    /// `None`. Pins the negative case so we never flag well-named
    /// binaries.
    #[test]
    fn detect_binary_disguise_kind_ignores_honest_zip_extension() {
        let bytes = b"PK\x03\x04rest of zip body";
        let kind = detect_binary_disguise_kind(&PathBuf::from("payload.zip"), bytes);
        assert_eq!(kind, None);
    }

    /// Contract: a real markdown file (UTF-8 text starting with `#`)
    /// returns `None`. Pins the negative case for the common path so the
    /// detector does not silently widen.
    #[test]
    fn detect_binary_disguise_kind_returns_none_for_real_markdown() {
        let bytes = b"# Hello\n\nThis is a real skill.\n";
        assert_eq!(
            detect_binary_disguise_kind(&PathBuf::from("SKILL.md"), bytes),
            None
        );
    }

    /// Contract: each currently registered magic-byte family is
    /// detected. Acts as a lock against accidentally dropping a magic
    /// from `BINARY_MAGICS` during a refactor.
    #[test]
    fn detect_binary_disguise_kind_covers_all_magics() {
        let cases = [
            (&b"\x1f\x8b\x08\x00"[..], "gzip"),
            (&b"MZ\x90\x00"[..], "PE/EXE"),
            (&b"\x7fELF\x02"[..], "ELF"),
            (&b"\x89PNG\r\n\x1a\n"[..], "PNG"),
            (&b"BMabc"[..], "BMP"),
        ];
        for (bytes, expected_kind) in cases {
            let kind = detect_binary_disguise_kind(&PathBuf::from("doc.md"), bytes);
            assert_eq!(kind, Some(expected_kind), "magic {expected_kind} regressed");
        }
    }

    /// Contract: case-insensitive extension match works for
    /// `.markdown` and uppercase variants.
    #[test]
    fn detect_binary_disguise_kind_recognizes_markdown_extension_variants() {
        let bytes = b"PK\x03\x04";
        for path in ["doc.md", "doc.MD", "doc.Md", "doc.markdown", "doc.MARKDOWN"] {
            assert_eq!(
                detect_binary_disguise_kind(&PathBuf::from(path), bytes),
                Some("ZIP"),
                "{path} should be recognized as markdown"
            );
        }
    }
}
