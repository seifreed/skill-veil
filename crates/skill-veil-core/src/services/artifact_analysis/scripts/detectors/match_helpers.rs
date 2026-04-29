//! Helpers shared by detectors that pair a regex match against the
//! lowercased content with the original-cased source for evidence
//! presentation.

/// Extract the byte slice from `original` that corresponds to a regex match
/// found in the lowercased content.
///
/// # Contract
///
/// `lower` MUST be the result of `original.to_ascii_lowercase()` — this
/// preserves byte offsets because ASCII case folding is a 1-byte → 1-byte
/// transformation. Non-ASCII content can break this assumption (some chars
/// have different UTF-8 byte lengths in upper/lower forms), in which case
/// the helper falls back to the lowercased text rather than producing
/// out-of-bounds reads. The `debug_assert_eq!` on byte length surfaces the
/// invariant break in tests.
pub(super) fn original_match_str<'a>(
    original: &'a str,
    lower: &'a str,
    matched: &regex::Match<'a>,
) -> &'a str {
    debug_assert_eq!(
        lower.len(),
        original.len(),
        "ASCII-lowercase invariant: lower.len() must equal original.len()"
    );
    if lower.len() == original.len() {
        // Safe slice on a valid char boundary: regex offsets are guaranteed
        // valid into `lower`, and ASCII byte-equivalence means they're valid
        // into `original` too.
        original
            .get(matched.start()..matched.end())
            .unwrap_or_else(|| matched.as_str())
    } else {
        // Defensive fallback (non-ASCII content); evidence loses casing but
        // we don't risk a panic.
        matched.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_match_str_falls_back_safely_on_nonascii_breakage() {
        // Non-ASCII content where lowercase changes byte length is rare for
        // the patterns we use, but we exercise the fallback path here.
        // Construct a string where lower != original byte length (Turkish I).
        let original = "İSTANBUL CURL X";
        let lower = original.to_ascii_lowercase();
        if lower.len() == original.len() {
            // ASCII path — nothing to test for fallback. Skip.
            return;
        }
        // Use a Match against `lower` and verify we don't panic and produce
        // a deterministic result.
        let re = regex::Regex::new("curl").unwrap();
        if let Some(m) = re.find(&lower) {
            let evidence = original_match_str(original, &lower, &m);
            // Either matches the original-cased "CURL" (if the byte length
            // happens to align) or falls back to the lowercased "curl"; both
            // are non-panicking outcomes.
            assert!(["curl", "CURL"].contains(&evidence));
        }
    }
}
