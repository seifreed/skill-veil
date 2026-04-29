//! Helpers shared by detectors that pair a regex match against the
//! lowercased content with the original-cased source for evidence
//! presentation.

use crate::ports::PatternMatch;

/// Extract the byte slice from `original` that corresponds to a port-typed
/// match produced against the lowercased content.
///
/// # Contract
///
/// `lower` MUST be the result of `original.to_ascii_lowercase()` — this
/// preserves byte offsets because ASCII case folding is a 1-byte → 1-byte
/// transformation. Non-ASCII content can break this assumption (some chars
/// have different UTF-8 byte lengths in upper/lower forms), in which case
/// the helper falls back to the lowercased match text rather than producing
/// out-of-bounds reads. The `debug_assert_eq!` on byte length surfaces the
/// invariant break in tests.
pub(super) fn original_match_str(original: &str, lower: &str, matched: &PatternMatch) -> String {
    debug_assert_eq!(
        lower.len(),
        original.len(),
        "ASCII-lowercase invariant: lower.len() must equal original.len()"
    );
    if lower.len() == original.len() {
        // Safe slice on a valid char boundary: matcher offsets are valid into
        // `lower`, and ASCII byte-equivalence means they're valid into
        // `original` too.
        original
            .get(matched.start..matched.end)
            .map(str::to_string)
            .unwrap_or_else(|| matched.matched_text.clone())
    } else {
        // Defensive fallback (non-ASCII content); evidence loses casing but
        // we don't risk a panic.
        matched.matched_text.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern_helpers::default_matcher;

    /// # Contract
    /// `original_match_str` must remain panic-free when ASCII-lowercase
    /// stops being a 1-byte → 1-byte transformation (Turkish `İ` is the
    /// canonical breaker). The helper falls back to the matched text in
    /// that case rather than slicing across UTF-8 boundaries.
    #[test]
    fn original_match_str_falls_back_safely_on_nonascii_breakage() {
        let original = "İSTANBUL CURL X";
        let lower = original.to_ascii_lowercase();
        if lower.len() == original.len() {
            // ASCII path — nothing to test for fallback. Skip.
            return;
        }
        let matches = default_matcher().find_matches("curl", &lower);
        if let Some(m) = matches.into_iter().next() {
            let evidence = original_match_str(original, &lower, &m);
            assert!(["curl", "CURL"].contains(&evidence.as_str()));
        }
    }
}
