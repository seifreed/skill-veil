//! Small text helpers shared across CLI subsystems.

/// Clip `text` to at most `max_chars` Unicode scalar values, returning the
/// (possibly clipped) text and whether truncation occurred. Counting by
/// `chars()` rather than bytes keeps a multi-byte boundary intact so the
/// result is always valid UTF-8.
pub(crate) fn clip_to_chars(text: &str, max_chars: usize) -> (String, bool) {
    if text.chars().count() <= max_chars {
        return (text.to_string(), false);
    }
    (text.chars().take(max_chars).collect(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_to_chars_leaves_short_text_untouched() {
        let (out, clipped) = clip_to_chars("héllo", 16);

        assert_eq!(out, "héllo");
        assert!(!clipped);
    }

    /// # Contract
    ///
    /// Clipping counts Unicode scalar values, not bytes: a 5-char limit on a
    /// string of multi-byte chars yields exactly 5 chars and flags truncation.
    #[test]
    fn clip_to_chars_truncates_by_char_count() {
        let (out, clipped) = clip_to_chars("ααααααα", 5);

        assert_eq!(out.chars().count(), 5);
        assert!(clipped);
    }
}
