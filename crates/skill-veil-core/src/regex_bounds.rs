//! Shared size bounds for compiling `regex` patterns that originate from
//! rule packs (YAML official/community packs and external NOVA packs).
//!
//! Rust's `regex` crate is backtracking-free, so the risk is not ReDoS but
//! the memory a pathological pattern (`a{1000000}{2}`, multi-MB alternations)
//! can request: the NFA at compile time and the lazy DFA cache at match time.
//! The crate defaults (10 MiB NFA / 2 MiB DFA) already bound this, but every
//! site that compiles an attacker-influenced pattern applies the SAME tighter
//! 8 MiB caps through this one helper so the bound can never silently differ
//! between the YAML matcher and the NOVA evaluator/parser.

use regex::{Regex, RegexBuilder};

/// Upper bound on the compiled NFA size for a single pattern. Tightened from
/// the crate's 10 MiB default so genuinely-complex curated IOC patterns still
/// compile while catastrophic patterns are rejected at compile time.
pub(crate) const REGEX_NFA_SIZE_LIMIT: usize = 8 * (1 << 20);

/// Upper bound on the lazy DFA cache for a single compiled pattern. Bounds
/// runtime memory growth on adversarial inputs, complementing the NFA cap.
pub(crate) const REGEX_DFA_SIZE_LIMIT: usize = 8 * (1 << 20);

/// A `RegexBuilder` for `pattern` with the shared size caps applied. Callers
/// that need extra flags (e.g. `case_insensitive`) chain them before `build`.
pub(crate) fn bounded_regex_builder(pattern: &str) -> RegexBuilder {
    let mut builder = RegexBuilder::new(pattern);
    builder
        .size_limit(REGEX_NFA_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT);
    builder
}

/// Compile `pattern` with the shared size caps. Returns `Err` for invalid
/// syntax or a pattern that exceeds the caps.
pub(crate) fn build_bounded_regex(pattern: &str) -> Result<Regex, regex::Error> {
    bounded_regex_builder(pattern).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: an ordinary pattern compiles through the bounded builder.
    #[test]
    fn build_bounded_regex_accepts_ordinary_pattern() {
        assert!(build_bounded_regex(r"\b(curl|wget)\b\s+https?://").is_ok());
    }

    /// Contract: a pattern whose automaton exceeds the cap is rejected at
    /// compile time rather than compiling and exhausting memory at match time.
    #[test]
    fn build_bounded_regex_rejects_oversized_pattern() {
        assert!(build_bounded_regex("a{1000000}{2}").is_err());
    }

    /// Contract: the builder form carries the same caps, so flag-augmented
    /// (e.g. case-insensitive) compiles are bounded identically.
    #[test]
    fn bounded_regex_builder_rejects_oversized_pattern() {
        assert!(bounded_regex_builder("a{1000000}{2}")
            .case_insensitive(true)
            .build()
            .is_err());
    }
}
