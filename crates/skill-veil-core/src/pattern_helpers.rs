//! Helpers for hardcoded domain patterns.
//!
//! The hexagonal contract sealed in [`crate::ports`] requires the domain
//! to depend only on [`PatternMatcher`]; concrete regex usage is confined
//! to [`crate::adapters::RegexPatternMatcher`]. Heuristics that rely on
//! literal patterns (e.g. instruction-bait detection in
//! [`crate::analyzer::assessment`]) still need a one-shot compilation
//! against the default adapter so they can sit in `LazyLock` statics
//! without taking on `regex::Regex` themselves.
//!
//! [`default_matcher`] provides the process-wide default adapter. The
//! [`lazy_pattern!`] macro hides the boilerplate of building a
//! [`crate::ports::CompiledPattern`] inside a `LazyLock` so callsites
//! read like the prior `LazyLock<Regex>` declarations they replaced.

use crate::adapters::RegexPatternMatcher;
use crate::ports::PatternMatcher;
use std::sync::OnceLock;

/// Shared adapter used by [`lazy_pattern!`] for hardcoded domain
/// patterns. Tests that need a different matcher inject one through
/// `Scanner::with_custom_adapters` rather than swapping this default.
#[must_use]
pub fn default_matcher() -> &'static (dyn PatternMatcher + 'static) {
    static MATCHER: OnceLock<RegexPatternMatcher> = OnceLock::new();
    MATCHER.get_or_init(RegexPatternMatcher::new)
}

/// Declare a `LazyLock<CompiledPattern>` over a hardcoded pattern.
///
/// The pattern is compiled lazily through [`default_matcher`]. Compile
/// failures panic at first use because hardcoded patterns are part of
/// the binary contract — a malformed literal is a build-time bug, not
/// runtime data. Tests cover the patterns directly so the panic only
/// fires when a developer hand-edits an invalid literal.
///
/// # Examples
/// ```ignore
/// lazy_pattern!(MY_RE, r"(?i)\bfoo\b");
/// // ...
/// if MY_RE.is_match(text) { /* ... */ }
/// ```
#[macro_export]
macro_rules! lazy_pattern {
    ($name:ident, $pattern:expr $(,)?) => {
        $crate::lazy_pattern!(@build (), $name, $pattern);
    };
    ($vis:vis $name:ident, $pattern:expr $(,)?) => {
        $crate::lazy_pattern!(@build ($vis), $name, $pattern);
    };
    (@build ($($vis:tt)*), $name:ident, $pattern:expr) => {
        $($vis)* static $name: std::sync::LazyLock<$crate::ports::CompiledPattern> =
            std::sync::LazyLock::new(|| {
                $crate::pattern_helpers::default_matcher()
                    .compile($pattern)
                    .expect(concat!(
                        "hardcoded pattern must compile: ",
                        stringify!($name)
                    ))
            });
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// `default_matcher` returns a stable `'static` reference; repeated
    /// calls reuse the same instance so `LazyLock<CompiledPattern>`
    /// statics share one regex compilation across the process.
    #[test]
    fn default_matcher_returns_stable_singleton() {
        let a: *const dyn PatternMatcher = default_matcher();
        let b: *const dyn PatternMatcher = default_matcher();
        assert!(std::ptr::addr_eq(a, b));
    }

    lazy_pattern!(LAZY_DIGITS, r"\d+");

    /// # Contract
    /// `lazy_pattern!` produces a `LazyLock<CompiledPattern>` that
    /// drives `find_matches`, `is_match`, and `captures_iter` in lockstep.
    #[test]
    fn lazy_pattern_macro_drives_all_three_operations() {
        assert!(LAZY_DIGITS.is_match("abc 42"));
        assert!(!LAZY_DIGITS.is_match("no digits here"));
        assert_eq!(LAZY_DIGITS.find_matches("a 1 b 2 c").len(), 2);
        assert_eq!(LAZY_DIGITS.captures_iter("a 1 b 2 c").len(), 2);
    }
}
