//! Pattern matcher implementation using the regex crate

use crate::ports::{Captures, CompiledPattern, PatternError, PatternMatch, PatternMatcher};
use regex::Regex;
use std::sync::Arc;

/// Pattern matcher implementation using the regex crate
#[derive(Debug, Default, Clone)]
pub struct RegexPatternMatcher;

impl RegexPatternMatcher {
    /// Create a new regex-based pattern matcher
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

fn match_to_pattern(m: regex::Match<'_>) -> PatternMatch {
    PatternMatch {
        start: m.start(),
        end: m.end(),
        matched_text: m.as_str().to_string(),
    }
}

fn captures_to_groups(caps: &regex::Captures<'_>) -> Captures {
    let groups = caps
        .iter()
        .map(|opt| opt.map(match_to_pattern))
        .collect::<Vec<_>>();
    Captures::new(groups)
}

impl PatternMatcher for RegexPatternMatcher {
    fn find_matches(&self, pattern: &str, text: &str) -> Vec<PatternMatch> {
        match Regex::new(pattern) {
            Ok(re) => re.find_iter(text).map(match_to_pattern).collect(),
            Err(e) => {
                tracing::warn!("Invalid regex pattern '{}': {}", pattern, e);
                Vec::new()
            }
        }
    }

    fn is_match(&self, pattern: &str, text: &str) -> bool {
        match Regex::new(pattern) {
            Ok(re) => re.is_match(text),
            Err(e) => {
                tracing::warn!("Invalid regex pattern '{}': {}", pattern, e);
                false
            }
        }
    }

    fn captures_iter(&self, pattern: &str, text: &str) -> Vec<Captures> {
        match Regex::new(pattern) {
            Ok(re) => re
                .captures_iter(text)
                .map(|c| captures_to_groups(&c))
                .collect(),
            Err(e) => {
                tracing::warn!("Invalid regex pattern '{}': {}", pattern, e);
                Vec::new()
            }
        }
    }

    fn compile(&self, pattern: &str) -> Result<CompiledPattern, PatternError> {
        let re =
            Arc::new(Regex::new(pattern).map_err(|e| PatternError::InvalidPattern(e.to_string()))?);
        let re_find = Arc::clone(&re);
        let re_is_match = Arc::clone(&re);
        let re_captures = re;

        Ok(CompiledPattern::new(
            Box::new(move |text: &str| re_find.find_iter(text).map(match_to_pattern).collect()),
            Box::new(move |text: &str| re_is_match.is_match(text)),
            Box::new(move |text: &str| {
                re_captures
                    .captures_iter(text)
                    .map(|c| captures_to_groups(&c))
                    .collect()
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// `find_matches` returns every regex hit in source order with byte
    /// offsets and the matched substring preserved verbatim.
    #[test]
    fn find_matches_returns_every_hit_in_source_order() {
        let matcher = RegexPatternMatcher::new();
        let matches = matcher.find_matches(r"\d+", "abc 123 def 456");

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].matched_text, "123");
        assert_eq!(matches[1].matched_text, "456");
    }

    /// # Contract
    /// `find_matches` returns an empty vector when the pattern does not
    /// occur in the text — never a sentinel match.
    #[test]
    fn find_matches_returns_empty_when_pattern_absent() {
        let matcher = RegexPatternMatcher::new();
        let matches = matcher.find_matches(r"\d+", "no numbers here");

        assert!(matches.is_empty());
    }

    /// # Contract
    /// A `CompiledPattern` reuses one compilation across `find_matches`,
    /// `is_match`, and `captures_iter`; all three answer consistently.
    #[test]
    fn compile_shares_state_across_three_operations() {
        let matcher = RegexPatternMatcher::new();
        let compiled = matcher.compile(r"hello\s+world").unwrap();

        let matches = compiled.find_matches("say hello   world!");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_text, "hello   world");

        assert!(compiled.is_match("say hello   world!"));
        assert!(!compiled.is_match("say goodbye"));

        let caps = compiled.captures_iter("say hello   world!");
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].get(0).unwrap().matched_text, "hello   world");
    }

    /// # Contract
    /// `compile` surfaces invalid regex syntax as `PatternError`; it must
    /// never panic so tests can drive validation via `is_err()`.
    #[test]
    fn compile_returns_err_for_invalid_regex_syntax() {
        let matcher = RegexPatternMatcher::new();
        let result = matcher.compile(r"[invalid");

        assert!(result.is_err());
    }

    /// # Contract
    /// `is_match` and `captures_iter` on the trait must agree with
    /// `find_matches` on whether a pattern occurs.
    #[test]
    fn is_match_and_captures_agree_with_find_matches() {
        let matcher = RegexPatternMatcher::new();
        let text = "user@example.com talks to admin@example.com";
        let pattern = r"(\w+)@example\.com";

        assert!(matcher.is_match(pattern, text));
        assert_eq!(matcher.find_matches(pattern, text).len(), 2);

        let caps = matcher.captures_iter(pattern, text);
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].get(1).unwrap().matched_text, "user");
        assert_eq!(caps[1].get(1).unwrap().matched_text, "admin");
    }
}
