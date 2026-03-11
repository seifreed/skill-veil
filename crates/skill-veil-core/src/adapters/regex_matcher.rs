//! Pattern matcher implementation using the regex crate

use crate::ports::{CompiledPattern, PatternError, PatternMatch, PatternMatcher};
use regex::Regex;

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

impl PatternMatcher for RegexPatternMatcher {
    fn find_matches(&self, pattern: &str, text: &str) -> Vec<PatternMatch> {
        match Regex::new(pattern) {
            Ok(re) => re
                .find_iter(text)
                .map(|m| PatternMatch {
                    start: m.start(),
                    end: m.end(),
                    matched_text: m.as_str().to_string(),
                })
                .collect(),
            Err(e) => {
                tracing::warn!("Invalid regex pattern '{}': {}", pattern, e);
                Vec::new()
            }
        }
    }

    fn compile(&self, pattern: &str) -> Result<CompiledPattern, PatternError> {
        let re = Regex::new(pattern).map_err(|e| PatternError::InvalidPattern(e.to_string()))?;

        Ok(CompiledPattern::new(move |text: &str| {
            re.find_iter(text)
                .map(|m| PatternMatch {
                    start: m.start(),
                    end: m.end(),
                    matched_text: m.as_str().to_string(),
                })
                .collect()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_matches() {
        let matcher = RegexPatternMatcher::new();
        let matches = matcher.find_matches(r"\d+", "abc 123 def 456");

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].matched_text, "123");
        assert_eq!(matches[1].matched_text, "456");
    }

    #[test]
    fn test_find_no_matches() {
        let matcher = RegexPatternMatcher::new();
        let matches = matcher.find_matches(r"\d+", "no numbers here");

        assert!(matches.is_empty());
    }

    #[test]
    fn test_compile_pattern() {
        let matcher = RegexPatternMatcher::new();
        let compiled = matcher.compile(r"hello\s+world").unwrap();

        let matches = compiled.find_matches("say hello   world!");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_text, "hello   world");
    }

    #[test]
    fn test_invalid_pattern() {
        let matcher = RegexPatternMatcher::new();
        let result = matcher.compile(r"[invalid");

        assert!(result.is_err());
    }
}
