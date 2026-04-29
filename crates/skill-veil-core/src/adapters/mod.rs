//! Infrastructure adapters implementing port traits
//!
//! This module provides default implementations of the port traits
//! using common libraries (pulldown-cmark, regex, std::fs).

pub mod pattern_helpers;
mod pulldown_parser;
mod regex_matcher;
mod std_filesystem;

pub use pulldown_parser::PulldownMarkdownParser;
pub use regex_matcher::RegexPatternMatcher;
pub use std_filesystem::StdFileSystemProvider;
