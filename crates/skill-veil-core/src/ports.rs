//! Port traits for dependency inversion
//!
//! These traits define the interfaces that the domain layer depends on,
//! allowing infrastructure implementations to be swapped. This enables:
//!
//! - **Testing**: Mock implementations for unit tests
//! - **Flexibility**: Alternative implementations (e.g., different parsers)
//! - **Decoupling**: Core logic is independent of specific libraries
//!
//! # Available Traits
//!
//! - [`MarkdownParser`]: Parse markdown content into sections
//! - [`PatternMatcher`]: Match patterns (regex) in text
//! - [`FileSystemProvider`]: File system operations
//!
//! # Default Implementations
//!
//! Default implementations are provided in the [`adapters`] module:
//! - [`PulldownMarkdownParser`]: Uses pulldown-cmark
//! - [`RegexPatternMatcher`]: Uses the regex crate
//! - [`StdFileSystemProvider`]: Uses std::fs
//!
//! [`adapters`]: crate::adapters
//! [`PulldownMarkdownParser`]: crate::adapters::PulldownMarkdownParser
//! [`RegexPatternMatcher`]: crate::adapters::RegexPatternMatcher
//! [`StdFileSystemProvider`]: crate::adapters::StdFileSystemProvider

use crate::analyzer::Section;
use std::path::{Path, PathBuf};

/// Error type for parser operations
///
/// Returned by [`MarkdownParser::parse_sections`] when parsing fails.
#[derive(Debug, thiserror::Error)]
pub enum ParserError {
    /// Failed to parse the content
    #[error("Failed to parse content: {0}")]
    ParseError(String),
}

/// Error type for file system operations
///
/// Returned by [`FileSystemProvider`] methods when operations fail.
#[derive(Debug, thiserror::Error)]
pub enum FileSystemError {
    /// I/O error from the underlying file system
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// The specified path was not found
    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),
}

/// Trait for markdown parsing - allows swapping pulldown-cmark for other parsers
///
/// Implement this trait to provide custom markdown parsing logic.
/// The default implementation is [`PulldownMarkdownParser`].
///
/// [`PulldownMarkdownParser`]: crate::adapters::PulldownMarkdownParser
pub trait MarkdownParser: Send + Sync {
    /// Parse markdown content into sections
    ///
    /// Extracts heading-based sections from markdown content, including
    /// any code blocks within each section.
    fn parse_sections(&self, content: &str) -> Result<Vec<Section>, ParserError>;
}

/// Trait for pattern matching - allows swapping regex for other matchers
///
/// Implement this trait to provide custom pattern matching logic.
/// The default implementation is [`RegexPatternMatcher`].
///
/// [`RegexPatternMatcher`]: crate::adapters::RegexPatternMatcher
pub trait PatternMatcher: Send + Sync {
    /// Find all matches of a pattern in the given text
    ///
    /// Returns a vector of [`PatternMatch`] for each occurrence found.
    fn find_matches(&self, pattern: &str, text: &str) -> Vec<PatternMatch>;

    /// Compile a pattern for efficient reuse
    ///
    /// Use this when the same pattern will be matched against multiple texts.
    fn compile(&self, pattern: &str) -> Result<CompiledPattern, PatternError>;
}

/// A match found by the pattern matcher
///
/// Contains the position and content of a single pattern match.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Start offset in the original text (0-based, in bytes)
    pub start: usize,
    /// End offset in the original text (exclusive, in bytes)
    pub end: usize,
    /// The matched text content
    pub matched_text: String,
}

/// Type alias for pattern matching function used in CompiledPattern
type MatchFn = Box<dyn Fn(&str) -> Vec<PatternMatch> + Send + Sync>;

/// A compiled pattern for efficient reuse
///
/// Created by [`PatternMatcher::compile`] for patterns that will be
/// matched against multiple texts.
pub struct CompiledPattern {
    inner: MatchFn,
}

impl CompiledPattern {
    /// Create a new compiled pattern from a match function
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&str) -> Vec<PatternMatch> + Send + Sync + 'static,
    {
        Self { inner: Box::new(f) }
    }

    /// Find all matches in the given text
    pub fn find_matches(&self, text: &str) -> Vec<PatternMatch> {
        (self.inner)(text)
    }
}

/// Error type for pattern operations
///
/// Returned by [`PatternMatcher::compile`] when pattern compilation fails.
#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    /// The pattern syntax is invalid
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
}

/// Raw file content returned by the filesystem port.
///
/// The core can decide how to decode these bytes depending on context.
#[derive(Debug, Clone)]
pub struct FileContent {
    bytes: Vec<u8>,
}

impl FileContent {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn decode_utf8_lossy(&self) -> DecodedText {
        let decode_warning = std::str::from_utf8(&self.bytes).is_err();
        DecodedText {
            text: String::from_utf8_lossy(&self.bytes).into_owned(),
            decode_warning,
        }
    }
}

/// Decoded text plus whether lossy decoding was required.
#[derive(Debug, Clone)]
pub struct DecodedText {
    pub text: String,
    pub decode_warning: bool,
}

/// Trait for file system operations - allows mocking in tests
///
/// Implement this trait to provide custom file system access.
/// The default implementation is [`StdFileSystemProvider`].
///
/// [`StdFileSystemProvider`]: crate::adapters::StdFileSystemProvider
pub trait FileSystemProvider: Send + Sync {
    /// Read raw file contents
    ///
    /// # Errors
    /// Returns [`FileSystemError::PathNotFound`] if the file does not exist,
    /// or [`FileSystemError::IoError`] for other I/O errors.
    fn read_file_bytes(&self, path: &Path) -> Result<FileContent, FileSystemError>;

    /// List files in a directory matching a glob pattern
    ///
    /// # Arguments
    /// * `path` - The directory to search
    /// * `pattern` - A glob pattern (e.g., "*.md")
    /// * `recursive` - Whether to search subdirectories
    fn list_files(
        &self,
        path: &Path,
        pattern: &str,
        recursive: bool,
    ) -> Result<Vec<PathBuf>, FileSystemError>;

    /// Check if a path exists
    fn exists(&self, path: &Path) -> bool;
}
