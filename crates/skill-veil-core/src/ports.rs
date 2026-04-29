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

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A section parsed from a markdown document.
///
/// This is the output contract of the [`MarkdownParser`] port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub level: u8,
    pub content: String,
    pub code_blocks: Vec<CodeBlock>,
}

/// A fenced code block within a [`Section`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBlock {
    pub language: Option<String>,
    pub code: String,
}

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

    /// Check whether a pattern occurs in the given text.
    ///
    /// Implementations can override this for performance; the default
    /// derives the answer from [`PatternMatcher::find_matches`].
    fn is_match(&self, pattern: &str, text: &str) -> bool {
        !self.find_matches(pattern, text).is_empty()
    }

    /// Iterate captures (full match plus capture groups) over a pattern.
    ///
    /// Each [`Captures`] entry corresponds to one match in `text`. Group
    /// `0` is the full match; subsequent groups follow the pattern's
    /// declaration order. Groups that did not participate in a particular
    /// match are returned as `None`.
    fn captures_iter(&self, pattern: &str, text: &str) -> Vec<Captures>;
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

/// Capture groups produced by [`PatternMatcher::captures_iter`].
///
/// Group `0` is the full match. Groups that did not participate in a
/// particular match are stored as `None`. Use [`Captures::get`] for a
/// nullable lookup that mirrors the regex crate's `.get(idx)` ergonomics
/// without leaking the concrete `Match` type.
#[derive(Debug, Clone)]
pub struct Captures {
    groups: Vec<Option<PatternMatch>>,
}

impl Captures {
    /// Build captures from a vector of optional groups.
    #[must_use]
    pub fn new(groups: Vec<Option<PatternMatch>>) -> Self {
        Self { groups }
    }

    /// Return the capture group at `idx`, if present.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&PatternMatch> {
        self.groups.get(idx).and_then(Option::as_ref)
    }

    /// Total number of capture slots (including non-participating groups).
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Whether the captures collection holds no groups.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

/// Closure stored inside [`CompiledPattern`] for finding matches.
type FindFn = Box<dyn Fn(&str) -> Vec<PatternMatch> + Send + Sync>;
/// Closure stored inside [`CompiledPattern`] for membership tests.
type IsMatchFn = Box<dyn Fn(&str) -> bool + Send + Sync>;
/// Closure stored inside [`CompiledPattern`] for capture iteration.
type CapturesFn = Box<dyn Fn(&str) -> Vec<Captures> + Send + Sync>;

/// A compiled pattern for efficient reuse
///
/// Created by [`PatternMatcher::compile`] for patterns that will be
/// matched against multiple texts. The three operation closures share
/// the underlying compiled state in the adapter so that a single
/// pattern compilation services all three operations.
pub struct CompiledPattern {
    find: FindFn,
    is_match: IsMatchFn,
    captures: CapturesFn,
}

impl CompiledPattern {
    /// Build a compiled pattern from its three operation closures.
    ///
    /// Adapters are expected to share their compiled state (e.g. an
    /// `Arc<Regex>`) across the three closures so that `find_matches`,
    /// `is_match`, and `captures_iter` all reuse the same compilation.
    #[must_use]
    pub fn new(find: FindFn, is_match: IsMatchFn, captures: CapturesFn) -> Self {
        Self {
            find,
            is_match,
            captures,
        }
    }

    /// Find every occurrence of the pattern in `text`.
    pub fn find_matches(&self, text: &str) -> Vec<PatternMatch> {
        (self.find)(text)
    }

    /// Whether the pattern occurs at least once in `text`.
    pub fn is_match(&self, text: &str) -> bool {
        (self.is_match)(text)
    }

    /// Iterate captures (full match plus groups) for every occurrence.
    pub fn captures_iter(&self, text: &str) -> Vec<Captures> {
        (self.captures)(text)
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

/// Subset of `std::fs::Metadata` exposed through the
/// [`FileSystemProvider`] port. Keeping the surface minimal lets test
/// adapters synthesize values without instantiating real OS metadata.
#[derive(Debug, Clone, Copy)]
pub struct FileMeta {
    /// Total size of the file in bytes.
    pub len: u64,
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

    /// Look up the size (and other minimal metadata) for a path.
    ///
    /// Adapters MUST resolve this through the same backing store as
    /// `read_file_bytes` and `list_files` so test doubles see consistent
    /// behaviour. The default implementation here delegates to
    /// `read_file_bytes` and reports the resulting byte length, which lets
    /// every existing adapter pick up the new method without code changes
    /// while keeping the contract honoured. Adapters with cheaper metadata
    /// access (real filesystem, mocks with explicit metadata) should
    /// override this method.
    ///
    /// # Errors
    /// Returns [`FileSystemError::PathNotFound`] when the path does not
    /// exist, or [`FileSystemError::IoError`] for other I/O failures.
    fn metadata(&self, path: &Path) -> Result<FileMeta, FileSystemError> {
        let bytes = self.read_file_bytes(path)?;
        Ok(FileMeta {
            len: bytes.as_bytes().len() as u64,
        })
    }
}
