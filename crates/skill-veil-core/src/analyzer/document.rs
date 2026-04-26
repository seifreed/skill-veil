use crate::analyzer::assessment::assess_artifact;
use crate::analyzer::references::extract_references;
use crate::analyzer::types::{AnalyzerError, CodeBlock, Section, SkillDocument};
use crate::ports::{FileSystemError, FileSystemProvider, MarkdownParser};
use std::path::{Path, PathBuf};

impl SkillDocument {
    pub fn from_file_with_provider<P: MarkdownParser, F: FileSystemProvider>(
        path: impl AsRef<Path>,
        parser: &P,
        fs_provider: &F,
    ) -> Result<Self, AnalyzerError> {
        let path = path.as_ref();
        let bytes = fs_provider
            .read_file_bytes(path)
            .map_err(file_system_error_to_io_error)?
            .as_bytes()
            .to_vec();
        let decode_warning = std::str::from_utf8(&bytes).is_err();
        let content = String::from_utf8_lossy(&bytes).into_owned();
        Self::parse_with_parser(path.to_path_buf(), content, parser).map(|mut doc| {
            doc.decode_warning = decode_warning;
            doc
        })
    }

    pub fn parse_with_parser<P: MarkdownParser>(
        path: PathBuf,
        content: String,
        parser: &P,
    ) -> Result<Self, AnalyzerError> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let (sections, parse_warning) = match parser.parse_sections(&content) {
            Ok(sections) => (sections, false),
            Err(_error) => (Vec::new(), true),
        };
        let referenced_files = extract_references(&content, &path);
        let assessment = assess_artifact(path.as_path(), &content, &sections, &referenced_files);

        Ok(Self {
            path,
            name,
            extension_kind: assessment.extension_kind,
            identity_source: assessment.identity_source,
            structural_validity: assessment.structural_validity,
            classification: assessment.classification,
            structural_signals: assessment.structural_signals,
            decode_warning: false,
            parse_warning,
            sections,
            raw_content: content,
            referenced_files,
        })
    }

    pub fn get_section(&self, name: &str) -> Option<&Section> {
        let name_lower = name.to_lowercase();
        self.sections.iter().find(|s| s.name == name_lower)
    }

    pub fn all_code_blocks(&self) -> Vec<&CodeBlock> {
        self.sections
            .iter()
            .flat_map(|s| s.code_blocks.iter())
            .collect()
    }

    /// Whether any code block in this document declares a fence language
    /// equal to `lang`.
    ///
    /// Comparison is exact-match on lowercase strings. The parser
    /// normalizes fence languages to ASCII lowercase at parse time (see
    /// `adapters/pulldown_parser.rs` — the `Fenced(lang)` branch in the
    /// code-block handler), so callers MUST pass `lang` in lowercase.
    /// `kind: code_language` rule conditions in YAML rule packs use
    /// lowercase tokens by convention, matching this contract.
    pub fn has_code_language(&self, lang: &str) -> bool {
        self.all_code_blocks()
            .iter()
            .any(|cb| cb.language.as_deref() == Some(lang))
    }
}

fn file_system_error_to_io_error(error: FileSystemError) -> std::io::Error {
    match error {
        FileSystemError::IoError(error) => error,
        FileSystemError::PathNotFound(path) => {
            std::io::Error::new(std::io::ErrorKind::NotFound, path.display().to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::adapters::PulldownMarkdownParser;
    use crate::analyzer::types::SkillDocument;
    use std::path::PathBuf;

    fn parse_doc(content: &str) -> SkillDocument {
        let parser = PulldownMarkdownParser::new();
        SkillDocument::parse_with_parser(
            PathBuf::from("/tmp/skill.md"),
            content.to_string(),
            &parser,
        )
        .expect("parse_with_parser must succeed for the inline fixture")
    }

    /// Contract: `has_code_language("python")` matches a `Python` (or
    /// `PYTHON`) fence because the parser normalizes fence languages to
    /// lowercase. Anchors the bug fix — turns a previously latent
    /// case-insensitivity contract into a tested one.
    #[test]
    fn has_code_language_matches_uppercase_fence_when_caller_uses_lowercase() {
        let upper = parse_doc("## Setup\n```Python\nprint('hi')\n```\n");
        let screaming = parse_doc("## Setup\n```PYTHON\nprint('hi')\n```\n");
        assert!(upper.has_code_language("python"));
        assert!(screaming.has_code_language("python"));
    }

    /// Contract: `has_code_language` returns `false` when no code block
    /// declares the requested language. Pins the negative case so the
    /// case-insensitive-LHS contract doesn't accidentally widen to
    /// "matches anything".
    #[test]
    fn has_code_language_returns_false_for_unknown_lang() {
        let doc = parse_doc("## Setup\n```python\nprint('hi')\n```\n");
        assert!(!doc.has_code_language("ruby"));
    }
}
