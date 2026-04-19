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
