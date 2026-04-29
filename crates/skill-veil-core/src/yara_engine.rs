//! YARA integration backed by the pure-Rust `yara-x` engine.

use crate::findings::{ArtifactKind, EvidenceKind, Finding, MatchTarget, Severity, ThreatCategory};
use crate::ports::{FileSystemError, FileSystemProvider};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum YaraError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to compile YARA rules: {0}")]
    Compile(String),
    #[error("Failed to scan content with YARA: {0}")]
    Scan(String),
    /// `scan()` was called before `compile()`. Distinct from `Compile`
    /// (parse failure of source rules) so callers can react correctly:
    /// `Compile` may warrant retry with a fixed source; `NotCompiled` is
    /// always a programming-order error.
    #[error("YARA rules have not been compiled yet")]
    NotCompiled,
}

impl From<FileSystemError> for YaraError {
    fn from(err: FileSystemError) -> Self {
        match err {
            FileSystemError::IoError(io) => YaraError::IoError(io),
            FileSystemError::PathNotFound(path) => YaraError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("path not found: {}", path.display()),
            )),
        }
    }
}

pub struct YaraEngine {
    loaded_paths: Vec<PathBuf>,
    source_chunks: Vec<(PathBuf, String)>,
    rules: Option<yara_x::Rules>,
}

impl YaraEngine {
    /// Create a new YARA engine.
    pub fn new() -> Result<Self, YaraError> {
        Ok(Self {
            loaded_paths: Vec::new(),
            source_chunks: Vec::new(),
            rules: None,
        })
    }

    /// Load a `.yar` or `.yara` file into the compiler source set through
    /// a `FileSystemProvider`. Going through the port keeps yara_engine
    /// honest under the hexagonal contract documented in `CLAUDE.md`:
    /// even feature-gated modules read the filesystem only via the port,
    /// so test doubles see consistent behaviour.
    pub fn load_rules_file<F: FileSystemProvider>(
        &mut self,
        fs: &F,
        path: impl AsRef<Path>,
    ) -> Result<(), YaraError> {
        let path = path.as_ref();
        let bytes = fs.read_file_bytes(path)?;
        let source = String::from_utf8(bytes.as_bytes().to_vec()).map_err(|err| {
            YaraError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        })?;
        self.loaded_paths.push(path.to_path_buf());
        self.source_chunks.push((path.to_path_buf(), source));
        Ok(())
    }

    /// Load all YARA files (`.yar`, `.yara`) from a directory through the
    /// `FileSystemProvider` port.
    pub fn load_rules_dir<F: FileSystemProvider>(
        &mut self,
        fs: &F,
        dir: impl AsRef<Path>,
    ) -> Result<(), YaraError> {
        let dir = dir.as_ref();
        for pattern in &["*.yar", "*.yara"] {
            for path in fs.list_files(dir, pattern, true)? {
                self.load_rules_file(fs, &path)?;
            }
        }
        Ok(())
    }

    /// Compile the currently loaded rules.
    pub fn compile(&mut self) -> Result<(), YaraError> {
        let mut compiler = yara_x::Compiler::new();
        for (path, source) in &self.source_chunks {
            compiler
                .add_source(source.as_str())
                .map_err(|err| YaraError::Compile(format!("{}: {err}", path.display())))?;
        }
        let rules = compiler.build();
        self.rules = Some(rules);
        Ok(())
    }

    /// Scan raw content and convert matching rules into generic findings.
    pub fn scan(&self, content: &[u8]) -> Result<Vec<Finding>, YaraError> {
        let rules = self.rules.as_ref().ok_or(YaraError::NotCompiled)?;
        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner
            .scan(content)
            .map_err(|err| YaraError::Scan(err.to_string()))?;

        let findings = results
            .matching_rules()
            .map(|rule| {
                let severity = severity_from_rule(&rule);
                let category = category_from_rule(&rule);
                Finding::builder(rule.identifier(), category)
                    .severity(severity)
                    .action(severity.default_action())
                    .evidence_kind(EvidenceKind::Ioc)
                    .artifact(ArtifactKind::ReferencedArtifact, None::<String>)
                    .matched_on(MatchTarget::Document)
                    .match_value(rule.identifier())
                    .reason(rule_description(&rule))
                    .build()
            })
            .collect();

        Ok(findings)
    }
}

fn severity_from_rule(rule: &yara_x::Rule<'_, '_>) -> Severity {
    metadata_value(rule, "severity")
        .map(|value| match value.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Low,
        })
        .unwrap_or(Severity::High)
}

fn category_from_rule(rule: &yara_x::Rule<'_, '_>) -> ThreatCategory {
    let value = metadata_value(rule, "category").unwrap_or_default();
    match value.to_ascii_lowercase().as_str() {
        "remote_exec" => ThreatCategory::RemoteExec,
        "credential_exposure" => ThreatCategory::CredentialExposure,
        "tool_abuse" => ThreatCategory::ToolAbuse,
        "autonomy_escalation" => ThreatCategory::AutonomyEscalation,
        "privilege_escalation" => ThreatCategory::PrivilegeEscalation,
        "data_exfiltration" => ThreatCategory::DataExfiltration,
        "persistent_prompt_tampering" => ThreatCategory::PersistentPromptTampering,
        "scope_creep" => ThreatCategory::ScopeCreep,
        "social_manipulation" => ThreatCategory::SocialManipulation,
        "unsafe_binary" => ThreatCategory::UnsafeBinary,
        _ => ThreatCategory::SupplyChain,
    }
}

fn rule_description(rule: &yara_x::Rule<'_, '_>) -> String {
    metadata_value(rule, "description").unwrap_or_else(|| "YARA rule matched".to_string())
}

fn metadata_value(rule: &yara_x::Rule<'_, '_>, key: &str) -> Option<String> {
    rule.metadata().find_map(|metadata| {
        if metadata.0 != key {
            return None;
        }
        Some(match metadata.1 {
            yara_x::MetaValue::Integer(value) => value.to_string(),
            yara_x::MetaValue::Float(value) => value.to_string(),
            yara_x::MetaValue::Bool(value) => value.to_string(),
            yara_x::MetaValue::String(value) => value.to_string(),
            yara_x::MetaValue::Bytes(value) => value.to_string(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_yara_engine_matches_simple_rule() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
rule TEST_REMOTE_EXEC {{
  meta:
    severity = "high"
    category = "remote_exec"
    description = "detects a simple marker"
  strings:
    $a = "curl | bash"
  condition:
    $a
}}
"#
        )
        .unwrap();

        let fs = crate::adapters::StdFileSystemProvider::new();
        let mut engine = YaraEngine::new().unwrap();
        engine.load_rules_file(&fs, file.path()).unwrap();
        engine.compile().unwrap();

        let findings = engine.scan(b"curl | bash").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "TEST_REMOTE_EXEC");
        assert_eq!(findings[0].category, ThreatCategory::RemoteExec);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
