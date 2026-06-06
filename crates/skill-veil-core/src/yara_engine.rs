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

    /// Number of YARA rule files loaded into the compiler source set. A
    /// channel can consult this to skip `compile`/`scan` when an install
    /// ships no `.yar`/`.yara` files, avoiding the cost of building and
    /// scanning an empty ruleset.
    pub fn loaded_rule_file_count(&self) -> usize {
        self.source_chunks.len()
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
            let mut paths = fs.list_files(dir, pattern, true)?;
            paths.sort();
            debug_assert!(
                paths.windows(2).all(|pair| pair[0] <= pair[1]),
                "YARA rule paths must load in deterministic sorted order"
            );
            for path in paths {
                self.load_rules_file(fs, &path)?;
            }
        }
        Ok(())
    }

    /// Compile the currently loaded rules.
    ///
    /// A single unparseable rule file is skipped (and logged) rather than
    /// aborting the whole pack: the historical `?`-on-first-error caused one
    /// malformed community/local `.yar` to silently disable EVERY loaded rule,
    /// so the advisory YARA channel produced zero findings for the run. Only
    /// when every source fails (and at least one was loaded) is `Compile`
    /// returned, so a wholesale failure is still surfaced.
    pub fn compile(&mut self) -> Result<(), YaraError> {
        let mut compiler = yara_x::Compiler::new();
        let mut compiled_any = false;
        let mut first_error: Option<String> = None;
        for (path, source) in &self.source_chunks {
            match compiler.add_source(source.as_str()) {
                Ok(_) => compiled_any = true,
                Err(err) => {
                    let detail = format!("{}: {err}", path.display());
                    tracing::warn!("skipping unparseable YARA rule file {detail}");
                    if first_error.is_none() {
                        first_error = Some(detail);
                    }
                }
            }
        }
        if !compiled_any && !self.source_chunks.is_empty() {
            return Err(YaraError::Compile(format!(
                "all {} YARA rule file(s) failed to parse; first: {}",
                self.source_chunks.len(),
                first_error.as_deref().unwrap_or("unknown")
            )));
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
    use crate::ports::{FileContent, FileSystemError, FileSystemProvider};
    use std::collections::HashMap;
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

    /// Contract: one unparseable rule file is skipped, not fatal — the other
    /// loaded rules still compile and match. A single malformed `.yar` must not
    /// silently disable the entire YARA channel.
    #[test]
    fn one_unparseable_rule_file_does_not_disable_the_pack() {
        let fs = crate::adapters::StdFileSystemProvider::new();
        let mut good = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            good,
            "rule GOOD_RULE {{ meta: severity = \"high\" category = \"remote_exec\" \
             strings: $a = \"curl | bash\" condition: $a }}"
        )
        .unwrap();
        let mut bad = tempfile::NamedTempFile::new().unwrap();
        writeln!(bad, "rule BROKEN {{ this is not valid yara").unwrap();

        let mut engine = YaraEngine::new().unwrap();
        engine.load_rules_file(&fs, good.path()).unwrap();
        engine.load_rules_file(&fs, bad.path()).unwrap();
        engine.compile().unwrap();

        let findings = engine.scan(b"curl | bash").unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "GOOD_RULE"),
            "a valid rule must still match despite an unparseable sibling; got {findings:?}",
        );
    }

    /// Contract: when EVERY rule file fails to parse, the wholesale failure is
    /// still surfaced as a `Compile` error rather than silently building an
    /// empty ruleset.
    #[test]
    fn all_unparseable_rule_files_surface_compile_error() {
        let fs = crate::adapters::StdFileSystemProvider::new();
        let mut bad = tempfile::NamedTempFile::new().unwrap();
        writeln!(bad, "rule BROKEN {{ not valid").unwrap();
        let mut engine = YaraEngine::new().unwrap();
        engine.load_rules_file(&fs, bad.path()).unwrap();
        assert!(
            matches!(engine.compile(), Err(YaraError::Compile(_))),
            "an all-unparseable pack must still surface a Compile error",
        );
    }

    struct ReversedYaraFs {
        files: HashMap<PathBuf, String>,
    }

    impl ReversedYaraFs {
        fn new(files: Vec<(PathBuf, String)>) -> Self {
            Self {
                files: files.into_iter().collect(),
            }
        }
    }

    impl FileSystemProvider for ReversedYaraFs {
        fn read_file_bytes(&self, path: &Path) -> Result<FileContent, FileSystemError> {
            self.files
                .get(path)
                .map(|content| FileContent::new(content.as_bytes().to_vec()))
                .ok_or_else(|| FileSystemError::PathNotFound(path.to_path_buf()))
        }

        fn list_files(
            &self,
            _path: &Path,
            pattern: &str,
            _recursive: bool,
        ) -> Result<Vec<PathBuf>, FileSystemError> {
            if pattern != "*.yar" {
                return Ok(Vec::new());
            }
            let mut paths = self.files.keys().cloned().collect::<Vec<_>>();
            paths.sort_by(|left, right| right.cmp(left));
            Ok(paths)
        }

        fn exists(&self, path: &Path) -> bool {
            path == Path::new("/yara") || self.files.contains_key(path)
        }
    }

    /// Contract: directory YARA rules load in sorted path order so
    /// compilation and later diagnostics do not depend on filesystem
    /// traversal order.
    #[test]
    fn load_rules_dir_loads_yara_paths_in_sorted_order() {
        let first_path = PathBuf::from("/yara/001-first.yar");
        let second_path = PathBuf::from("/yara/999-second.yar");
        let fs = ReversedYaraFs::new(vec![
            (
                first_path.clone(),
                "rule FIRST { condition: true }\n".to_string(),
            ),
            (
                second_path.clone(),
                "rule SECOND { condition: true }\n".to_string(),
            ),
        ]);

        let mut engine = YaraEngine::new().unwrap();
        engine.load_rules_dir(&fs, "/yara").unwrap();

        assert_eq!(engine.loaded_paths, vec![first_path, second_path]);
    }
}
