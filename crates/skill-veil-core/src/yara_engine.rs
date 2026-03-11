//! YARA integration for advanced pattern detection
//!
//! Provides YARA rule compilation and matching capabilities.
//! This module is only available with the `yara` feature.

#![cfg(feature = "yara")]

use crate::findings::{Finding, MatchTarget, Severity, ThreatCategory};
use std::path::Path;
use thiserror::Error;

/// Timeout in seconds for YARA scanning operations
const YARA_SCAN_TIMEOUT_SECS: i32 = 30;

#[derive(Error, Debug)]
pub enum YaraError {
    #[error("Failed to compile YARA rules: {0}")]
    CompilationError(String),
    #[error("Failed to scan with YARA: {0}")]
    ScanError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// YARA engine for advanced pattern matching
pub struct YaraEngine {
    compiler: yara::Compiler,
    rules: Option<yara::Rules>,
}

impl YaraEngine {
    /// Create a new YARA engine
    pub fn new() -> Result<Self, YaraError> {
        let compiler =
            yara::Compiler::new().map_err(|e| YaraError::CompilationError(e.to_string()))?;

        Ok(Self {
            compiler,
            rules: None,
        })
    }

    /// Load YARA rules from a file
    pub fn load_rules_file(&mut self, path: impl AsRef<Path>) -> Result<(), YaraError> {
        let content = std::fs::read_to_string(path.as_ref())?;
        self.compiler = self
            .compiler
            .add_rules_str(&content)
            .map_err(|e| YaraError::CompilationError(e.to_string()))?;
        Ok(())
    }

    /// Load YARA rules from a directory
    pub fn load_rules_dir(&mut self, dir: impl AsRef<Path>) -> Result<(), YaraError> {
        for entry in walkdir::WalkDir::new(dir.as_ref())
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "yar" || ext == "yara")
                    .unwrap_or(false)
            })
        {
            self.load_rules_file(entry.path())?;
        }
        Ok(())
    }

    /// Compile loaded rules
    pub fn compile(&mut self) -> Result<(), YaraError> {
        self.rules = Some(
            self.compiler
                .compile_rules()
                .map_err(|e| YaraError::CompilationError(e.to_string()))?,
        );
        Ok(())
    }

    /// Scan content with compiled YARA rules
    pub fn scan(&self, content: &[u8]) -> Result<Vec<Finding>, YaraError> {
        let rules = self
            .rules
            .as_ref()
            .ok_or_else(|| YaraError::ScanError("Rules not compiled".to_string()))?;

        let matches = rules
            .scan_mem(content, YARA_SCAN_TIMEOUT_SECS)
            .map_err(|e| YaraError::ScanError(e.to_string()))?;

        let mut findings = Vec::new();

        for matched_rule in matches {
            let (category, severity) = parse_yara_meta(&matched_rule);

            for string_match in matched_rule.strings {
                for match_instance in string_match.matches {
                    let match_value = String::from_utf8_lossy(
                        &content
                            [match_instance.offset..match_instance.offset + match_instance.length],
                    )
                    .to_string();

                    findings.push(
                        Finding::builder(format!("YARA_{}", matched_rule.identifier), category)
                            .severity(severity)
                            .confidence(0.95)
                            .matched_on(MatchTarget::Document)
                            .match_value(match_value)
                            .reason(format!("YARA rule '{}' matched", matched_rule.identifier))
                            .build(),
                    );
                }
            }
        }

        Ok(findings)
    }
}

/// Parse metadata from YARA rule to get category and severity
fn parse_yara_meta(rule: &yara::Rule) -> (ThreatCategory, Severity) {
    let mut category = ThreatCategory::Generic;
    let mut severity = Severity::Medium;

    for meta in &rule.metadatas {
        match meta.identifier.as_str() {
            "category" => {
                if let yara::MetadataValue::String(s) = &meta.value {
                    category = match s.as_str() {
                        "remote_exec" => ThreatCategory::RemoteExec,
                        "supply_chain" => ThreatCategory::SupplyChain,
                        "credential_exposure" => ThreatCategory::CredentialExposure,
                        "privilege_escalation" => ThreatCategory::PrivilegeEscalation,
                        "data_exfiltration" => ThreatCategory::DataExfiltration,
                        "obfuscation" => ThreatCategory::Obfuscation,
                        _ => ThreatCategory::Generic,
                    };
                }
            }
            "severity" => {
                if let yara::MetadataValue::String(s) = &meta.value {
                    severity = match s.as_str() {
                        "low" => Severity::Low,
                        "medium" => Severity::Medium,
                        "high" => Severity::High,
                        "critical" => Severity::Critical,
                        _ => Severity::Medium,
                    };
                }
            }
            _ => {}
        }
    }

    (category, severity)
}
