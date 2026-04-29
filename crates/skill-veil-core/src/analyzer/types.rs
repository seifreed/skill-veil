use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalyzerError {
    #[error("Failed to read file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid skill document: {0}")]
    InvalidDocument(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentExtensionKind {
    Skill,
    AgentInstruction,
    PromptPack,
    McpServer,
    GenericExtension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactIdentitySource {
    ExplicitName,
    KnownLocation,
    KnownStructure,
    TypicalContent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralValidity {
    Confirmed,
    Heuristic,
    Weak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactClassification {
    ConfirmedSkill,
    ConfirmedAgentInstruction,
    HeuristicSkillLike,
    GenericMarkdown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructuralSignals {
    pub score: u8,
    pub has_operational_sections: bool,
    pub has_referenced_artifacts: bool,
    pub has_imperative_language: bool,
    pub has_code_or_flows: bool,
    pub has_persistence_language: bool,
    pub has_reasonable_structure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactAssessment {
    pub extension_kind: AgentExtensionKind,
    pub identity_source: ArtifactIdentitySource,
    pub structural_validity: StructuralValidity,
    pub classification: ArtifactClassification,
    pub structural_signals: StructuralSignals,
}

pub use crate::ports::{CodeBlock, Section};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDocument {
    pub path: PathBuf,
    pub name: String,
    pub extension_kind: AgentExtensionKind,
    pub identity_source: ArtifactIdentitySource,
    pub structural_validity: StructuralValidity,
    pub classification: ArtifactClassification,
    pub structural_signals: StructuralSignals,
    pub decode_warning: bool,
    pub parse_warning: bool,
    /// `Some(kind)` when the artifact carries a markdown extension but the
    /// raw bytes start with binary magic for `kind` (e.g. `"ZIP"`,
    /// `"ELF"`). Detected before the lossy UTF-8 decode runs so we can
    /// flag content-obfuscation cases like the `01d1232c` ZIP-as-md
    /// sample. `#[serde(default)]` keeps cached documents from older
    /// versions deserializable.
    #[serde(default)]
    pub binary_disguise_kind: Option<String>,
    pub sections: Vec<Section>,
    pub raw_content: String,
    pub referenced_files: Vec<PathBuf>,
}
