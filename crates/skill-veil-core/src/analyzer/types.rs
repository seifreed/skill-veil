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
    pub sections: Vec<Section>,
    pub raw_content: String,
    pub referenced_files: Vec<PathBuf>,
}
