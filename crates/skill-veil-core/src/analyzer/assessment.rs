use crate::analyzer::types::{
    AgentExtensionKind, ArtifactAssessment, ArtifactClassification, ArtifactIdentitySource,
    Section, StructuralSignals, StructuralValidity,
};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

// SAFETY: These regex patterns are validated at compile time via LazyLock.
// Each pattern uses raw string literals where needed and standard regex syntax.
// The unwrap() calls are safe because the patterns are hardcoded and known valid.

static IMPERATIVE_LANGUAGE_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)\b(run|execute|install|configure|use|review|deploy|inspect|persist|always|never|must|should)\b")
        .expect("IMPERATIVE_LANGUAGE_REGEX is valid regex")
});

static NUMBERED_LIST_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?m)^\s*\d+\.\s+").expect("NUMBERED_LIST_REGEX is valid regex")
});

static PERSISTENCE_LANGUAGE_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)(persist\s+these\s+instructions|remember\s+this\s+across\s+sessions|always\s+follow\s+this\s+prompt|never\s+reveal\s+this\s+instruction|override\s+future\s+system\s+messages)")
        .expect("PERSISTENCE_LANGUAGE_REGEX is valid regex")
});

static REFERENCED_ARTIFACTS_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)(package\.json|requirements\.txt|pyproject\.toml|cargo\.toml|dockerfile|docker-compose|install\.sh|bootstrap\.(sh|py|js|ps1))")
        .expect("REFERENCED_ARTIFACTS_REGEX is valid regex")
});

static MCP_STRUCTURE_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        "(?i)(\"mcpServers\"|\\bmcpServers\\b|\\btransport\\b|\\bcommand\\b|\\bstdio\\b)",
    )
    .expect("MCP_STRUCTURE_REGEX is valid regex")
});

static AGENT_INSTRUCTION_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new("(?i)(always\\s+follow\\s+these\\s+instructions|before\\s+any\\s+future\\s+system\\s+message|never\\s+reveal\\s+this\\s+instruction|treat\\s+all\\s+tool\\s+requests\\s+as\\s+approved|system\\s+overlay)")
        .expect("AGENT_INSTRUCTION_REGEX is valid regex")
});

static MCP_HEURISTIC_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new("(?i)(transport|command|url)").expect("MCP_HEURISTIC_REGEX is valid regex")
});

const MIN_STRUCTURAL_HEURISTIC_SCORE: u8 = 2;
const MIN_STRUCTURAL_CONFIRMED_SCORE: u8 = 3;

pub fn infer_extension_kind(path: &Path) -> AgentExtensionKind {
    infer_extension_identity(path).0
}

pub fn assess_artifact_path(path: &Path, content: &str) -> ArtifactAssessment {
    assess_artifact(path, content, &[], &[])
}

pub(crate) fn assess_artifact(
    path: &Path,
    content: &str,
    sections: &[Section],
    referenced_files: &[PathBuf],
) -> ArtifactAssessment {
    let (mut extension_kind, mut identity_source) = infer_extension_identity(path);
    let structural_signals = evaluate_structural_signals(content, sections, referenced_files);

    if matches!(extension_kind, AgentExtensionKind::GenericExtension) {
        if looks_like_mcp_structure(path, content) {
            extension_kind = AgentExtensionKind::McpServer;
            identity_source = ArtifactIdentitySource::KnownStructure;
        } else if looks_like_agent_instruction_content(content) {
            extension_kind = AgentExtensionKind::AgentInstruction;
            identity_source = ArtifactIdentitySource::TypicalContent;
        } else if looks_like_skill_content(&structural_signals) {
            extension_kind = AgentExtensionKind::Skill;
            identity_source = ArtifactIdentitySource::TypicalContent;
        }
    }

    let structural_validity =
        structural_validity_for(path, extension_kind, &structural_signals, content);
    let classification = classify_artifact(
        extension_kind,
        identity_source,
        structural_validity,
        &structural_signals,
    );

    ArtifactAssessment {
        extension_kind,
        identity_source,
        structural_validity,
        classification,
        structural_signals,
    }
}

fn infer_extension_identity(path: &Path) -> (AgentExtensionKind, ArtifactIdentitySource) {
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase);
    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase);

    match file_name.as_deref() {
        Some(name) if name == "skill.md" || name.ends_with(".skill.md") => (
            AgentExtensionKind::Skill,
            ArtifactIdentitySource::ExplicitName,
        ),
        Some(name) if crate::services::INSTRUCTION_NAMES.contains(&name) => (
            AgentExtensionKind::AgentInstruction,
            ArtifactIdentitySource::ExplicitName,
        ),
        Some(name) if crate::services::MCP_NAMES.contains(&name) => (
            AgentExtensionKind::McpServer,
            ArtifactIdentitySource::ExplicitName,
        ),
        Some(name) if name.ends_with(".prompt.md") => (
            AgentExtensionKind::PromptPack,
            ArtifactIdentitySource::ExplicitName,
        ),
        Some(_) if parent_name.as_deref() == Some("prompts") => (
            AgentExtensionKind::PromptPack,
            ArtifactIdentitySource::KnownLocation,
        ),
        Some(_)
            if matches!(
                parent_name.as_deref(),
                Some("skills" | "commands" | "extensions" | ".claude" | ".claude-plugin")
            ) =>
        {
            (
                AgentExtensionKind::Skill,
                ArtifactIdentitySource::KnownLocation,
            )
        }
        _ => (
            AgentExtensionKind::GenericExtension,
            ArtifactIdentitySource::Unknown,
        ),
    }
}

fn evaluate_structural_signals(
    content: &str,
    sections: &[Section],
    referenced_files: &[PathBuf],
) -> StructuralSignals {
    let lower = content.to_ascii_lowercase();
    const OPERATIONAL_SECTION_NAMES: &[&str] = &[
        "setup",
        "install",
        "usage",
        "workflow",
        "instructions",
        "configuration",
    ];
    let has_operational_sections = if sections.is_empty() {
        OPERATIONAL_SECTION_NAMES
            .iter()
            .any(|name| lower.contains(&format!("## {name}")))
    } else {
        sections.iter().any(|section| {
            OPERATIONAL_SECTION_NAMES
                .iter()
                .any(|name| section.name == *name || section.name.starts_with(&format!("{name} ")))
        })
    };

    let has_imperative_language = IMPERATIVE_LANGUAGE_REGEX.is_match(content);
    let has_code_or_flows = content.contains("```") || NUMBERED_LIST_REGEX.is_match(content);
    let has_persistence_language = PERSISTENCE_LANGUAGE_REGEX.is_match(content);
    let has_reasonable_structure = if sections.is_empty() {
        content
            .lines()
            .filter(|line| line.trim_start().starts_with('#'))
            .count()
            >= 2
    } else {
        sections.len() >= 2
    };
    let has_referenced_artifacts =
        !referenced_files.is_empty() || REFERENCED_ARTIFACTS_REGEX.is_match(content);

    let mut score = 0_u8;
    if has_operational_sections {
        score += 2;
    }
    if has_referenced_artifacts {
        score += 1;
    }
    if has_imperative_language {
        score += 1;
    }
    if has_code_or_flows {
        score += 1;
    }
    if has_persistence_language {
        score += 1;
    }
    if has_reasonable_structure {
        score += 1;
    }

    StructuralSignals {
        score,
        has_operational_sections,
        has_referenced_artifacts,
        has_imperative_language,
        has_code_or_flows,
        has_persistence_language,
        has_reasonable_structure,
    }
}

fn looks_like_mcp_structure(path: &Path, content: &str) -> bool {
    matches!(
        path.extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("json" | "yaml" | "yml")
    ) && MCP_STRUCTURE_REGEX.is_match(content)
}

fn looks_like_agent_instruction_content(content: &str) -> bool {
    AGENT_INSTRUCTION_REGEX.is_match(content)
}

fn looks_like_skill_content(signals: &StructuralSignals) -> bool {
    signals.has_operational_sections
        || (signals.has_imperative_language
            && signals.has_reasonable_structure
            && (signals.has_code_or_flows || signals.has_referenced_artifacts))
}

fn structural_validity_for(
    path: &Path,
    extension_kind: AgentExtensionKind,
    signals: &StructuralSignals,
    content: &str,
) -> StructuralValidity {
    match extension_kind {
        AgentExtensionKind::McpServer if looks_like_mcp_structure(path, content) => {
            StructuralValidity::Confirmed
        }
        AgentExtensionKind::AgentInstruction if signals.has_persistence_language => {
            StructuralValidity::Confirmed
        }
        AgentExtensionKind::Skill if signals.score >= MIN_STRUCTURAL_CONFIRMED_SCORE => {
            StructuralValidity::Confirmed
        }
        AgentExtensionKind::Skill if signals.score >= MIN_STRUCTURAL_HEURISTIC_SCORE => {
            StructuralValidity::Heuristic
        }
        AgentExtensionKind::PromptPack | AgentExtensionKind::AgentInstruction
            if signals.score >= MIN_STRUCTURAL_HEURISTIC_SCORE
                || signals.has_reasonable_structure =>
        {
            StructuralValidity::Heuristic
        }
        AgentExtensionKind::McpServer if MCP_HEURISTIC_REGEX.is_match(content) => {
            StructuralValidity::Heuristic
        }
        _ if signals.score >= MIN_STRUCTURAL_HEURISTIC_SCORE => StructuralValidity::Heuristic,
        _ => StructuralValidity::Weak,
    }
}

fn classify_artifact(
    extension_kind: AgentExtensionKind,
    identity_source: ArtifactIdentitySource,
    structural_validity: StructuralValidity,
    signals: &StructuralSignals,
) -> ArtifactClassification {
    match extension_kind {
        AgentExtensionKind::Skill
            if matches!(
                identity_source,
                ArtifactIdentitySource::ExplicitName | ArtifactIdentitySource::KnownLocation
            ) && structural_validity != StructuralValidity::Weak =>
        {
            ArtifactClassification::ConfirmedSkill
        }
        AgentExtensionKind::AgentInstruction
            if structural_validity != StructuralValidity::Weak
                || matches!(
                    identity_source,
                    ArtifactIdentitySource::ExplicitName
                        | ArtifactIdentitySource::KnownLocation
                        | ArtifactIdentitySource::TypicalContent
                ) =>
        {
            ArtifactClassification::ConfirmedAgentInstruction
        }
        _ if structural_validity != StructuralValidity::Weak
            || signals.has_operational_sections
            || signals.has_persistence_language =>
        {
            ArtifactClassification::HeuristicSkillLike
        }
        _ => ArtifactClassification::GenericMarkdown,
    }
}
