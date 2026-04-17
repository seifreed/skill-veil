use super::weights::{
    EVIDENCE_WEIGHT_BEHAVIOR, EVIDENCE_WEIGHT_CONTEXT, EVIDENCE_WEIGHT_INTENT, EVIDENCE_WEIGHT_IOC,
    SEVERITY_WEIGHT_CRITICAL, SEVERITY_WEIGHT_HIGH, SEVERITY_WEIGHT_LOW, SEVERITY_WEIGHT_MEDIUM,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use strum_macros::Display;

/// Threat category classification
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ThreatCategory {
    /// Remote code execution risks
    RemoteExec,
    /// Supply chain security risks
    SupplyChain,
    /// Persistent prompt or instruction tampering.
    PersistentPromptTampering,
    /// Credential/secret exposure
    CredentialExposure,
    /// Tool invocation or tool permission abuse.
    ToolAbuse,
    /// Agent autonomy increases without clear control.
    AutonomyEscalation,
    /// Privilege escalation attempts
    PrivilegeEscalation,
    /// Data exfiltration indicators
    DataExfiltration,
    /// Persuasive/manipulative language
    PersuasiveLanguage,
    /// Social manipulation of the operator or agent.
    SocialManipulation,
    /// Scope creep in permissions
    ScopeCreep,
    /// Obfuscation techniques
    Obfuscation,
    /// Unsafe binary execution
    UnsafeBinary,
    /// Generic security concern
    Generic,
}

/// Operational context affected by a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum OperationalContext {
    Install,
    Network,
    Secrets,
    CodeModification,
    ExternalComms,
}

/// Severity level of a finding
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Severity {
    /// Low severity - informational
    Low,
    /// Medium severity - requires attention
    Medium,
    /// High severity - should be addressed
    High,
    /// Critical severity - must be blocked
    Critical,
}

impl Severity {
    /// Get the numeric weight for risk scoring
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Low => SEVERITY_WEIGHT_LOW,
            Severity::Medium => SEVERITY_WEIGHT_MEDIUM,
            Severity::High => SEVERITY_WEIGHT_HIGH,
            Severity::Critical => SEVERITY_WEIGHT_CRITICAL,
        }
    }

    /// Get the default recommended action for this severity level
    pub fn default_action(&self) -> RecommendedAction {
        match self {
            Severity::Critical | Severity::High => RecommendedAction::Block,
            Severity::Medium => RecommendedAction::RequireApproval,
            Severity::Low => RecommendedAction::Log,
        }
    }

    /// Get the action string representation for policy recommendations
    pub fn action_str(&self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "BLOCK",
            Severity::Medium => "REQUIRE_APPROVAL",
            Severity::Low => "LOG",
        }
    }
}

/// What was matched by the rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchTarget {
    /// Match in the raw document content
    Document,
    /// Match in a specific section
    Section { name: String },
    /// Match in a code block
    CodeBlock { language: Option<String> },
    /// Match in a referenced file
    ReferencedFile { path: String },
}

impl fmt::Display for MatchTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchTarget::Document => write!(f, "document"),
            MatchTarget::Section { name } => write!(f, "section:{}", name),
            MatchTarget::CodeBlock { language } => {
                write!(f, "code_block:{}", language.as_deref().unwrap_or("unknown"))
            }
            MatchTarget::ReferencedFile { path } => write!(f, "file:{}", path),
        }
    }
}

/// Classification of the evidence behind a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EvidenceKind {
    /// A known IOC such as a hash, domain, publisher, or infrastructure indicator.
    Ioc,
    /// A concrete behavioral pattern such as execution or exfiltration.
    Behavior,
    /// Language that indicates malicious or manipulative intent.
    Intent,
    /// Environmental or contextual signals that increase risk.
    Context,
}

impl EvidenceKind {
    /// Additional weight used by explainable risk scoring.
    pub fn weight(&self) -> u32 {
        match self {
            Self::Ioc => EVIDENCE_WEIGHT_IOC,
            Self::Behavior => EVIDENCE_WEIGHT_BEHAVIOR,
            Self::Intent => EVIDENCE_WEIGHT_INTENT,
            Self::Context => EVIDENCE_WEIGHT_CONTEXT,
        }
    }

    /// Short explanation for reports and UIs.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Ioc => "Known malicious indicator",
            Self::Behavior => "Concrete risky behavior",
            Self::Intent => "Manipulative or coercive intent",
            Self::Context => "Contextual risk signal",
        }
    }
}

/// Artifact type where the finding was observed.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ArtifactKind {
    /// The primary skill or prompt document.
    SkillDocument,
    /// Persistent instruction document such as AGENTS.md or SYSTEM.md.
    AgentInstruction,
    /// Prompt pack document or prompt bundle entry.
    PromptPackDocument,
    /// MCP server manifest or MCP descriptor.
    McpServerManifest,
    /// A code snippet embedded in the document.
    CodeSnippet,
    /// A referenced script or executable artifact.
    ReferencedArtifact,
    /// A package manifest or infrastructure descriptor.
    PackageManifest,
    /// A dependency lockfile associated with a package manifest.
    Lockfile,
    /// Any other text artifact.
    GenericArtifact,
}

/// High-level scope of the artifact within the package.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ArtifactScope {
    AgentEntrypoint,
    PackageRootArtifact,
    SupportingArtifact,
}

/// Coarse signal family used for final package verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SignalClass {
    Hygiene,
    SuspiciousPackageBehavior,
    MaliciousBehavior,
    ReviewSignal,
}

/// Final package-level judgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum Verdict {
    Benign,
    Suspicious,
    Malicious,
}

/// Recommended action based on findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum RecommendedAction {
    /// Log the finding for awareness
    Log,
    /// Require human approval before proceeding
    RequireApproval,
    /// Block the skill from being used
    Block,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum BlastRadiusLevel {
    #[default]
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PackageHealth {
    Healthy,
    NeedsReview,
    Elevated,
}
