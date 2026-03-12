//! Finding data structures for security analysis results
//!
//! Defines the core types for representing detected security signals.

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilitySource, ArtifactGraph};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use strum_macros::Display;

/// Weight applied to Low severity findings in risk score calculation
pub const SEVERITY_WEIGHT_LOW: u32 = 10;
/// Weight applied to Medium severity findings in risk score calculation
pub const SEVERITY_WEIGHT_MEDIUM: u32 = 30;
/// Weight applied to High severity findings in risk score calculation
pub const SEVERITY_WEIGHT_HIGH: u32 = 60;
/// Weight applied to Critical severity findings in risk score calculation
pub const SEVERITY_WEIGHT_CRITICAL: u32 = 90;

/// Risk score threshold above which action is Block
pub const RISK_THRESHOLD_BLOCK: u32 = 50;
/// Risk score threshold above which action is RequireApproval
pub const RISK_THRESHOLD_APPROVAL: u32 = 20;
/// Bonus applied to IOC-backed findings in explainable risk scoring.
pub const EVIDENCE_WEIGHT_IOC: u32 = 10;
/// Bonus applied to behavioral findings in explainable risk scoring.
pub const EVIDENCE_WEIGHT_BEHAVIOR: u32 = 8;
/// Bonus applied to intent findings in explainable risk scoring.
pub const EVIDENCE_WEIGHT_INTENT: u32 = 4;
/// Bonus applied to context findings in explainable risk scoring.
pub const EVIDENCE_WEIGHT_CONTEXT: u32 = 3;
/// Bonus applied when an artifact exposes install-time execution capability.
pub const CAPABILITY_WEIGHT_INSTALL_EXECUTION: u32 = 8;
/// Bonus applied when an artifact exposes network access.
pub const CAPABILITY_WEIGHT_NETWORK_ACCESS: u32 = 6;
/// Bonus applied when an artifact exposes local binaries.
pub const CAPABILITY_WEIGHT_EXPOSES_BINARY: u32 = 4;
/// Bonus applied when an artifact requests privileged runtime.
pub const CAPABILITY_WEIGHT_PRIVILEGED_RUNTIME: u32 = 18;
/// Bonus applied when an artifact can access the host filesystem.
pub const CAPABILITY_WEIGHT_HOST_FILESYSTEM_ACCESS: u32 = 16;
/// Bonus applied when an artifact can execute child processes.
pub const CAPABILITY_WEIGHT_PROCESS_EXECUTION: u32 = 10;
/// Bonus applied when an artifact can read or expose secrets.
pub const CAPABILITY_WEIGHT_SECRET_ACCESS: u32 = 14;
/// Bonus applied when an artifact establishes persistence.
pub const CAPABILITY_WEIGHT_PERSISTENCE_SURFACE: u32 = 12;
/// Bonus applied when an artifact can write to the filesystem.
pub const CAPABILITY_WEIGHT_FILESYSTEM_WRITE: u32 = 9;
/// Bonus applied when an artifact declares browser automation access.
pub const CAPABILITY_WEIGHT_BROWSER_ACCESS: u32 = 8;
/// Bonus applied when an artifact can access identity or OAuth material.
pub const CAPABILITY_WEIGHT_IDENTITY_ACCESS: u32 = 14;
/// Bonus applied when an artifact exposes inbound network/webhook surface.
pub const CAPABILITY_WEIGHT_INBOUND_SURFACE: u32 = 10;
/// Bonus applied to the high-risk privileged + host filesystem combination.
pub const CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST: u32 = 25;
/// Bonus applied to install-time execution with network access.
pub const CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK: u32 = 12;
/// Bonus applied to install-time execution that also exposes binaries.
pub const CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY: u32 = 8;
/// Dampening factor for hygiene-only signals.
pub const SIGNAL_WEIGHT_HYGIENE: f32 = 0.35;
/// Dampening factor for suspicious but not clearly malicious signals.
pub const SIGNAL_WEIGHT_SUSPICIOUS: f32 = 0.75;
/// Weight for clearly malicious behavior.
pub const SIGNAL_WEIGHT_MALICIOUS: f32 = 1.0;
/// Dampening factor for generic review signals.
pub const SIGNAL_WEIGHT_REVIEW: f32 = 0.5;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
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

/// Structured reason contributing to the final verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictReason {
    pub scope: ArtifactScope,
    pub category: ThreatCategory,
    pub signal_class: SignalClass,
    pub rationale: String,
}

/// Aggregated root-cause cluster for package-level reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseGroup {
    pub scope: ArtifactScope,
    pub category: ThreatCategory,
    pub signal_class: SignalClass,
    pub finding_count: usize,
    pub strongest_action: RecommendedAction,
    pub representative_rules: Vec<String>,
}

/// Recommended action based on findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
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

impl RecommendedAction {
    pub(crate) fn priority(self) -> u8 {
        match self {
            Self::Log => 0,
            Self::RequireApproval => 1,
            Self::Block => 2,
        }
    }

    pub fn max(left: Self, right: Self) -> Self {
        if left.priority() >= right.priority() {
            left
        } else {
            right
        }
    }
}

/// A security finding from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// The rule ID that generated this finding
    pub rule_id: String,
    /// Threat category
    pub category: ThreatCategory,
    /// Severity level
    pub severity: Severity,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Raw confidence before evidence/category calibration.
    pub raw_confidence: f32,
    /// Explanation of how confidence was calibrated.
    pub confidence_rationale: String,
    /// What was matched
    pub matched_on: MatchTarget,
    /// The actual matched value/text
    pub match_value: String,
    /// Human-readable reason/explanation
    pub reason: String,
    /// Explicit remediation guidance for triage or mitigation.
    pub remediation: String,
    /// Explicit recommendation for triage or enforcement.
    pub recommended_action: RecommendedAction,
    /// Evidence class for explainability.
    pub evidence_kind: EvidenceKind,
    /// Artifact type where the evidence was found.
    pub artifact_kind: ArtifactKind,
    /// High-level artifact scope within the package.
    pub artifact_scope: ArtifactScope,
    /// Coarse signal family for package-level verdicts.
    pub signal_class: SignalClass,
    /// Path to the artifact where the evidence was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// Operational contexts impacted by this finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_contexts: Vec<OperationalContext>,
    /// Line number if available
    pub line_number: Option<usize>,
}

/// Default confidence score for findings
const DEFAULT_FINDING_CONFIDENCE: f32 = 0.9;

/// Builder for creating Finding instances
///
/// Use `Finding::builder()` to create a new builder, then chain
/// setter methods and call `.build()` to create the Finding.
///
/// # Example
/// ```
/// use skill_veil_core::findings::{Finding, ThreatCategory, Severity, MatchTarget};
///
/// let finding = Finding::builder("RULE_001", ThreatCategory::RemoteExec)
///     .severity(Severity::High)
///     .confidence(0.95)
///     .matched_on(MatchTarget::Document)
///     .match_value("curl | bash")
///     .reason("Remote code execution detected")
///     .line(42)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    rule_id: String,
    category: ThreatCategory,
    severity: Severity,
    confidence: f32,
    matched_on: MatchTarget,
    match_value: String,
    reason: String,
    remediation: String,
    recommended_action: RecommendedAction,
    evidence_kind: EvidenceKind,
    artifact_kind: ArtifactKind,
    artifact_scope: ArtifactScope,
    signal_class: SignalClass,
    artifact_path: Option<String>,
    line_number: Option<usize>,
}

impl FindingBuilder {
    /// Create a new FindingBuilder with required fields
    ///
    /// # Arguments
    /// * `rule_id` - The unique rule identifier
    /// * `category` - The threat category
    #[must_use]
    pub fn new(rule_id: impl Into<String>, category: ThreatCategory) -> Self {
        Self {
            rule_id: rule_id.into(),
            category,
            severity: Severity::Medium,
            confidence: DEFAULT_FINDING_CONFIDENCE,
            matched_on: MatchTarget::Document,
            match_value: String::new(),
            reason: String::new(),
            remediation: String::new(),
            recommended_action: Severity::Medium.default_action(),
            evidence_kind: EvidenceKind::Behavior,
            artifact_kind: ArtifactKind::SkillDocument,
            artifact_scope: ArtifactScope::AgentEntrypoint,
            signal_class: SignalClass::MaliciousBehavior,
            artifact_path: None,
            line_number: None,
        }
    }

    /// Set the severity level
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self.recommended_action = severity.default_action();
        self
    }

    /// Set the confidence score (0.0 - 1.0)
    pub fn confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set what was matched
    pub fn matched_on(mut self, matched_on: MatchTarget) -> Self {
        self.matched_on = matched_on;
        self
    }

    /// Set the matched value/text
    pub fn match_value(mut self, match_value: impl Into<String>) -> Self {
        self.match_value = match_value.into();
        self
    }

    /// Set the human-readable reason/explanation
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Set remediation guidance explicitly.
    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = remediation.into();
        self
    }

    /// Set the recommended action explicitly.
    pub fn action(mut self, action: RecommendedAction) -> Self {
        self.recommended_action = action;
        self
    }

    /// Set the evidence class.
    pub fn evidence_kind(mut self, evidence_kind: EvidenceKind) -> Self {
        self.evidence_kind = evidence_kind;
        self
    }

    /// Set the artifact context.
    pub fn artifact(mut self, artifact_kind: ArtifactKind, artifact_path: Option<String>) -> Self {
        self.artifact_kind = artifact_kind;
        self.artifact_scope = artifact_scope_for_kind(artifact_kind);
        self.artifact_path = artifact_path;
        self
    }

    /// Set the artifact scope explicitly.
    pub fn artifact_scope(mut self, artifact_scope: ArtifactScope) -> Self {
        self.artifact_scope = artifact_scope;
        self
    }

    /// Set the signal class explicitly.
    pub fn signal_class(mut self, signal_class: SignalClass) -> Self {
        self.signal_class = signal_class;
        self
    }

    /// Set the line number
    pub fn line(mut self, line: usize) -> Self {
        self.line_number = Some(line);
        self
    }

    /// Build the Finding instance
    #[must_use]
    pub fn build(self) -> Finding {
        let policy_contexts = default_operational_contexts(self.category, self.artifact_kind);
        let (confidence, confidence_rationale) =
            calibrate_confidence(self.confidence, self.evidence_kind, self.category);
        let signal_class = if self.signal_class == SignalClass::MaliciousBehavior {
            signal_class_for(self.category)
        } else {
            self.signal_class
        };
        Finding {
            rule_id: self.rule_id,
            category: self.category,
            severity: self.severity,
            confidence,
            raw_confidence: self.confidence,
            confidence_rationale,
            matched_on: self.matched_on,
            match_value: self.match_value,
            reason: self.reason,
            remediation: if self.remediation.is_empty() {
                default_remediation(self.category, &policy_contexts).to_string()
            } else {
                self.remediation
            },
            recommended_action: self.recommended_action,
            evidence_kind: self.evidence_kind,
            artifact_kind: self.artifact_kind,
            artifact_scope: self.artifact_scope,
            signal_class,
            artifact_path: self.artifact_path,
            policy_contexts,
            line_number: self.line_number,
        }
    }
}

impl Finding {
    /// Create a new FindingBuilder with required fields
    ///
    /// This is the preferred way to create Finding instances.
    ///
    /// # Arguments
    /// * `rule_id` - The unique rule identifier
    /// * `category` - The threat category
    ///
    /// # Example
    /// ```
    /// use skill_veil_core::findings::{Finding, ThreatCategory, Severity, MatchTarget};
    ///
    /// let finding = Finding::builder("RULE_001", ThreatCategory::RemoteExec)
    ///     .severity(Severity::High)
    ///     .confidence(0.95)
    ///     .matched_on(MatchTarget::Document)
    ///     .match_value("curl | bash")
    ///     .reason("Remote code execution detected")
    ///     .build();
    /// ```
    #[must_use]
    pub fn builder(rule_id: impl Into<String>, category: ThreatCategory) -> FindingBuilder {
        FindingBuilder::new(rule_id, category)
    }

    /// Set the line number for this finding
    #[must_use]
    pub fn with_line(mut self, line: usize) -> Self {
        self.line_number = Some(line);
        self
    }

    /// Attach artifact context after the finding has been created.
    #[must_use]
    pub fn with_artifact(
        mut self,
        artifact_kind: ArtifactKind,
        artifact_path: impl Into<String>,
    ) -> Self {
        self.artifact_kind = artifact_kind;
        self.artifact_scope = artifact_scope_for_kind(artifact_kind);
        self.artifact_path = Some(artifact_path.into());
        self
    }

    /// Replace the match target after the finding has been created.
    #[must_use]
    pub fn with_match_target(mut self, matched_on: MatchTarget) -> Self {
        self.matched_on = matched_on;
        self
    }

    /// Calculate the weighted score for this finding
    pub fn weighted_score(&self) -> f32 {
        self.severity.weight() as f32 * self.confidence * signal_weight(self.signal_class)
    }
}

pub fn artifact_scope_for_kind(artifact_kind: ArtifactKind) -> ArtifactScope {
    match artifact_kind {
        ArtifactKind::SkillDocument
        | ArtifactKind::AgentInstruction
        | ArtifactKind::PromptPackDocument
        | ArtifactKind::McpServerManifest => ArtifactScope::AgentEntrypoint,
        ArtifactKind::PackageManifest | ArtifactKind::Lockfile | ArtifactKind::GenericArtifact => {
            ArtifactScope::PackageRootArtifact
        }
        ArtifactKind::ReferencedArtifact | ArtifactKind::CodeSnippet => {
            ArtifactScope::SupportingArtifact
        }
    }
}

pub fn signal_class_for(category: ThreatCategory) -> SignalClass {
    match category {
        ThreatCategory::SupplyChain | ThreatCategory::ScopeCreep => SignalClass::Hygiene,
        ThreatCategory::RemoteExec
        | ThreatCategory::CredentialExposure
        | ThreatCategory::DataExfiltration
        | ThreatCategory::PrivilegeEscalation
        | ThreatCategory::UnsafeBinary => SignalClass::MaliciousBehavior,
        ThreatCategory::PersistentPromptTampering
        | ThreatCategory::ToolAbuse
        | ThreatCategory::AutonomyEscalation
        | ThreatCategory::Obfuscation
        | ThreatCategory::SocialManipulation => SignalClass::SuspiciousPackageBehavior,
        ThreatCategory::PersuasiveLanguage | ThreatCategory::Generic => SignalClass::ReviewSignal,
    }
}

fn signal_weight(signal_class: SignalClass) -> f32 {
    match signal_class {
        SignalClass::Hygiene => SIGNAL_WEIGHT_HYGIENE,
        SignalClass::SuspiciousPackageBehavior => SIGNAL_WEIGHT_SUSPICIOUS,
        SignalClass::MaliciousBehavior => SIGNAL_WEIGHT_MALICIOUS,
        SignalClass::ReviewSignal => SIGNAL_WEIGHT_REVIEW,
    }
}

fn default_remediation(category: ThreatCategory, policy_contexts: &[OperationalContext]) -> String {
    let context_hint = if policy_contexts.is_empty() {
        "Primary operational context: review required.".to_string()
    } else {
        let labels = policy_contexts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        format!("Primary operational contexts: {labels}.")
    };

    let base = match category {
        ThreatCategory::RemoteExec => {
            "Eliminate remote execution paths or require verified hashes, pinned sources, and explicit human approval before running downloaded code."
        }
        ThreatCategory::SupplyChain => {
            "Pin dependencies and artifacts, add lockfiles, and verify provenance before installation or execution."
        }
        ThreatCategory::PersistentPromptTampering => {
            "Remove persistent instruction overrides, prevent writes to long-lived instruction files, and require explicit review for memory, prompt, or system-behavior changes."
        }
        ThreatCategory::CredentialExposure => {
            "Move secrets to secure storage, rotate exposed credentials, and avoid embedding tokens in skills, manifests, or scripts."
        }
        ThreatCategory::ToolAbuse => {
            "Restrict tool scopes to the minimum required, disable destructive tool paths by default, and require review before enabling filesystem, browser, shell, or admin-capable tools."
        }
        ThreatCategory::AutonomyEscalation => {
            "Reduce autonomy, add approval gates for high-impact actions, and block self-approval, self-propagation, or unattended coordination workflows."
        }
        ThreatCategory::PrivilegeEscalation => {
            "Remove privileged execution, host mounts, or elevated system access unless strictly required, isolated, and manually reviewed."
        }
        ThreatCategory::DataExfiltration => {
            "Block outbound transfer of sensitive data, constrain network egress, and require explicit approval for external communication or uploads."
        }
        ThreatCategory::PersuasiveLanguage | ThreatCategory::SocialManipulation => {
            "Treat manipulative language as a review signal, reject anti-safety framing, and require human validation before acting on urgent, coercive, or trust-bypassing instructions."
        }
        ThreatCategory::ScopeCreep => {
            "Reduce requested permissions and keep artifact capabilities aligned with the smallest operational scope."
        }
        ThreatCategory::Obfuscation => {
            "Deobfuscate payloads before execution and require manual review for encoded or hidden behavior."
        }
        ThreatCategory::UnsafeBinary => {
            "Validate binary origin, signatures, and integrity before execution."
        }
        ThreatCategory::Generic => {
            "Review the artifact manually and tighten controls around execution, network access, and secrets."
        }
    };

    format!("{base} {context_hint}")
}

fn calibrate_confidence(
    raw_confidence: f32,
    evidence_kind: EvidenceKind,
    category: ThreatCategory,
) -> (f32, String) {
    let evidence_baseline: f32 = match evidence_kind {
        EvidenceKind::Ioc => 0.98,
        EvidenceKind::Behavior => 0.92,
        EvidenceKind::Intent => 0.84,
        EvidenceKind::Context => 0.78,
    };
    let category_baseline: f32 = match category {
        ThreatCategory::RemoteExec
        | ThreatCategory::CredentialExposure
        | ThreatCategory::DataExfiltration => 0.94,
        ThreatCategory::SupplyChain
        | ThreatCategory::PrivilegeEscalation
        | ThreatCategory::UnsafeBinary => 0.9,
        ThreatCategory::PersistentPromptTampering | ThreatCategory::ToolAbuse => 0.86,
        ThreatCategory::AutonomyEscalation | ThreatCategory::ScopeCreep => 0.84,
        ThreatCategory::SocialManipulation | ThreatCategory::PersuasiveLanguage => 0.8,
        ThreatCategory::Obfuscation => 0.82,
        ThreatCategory::Generic => 0.76,
    };
    let baseline = ((evidence_baseline + category_baseline) / 2.0).clamp(0.1, 0.99);
    let calibrated = ((raw_confidence * 0.7) + (baseline * 0.3)).clamp(0.1, 0.99);
    let rationale = format!(
        "Calibrated from raw {:.2} using evidence={} baseline {:.2} and category={} baseline {:.2}",
        raw_confidence, evidence_kind, evidence_baseline, category, category_baseline
    );
    (calibrated, rationale)
}

pub fn default_operational_contexts(
    category: ThreatCategory,
    artifact_kind: ArtifactKind,
) -> Vec<OperationalContext> {
    let mut contexts = Vec::new();

    match category {
        ThreatCategory::RemoteExec | ThreatCategory::SupplyChain | ThreatCategory::UnsafeBinary => {
            contexts.push(OperationalContext::Install);
        }
        ThreatCategory::CredentialExposure => contexts.push(OperationalContext::Secrets),
        ThreatCategory::ToolAbuse => {
            contexts.push(OperationalContext::CodeModification);
            contexts.push(OperationalContext::Secrets);
        }
        ThreatCategory::AutonomyEscalation => {
            contexts.push(OperationalContext::CodeModification);
            contexts.push(OperationalContext::ExternalComms);
        }
        ThreatCategory::PersistentPromptTampering => {
            contexts.push(OperationalContext::CodeModification);
            contexts.push(OperationalContext::ExternalComms);
        }
        ThreatCategory::ScopeCreep | ThreatCategory::PrivilegeEscalation => {
            contexts.push(OperationalContext::CodeModification);
        }
        ThreatCategory::DataExfiltration => {
            contexts.push(OperationalContext::Network);
            contexts.push(OperationalContext::ExternalComms);
            contexts.push(OperationalContext::Secrets);
        }
        ThreatCategory::PersuasiveLanguage | ThreatCategory::SocialManipulation => {
            contexts.push(OperationalContext::ExternalComms);
            contexts.push(OperationalContext::CodeModification);
        }
        ThreatCategory::Obfuscation | ThreatCategory::Generic => {}
    }

    if matches!(
        artifact_kind,
        ArtifactKind::PackageManifest
            | ArtifactKind::ReferencedArtifact
            | ArtifactKind::McpServerManifest
    ) && matches!(
        category,
        ThreatCategory::RemoteExec | ThreatCategory::SupplyChain | ThreatCategory::UnsafeBinary
    ) {
        contexts.push(OperationalContext::Install);
    }

    contexts.sort_by_key(|context| match context {
        OperationalContext::Install => 0,
        OperationalContext::Network => 1,
        OperationalContext::Secrets => 2,
        OperationalContext::CodeModification => 3,
        OperationalContext::ExternalComms => 4,
    });
    contexts.dedup();
    contexts
}

/// Summary of all findings for a skill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    /// Total number of findings
    pub total_findings: usize,
    /// Breakdown by severity
    pub by_severity: SeverityCounts,
    /// Breakdown by category
    pub by_category: Vec<(ThreatCategory, usize)>,
    /// Overall risk score (0-100)
    pub risk_score: u32,
    /// Recommended action based on score
    pub recommended_action: RecommendedAction,
    /// Explainable score factors that contributed to the risk score
    pub score_breakdown: Vec<RiskFactor>,
    /// Contextual triggers that forced or escalated the recommended action.
    pub action_triggers: Vec<ActionTrigger>,
}

/// Count of findings by severity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

/// Explainable score factor aggregated across findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor: String,
    pub contribution: u32,
    pub rationale: String,
}

/// Explicit contextual reason that escalated enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTrigger {
    pub action: RecommendedAction,
    pub factor: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVerdictReport {
    pub verdict: Verdict,
    pub package_health: PackageHealth,
    pub hygiene_summary: HygieneSummary,
    pub declared_permissions: Vec<DeclaredPermission>,
    pub effective_capabilities: Vec<String>,
    pub blast_radius_summary: BlastRadiusSummary,
    pub verdict_reasons: Vec<VerdictReason>,
    pub root_cause_groups: Vec<RootCauseGroup>,
    pub top_risk_drivers: Vec<RiskFactor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum DeclaredPermission {
    BrowserFull,
    FileWrite,
    ShellExec,
    NetworkAccess,
    SecretsAccess,
    OAuthScopes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum BlastRadiusLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlastRadiusSummary {
    pub level: Option<BlastRadiusLevel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_permissions: Vec<DeclaredPermission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PackageHealth {
    Healthy,
    NeedsReview,
    Elevated,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HygieneSummary {
    pub package_root_findings: usize,
    pub supporting_findings: usize,
    pub top_rules: Vec<String>,
}

/// Summary of the scanner deduplication pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeduplicationSummary {
    pub original_findings: usize,
    pub unique_findings: usize,
    pub duplicates_removed: usize,
}

pub use crate::verdict::derive_package_verdict;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FindingDedupKey {
    rule_id: String,
    category: String,
    matched_on: String,
    match_value: String,
    artifact_kind: String,
    artifact_path: Option<String>,
}

/// Remove semantically duplicate findings while preserving the strongest variant.
#[must_use]
pub fn deduplicate_findings(findings: Vec<Finding>) -> (Vec<Finding>, DeduplicationSummary) {
    let original_findings = findings.len();
    let mut deduped = BTreeMap::<FindingDedupKey, Finding>::new();

    for finding in findings {
        let key = FindingDedupKey {
            rule_id: finding.rule_id.clone(),
            category: finding.category.to_string(),
            matched_on: finding.matched_on.to_string(),
            match_value: finding.match_value.clone(),
            artifact_kind: finding.artifact_kind.to_string(),
            artifact_path: finding.artifact_path.clone(),
        };

        deduped
            .entry(key)
            .and_modify(|existing| {
                let finding_is_stronger = finding.severity > existing.severity
                    || (finding.severity == existing.severity
                        && finding.confidence > existing.confidence);

                existing.severity = existing.severity.max(finding.severity);
                existing.confidence = existing.confidence.max(finding.confidence);
                existing.recommended_action =
                    RecommendedAction::max(existing.recommended_action, finding.recommended_action);

                if finding_is_stronger || finding.reason.len() > existing.reason.len() {
                    existing.reason = finding.reason.clone();
                }
                if finding_is_stronger || finding.remediation.len() > existing.remediation.len() {
                    existing.remediation = finding.remediation.clone();
                }
                if existing.line_number.is_none() {
                    existing.line_number = finding.line_number;
                }
            })
            .or_insert(finding);
    }

    let mut unique_findings: Vec<_> = deduped.into_values().collect();
    unique_findings.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then_with(|| left.artifact_path.cmp(&right.artifact_path))
            .then_with(|| left.line_number.cmp(&right.line_number))
            .then_with(|| left.match_value.cmp(&right.match_value))
    });

    let unique_count = unique_findings.len();
    (
        unique_findings,
        DeduplicationSummary {
            original_findings,
            unique_findings: unique_count,
            duplicates_removed: original_findings.saturating_sub(unique_count),
        },
    )
}

impl FindingSummary {
    /// Calculate summary from a list of findings
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self::from_findings_and_graph(findings, &ArtifactGraph::new())
    }

    /// Calculate summary from findings plus graph-derived contextual risk.
    #[must_use]
    pub fn from_findings_and_graph(findings: &[Finding], artifact_graph: &ArtifactGraph) -> Self {
        let mut by_severity = SeverityCounts::default();
        let mut category_map = std::collections::HashMap::new();
        let mut factor_map = std::collections::HashMap::<String, RiskFactor>::new();

        let mut total_score: f32 = 0.0;

        for finding in findings {
            match finding.severity {
                Severity::Low => by_severity.low += 1,
                Severity::Medium => by_severity.medium += 1,
                Severity::High => by_severity.high += 1,
                Severity::Critical => by_severity.critical += 1,
            }

            *category_map.entry(finding.category).or_insert(0) += 1;
            total_score += finding.weighted_score();

            let evidence_factor = format!("evidence:{}", finding.evidence_kind);
            let evidence_weight = finding.evidence_kind.weight();
            factor_map
                .entry(evidence_factor.clone())
                .and_modify(|factor| factor.contribution += evidence_weight)
                .or_insert(RiskFactor {
                    factor: evidence_factor,
                    contribution: evidence_weight,
                    rationale: finding.evidence_kind.description().to_string(),
                });

            let artifact_factor = format!("artifact:{}", finding.artifact_kind);
            factor_map
                .entry(artifact_factor.clone())
                .and_modify(|factor| factor.contribution += 1)
                .or_insert(RiskFactor {
                    factor: artifact_factor,
                    contribution: 1,
                    rationale: "Risk observed in this artifact class".to_string(),
                });
        }

        let (graph_score, graph_action, graph_factors, mut action_triggers) =
            graph_risk_context(artifact_graph);
        total_score += graph_score as f32;

        for factor in graph_factors {
            factor_map
                .entry(factor.factor.clone())
                .and_modify(|existing| existing.contribution += factor.contribution)
                .or_insert(factor);
        }

        let risk_score = (total_score.min(100.0)) as u32;

        let score_based_action = if risk_score > RISK_THRESHOLD_BLOCK {
            RecommendedAction::Block
        } else if risk_score > RISK_THRESHOLD_APPROVAL {
            RecommendedAction::RequireApproval
        } else {
            RecommendedAction::Log
        };

        let finding_based_action = findings
            .iter()
            .fold(RecommendedAction::Log, |current, finding| {
                RecommendedAction::max(current, finding.recommended_action)
            });
        let recommended_action = RecommendedAction::max(
            RecommendedAction::max(score_based_action, finding_based_action),
            graph_action,
        );

        let by_category: Vec<_> = category_map.into_iter().collect();
        let mut score_breakdown: Vec<_> = factor_map.into_values().collect();
        score_breakdown.sort_by(|left, right| right.contribution.cmp(&left.contribution));

        Self {
            total_findings: findings.len(),
            by_severity,
            by_category,
            risk_score,
            recommended_action,
            score_breakdown,
            action_triggers: {
                action_triggers
                    .sort_by(|left, right| right.action.priority().cmp(&left.action.priority()));
                action_triggers
            },
        }
    }
}

fn graph_risk_context(
    artifact_graph: &ArtifactGraph,
) -> (u32, RecommendedAction, Vec<RiskFactor>, Vec<ActionTrigger>) {
    let mut total_score = 0;
    let mut action = RecommendedAction::Log;
    let mut factors = Vec::new();
    let mut triggers = Vec::new();

    for node in &artifact_graph.nodes {
        for capability in &node.capabilities {
            let source_label = match capability.source {
                ArtifactCapabilitySource::Declared => "declared",
                ArtifactCapabilitySource::Observed => "observed",
            };
            let (factor, contribution, rationale) = match capability.capability {
                ArtifactCapability::InstallExecution => (
                    format!("capability:{source_label}:install_execution"),
                    CAPABILITY_WEIGHT_INSTALL_EXECUTION,
                    format!("Artifact can execute code during installation ({source_label})"),
                ),
                ArtifactCapability::BrowserAccess => (
                    format!("capability:{source_label}:browser_access"),
                    CAPABILITY_WEIGHT_BROWSER_ACCESS,
                    format!("Artifact requests broad browser automation access ({source_label})"),
                ),
                ArtifactCapability::NetworkAccess => (
                    format!("capability:{source_label}:network_access"),
                    CAPABILITY_WEIGHT_NETWORK_ACCESS,
                    format!("Artifact can expose or request network connectivity ({source_label})"),
                ),
                ArtifactCapability::ExposesBinary => (
                    format!("capability:{source_label}:exposes_binary"),
                    CAPABILITY_WEIGHT_EXPOSES_BINARY,
                    format!("Artifact exposes executable entrypoints ({source_label})"),
                ),
                ArtifactCapability::PrivilegedRuntime => (
                    format!("capability:{source_label}:privileged_runtime"),
                    CAPABILITY_WEIGHT_PRIVILEGED_RUNTIME,
                    format!("Artifact requests privileged runtime access ({source_label})"),
                ),
                ArtifactCapability::HostFilesystemAccess => (
                    format!("capability:{source_label}:host_filesystem_access"),
                    CAPABILITY_WEIGHT_HOST_FILESYSTEM_ACCESS,
                    format!("Artifact can access host filesystem paths ({source_label})"),
                ),
                ArtifactCapability::ProcessExecution => (
                    format!("capability:{source_label}:process_execution"),
                    CAPABILITY_WEIGHT_PROCESS_EXECUTION,
                    format!("Artifact can execute child processes ({source_label})"),
                ),
                ArtifactCapability::SecretAccess => (
                    format!("capability:{source_label}:secret_access"),
                    CAPABILITY_WEIGHT_SECRET_ACCESS,
                    format!("Artifact can access or expose secrets ({source_label})"),
                ),
                ArtifactCapability::PersistenceSurface => (
                    format!("capability:{source_label}:persistence_surface"),
                    CAPABILITY_WEIGHT_PERSISTENCE_SURFACE,
                    format!("Artifact can establish persistence ({source_label})"),
                ),
                ArtifactCapability::FilesystemWrite => (
                    format!("capability:{source_label}:filesystem_write"),
                    CAPABILITY_WEIGHT_FILESYSTEM_WRITE,
                    format!("Artifact can write to the filesystem ({source_label})"),
                ),
                ArtifactCapability::IdentityAccess => (
                    format!("capability:{source_label}:identity_access"),
                    CAPABILITY_WEIGHT_IDENTITY_ACCESS,
                    format!("Artifact requests access to OAuth or identity-linked resources ({source_label})"),
                ),
                ArtifactCapability::InboundNetworkSurface => (
                    format!("capability:{source_label}:inbound_network_surface"),
                    CAPABILITY_WEIGHT_INBOUND_SURFACE,
                    format!("Artifact exposes an inbound network or webhook surface ({source_label})"),
                ),
            };

            total_score += contribution;
            factors.push(RiskFactor {
                factor,
                contribution,
                rationale: format!("{rationale}: {}", node.path),
            });
        }

        let has_privileged = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::PrivilegedRuntime);
        let has_host_fs = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::HostFilesystemAccess);
        let has_install = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::InstallExecution);
        let has_network = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::NetworkAccess);
        let has_binary = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::ExposesBinary);
        let has_secret_access = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::SecretAccess);
        let has_persistence = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::PersistenceSurface);
        let has_browser_access = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::BrowserAccess);
        let has_identity_access = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::IdentityAccess);

        if has_privileged && has_host_fs {
            total_score += CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST;
            action = RecommendedAction::max(action, RecommendedAction::Block);
            factors.push(RiskFactor {
                factor: "capability_combo:privileged_host_filesystem".to_string(),
                contribution: CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST,
                rationale: format!(
                    "Artifact combines privileged runtime with host filesystem access: {}",
                    node.path
                ),
            });
            triggers.push(ActionTrigger {
                action: RecommendedAction::Block,
                factor: "capability_combo:privileged_host_filesystem".to_string(),
                rationale: format!(
                    "Block forced because {} combines privileged runtime with host filesystem access",
                    node.path
                ),
            });
        }

        if has_install && has_network {
            total_score += CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK;
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            factors.push(RiskFactor {
                factor: "capability_combo:install_network".to_string(),
                contribution: CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK,
                rationale: format!(
                    "Artifact combines install-time execution with network access: {}",
                    node.path
                ),
            });
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:install_network".to_string(),
                rationale: format!(
                    "Approval forced because {} combines install-time execution with network access",
                    node.path
                ),
            });
        }

        if has_install && has_binary {
            total_score += CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY;
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            factors.push(RiskFactor {
                factor: "capability_combo:install_binary".to_string(),
                contribution: CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY,
                rationale: format!(
                    "Artifact combines install-time execution with exposed binaries: {}",
                    node.path
                ),
            });
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:install_binary".to_string(),
                rationale: format!(
                    "Approval forced because {} combines install-time execution with exposed binaries",
                    node.path
                ),
            });
        }

        if has_secret_access && has_network {
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:secret_access_network".to_string(),
                rationale: format!(
                    "Approval forced because {} combines secret access with network connectivity",
                    node.path
                ),
            });
        }

        if has_persistence && has_network {
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:persistence_network".to_string(),
                rationale: format!(
                    "Approval forced because {} combines persistence with network connectivity",
                    node.path
                ),
            });
        }

        if has_browser_access && has_identity_access {
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:browser_identity_scope".to_string(),
                rationale: format!(
                    "Approval forced because {} combines broad browser automation with identity-linked access",
                    node.path
                ),
            });
        }
    }

    (total_score, action, factors, triggers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_graph::{
        ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactGraph,
    };

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_weights() {
        assert_eq!(Severity::Low.weight(), SEVERITY_WEIGHT_LOW);
        assert_eq!(Severity::Medium.weight(), SEVERITY_WEIGHT_MEDIUM);
        assert_eq!(Severity::High.weight(), SEVERITY_WEIGHT_HIGH);
        assert_eq!(Severity::Critical.weight(), SEVERITY_WEIGHT_CRITICAL);
    }

    #[test]
    fn test_finding_weighted_score() {
        let finding = Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
            .severity(Severity::High)
            .confidence(0.95)
            .matched_on(MatchTarget::Document)
            .match_value("curl | bash")
            .reason("Remote execution detected")
            .build();
        assert!((finding.weighted_score() - 56.6).abs() < 0.2);
    }

    #[test]
    fn test_finding_summary() {
        let findings = vec![
            Finding::builder("R1", ThreatCategory::RemoteExec)
                .severity(Severity::High)
                .confidence(0.9)
                .matched_on(MatchTarget::Document)
                .match_value("test")
                .reason("test")
                .build(),
            Finding::builder("R2", ThreatCategory::SupplyChain)
                .severity(Severity::Medium)
                .confidence(0.8)
                .matched_on(MatchTarget::Document)
                .match_value("test")
                .reason("test")
                .build(),
        ];

        let summary = FindingSummary::from_findings(&findings);
        assert_eq!(summary.total_findings, 2);
        assert_eq!(summary.by_severity.high, 1);
        assert_eq!(summary.by_severity.medium, 1);
        assert_eq!(summary.recommended_action, RecommendedAction::Block);
        assert!(!summary.score_breakdown.is_empty());
    }

    #[test]
    fn test_finding_builder_defaults() {
        let finding = Finding::builder("TEST_RULE", ThreatCategory::Generic).build();
        assert_eq!(finding.rule_id, "TEST_RULE");
        assert_eq!(finding.category, ThreatCategory::Generic);
        assert_eq!(finding.severity, Severity::Medium); // default
        assert!((finding.raw_confidence - 0.9).abs() < 0.01);
        assert!(finding.confidence < finding.raw_confidence);
        assert_eq!(
            finding.recommended_action,
            RecommendedAction::RequireApproval
        );
        assert_eq!(finding.evidence_kind, EvidenceKind::Behavior);
        assert_eq!(finding.artifact_kind, ArtifactKind::SkillDocument);
        assert!(!finding.remediation.is_empty());
        assert!(!finding.confidence_rationale.is_empty());
        assert!(finding.line_number.is_none());
    }

    #[test]
    fn test_finding_builder_with_line() {
        let finding = Finding::builder("TEST_RULE", ThreatCategory::RemoteExec)
            .severity(Severity::Critical)
            .line(42)
            .build();
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.line_number, Some(42));
        assert_eq!(finding.recommended_action, RecommendedAction::Block);
    }

    #[test]
    fn test_finding_builder_with_evidence_and_artifact() {
        let finding = Finding::builder("TEST_RULE", ThreatCategory::SupplyChain)
            .severity(Severity::High)
            .evidence_kind(EvidenceKind::Ioc)
            .artifact(
                ArtifactKind::ReferencedArtifact,
                Some("scripts/install.sh".to_string()),
            )
            .build();

        assert_eq!(finding.evidence_kind, EvidenceKind::Ioc);
        assert_eq!(finding.artifact_kind, ArtifactKind::ReferencedArtifact);
        assert_eq!(finding.artifact_path.as_deref(), Some("scripts/install.sh"));
        assert!(finding
            .policy_contexts
            .contains(&OperationalContext::Install));
    }

    #[test]
    fn test_summary_respects_highest_recommended_action() {
        let findings = vec![Finding::builder("R1", ThreatCategory::SupplyChain)
            .severity(Severity::Low)
            .confidence(0.1)
            .action(RecommendedAction::Block)
            .matched_on(MatchTarget::Document)
            .match_value("danger")
            .reason("explicit block")
            .build()];

        let summary = FindingSummary::from_findings(&findings);
        assert_eq!(summary.recommended_action, RecommendedAction::Block);
    }

    #[test]
    fn test_summary_escalates_for_high_risk_capability_combo() {
        let findings = vec![Finding::builder("R1", ThreatCategory::Generic)
            .severity(Severity::Low)
            .confidence(0.2)
            .action(RecommendedAction::Log)
            .matched_on(MatchTarget::Document)
            .match_value("note")
            .reason("note")
            .build()];

        let mut graph = ArtifactGraph::new();
        graph.add_node_with_capabilities(
            "docker-compose.yml",
            ArtifactKind::PackageManifest,
            vec![
                ArtifactCapabilityFact {
                    capability: ArtifactCapability::PrivilegedRuntime,
                    source: ArtifactCapabilitySource::Declared,
                },
                ArtifactCapabilityFact {
                    capability: ArtifactCapability::HostFilesystemAccess,
                    source: ArtifactCapabilitySource::Declared,
                },
            ],
        );

        let summary = FindingSummary::from_findings_and_graph(&findings, &graph);
        assert_eq!(summary.recommended_action, RecommendedAction::Block);
        assert!(summary
            .score_breakdown
            .iter()
            .any(|factor| factor.factor == "capability_combo:privileged_host_filesystem"));
    }

    #[test]
    fn test_deduplicate_findings_keeps_strongest_variant() {
        let duplicate_a = Finding::builder("RULE_DUP", ThreatCategory::SupplyChain)
            .severity(Severity::Medium)
            .confidence(0.55)
            .matched_on(MatchTarget::Document)
            .match_value("curl https://example.com/install.sh")
            .reason("Short reason")
            .build();
        let duplicate_b = Finding::builder("RULE_DUP", ThreatCategory::SupplyChain)
            .severity(Severity::High)
            .confidence(0.9)
            .matched_on(MatchTarget::Document)
            .match_value("curl https://example.com/install.sh")
            .reason("Longer reason with more context")
            .remediation(
                "Pinned remediation text with extra context about provenance and review gates",
            )
            .line(12)
            .build();

        let (findings, summary) = deduplicate_findings(vec![duplicate_a, duplicate_b]);

        assert_eq!(summary.original_findings, 2);
        assert_eq!(summary.unique_findings, 1);
        assert_eq!(summary.duplicates_removed, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].confidence >= 0.85);
        assert_eq!(findings[0].line_number, Some(12));
        assert_eq!(findings[0].reason, "Longer reason with more context");
        assert_eq!(
            findings[0].remediation,
            "Pinned remediation text with extra context about provenance and review gates"
        );
    }

    #[test]
    fn test_operational_contexts_capture_phase2_categories() {
        let prompt_tampering =
            Finding::builder("PROMPT_TAMPER", ThreatCategory::PersistentPromptTampering)
                .evidence_kind(EvidenceKind::Intent)
                .build();
        let tool_abuse = Finding::builder("TOOL_ABUSE", ThreatCategory::ToolAbuse)
            .evidence_kind(EvidenceKind::Behavior)
            .build();
        let autonomy = Finding::builder("AUTO", ThreatCategory::AutonomyEscalation)
            .evidence_kind(EvidenceKind::Intent)
            .build();
        let social = Finding::builder("SOCIAL", ThreatCategory::SocialManipulation)
            .evidence_kind(EvidenceKind::Intent)
            .build();

        assert!(prompt_tampering
            .policy_contexts
            .contains(&OperationalContext::CodeModification));
        assert!(tool_abuse
            .policy_contexts
            .contains(&OperationalContext::Secrets));
        assert!(autonomy
            .policy_contexts
            .contains(&OperationalContext::ExternalComms));
        assert!(social
            .policy_contexts
            .contains(&OperationalContext::ExternalComms));
    }

    #[test]
    fn test_confidence_calibration_prefers_behavior_over_intent() {
        let behavior = Finding::builder("BEHAVIOR", ThreatCategory::RemoteExec)
            .confidence(0.8)
            .evidence_kind(EvidenceKind::Behavior)
            .build();
        let intent = Finding::builder("INTENT", ThreatCategory::SocialManipulation)
            .confidence(0.8)
            .evidence_kind(EvidenceKind::Intent)
            .build();

        assert!(behavior.confidence > intent.confidence);
        assert!(behavior.confidence_rationale.contains("evidence=behavior"));
        assert!(intent.confidence_rationale.contains("evidence=intent"));
    }

    #[test]
    fn test_compound_verdict_escalates_prompt_override_plus_exec() {
        let findings = vec![
            Finding::builder(
                "OFFICIAL_PROMPT_OVERRIDE_WITH_PERSISTENCE",
                ThreatCategory::PersistentPromptTampering,
            )
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("override + persistence")
            .reason("prompt override")
            .build(),
            Finding::builder(
                "OFFICIAL_REMOTE_FETCH_EXEC_POLYGLOT",
                ThreatCategory::RemoteExec,
            )
            .artifact_scope(ArtifactScope::SupportingArtifact)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("fetch + exec")
            .reason("remote exec")
            .build(),
        ];

        let primary = FindingSummary::from_findings(&findings[..1]);
        let supporting = FindingSummary::from_findings(&findings[1..]);
        let package = FindingSummary::from_findings(&findings);
        let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

        assert_eq!(verdict.verdict, Verdict::Malicious);
        assert!(verdict.verdict_reasons.iter().any(|reason| reason
            .rationale
            .contains("prompt override is paired with execution")));
    }

    #[test]
    fn test_compound_verdict_escalates_remote_fetch_plus_install_hook() {
        let findings = vec![
            Finding::builder(
                "MANIFEST_PACKAGE_JSON_INSTALL_HOOK",
                ThreatCategory::SupplyChain,
            )
            .artifact_scope(ArtifactScope::PackageRootArtifact)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("postinstall")
            .reason("install hook")
            .build(),
            Finding::builder(
                "OFFICIAL_REMOTE_FETCH_EXEC_POLYGLOT",
                ThreatCategory::RemoteExec,
            )
            .artifact_scope(ArtifactScope::SupportingArtifact)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("requests.get + exec")
            .reason("remote exec")
            .build(),
        ];

        let primary = FindingSummary::from_findings(&[]);
        let supporting = FindingSummary::from_findings(&findings[1..]);
        let package = FindingSummary::from_findings(&findings);
        let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

        assert_eq!(verdict.verdict, Verdict::Malicious);
        assert!(verdict.verdict_reasons.iter().any(|reason| reason
            .rationale
            .contains("install hook is paired with remote fetch")));
    }

    #[test]
    fn test_compound_verdict_escalates_broad_permissions_plus_autonomy() {
        let findings = vec![
            Finding::builder(
                "DECLARED_PERMISSION_BROWSER_FULL",
                ThreatCategory::ScopeCreep,
            )
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .action(RecommendedAction::Log)
            .matched_on(MatchTarget::Document)
            .match_value("browser full")
            .reason("declared permission")
            .build(),
            Finding::builder(
                "OFFICIAL_FORCED_APPROVAL_BYPASS",
                ThreatCategory::AutonomyEscalation,
            )
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("skip approval gate")
            .reason("approval bypass")
            .build(),
        ];

        let primary = FindingSummary::from_findings(&findings);
        let supporting = FindingSummary::from_findings(&[]);
        let package = FindingSummary::from_findings(&findings);
        let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

        assert_eq!(verdict.verdict, Verdict::Malicious);
        assert!(verdict.verdict_reasons.iter().any(|reason| reason
            .rationale
            .contains("broad permissions are paired with autonomous execution semantics")));
    }

    #[test]
    fn test_oauth_without_high_risk_autonomy_does_not_escalate_to_malicious() {
        let findings = vec![
            Finding::builder(
                "DECLARED_PERMISSION_OAUTH_SCOPES",
                ThreatCategory::ScopeCreep,
            )
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .action(RecommendedAction::Log)
            .matched_on(MatchTarget::Document)
            .match_value("oauth scopes")
            .reason("declared permission")
            .build(),
            Finding::builder(
                "OFFICIAL_AUTONOMY_ESCALATION_NO_REVIEW",
                ThreatCategory::AutonomyEscalation,
            )
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .signal_class(SignalClass::SuspiciousPackageBehavior)
            .action(RecommendedAction::RequireApproval)
            .matched_on(MatchTarget::Document)
            .match_value("continue automatically")
            .reason("approval wording without explicit high-risk action")
            .build(),
        ];

        let primary = FindingSummary::from_findings(&findings);
        let supporting = FindingSummary::from_findings(&[]);
        let package = FindingSummary::from_findings(&findings);
        let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

        assert_eq!(verdict.verdict, Verdict::Suspicious);
    }

    #[test]
    fn test_compound_verdict_escalates_mcp_remote_endpoint_plus_exec_surface() {
        let findings = vec![
            Finding::builder("MCP_REMOTE_SERVER_ENDPOINT", ThreatCategory::SupplyChain)
                .artifact_scope(ArtifactScope::PackageRootArtifact)
                .action(RecommendedAction::RequireApproval)
                .matched_on(MatchTarget::Document)
                .match_value("remote endpoint")
                .reason("mcp remote endpoint")
                .build(),
            Finding::builder("MCP_REMOTE_EXEC_SURFACE", ThreatCategory::RemoteExec)
                .artifact_scope(ArtifactScope::PackageRootArtifact)
                .action(RecommendedAction::RequireApproval)
                .matched_on(MatchTarget::Document)
                .match_value("remote endpoint with stdio")
                .reason("mcp remote exec")
                .build(),
        ];

        let primary = FindingSummary::from_findings(&[]);
        let supporting = FindingSummary::from_findings(&[]);
        let package = FindingSummary::from_findings(&findings);
        let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

        assert_eq!(verdict.verdict, Verdict::Malicious);
        assert!(verdict.verdict_reasons.iter().any(|reason| reason
            .rationale
            .contains("MCP remote endpoint is paired with command or stdio")));
    }

    #[test]
    fn test_isolated_weak_package_root_signal_downgrades_to_benign() {
        let findings =
            vec![
                Finding::builder("MCP_TOOLING_TRANSPORT_DECLARED", ThreatCategory::ToolAbuse)
                    .artifact_scope(ArtifactScope::PackageRootArtifact)
                    .action(RecommendedAction::RequireApproval)
                    .matched_on(MatchTarget::Document)
                    .match_value("mcp transport")
                    .reason("transport declared")
                    .build(),
            ];

        let primary = FindingSummary::from_findings(&[]);
        let supporting = FindingSummary::from_findings(&[]);
        let package = FindingSummary::from_findings(&findings);
        let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

        assert_eq!(verdict.verdict, Verdict::Benign);
    }

    #[test]
    fn test_hygiene_only_agent_entrypoint_signal_stays_benign() {
        let findings = vec![
            Finding::builder(
                "DECLARED_PERMISSION_NETWORK_ACCESS",
                ThreatCategory::ScopeCreep,
            )
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .action(RecommendedAction::Log)
            .matched_on(MatchTarget::Document)
            .match_value("network access")
            .reason("declared network access")
            .build(),
            Finding::builder("CAPABILITY_PERMISSION_MISMATCH", ThreatCategory::ScopeCreep)
                .artifact_scope(ArtifactScope::AgentEntrypoint)
                .action(RecommendedAction::RequireApproval)
                .matched_on(MatchTarget::Document)
                .match_value("narrow intent with broad capability request")
                .reason("permission mismatch")
                .build(),
        ];

        let primary = FindingSummary::from_findings(&findings);
        let supporting = FindingSummary::from_findings(&[]);
        let package = FindingSummary::from_findings(&findings);
        let verdict = derive_package_verdict(&findings, &primary, &supporting, &package);

        assert_eq!(verdict.verdict, Verdict::Benign);
        assert_eq!(verdict.package_health, PackageHealth::Healthy);
    }
}
