use serde::{Deserialize, Serialize};
use std::fmt;
use strum_macros::Display;

pub const SEVERITY_WEIGHT_LOW: u32 = 10;
pub const SEVERITY_WEIGHT_MEDIUM: u32 = 30;
pub const SEVERITY_WEIGHT_HIGH: u32 = 60;
pub const SEVERITY_WEIGHT_CRITICAL: u32 = 90;
pub const RISK_THRESHOLD_BLOCK: u32 = 50;
pub const RISK_THRESHOLD_APPROVAL: u32 = 20;
pub const EVIDENCE_WEIGHT_IOC: u32 = 10;
pub const EVIDENCE_WEIGHT_BEHAVIOR: u32 = 8;
pub const EVIDENCE_WEIGHT_INTENT: u32 = 4;
pub const EVIDENCE_WEIGHT_CONTEXT: u32 = 3;
pub const CAPABILITY_WEIGHT_INSTALL_EXECUTION: u32 = 8;
pub const CAPABILITY_WEIGHT_NETWORK_ACCESS: u32 = 6;
pub const CAPABILITY_WEIGHT_EXPOSES_BINARY: u32 = 4;
pub const CAPABILITY_WEIGHT_PRIVILEGED_RUNTIME: u32 = 18;
pub const CAPABILITY_WEIGHT_HOST_FILESYSTEM_ACCESS: u32 = 16;
pub const CAPABILITY_WEIGHT_PROCESS_EXECUTION: u32 = 10;
pub const CAPABILITY_WEIGHT_SECRET_ACCESS: u32 = 14;
pub const CAPABILITY_WEIGHT_PERSISTENCE_SURFACE: u32 = 12;
pub const CAPABILITY_WEIGHT_FILESYSTEM_WRITE: u32 = 9;
pub const CAPABILITY_WEIGHT_BROWSER_ACCESS: u32 = 8;
pub const CAPABILITY_WEIGHT_IDENTITY_ACCESS: u32 = 14;
pub const CAPABILITY_WEIGHT_INBOUND_SURFACE: u32 = 10;
pub const CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST: u32 = 25;
pub const CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK: u32 = 12;
pub const CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY: u32 = 8;
pub const SIGNAL_WEIGHT_HYGIENE: f32 = 0.35;
pub const SIGNAL_WEIGHT_SUSPICIOUS: f32 = 0.75;
pub const SIGNAL_WEIGHT_MALICIOUS: f32 = 1.0;
pub const SIGNAL_WEIGHT_REVIEW: f32 = 0.5;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ThreatCategory {
    RemoteExec,
    SupplyChain,
    PersistentPromptTampering,
    CredentialExposure,
    ToolAbuse,
    AutonomyEscalation,
    PrivilegeEscalation,
    DataExfiltration,
    PersuasiveLanguage,
    SocialManipulation,
    ScopeCreep,
    Obfuscation,
    UnsafeBinary,
    Generic,
}

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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Low => SEVERITY_WEIGHT_LOW,
            Severity::Medium => SEVERITY_WEIGHT_MEDIUM,
            Severity::High => SEVERITY_WEIGHT_HIGH,
            Severity::Critical => SEVERITY_WEIGHT_CRITICAL,
        }
    }

    pub fn default_action(&self) -> RecommendedAction {
        match self {
            Severity::Critical | Severity::High => RecommendedAction::Block,
            Severity::Medium => RecommendedAction::RequireApproval,
            Severity::Low => RecommendedAction::Log,
        }
    }

    pub fn action_str(&self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "BLOCK",
            Severity::Medium => "REQUIRE_APPROVAL",
            Severity::Low => "LOG",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchTarget {
    Document,
    Section { name: String },
    CodeBlock { language: Option<String> },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EvidenceKind {
    Ioc,
    Behavior,
    Intent,
    Context,
}

impl EvidenceKind {
    pub fn weight(&self) -> u32 {
        match self {
            Self::Ioc => EVIDENCE_WEIGHT_IOC,
            Self::Behavior => EVIDENCE_WEIGHT_BEHAVIOR,
            Self::Intent => EVIDENCE_WEIGHT_INTENT,
            Self::Context => EVIDENCE_WEIGHT_CONTEXT,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Ioc => "Known malicious indicator",
            Self::Behavior => "Concrete risky behavior",
            Self::Intent => "Manipulative or coercive intent",
            Self::Context => "Contextual risk signal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ArtifactKind {
    SkillDocument,
    AgentInstruction,
    PromptPackDocument,
    McpServerManifest,
    CodeSnippet,
    ReferencedArtifact,
    PackageManifest,
    Lockfile,
    GenericArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ArtifactScope {
    AgentEntrypoint,
    PackageRootArtifact,
    SupportingArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SignalClass {
    Hygiene,
    SuspiciousPackageBehavior,
    MaliciousBehavior,
    ReviewSignal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum Verdict {
    Benign,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictReason {
    pub scope: ArtifactScope,
    pub category: ThreatCategory,
    pub signal_class: SignalClass,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseGroup {
    pub scope: ArtifactScope,
    pub category: ThreatCategory,
    pub signal_class: SignalClass,
    pub finding_count: usize,
    pub strongest_action: RecommendedAction,
    pub representative_rules: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum RecommendedAction {
    Log,
    RequireApproval,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub confidence: f32,
    pub raw_confidence: f32,
    pub confidence_rationale: String,
    pub matched_on: MatchTarget,
    pub match_value: String,
    pub reason: String,
    pub remediation: String,
    pub recommended_action: RecommendedAction,
    pub evidence_kind: EvidenceKind,
    pub artifact_kind: ArtifactKind,
    pub artifact_scope: ArtifactScope,
    pub signal_class: SignalClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_contexts: Vec<OperationalContext>,
    pub line_number: Option<usize>,
}

const DEFAULT_FINDING_CONFIDENCE: f32 = 0.9;

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

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self.recommended_action = severity.default_action();
        self
    }

    pub fn confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn matched_on(mut self, matched_on: MatchTarget) -> Self {
        self.matched_on = matched_on;
        self
    }

    pub fn match_value(mut self, match_value: impl Into<String>) -> Self {
        self.match_value = match_value.into();
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = remediation.into();
        self
    }

    pub fn action(mut self, action: RecommendedAction) -> Self {
        self.recommended_action = action;
        self
    }

    pub fn evidence_kind(mut self, evidence_kind: EvidenceKind) -> Self {
        self.evidence_kind = evidence_kind;
        self
    }

    pub fn artifact(mut self, artifact_kind: ArtifactKind, artifact_path: Option<String>) -> Self {
        self.artifact_kind = artifact_kind;
        self.artifact_scope = artifact_scope_for_kind(artifact_kind);
        self.artifact_path = artifact_path;
        self
    }

    pub fn artifact_scope(mut self, artifact_scope: ArtifactScope) -> Self {
        self.artifact_scope = artifact_scope;
        self
    }

    pub fn signal_class(mut self, signal_class: SignalClass) -> Self {
        self.signal_class = signal_class;
        self
    }

    pub fn line(mut self, line: usize) -> Self {
        self.line_number = Some(line);
        self
    }

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
    #[must_use]
    pub fn builder(rule_id: impl Into<String>, category: ThreatCategory) -> FindingBuilder {
        FindingBuilder::new(rule_id, category)
    }

    #[must_use]
    pub fn with_line(mut self, line: usize) -> Self {
        self.line_number = Some(line);
        self
    }

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

    #[must_use]
    pub fn with_match_target(mut self, matched_on: MatchTarget) -> Self {
        self.matched_on = matched_on;
        self
    }

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
