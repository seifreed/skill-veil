use super::{
    artifact_scope_for_kind, calibrate_confidence, default_operational_contexts,
    default_remediation, signal_class_for, ArtifactKind, ArtifactScope, EvidenceKind, Finding,
    MatchTarget, RecommendedAction, Severity, SignalClass, ThreatCategory,
};

const DEFAULT_FINDING_CONFIDENCE: f32 = 0.9;

const REMOTE_EXEC_INDICATORS: &[&str] = &[
    "http://",
    "https://",
    "curl ",
    "wget ",
    "fetch(",
    "requests.get",
    "urllib.request.urlopen",
    "invoke-webrequest",
    "iwr ",
];
const SENSITIVE_PAYLOAD_KEYWORDS: &[&str] = &["cookie", "token", "secret", "session"];
const TRANSMIT_VERBS: &[&str] = &["send", "post", "upload", "forward", "exfiltrate"];
const EXFIL_CHANNELS: &[&str] = &[
    "discord.com/api/webhooks",
    "api.telegram.org/bot",
    "smtp.",
    "sendgrid",
    "mailgun",
];

fn signal_weight(signal_class: SignalClass) -> f32 {
    match signal_class {
        SignalClass::Hygiene => super::SIGNAL_WEIGHT_HYGIENE,
        SignalClass::SuspiciousPackageBehavior => super::SIGNAL_WEIGHT_SUSPICIOUS,
        SignalClass::MaliciousBehavior => super::SIGNAL_WEIGHT_MALICIOUS,
        SignalClass::ReviewSignal => super::SIGNAL_WEIGHT_REVIEW,
    }
}

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
    signal_class: Option<SignalClass>,
    artifact_path: Option<String>,
    line_number: Option<usize>,
    action_explicit: bool,
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
            signal_class: None,
            artifact_path: None,
            line_number: None,
            action_explicit: false,
        }
    }

    /// Set the severity level
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        if !self.action_explicit {
            self.recommended_action = severity.default_action();
        }
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
    ///
    /// When called, the action is treated as intentional and will not be
    /// overridden by a subsequent `.severity()` call.
    pub fn action(mut self, action: RecommendedAction) -> Self {
        self.recommended_action = action;
        self.action_explicit = true;
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
        self.signal_class = Some(signal_class);
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
        let operational_contexts = default_operational_contexts(self.category, self.artifact_kind);
        let (confidence, confidence_rationale) =
            calibrate_confidence(self.confidence, self.evidence_kind, self.category);
        let signal_class = self
            .signal_class
            .unwrap_or_else(|| signal_class_for(self.category));
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
                default_remediation(self.category, &operational_contexts).to_string()
            } else {
                self.remediation
            },
            recommended_action: self.recommended_action,
            evidence_kind: self.evidence_kind,
            artifact_kind: self.artifact_kind,
            artifact_scope: self.artifact_scope,
            signal_class,
            artifact_path: self.artifact_path,
            operational_contexts,
            line_number: self.line_number,
            suppression: None,
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

    /// Whether this finding represents conclusive evidence of malicious behavior
    /// in a supporting artifact (code block or referenced file).
    #[must_use]
    pub fn is_conclusive_malicious_evidence(&self) -> bool {
        if self.artifact_scope != ArtifactScope::SupportingArtifact
            || self.signal_class != SignalClass::MaliciousBehavior
            || self.recommended_action != RecommendedAction::Block
        {
            return false;
        }

        let is_code_context = matches!(
            self.matched_on,
            MatchTarget::CodeBlock { .. } | MatchTarget::ReferencedFile { .. }
        );

        if !is_code_context {
            return false;
        }

        let value = self.match_value.to_ascii_lowercase();
        self.evidence_matches_category(&value)
    }

    fn evidence_matches_category(&self, value: &str) -> bool {
        let has_remote_indicator = REMOTE_EXEC_INDICATORS.iter().any(|s| value.contains(s));
        let has_sensitive_payload = SENSITIVE_PAYLOAD_KEYWORDS.iter().any(|s| value.contains(s));
        let has_transmit_verb = TRANSMIT_VERBS.iter().any(|s| value.contains(s));
        let has_exfil_channel = EXFIL_CHANNELS.iter().any(|s| value.contains(s));

        match self.category {
            ThreatCategory::RemoteExec => has_remote_indicator,
            ThreatCategory::DataExfiltration => {
                (has_sensitive_payload && has_transmit_verb) || has_exfil_channel
            }
            ThreatCategory::PersistentPromptTampering => true,
            ThreatCategory::CredentialExposure => true,
            ThreatCategory::PrivilegeEscalation => true,
            ThreatCategory::SupplyChain => has_remote_indicator || has_transmit_verb,
            ThreatCategory::Obfuscation | ThreatCategory::UnsafeBinary => true,
            ThreatCategory::ToolAbuse
            | ThreatCategory::AutonomyEscalation
            | ThreatCategory::PersuasiveLanguage
            | ThreatCategory::SocialManipulation
            | ThreatCategory::ScopeCreep
            | ThreatCategory::Generic => false,
        }
    }
}
