use super::{
    ArtifactKind, EvidenceKind, OperationalContext, ThreatCategory, CATEGORY_BASELINE_AUTONOMY,
    CATEGORY_BASELINE_GENERIC, CATEGORY_BASELINE_HIGH_RISK, CATEGORY_BASELINE_OBFUSCATION,
    CATEGORY_BASELINE_SOCIAL, CATEGORY_BASELINE_SUPPLY_CHAIN, CATEGORY_BASELINE_TOOL_ABUSE,
    EVIDENCE_BASELINE_BEHAVIOR, EVIDENCE_BASELINE_CONTEXT, EVIDENCE_BASELINE_INTENT,
    EVIDENCE_BASELINE_IOC,
};

pub(crate) fn calibrate_confidence(
    raw_confidence: f32,
    evidence_kind: EvidenceKind,
    category: ThreatCategory,
) -> (f32, String) {
    let evidence_baseline: f32 = match evidence_kind {
        EvidenceKind::Ioc => EVIDENCE_BASELINE_IOC,
        EvidenceKind::Behavior => EVIDENCE_BASELINE_BEHAVIOR,
        EvidenceKind::Intent => EVIDENCE_BASELINE_INTENT,
        EvidenceKind::Context => EVIDENCE_BASELINE_CONTEXT,
    };
    let category_baseline: f32 = match category {
        ThreatCategory::RemoteExec
        | ThreatCategory::CredentialExposure
        | ThreatCategory::DataExfiltration => CATEGORY_BASELINE_HIGH_RISK,
        ThreatCategory::SupplyChain
        | ThreatCategory::PrivilegeEscalation
        | ThreatCategory::UnsafeBinary => CATEGORY_BASELINE_SUPPLY_CHAIN,
        ThreatCategory::PersistentPromptTampering | ThreatCategory::ToolAbuse => {
            CATEGORY_BASELINE_TOOL_ABUSE
        }
        ThreatCategory::AutonomyEscalation | ThreatCategory::ScopeCreep => {
            CATEGORY_BASELINE_AUTONOMY
        }
        ThreatCategory::SocialManipulation | ThreatCategory::PersuasiveLanguage => {
            CATEGORY_BASELINE_SOCIAL
        }
        ThreatCategory::Obfuscation => CATEGORY_BASELINE_OBFUSCATION,
        ThreatCategory::Generic => CATEGORY_BASELINE_GENERIC,
    };
    let baseline = ((evidence_baseline + category_baseline) / 2.0).clamp(0.1, 0.99);
    let calibrated = ((raw_confidence * 0.7) + (baseline * 0.3)).clamp(0.1, 0.99);
    let rationale = format!(
        "Calibrated from raw {:.2} using evidence={} baseline {:.2} and category={} baseline {:.2}",
        raw_confidence, evidence_kind, evidence_baseline, category, category_baseline
    );
    (calibrated, rationale)
}

pub(crate) fn default_remediation(
    category: ThreatCategory,
    contexts: &[OperationalContext],
) -> String {
    let context_hint = if contexts.is_empty() {
        "Primary operational context: review required.".to_string()
    } else {
        let labels = contexts
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

pub fn default_operational_contexts(
    category: ThreatCategory,
    _artifact_kind: ArtifactKind,
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
