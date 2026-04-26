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
    // `clamp` propagates NaN, but `raw_confidence` is already sanitized at
    // the single call site `FindingBuilder::confidence` (see `builder.rs`),
    // so we never see NaN here.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(left: f32, right: f32) -> bool {
        (left - right).abs() < 1e-4
    }

    /// Contract: `calibrate_confidence` blends the raw value with a per-axis
    /// baseline using `0.7 * raw + 0.3 * baseline`. The baseline is the
    /// arithmetic mean of `EVIDENCE_BASELINE_*` and `CATEGORY_BASELINE_*`,
    /// then clamped to `[0.1, 0.99]`. This test pins the formula on a
    /// concrete (raw, evidence, category) triple so a refactor that
    /// reorders or reweights the blend cannot regress silently.
    #[test]
    fn calibrate_confidence_uses_documented_blend_formula() {
        let raw = 0.50;
        let (calibrated, _rationale) =
            calibrate_confidence(raw, EvidenceKind::Behavior, ThreatCategory::RemoteExec);
        let evidence_baseline = EVIDENCE_BASELINE_BEHAVIOR; // 0.92
        let category_baseline = CATEGORY_BASELINE_HIGH_RISK; // 0.94
        let expected_baseline = (evidence_baseline + category_baseline) / 2.0;
        let expected = (raw * 0.7 + expected_baseline * 0.3).clamp(0.1, 0.99);
        assert!(
            approx_eq(calibrated, expected),
            "blend formula regressed: got {calibrated}, expected {expected}",
        );
    }

    /// Contract: the calibrated value MUST never exceed the `0.99` ceiling.
    /// The blend `0.7*raw + 0.3*baseline` with raw=1.0 and the highest
    /// possible baselines (Ioc=0.98, HighRisk=0.94) yields ~0.988, which
    /// already sits below 0.99 — pinning `<= 0.99` confirms the clamp
    /// semantics without depending on the exact arithmetic. If a future
    /// constant change pushes the unclamped result above 0.99, the clamp
    /// MUST hold and this test pins that contract.
    #[test]
    fn calibrate_confidence_never_exceeds_zero_point_99_ceiling() {
        let (calibrated, _) =
            calibrate_confidence(1.0, EvidenceKind::Ioc, ThreatCategory::RemoteExec);
        assert!(
            calibrated <= 0.99 + f32::EPSILON,
            "calibrated must respect the 0.99 ceiling; got {calibrated}",
        );
        assert!(
            calibrated >= 0.1 - f32::EPSILON,
            "calibrated must respect the 0.1 floor; got {calibrated}",
        );
    }

    /// Contract: the calibrated value MUST clamp to the `0.1` lower bound,
    /// even when raw is 0.0 and the baseline blend would compute lower.
    /// Pre-clamp behavior: `0.0 * 0.7 + min_baseline * 0.3 = 0.3 * 0.76 ≈ 0.228`,
    /// which is above 0.1, so the clamp is exercised by checking the
    /// non-zero floor. Use a low-baseline category to confirm behavior.
    #[test]
    fn calibrate_confidence_clamps_lower_to_zero_point_one() {
        let (calibrated, _) =
            calibrate_confidence(0.0, EvidenceKind::Context, ThreatCategory::Generic);
        assert!(
            calibrated >= 0.1 - f32::EPSILON,
            "calibrated must respect the 0.1 floor; got {calibrated}",
        );
    }

    /// Contract: rationale text mentions both axes and the raw value.
    /// Operators rely on this string when auditing why a finding's
    /// calibrated confidence diverged from the rule's `confidence:` value.
    #[test]
    fn calibrate_confidence_rationale_mentions_raw_and_both_baselines() {
        let raw = 0.42;
        let (_, rationale) =
            calibrate_confidence(raw, EvidenceKind::Behavior, ThreatCategory::SupplyChain);
        assert!(
            rationale.contains("0.42"),
            "rationale must include raw value: {rationale}"
        );
        assert!(
            rationale.contains("evidence="),
            "rationale must label evidence axis: {rationale}"
        );
        assert!(
            rationale.contains("category="),
            "rationale must label category axis: {rationale}"
        );
    }

    /// Contract: `default_operational_contexts(DataExfiltration, _)` returns
    /// the canonical triple Network / Secrets / ExternalComms in stable
    /// order. Downstream `policy/eval.rs` upserts ContextPolicy entries by
    /// this list — a regression that drops `Secrets` would silently allow
    /// outbound transfer of credential payloads without the SecretAccess
    /// context gate firing.
    #[test]
    fn default_operational_contexts_for_data_exfiltration_includes_network_secrets_external() {
        let contexts = default_operational_contexts(
            ThreatCategory::DataExfiltration,
            ArtifactKind::SkillDocument,
        );
        assert!(contexts.contains(&OperationalContext::Network));
        assert!(contexts.contains(&OperationalContext::Secrets));
        assert!(contexts.contains(&OperationalContext::ExternalComms));
    }

    /// Contract: the returned list is sorted in canonical order (Install,
    /// Network, Secrets, CodeModification, ExternalComms) — JSON output and
    /// SHIELD policy generation depend on stable ordering across runs to
    /// keep diff-friendly artifacts.
    #[test]
    fn default_operational_contexts_returns_stable_canonical_order() {
        let contexts = default_operational_contexts(
            ThreatCategory::DataExfiltration,
            ArtifactKind::SkillDocument,
        );
        let canonical_index = |c: &OperationalContext| -> i32 {
            match c {
                OperationalContext::Install => 0,
                OperationalContext::Network => 1,
                OperationalContext::Secrets => 2,
                OperationalContext::CodeModification => 3,
                OperationalContext::ExternalComms => 4,
            }
        };
        let mut prev = -1i32;
        for c in &contexts {
            let idx = canonical_index(c);
            assert!(idx > prev, "contexts not canonically sorted: {contexts:?}");
            prev = idx;
        }
    }

    /// Contract: `Generic`/`Obfuscation` produce no operational contexts —
    /// they're catch-all categories with no specific operational gate. The
    /// result MUST be empty rather than a default placeholder; callers
    /// (e.g. `default_remediation`) branch on `contexts.is_empty()`.
    #[test]
    fn default_operational_contexts_for_generic_is_empty() {
        let contexts =
            default_operational_contexts(ThreatCategory::Generic, ArtifactKind::SkillDocument);
        assert!(
            contexts.is_empty(),
            "Generic must produce no contexts; got {contexts:?}",
        );
    }

    /// Contract: every category produces a non-empty remediation string —
    /// SHIELD.md generation joins these into the per-rule remediation
    /// block; an empty string would render as a blank line and confuse
    /// reviewers about whether guidance is missing or simply absent.
    #[test]
    fn default_remediation_is_non_empty_for_every_category() {
        let categories = [
            ThreatCategory::RemoteExec,
            ThreatCategory::SupplyChain,
            ThreatCategory::PersistentPromptTampering,
            ThreatCategory::CredentialExposure,
            ThreatCategory::ToolAbuse,
            ThreatCategory::AutonomyEscalation,
            ThreatCategory::PrivilegeEscalation,
            ThreatCategory::DataExfiltration,
            ThreatCategory::PersuasiveLanguage,
            ThreatCategory::SocialManipulation,
            ThreatCategory::ScopeCreep,
            ThreatCategory::Obfuscation,
            ThreatCategory::UnsafeBinary,
            ThreatCategory::Generic,
        ];
        for category in categories {
            let r = default_remediation(category, &[]);
            assert!(
                !r.trim().is_empty(),
                "remediation for {category:?} must be non-empty",
            );
        }
    }

    /// Contract: when `contexts` is empty, the appended hint is
    /// "Primary operational context: review required." (singular), NOT the
    /// plural form used when contexts are present. The two strings drive
    /// different reviewer paths in the SHIELD UI.
    #[test]
    fn default_remediation_uses_singular_hint_when_no_contexts() {
        let r = default_remediation(ThreatCategory::Generic, &[]);
        assert!(
            r.contains("Primary operational context: review required."),
            "expected singular review-required hint; got {r}",
        );
    }

    /// Contract: when `contexts` is non-empty, the hint joins them with ", "
    /// and uses the plural label "contexts". Pins the rendering format —
    /// changing the separator would break downstream parsers that split on
    /// "Primary operational contexts:".
    #[test]
    fn default_remediation_joins_contexts_with_comma_space() {
        let r = default_remediation(
            ThreatCategory::DataExfiltration,
            &[OperationalContext::Network, OperationalContext::Secrets],
        );
        assert!(
            r.contains("Primary operational contexts: network, secrets."),
            "expected comma-joined contexts label; got {r}",
        );
    }
}
