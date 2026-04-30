//! Two-turn prompt builders: `build_manifest_prompt` for turn 1 (paths +
//! previews only) and `build_followup_prompt` for turn 2 (full content of
//! files the LLM requested in `insufficient_context`). Both honour the
//! `max_chars` budget by progressively dropping the largest supporting
//! artifacts before emitting the prompt.

use super::bundle::{
    build_manifest_entry, cap_findings_by_severity, cap_iocs, encode_bundle, verdict_label,
    wrap_untrusted, ManifestEntry, SerialisedArtifact, SerialisedFinding, SkillBundleInput,
    FINDING_ROW_AVG_CHARS, IOC_ENTRY_CHARS, MANIFEST_ENTRY_OVERHEAD,
};
use super::SYSTEM_PROMPT;
use crate::llm::types::LlmPrompt;
use skill_veil_core::ExtractedIocs;
use std::path::PathBuf;

/// Build a *manifest* prompt: SKILL.md + findings + IOCs + metadata list of
/// every supporting artifact (path/size/preview) without full contents.
/// This is turn-1 of the two-turn protocol.
///
/// Returns `(prompt, manifest)` — the manifest is also returned so the
/// orchestrator can look up paths when the LLM requests a follow-up.
pub(crate) fn build_manifest_prompt(
    input: SkillBundleInput<'_>,
    max_chars: usize,
) -> (LlmPrompt, Vec<ManifestEntry>) {
    let mut manifest: Vec<ManifestEntry> = input
        .supporting
        .iter()
        .map(|(p, c)| build_manifest_entry(p, c))
        .collect();

    // Cap findings (Critical-first) and IOCs before estimation so the budget
    // reflects what actually ships in the bundle.
    let (capped_findings, findings_truncated) = cap_findings_by_severity(input.our_findings);
    let (capped_iocs, iocs_truncated) = cap_iocs(input.extracted_iocs);

    // Smallest first so `pop()` removes the largest — drop heavy blobs
    // before small config files (.env, mcp.json, requirements.txt). Tiny
    // configs frequently carry the highest-signal evidence (exfil URLs,
    // credential paths) per byte, so they must survive truncation.
    manifest.sort_by_key(|a| a.size_bytes);
    let mut kept: Vec<ManifestEntry> = manifest.clone();
    while estimated_manifest_size(
        input.primary_content,
        &kept,
        capped_findings.len(),
        &capped_iocs,
    ) > max_chars
        && !kept.is_empty()
    {
        kept.pop();
    }

    #[derive(serde::Serialize)]
    struct ManifestBundle<'a> {
        primary_path: String,
        primary_content: &'a str,
        manifest: &'a [ManifestEntry],
        manifest_truncated_count: usize,
        our_verdict: &'static str,
        our_risk_score: u32,
        our_findings: Vec<SerialisedFinding>,
        findings_truncated_count: usize,
        extracted_iocs: &'a ExtractedIocs,
        iocs_truncated_count: usize,
    }

    let dropped = manifest.len() - kept.len();
    let wrapped_primary = wrap_untrusted(input.primary_content);
    let bundle = ManifestBundle {
        primary_path: input.primary_path.display().to_string(),
        primary_content: &wrapped_primary,
        manifest: &kept,
        manifest_truncated_count: dropped,
        our_verdict: verdict_label(input.our_verdict),
        our_risk_score: input.our_risk_score,
        our_findings: capped_findings,
        findings_truncated_count: findings_truncated,
        extracted_iocs: &capped_iocs,
        iocs_truncated_count: iocs_truncated,
    };
    let user_json = encode_bundle(&bundle);
    (
        LlmPrompt {
            system: SYSTEM_PROMPT.to_string(),
            user_json,
        },
        kept,
    )
}

/// Build the follow-up prompt when the LLM requested specific files in
/// `insufficient_context`. Includes those files' full contents (budget-bound),
/// plus the same primary/findings/IOCs context. If some requested files
/// don't fit the budget, they're listed in a `dropped_due_to_budget` field
/// so the LLM knows what it's missing.
pub(crate) fn build_followup_prompt(
    input: &SkillBundleInput<'_>,
    requested_files: &[(PathBuf, String)],
    max_chars: usize,
) -> LlmPrompt {
    let (capped_findings, findings_truncated) = cap_findings_by_severity(input.our_findings);
    let (capped_iocs, iocs_truncated) = cap_iocs(input.extracted_iocs);

    // Ascending sort → pop() drops largest first when over budget.
    let mut files: Vec<(PathBuf, String)> = requested_files.to_vec();
    files.sort_by_key(|a| a.1.len());

    let mut dropped: Vec<String> = Vec::new();
    while estimate_followup_size(
        input.primary_content,
        &files,
        capped_findings.len(),
        &capped_iocs,
        dropped.len(),
    ) > max_chars
    {
        let Some((p, c)) = files.pop() else {
            break;
        };
        dropped.push(format!("{} ({}B)", p.display(), c.len()));
    }

    #[derive(serde::Serialize)]
    struct FollowupBundle<'a> {
        turn: u8,
        primary_path: String,
        primary_content: &'a str,
        requested_files: Vec<SerialisedArtifact>,
        dropped_due_to_budget: Vec<String>,
        our_verdict: &'static str,
        our_risk_score: u32,
        our_findings: Vec<SerialisedFinding>,
        findings_truncated_count: usize,
        extracted_iocs: &'a ExtractedIocs,
        iocs_truncated_count: usize,
    }

    let wrapped_primary = wrap_untrusted(input.primary_content);
    let bundle = FollowupBundle {
        turn: 2,
        primary_path: input.primary_path.display().to_string(),
        primary_content: &wrapped_primary,
        requested_files: files
            .into_iter()
            .map(|(p, c)| SerialisedArtifact {
                path: p.display().to_string(),
                content: wrap_untrusted(&c),
            })
            .collect(),
        dropped_due_to_budget: dropped,
        our_verdict: verdict_label(input.our_verdict),
        our_risk_score: input.our_risk_score,
        our_findings: capped_findings,
        findings_truncated_count: findings_truncated,
        extracted_iocs: &capped_iocs,
        iocs_truncated_count: iocs_truncated,
    };
    let user_json = encode_bundle(&bundle);
    LlmPrompt {
        system: SYSTEM_PROMPT.to_string(),
        user_json,
    }
}

/// Estimate the serialised size of a follow-up bundle so the truncation
/// loop can pre-emptively drop oversized files before the prompt is sent.
///
/// # Completeness contract
///
/// MUST account for every component the bundle serialises:
/// `primary_content` + supporting files + findings rows + IOC rows +
/// dropped-file footnotes. The legacy `estimate_size` helper omitted
/// findings and IOCs, so a package with many findings or IOCs could
/// produce a bundle whose actual size exceeded `max_chars` even though
/// the estimate stayed under budget — triggering provider-side context
/// overflow errors. See `estimate_followup_size_includes_findings_and_iocs`.
fn estimate_followup_size(
    primary_content: &str,
    files: &[(PathBuf, String)],
    findings_count: usize,
    iocs: &ExtractedIocs,
    dropped_count: usize,
) -> usize {
    let support_bytes: usize = files
        .iter()
        .map(|(p, c)| p.as_os_str().len() + c.len() + 64)
        .sum();
    let findings_bytes = findings_count * FINDING_ROW_AVG_CHARS;
    let ioc_count = iocs.urls.len()
        + iocs.domains.len()
        + iocs.ipv4.len()
        + iocs.ipv6.len()
        + iocs.file_hashes.len();
    let ioc_bytes = ioc_count * IOC_ENTRY_CHARS;
    // 512 budget mirrors `estimated_manifest_size`: TOON header tokens,
    // verdict labels, score, truncated counts, dropped-file marker bytes.
    primary_content.len() + support_bytes + findings_bytes + ioc_bytes + dropped_count * 32 + 512
}

fn estimated_manifest_size(
    primary_content: &str,
    manifest: &[ManifestEntry],
    findings_count: usize,
    iocs: &ExtractedIocs,
) -> usize {
    let m_bytes: usize = manifest
        .iter()
        .map(|e| e.path.len() + e.preview.len() + MANIFEST_ENTRY_OVERHEAD)
        .sum();
    let findings_bytes = findings_count * FINDING_ROW_AVG_CHARS;
    let ioc_count = iocs.urls.len()
        + iocs.domains.len()
        + iocs.ipv4.len()
        + iocs.ipv6.len()
        + iocs.file_hashes.len();
    let ioc_bytes = ioc_count * IOC_ENTRY_CHARS;
    // 512 accounts for TOON header tokens, enum labels, risk_score, and the
    // handful of fixed fields on the bundle (verdict, truncated counts).
    primary_content.len() + m_bytes + findings_bytes + ioc_bytes + 512
}

#[cfg(test)]
mod tests {
    use super::super::{UNTRUSTED_CLOSE, UNTRUSTED_OPEN};
    use super::*;
    use skill_veil_core::{Finding, Verdict};
    use std::path::Path;

    fn sample_iocs() -> ExtractedIocs {
        ExtractedIocs::default()
    }

    fn make_finding(rule: &str, severity: skill_veil_core::Severity) -> Finding {
        use skill_veil_core::ThreatCategory;
        Finding::builder(rule, ThreatCategory::DataExfiltration)
            .severity(severity)
            .reason("test reason")
            .build()
    }

    #[test]
    fn estimated_size_counts_findings_and_iocs() {
        let manifest: Vec<ManifestEntry> = Vec::new();
        let empty_iocs = ExtractedIocs::default();
        let baseline = estimated_manifest_size("primary", &manifest, 0, &empty_iocs);

        let with_findings = estimated_manifest_size("primary", &manifest, 10, &empty_iocs);
        assert!(
            with_findings > baseline + 1_500,
            "expected findings to grow estimate by at least 1500 chars (diff={})",
            with_findings - baseline,
        );

        let iocs = ExtractedIocs {
            urls: vec!["https://x".to_string(); 5],
            ..Default::default()
        };
        let with_iocs = estimated_manifest_size("primary", &manifest, 0, &iocs);
        assert!(
            with_iocs > baseline + 200,
            "expected IOCs to grow estimate by at least 200 chars (diff={})",
            with_iocs - baseline,
        );
    }

    /// Contract: `estimate_followup_size` MUST account for findings and
    /// IOC rows, not just primary + supporting bytes. The legacy
    /// `estimate_size` omitted them and could let bundles slip past the
    /// budget by ~25 findings × 180 chars + ~50 IOC rows × 48 chars.
    #[test]
    fn estimate_followup_size_includes_findings_and_iocs() {
        let no_iocs = ExtractedIocs::default();
        let baseline = estimate_followup_size("primary", &[], 0, &no_iocs, 0);

        let with_findings = estimate_followup_size("primary", &[], 25, &no_iocs, 0);
        assert!(
            with_findings > baseline + 25 * (FINDING_ROW_AVG_CHARS - 1),
            "25 findings must inflate the estimate by ~25 × FINDING_ROW_AVG_CHARS; \
             got delta = {}",
            with_findings - baseline
        );

        let many_iocs = ExtractedIocs {
            urls: (0..10).map(|i| format!("https://x{i}")).collect(),
            ipv4: (0..10).map(|i| format!("8.8.8.{i}")).collect(),
            ..Default::default()
        };
        let with_iocs = estimate_followup_size("primary", &[], 0, &many_iocs, 0);
        assert!(
            with_iocs > baseline + 20 * (IOC_ENTRY_CHARS - 1),
            "20 IOCs must inflate the estimate; got delta = {}",
            with_iocs - baseline
        );
    }

    #[test]
    fn manifest_bundle_exposes_findings_truncated_count() {
        use skill_veil_core::{Severity, RISK_THRESHOLD_BLOCK};
        let iocs = ExtractedIocs::default();
        let findings: Vec<Finding> = (0..30)
            .map(|i| make_finding(&format!("R{i:03}"), Severity::High))
            .collect();
        let input = SkillBundleInput {
            primary_path: Path::new("/tmp/SKILL.md"),
            primary_content: "# skill\nshort",
            supporting: Vec::new(),
            our_verdict: Verdict::Suspicious,
            our_risk_score: RISK_THRESHOLD_BLOCK,
            our_findings: &findings,
            extracted_iocs: &iocs,
        };
        let (prompt, _manifest) = build_manifest_prompt(input, 50_000);
        assert!(
            prompt.user_json.contains("findings_truncated_count"),
            "bundle should expose findings_truncated_count field",
        );
        assert!(
            prompt.user_json.contains("findings_truncated_count: 5")
                || prompt.user_json.contains("\"findings_truncated_count\":5"),
            "expected truncated count of 5; got fragment: {}",
            &prompt.user_json[..prompt.user_json.len().min(500)],
        );
    }

    /// # Contract
    ///
    /// `build_followup_prompt` is the second turn of the manifest
    /// protocol — it ships the full content of files the LLM requested.
    /// It MUST wrap both the primary and every requested file with the
    /// documented untrusted markers, otherwise an attacker-controlled
    /// supporting artifact could appear as instructions to the model.
    #[test]
    fn followup_bundle_wraps_primary_and_requested_files_with_untrusted_markers() {
        let input = SkillBundleInput {
            primary_path: Path::new("/tmp/SKILL.md"),
            primary_content: "real skill body that must be wrapped",
            supporting: Vec::new(),
            our_verdict: Verdict::Benign,
            our_risk_score: 0,
            our_findings: &[],
            extracted_iocs: &sample_iocs(),
        };
        let requested = vec![(
            PathBuf::from("evil.py"),
            "supporting body that must also be wrapped".to_string(),
        )];
        let prompt = build_followup_prompt(&input, &requested, 10_000);

        let body = &prompt.user_json;
        assert!(
            body.contains(UNTRUSTED_OPEN),
            "followup bundle must include UNTRUSTED_OPEN marker; body: {body}",
        );
        assert!(
            body.contains(UNTRUSTED_CLOSE),
            "followup bundle must include UNTRUSTED_CLOSE marker; body: {body}",
        );
        assert!(body.contains("real skill body that must be wrapped"));
        assert!(body.contains("supporting body that must also be wrapped"));
    }

    /// # Contract
    ///
    /// The production manifest builder (`build_manifest_prompt`) MUST
    /// wrap the primary content and every manifest preview with the
    /// documented untrusted markers — a regression here would silently
    /// re-open the prompt-injection surface in the real enrichment flow.
    #[test]
    fn manifest_bundle_wraps_primary_and_previews_with_untrusted_markers() {
        let input = SkillBundleInput {
            primary_path: Path::new("/tmp/SKILL.md"),
            primary_content: "primary body marker target",
            supporting: vec![(
                PathBuf::from("worker.py"),
                "preview line one\npreview line two".to_string(),
            )],
            our_verdict: Verdict::Benign,
            our_risk_score: 0,
            our_findings: &[],
            extracted_iocs: &sample_iocs(),
        };
        let (prompt, manifest) = build_manifest_prompt(input, 10_000);

        assert!(prompt.user_json.contains(UNTRUSTED_OPEN));
        assert!(prompt.user_json.contains(UNTRUSTED_CLOSE));
        assert!(prompt.user_json.contains("primary body marker target"));

        let preview = &manifest[0].preview;
        assert!(
            preview.starts_with(UNTRUSTED_OPEN),
            "manifest preview must start with UNTRUSTED_OPEN; got: {preview}",
        );
        assert!(
            preview.ends_with(UNTRUSTED_CLOSE),
            "manifest preview must end with UNTRUSTED_CLOSE; got: {preview}",
        );
    }
}
