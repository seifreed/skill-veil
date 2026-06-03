//! Bundle data structures and serialisation helpers shared by both prompt
//! builders. Keeps the size estimators in one place so the truncation loops
//! and the row-budget constants stay in lockstep.

use super::{UNTRUSTED_CLOSE, UNTRUSTED_OPEN};
use serde::Serialize;
use skill_veil_core::{ExtractedIocs, Finding, Verdict};
use std::path::{Path, PathBuf};

/// Wrap an untrusted text blob with the documented delimiter markers so
/// the model can syntactically distinguish "data to analyze" from
/// "instructions to follow". The wrapping is purely for the LLM's
/// benefit; the markers are inert text.
pub(super) fn wrap_untrusted(content: &str) -> String {
    format!("{UNTRUSTED_OPEN}\n{content}\n{UNTRUSTED_CLOSE}")
}

/// Serialise a bundle as TOON (token-efficient JSON-equivalent). Falls back to
/// plain JSON if TOON rejects the value, and to an empty object literal as a
/// last resort. This keeps the prompt-building flow infallible.
pub(super) fn encode_bundle<T: Serialize>(value: &T) -> String {
    toon_format::encode(value, &toon_format::EncodeOptions::default())
        .unwrap_or_else(|_| serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string()))
}

/// Short structural description of a supporting artifact, included in the
/// manifest instead of its full content. Lets the LLM discover what exists
/// and request specific files for the follow-up turn.
#[derive(serde::Serialize, Clone, Debug)]
pub(crate) struct ManifestEntry {
    pub path: String,
    pub size_bytes: usize,
    pub preview: String,
}

const PREVIEW_LINES: usize = 15;
pub(super) const MANIFEST_ENTRY_OVERHEAD: usize = 96;

/// Bound on findings shipped in a single bundle. Chosen to keep a moderate
/// SKILL.md plus ~10 manifest entries under a 15 k-char budget while
/// preserving all Critical/High signals for typical packages (>95% have
/// <25 findings in our corpus).
const MAX_FINDINGS_IN_BUNDLE: usize = 25;

/// Bound per IOC bucket (`urls`, `domains`, `ipv4`, `ipv6`, `file_hashes`).
/// A bundle with 10 of each still gives the LLM enough signal to spot
/// exfil patterns without blowing the budget.
const MAX_IOCS_PER_TYPE: usize = 10;

/// Average TOON row size for a `SerialisedFinding` (rule_id,severity,
/// reason,artifact,line). Derived from measured bundles.
///
/// Worst-case sizing: `reason` is truncated to `FINDING_REASON_MAX_CHARS`
/// in `serialise_finding`, and the surrounding fields contribute roughly
/// `rule_id` ≈ 20-40, `severity` ≈ 8, `artifact` ≈ 0-50, `line` ≈ 0-5,
/// plus four commas and a row terminator. The pre-fix value of 180 was
/// the *typical* row, but a corpus packed with high-`reason` findings
/// (close to the 240-char ceiling) could blow the bundle budget by
/// ~25 × (real - 180) chars and trigger LLM context overflow without
/// any visible signal in the estimator. 280 absorbs the worst case
/// conservatively while staying well under the per-bundle budget.
pub(super) const FINDING_ROW_AVG_CHARS: usize = 280;

/// Maximum characters retained from a `Finding.reason` when serialising
/// into the LLM bundle. Mirrored in `serialise_finding`. The estimator
/// (`FINDING_ROW_AVG_CHARS`) MUST stay >= this value plus the overhead
/// of the surrounding TOON fields, otherwise the bundle can overrun the
/// budget without warning. The pair is checked in
/// `finding_row_estimate_covers_truncated_reason_plus_overhead`.
const FINDING_REASON_MAX_CHARS: usize = 240;

/// Average TOON row size for a single IOC entry (url/domain/ipv4 line).
pub(super) const IOC_ENTRY_CHARS: usize = 48;

pub(super) fn build_manifest_entry(path: &Path, content: &str) -> ManifestEntry {
    let preview_text: String = content
        .lines()
        .take(PREVIEW_LINES)
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n");
    ManifestEntry {
        path: path.display().to_string(),
        size_bytes: content.len(),
        preview: wrap_untrusted(&preview_text),
    }
}

/// Bundle data the prompt will serialise. Borrows from the scan result so we
/// don't copy findings.
pub(crate) struct SkillBundleInput<'a> {
    pub primary_path: &'a Path,
    pub primary_content: &'a str,
    pub supporting: Vec<(PathBuf, String)>,
    pub our_verdict: Verdict,
    pub our_risk_score: u32,
    pub our_findings: &'a [Finding],
    pub extracted_iocs: &'a ExtractedIocs,
}

#[derive(Serialize)]
pub(super) struct SerialisedArtifact {
    pub path: String,
    pub content: String,
}

#[derive(Serialize)]
pub(super) struct SerialisedFinding {
    pub rule_id: String,
    pub severity: String,
    pub reason: String,
    pub artifact: Option<String>,
    pub line: Option<usize>,
}

fn serialise_finding(f: &Finding) -> SerialisedFinding {
    SerialisedFinding {
        rule_id: f.rule_id.clone(),
        severity: format!("{:?}", f.severity),
        reason: f.reason.chars().take(FINDING_REASON_MAX_CHARS).collect(),
        artifact: f.artifact_path.clone(),
        line: f.line_number,
    }
}

/// Sort findings so Critical is first, then High, Medium, Low; within the
/// same severity we preserve scanner order for reproducibility. Truncates to
/// `MAX_FINDINGS_IN_BUNDLE` and reports how many were dropped.
pub(super) fn cap_findings_by_severity(findings: &[Finding]) -> (Vec<SerialisedFinding>, usize) {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    // Severity derives Ord (Low < Medium < High < Critical); we want descending.
    sorted.sort_by_key(|b| std::cmp::Reverse(b.severity));
    let kept: Vec<SerialisedFinding> = sorted
        .iter()
        .take(MAX_FINDINGS_IN_BUNDLE)
        .map(|f| serialise_finding(f))
        .collect();
    let dropped = findings.len().saturating_sub(kept.len());
    (kept, dropped)
}

/// Cap each IOC bucket to `MAX_IOCS_PER_TYPE` and report total dropped across
/// all buckets. `ExtractedIocs` is sorted at extraction time so the first N
/// are stable.
pub(super) fn cap_iocs(iocs: &ExtractedIocs) -> (ExtractedIocs, usize) {
    fn trunc<T: Clone>(v: &[T], limit: usize, dropped: &mut usize) -> Vec<T> {
        let kept: Vec<T> = v.iter().take(limit).cloned().collect();
        *dropped += v.len().saturating_sub(kept.len());
        kept
    }
    let mut dropped = 0;
    let capped = ExtractedIocs {
        urls: trunc(&iocs.urls, MAX_IOCS_PER_TYPE, &mut dropped),
        domains: trunc(&iocs.domains, MAX_IOCS_PER_TYPE, &mut dropped),
        ipv4: trunc(&iocs.ipv4, MAX_IOCS_PER_TYPE, &mut dropped),
        ipv6: trunc(&iocs.ipv6, MAX_IOCS_PER_TYPE, &mut dropped),
        file_hashes: trunc(&iocs.file_hashes, MAX_IOCS_PER_TYPE, &mut dropped),
    };
    (capped, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixture for the TOON-encoder contracts below: a uniform array
    /// of `SerialisedFinding`s wrapped in a single-field bundle. Defined
    /// inline so the encoder tests don't depend on any production bundle
    /// shape.
    #[derive(Serialize)]
    struct UniformFindingsBundle {
        our_findings: Vec<SerialisedFinding>,
    }

    fn bundle_with_n_findings(n: usize) -> UniformFindingsBundle {
        UniformFindingsBundle {
            our_findings: (0..n)
                .map(|i| SerialisedFinding {
                    rule_id: format!("RULE_{i:03}"),
                    severity: "High".to_string(),
                    reason: "hardcoded exfil endpoint".to_string(),
                    artifact: Some(format!("scripts/s{i}.py")),
                    line: Some(10 + i),
                })
                .collect(),
        }
    }

    fn make_finding(rule: &str, severity: skill_veil_core::Severity) -> Finding {
        use skill_veil_core::ThreatCategory;
        Finding::builder(rule, ThreatCategory::DataExfiltration)
            .severity(severity)
            .reason("test reason")
            .build()
    }

    /// Contract: the TOON encoder MUST shrink a uniform array of
    /// `SerialisedFinding` rows by at least 25% relative to JSON. This
    /// guards the prompt-size estimate that callers rely on to stay
    /// under provider context budgets.
    #[test]
    fn toon_serialization_shrinks_uniform_arrays() {
        let bundle = bundle_with_n_findings(30);
        let toon_len = encode_bundle(&bundle).len();
        let json_len = serde_json::to_string(&bundle).unwrap().len();
        let ratio = toon_len as f64 / json_len as f64;
        assert!(
            ratio < 0.75,
            "TOON should shrink uniform-array bundles by >25%; ratio={ratio:.3} (toon={toon_len}, json={json_len})",
        );
    }

    /// Contract: the TOON encoder MUST emit a tabular header
    /// (`our_findings[N]{...}:`) for uniform arrays of structs. The
    /// header is the signature that the compact form engaged; without
    /// it, the bundle would fall back to the verbose per-row layout
    /// and overrun prompt budgets.
    #[test]
    fn toon_output_contains_table_header() {
        let bundle = bundle_with_n_findings(30);
        let out = encode_bundle(&bundle);
        assert!(
            out.contains("our_findings[30]{rule_id,severity,reason,artifact,line}:"),
            "expected TOON tabular header for findings; got: {}",
            &out[..out.len().min(400)],
        );
    }

    #[test]
    fn cap_findings_keeps_critical_first_and_drops_low() {
        use skill_veil_core::Severity;
        let sevs = [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        let findings: Vec<Finding> = (0..40)
            .map(|i| make_finding(&format!("R{i:03}"), sevs[i % 4]))
            .collect();

        let (kept, dropped) = cap_findings_by_severity(&findings);
        assert_eq!(kept.len(), MAX_FINDINGS_IN_BUNDLE);
        assert_eq!(dropped, 40 - MAX_FINDINGS_IN_BUNDLE);

        let critical_count = kept.iter().filter(|f| f.severity == "Critical").count();
        assert_eq!(
            critical_count, 10,
            "all Critical findings must survive the cap; got {critical_count}",
        );
    }

    #[test]
    fn cap_iocs_truncates_each_bucket_to_max_per_type() {
        let big = ExtractedIocs {
            urls: (0..20).map(|i| format!("https://u{i}")).collect(),
            domains: (0..5).map(|i| format!("d{i}.example")).collect(),
            ipv4: (0..15).map(|i| format!("10.0.0.{i}")).collect(),
            ipv6: Vec::new(),
            file_hashes: Vec::new(),
        };
        let (capped, dropped) = cap_iocs(&big);
        assert_eq!(capped.urls.len(), MAX_IOCS_PER_TYPE);
        assert_eq!(capped.domains.len(), 5);
        assert_eq!(capped.ipv4.len(), MAX_IOCS_PER_TYPE);
        assert_eq!(dropped, 15);
    }

    #[test]
    fn encode_bundle_never_panics_and_fallback_chain_is_total() {
        let empty = bundle_with_n_findings(0);
        assert!(!encode_bundle(&empty).is_empty());

        let many = bundle_with_n_findings(100);
        let out = encode_bundle(&many);
        assert!(!out.is_empty());
        assert!(out.contains("our_findings"));

        assert_ne!(encode_bundle(&empty), "{}");
    }

    /// Contract: `FINDING_ROW_AVG_CHARS` MUST cover the truncated `reason`
    /// (`FINDING_REASON_MAX_CHARS`) plus a small overhead for the other
    /// TOON fields (`rule_id`, `severity`, `artifact`, `line`, separators).
    /// Pre-fix the estimator used 180, well below the 240-char `reason`
    /// ceiling — packing 25 high-`reason` findings into a bundle could
    /// overrun the prompt budget by ~1.5 k chars and trigger LLM context
    /// overflow without any signal in the estimator. This compile-time
    /// assertion pins the relationship so future tweaks don't silently
    /// regress it.
    #[test]
    fn finding_row_estimate_covers_truncated_reason_plus_overhead() {
        const _: () = assert!(FINDING_ROW_AVG_CHARS >= FINDING_REASON_MAX_CHARS);
    }

    /// Contract: a serialised finding's `reason` length never exceeds
    /// `FINDING_REASON_MAX_CHARS`. Pins the truncation so future edits
    /// to `serialise_finding` cannot silently widen the per-row budget
    /// past what `FINDING_ROW_AVG_CHARS` was sized for.
    #[test]
    fn serialise_finding_truncates_reason_to_max_chars() {
        use skill_veil_core::{Severity, ThreatCategory};
        let long_reason = "x".repeat(FINDING_REASON_MAX_CHARS * 3);
        let f = Finding::builder("R001", ThreatCategory::DataExfiltration)
            .severity(Severity::High)
            .reason(long_reason)
            .build();
        let s = serialise_finding(&f);
        assert!(
            s.reason.chars().count() <= FINDING_REASON_MAX_CHARS,
            "reason must be truncated to <= {FINDING_REASON_MAX_CHARS} chars; \
             got {} chars",
            s.reason.chars().count()
        );
    }
}
