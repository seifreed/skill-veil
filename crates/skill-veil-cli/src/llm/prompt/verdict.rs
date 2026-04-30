//! Parsing and validation of the LLM's structured response. Enforces the
//! schema mandated by `SYSTEM_PROMPT`: known verdict label, non-empty
//! analysis, sane confidence range. Tolerates code fences and minor casing
//! drift but rejects anything ambiguous.

use crate::llm::types::LlmVerdict;

/// Permitted values for `LlmVerdict.verdict`. The system prompt mandates
/// exactly these three; anything else is treated as a schema violation.
/// Comparison is performed case-insensitively to absorb minor model
/// formatting drift (`"Malicious"` vs `"malicious"`).
const ALLOWED_VERDICT_LABELS: &[&str] = &["malicious", "suspicious", "benign"];

/// Parse the assistant's response into a structured verdict. Tolerant of
/// responses that wrap JSON in code fences (`\`\`\`json ... \`\`\``).
///
/// Sanitizes the `confidence` field after deserialization: NaN maps to
/// `0.0` (worst-case — LLM input is untrusted, so a malformed value
/// should not be optimistically interpreted) and finite out-of-range
/// values clamp into `[0.0, 1.0]`. Mirrors `FindingBuilder::confidence`
/// (`crates/skill-veil-core/src/findings/builder.rs`), which guards the
/// rule-side input boundary.
///
/// Beyond confidence sanitisation the parser enforces the three semantic
/// contracts the system prompt mandates:
///
/// 1. `verdict` MUST match one of `ALLOWED_VERDICT_LABELS`
///    (case-insensitive). An unknown label means downstream scoring would
///    silently treat the response as `benign` (serde keeps the raw string
///    but the three-engine scorer only branches on the known set), so
///    we reject at the boundary instead.
/// 2. `analysis` MUST be non-empty after trimming. An empty narrative
///    means the model failed to justify its verdict — surfacing the
///    failure here lets the orchestrator either retry or fall back to
///    the scanner verdict, instead of shipping an unexplained verdict
///    to the user-facing report.
/// 3. `verdict` is normalised to lowercase before being returned so
///    downstream consumers can branch on the canonical form regardless
///    of whether the model emitted `"Malicious"` or `"malicious"`.
pub(crate) fn parse_verdict_json(raw: &str) -> Result<LlmVerdict, String> {
    let cleaned = strip_json_fences(raw);
    let mut verdict = serde_json::from_str::<LlmVerdict>(&cleaned).map_err(|e| e.to_string())?;
    sanitize_llm_confidence(&mut verdict);

    let lower = verdict.verdict.trim().to_ascii_lowercase();
    if !ALLOWED_VERDICT_LABELS.contains(&lower.as_str()) {
        return Err(format!(
            "LLM response `verdict` field must be one of {:?}, got {:?}",
            ALLOWED_VERDICT_LABELS, verdict.verdict
        ));
    }
    verdict.verdict = lower;

    if verdict.analysis.trim().is_empty() {
        return Err(
            "LLM response `analysis` field is empty; system prompt requires a 3-6 sentence narrative"
                .to_string(),
        );
    }

    Ok(verdict)
}

/// Clamp `verdict.confidence` into `[0.0, 1.0]` and replace NaN with
/// `0.0`. Extracted as a private helper so unit tests can verify the
/// clamping behavior directly without round-tripping through serde
/// (strict JSON rejects `NaN` at parse time, so the only way to hit the
/// NaN branch in production is via a serde feature flag or via a
/// provider that pre-deserializes — defending here is pure-Rust
/// defense-in-depth).
fn sanitize_llm_confidence(verdict: &mut LlmVerdict) {
    if verdict.confidence.is_nan() {
        verdict.confidence = 0.0;
    } else {
        verdict.confidence = verdict.confidence.clamp(0.0, 1.0);
    }
}

fn strip_json_fences(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_fence = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .map(|s| s.trim_start_matches(['\r', '\n']))
        .unwrap_or(trimmed);
    let without_trailing = without_fence.trim_end();
    let stripped = without_trailing
        .strip_suffix("```")
        .unwrap_or(without_trailing)
        .trim();
    stripped.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict_with_confidence(confidence: f32) -> LlmVerdict {
        LlmVerdict {
            verdict: "benign".to_string(),
            confidence,
            analysis: String::new(),
            key_signals: Vec::new(),
            agreement_with_scanner: None,
            insufficient_context: Vec::new(),
        }
    }

    #[test]
    fn parse_verdict_handles_plain_json() {
        let raw = r#"{"verdict":"malicious","confidence":0.9,"analysis":"x"}"#;
        let v = parse_verdict_json(raw).unwrap();
        assert_eq!(v.verdict, "malicious");
        assert!((v.confidence - 0.9).abs() < 1e-3);
    }

    #[test]
    fn parse_verdict_handles_fenced_json() {
        let raw = "```json\n{\"verdict\":\"benign\",\"confidence\":0.5,\"analysis\":\"x\"}\n```";
        let v = parse_verdict_json(raw).unwrap();
        assert_eq!(v.verdict, "benign");
    }

    #[test]
    fn parse_verdict_returns_err_on_garbage() {
        assert!(parse_verdict_json("not json").is_err());
    }

    /// Contract: confidence values above 1.0 clamp to 1.0. Mirrors the
    /// rule-side guard in `FindingBuilder::confidence`.
    #[test]
    fn parse_verdict_json_clamps_above_one() {
        let raw = r#"{"verdict":"benign","confidence":1.5,"analysis":"non-empty narrative"}"#;
        let v = parse_verdict_json(raw).expect("parse must succeed");
        assert!((v.confidence - 1.0).abs() < f32::EPSILON);
    }

    /// Contract: confidence values below 0.0 clamp to 0.0.
    #[test]
    fn parse_verdict_json_clamps_below_zero() {
        let raw = r#"{"verdict":"benign","confidence":-0.1,"analysis":"non-empty narrative"}"#;
        let v = parse_verdict_json(raw).expect("parse must succeed");
        assert!(v.confidence.abs() < f32::EPSILON);
    }

    /// Contract: NaN confidence maps to 0.0 (worst-case — LLM input is
    /// untrusted, so a malformed value must not be optimistically
    /// interpreted). Strict JSON rejects literal `NaN` at parse time, so
    /// we test the sanitizer directly.
    #[test]
    fn sanitize_llm_confidence_replaces_nan_with_zero() {
        let mut v = verdict_with_confidence(f32::NAN);
        sanitize_llm_confidence(&mut v);
        assert!(!v.confidence.is_nan());
        assert!(v.confidence.abs() < f32::EPSILON);
    }

    /// Contract: positive infinity clamps to 1.0; negative infinity to 0.0.
    #[test]
    fn sanitize_llm_confidence_handles_infinities() {
        let mut pos = verdict_with_confidence(f32::INFINITY);
        sanitize_llm_confidence(&mut pos);
        assert!((pos.confidence - 1.0).abs() < f32::EPSILON);

        let mut neg = verdict_with_confidence(f32::NEG_INFINITY);
        sanitize_llm_confidence(&mut neg);
        assert!(neg.confidence.abs() < f32::EPSILON);
    }

    /// Contract: in-range confidence is preserved bit-for-bit. Pins the
    /// no-op case so the sanitizer doesn't accidentally widen.
    #[test]
    fn parse_verdict_json_preserves_in_range_value() {
        let raw = r#"{"verdict":"benign","confidence":0.7,"analysis":"non-empty narrative"}"#;
        let v = parse_verdict_json(raw).expect("parse must succeed");
        assert!((v.confidence - 0.7).abs() < 1e-5);
    }

    /// # Contract
    ///
    /// `parse_verdict_json` MUST reject responses whose `verdict` field is
    /// not in `ALLOWED_VERDICT_LABELS`. Pre-fix: an unknown label like
    /// `"unsure"` deserialized cleanly because `LlmVerdict.verdict` is a
    /// `String`; downstream the three-engine scorer only branches on the
    /// known set, so an unknown label was silently treated as `benign`,
    /// hiding LLM disagreement from the scanner verdict.
    #[test]
    fn parse_verdict_rejects_unknown_verdict_label() {
        let raw = r#"{"verdict":"unsure","confidence":0.5,"analysis":"some text"}"#;
        let err = parse_verdict_json(raw).expect_err("unknown verdict label MUST fail validation");
        assert!(
            err.contains("verdict") && err.contains("unsure"),
            "error must name the offending value; got: {err}"
        );
    }

    /// # Contract
    ///
    /// `parse_verdict_json` MUST normalise the `verdict` field to lowercase
    /// before returning so downstream consumers can branch on the
    /// canonical `"malicious" | "suspicious" | "benign"` form regardless of
    /// the model's casing.
    #[test]
    fn parse_verdict_normalises_verdict_label_to_lowercase() {
        let raw = r#"{"verdict":"Malicious","confidence":0.9,"analysis":"clear exfil endpoint"}"#;
        let v = parse_verdict_json(raw).expect("Malicious is a valid label after lowercasing");
        assert_eq!(v.verdict, "malicious");
    }

    /// # Contract
    ///
    /// `parse_verdict_json` MUST reject responses whose `analysis` is empty
    /// (or whitespace-only) after trimming. The system prompt requires a
    /// 3-6 sentence narrative; an empty narrative means the model failed
    /// to justify its verdict and the orchestrator should treat the
    /// response as unusable instead of shipping an unexplained verdict.
    #[test]
    fn parse_verdict_rejects_empty_analysis() {
        let raw = r#"{"verdict":"benign","confidence":0.5,"analysis":"   "}"#;
        let err =
            parse_verdict_json(raw).expect_err("whitespace-only analysis MUST fail validation");
        assert!(
            err.contains("analysis"),
            "error must mention the missing analysis field; got: {err}"
        );
    }
}
