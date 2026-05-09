//! Domain types for the PromptIntel API.
//!
//! Mirrors the JSON shape returned by `https://api.promptintel.novahunting.ai/api/v1`.
//! Field names use `serde(rename_all = "snake_case")` only where the API
//! diverges; the bulk of the schema is already snake_case so plain
//! `Deserialize` works.

use serde::{Deserialize, Serialize};

/// Severity bucket used by PromptIntel curators. Mirrors the curator's
/// own `severity` string verbatim so the cross-check report can group
/// gaps by the same labels operators see in the upstream UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PromptSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl PromptSeverity {
    /// Render as a stable lowercase string for filenames, frontmatter,
    /// and JSON keys. Avoids round-tripping through serde for that
    /// (callers that want the JSON shape can `serde_json::to_value`
    /// instead).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// One entry in the PromptIntel database.
///
/// Only the fields skill-veil consumes are modelled. Unknown fields
/// are tolerated by omitting `#[serde(deny_unknown_fields)]` — the
/// API may add fields faster than this client tracks them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Prompt {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) prompt: String,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    /// Optional NOVA YARA-like rule maintained by the PromptIntel
    /// authors. We deliberately do NOT execute these — the project
    /// rule-language is YAML and the user explicitly opted to use NOVA
    /// rules only as inspiration for new semantic/taint rules.
    #[serde(default)]
    pub(crate) nova_rule: Option<String>,
    #[serde(default)]
    pub(crate) reference_urls: Vec<String>,
    #[serde(default)]
    pub(crate) author: Option<String>,
    #[serde(default)]
    pub(crate) created_at: Option<String>,
    pub(crate) severity: PromptSeverity,
    #[serde(default)]
    pub(crate) categories: Vec<String>,
    #[serde(default)]
    pub(crate) threats: Vec<String>,
    #[serde(default)]
    pub(crate) impact_description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PromptListEnvelope {
    pub(crate) data: Vec<Prompt>,
    pub(crate) pagination: Pagination,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Pagination {
    pub(crate) total: u32,
    pub(crate) pages: u32,
}

/// A single agent-feed entry — community-curated threat intel about
/// agent-skill behaviour. Mirrors `GET /api/v1/agent-feed`.
///
/// `iocs` requires the custom deserializer in [`feed_ioc::Vec`] because
/// the upstream API returns a mix of:
///   1. JSON-encoded strings: `"{\"type\":\"hash\",\"value\":\"...\"}"`
///   2. Already-parsed dicts: `{"type": "url", "value": "..."}`
///   3. Raw strings without a type tag.
///   4. `null` (no IOCs).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct FeedEntry {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) fingerprint: Option<String>,
    pub(crate) category: String,
    pub(crate) severity: PromptSeverity,
    /// Curator confidence, 0.0–1.0. The API ships this as either an
    /// integer (`1`) or a float (`0.88`); `f32` accepts both.
    #[serde(default)]
    pub(crate) confidence: Option<f32>,
    pub(crate) action: FeedAction,
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) source: Option<String>,
    #[serde(default)]
    pub(crate) source_identifier: Option<String>,
    #[serde(default)]
    pub(crate) recommendation_agent: Option<String>,
    #[serde(default, deserialize_with = "feed_ioc::deserialize_vec")]
    pub(crate) iocs: Vec<FeedIoc>,
    #[serde(default)]
    pub(crate) expires_at: Option<String>,
    #[serde(default)]
    pub(crate) revoked_at: Option<String>,
    #[serde(default)]
    pub(crate) created_at: Option<String>,
    #[serde(default)]
    pub(crate) revoked: bool,
}

/// Curator-recommended action for the agent runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FeedAction {
    Block,
    RequireApproval,
    Log,
    /// Forward-compatibility for any future action verb the API adds.
    /// We never act on this verb; it surfaces in the enrichment block
    /// verbatim so an operator notices upstream drift.
    #[serde(other)]
    Unknown,
}

/// A single indicator of compromise. `kind` is normalised to a typed
/// enum; raw upstream strings without a `type` tag deserialize as
/// [`FeedIocKind::Unknown`] so they surface in the enrichment block
/// without crashing the parser.
///
/// Serialised on disk as `{"type": "...", "value": "..."}` to match
/// the upstream API shape and so the cached `feed.json` is
/// round-trippable through any external tool that already speaks the
/// PromptIntel schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FeedIoc {
    #[serde(rename = "type")]
    pub(crate) kind: FeedIocKind,
    pub(crate) value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FeedIocKind {
    Hash,
    Ip,
    Url,
    Domain,
    FilePath,
    Email,
    Pattern,
    Port,
    TelegramBotToken,
    TelegramGroupId,
    Username,
    Other,
    /// Raw string without a `type` tag; cannot be matched against
    /// `ExtractedIocs` automatically but is preserved for display.
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FeedResponse {
    #[serde(default)]
    pub(crate) success: bool,
    #[serde(default)]
    pub(crate) data: Vec<FeedEntry>,
}

/// Submission payload for `POST /agents/reports`. Validated client-side
/// against the upstream contract so a malformed draft is rejected
/// before it spends quota (5/hour, 20/day).
///
/// The required fields and accepted enum variants were derived from
/// the upstream validation error response. We deliberately mirror the
/// upstream JSON shape (snake_case, lowercase enums) so the rendered
/// JSON can be reviewed verbatim with `--dry-run` and submitted
/// without further translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReportDraft {
    pub(crate) category: ReportCategory,
    pub(crate) severity: PromptSeverity,
    pub(crate) confidence: f32,
    /// Operator-chosen unique key — re-submitting the same fingerprint
    /// will be deduped server-side. Recommended convention: a UUID4
    /// or a hash of the normalised IOC set.
    pub(crate) fingerprint: String,
    /// 5–100 chars (upstream-enforced).
    pub(crate) title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) action: Option<FeedAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) iocs: Vec<ReportIoc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recommendation_agent: Option<String>,
}

/// Submission-side IOC: the upstream feed returns the same shape via
/// dict, so we serialise to `{"type": ..., "value": ...}` to match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReportIoc {
    #[serde(rename = "type")]
    pub(crate) kind: FeedIocKind,
    pub(crate) value: String,
}

/// Categories accepted by `POST /agents/reports`. Keep this list
/// aligned with the upstream validation contract — adding a variant
/// here without server-side support would surface as a 400 the next
/// time a user submits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReportCategory {
    Prompt,
    Tool,
    Mcp,
    Skill,
    Memory,
    SupplyChain,
    Vulnerability,
    Fraud,
    PolicyBypass,
    Anomaly,
    Other,
}

/// Validation outcome for [`ReportDraft::validate`]. Returned by
/// reference so a renderer can list every failure at once instead of
/// the upstream's first-error-wins style.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ReportValidationError {
    TitleTooShort { len: usize },
    TitleTooLong { len: usize },
    ConfidenceOutOfRange { value: f32 },
    FingerprintEmpty,
}

impl std::fmt::Display for ReportValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TitleTooShort { len } => {
                write!(f, "title is required to be 5-100 characters; got {len}")
            }
            Self::TitleTooLong { len } => {
                write!(f, "title must be at most 100 characters; got {len}")
            }
            Self::ConfidenceOutOfRange { value } => {
                write!(f, "confidence must be in [0.0, 1.0]; got {value}")
            }
            Self::FingerprintEmpty => f.write_str("fingerprint is required and must be non-empty"),
        }
    }
}

impl std::error::Error for ReportValidationError {}

impl ReportDraft {
    /// Validate against the upstream contract. Returns every failure
    /// found rather than short-circuiting on the first; an operator
    /// fixing a malformed draft sees the full picture in one round.
    pub(crate) fn validate(&self) -> Vec<ReportValidationError> {
        let mut errors = Vec::new();
        let title_len = self.title.chars().count();
        if title_len < 5 {
            errors.push(ReportValidationError::TitleTooShort { len: title_len });
        } else if title_len > 100 {
            errors.push(ReportValidationError::TitleTooLong { len: title_len });
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            errors.push(ReportValidationError::ConfidenceOutOfRange {
                value: self.confidence,
            });
        }
        if self.fingerprint.trim().is_empty() {
            errors.push(ReportValidationError::FingerprintEmpty);
        }
        errors
    }
}

/// Envelope returned by `GET /agents/reports/mine`.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub(crate) struct ReportListEnvelope {
    #[serde(default)]
    pub(crate) success: bool,
    #[serde(default)]
    pub(crate) data: Vec<FeedEntry>,
    #[serde(default)]
    pub(crate) pagination: Option<ReportListPagination>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub(crate) struct ReportListPagination {
    #[serde(default)]
    pub(crate) limit: u32,
    #[serde(default)]
    pub(crate) offset: u32,
    #[serde(default)]
    pub(crate) total: u32,
}

/// Envelope returned by `POST /agents/reports`. Captured opaquely
/// (`extra`) so a future schema addition does not break clients that
/// already rely on `success` + `id`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReportSubmissionResponse {
    #[serde(default)]
    pub(crate) success: bool,
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

mod feed_ioc {
    //! Custom deserializer for `FeedEntry::iocs`.
    //!
    //! The upstream API returns IOCs in three encodings within the same
    //! response. Plain `Vec<FeedIoc>` cannot accept all three, so we
    //! walk the array element-by-element and pick the right shape per
    //! item.
    use super::{FeedIoc, FeedIocKind};
    use serde::de::{self, Deserializer, SeqAccess, Visitor};
    use serde::Deserialize;
    use std::fmt;

    pub(super) fn deserialize_vec<'de, D>(deserializer: D) -> Result<Vec<FeedIoc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IocVecVisitor;
        impl<'de> Visitor<'de> for IocVecVisitor {
            type Value = Vec<FeedIoc>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("array of IOC entries (string, object, or null)")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Vec::new())
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Vec::new())
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                d.deserialize_seq(IocVecVisitor)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(item) = seq.next_element::<serde_json::Value>()? {
                    if let Some(parsed) = parse_one(&item) {
                        out.push(parsed);
                    }
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(IocVecVisitor)
    }

    fn parse_one(value: &serde_json::Value) -> Option<FeedIoc> {
        match value {
            serde_json::Value::Object(_) => {
                #[derive(Deserialize)]
                struct Bare {
                    #[serde(rename = "type", default)]
                    kind: Option<String>,
                    #[serde(default)]
                    value: Option<String>,
                }
                let bare: Bare = serde_json::from_value(value.clone()).ok()?;
                let v = bare.value?;
                Some(FeedIoc {
                    kind: classify(bare.kind.as_deref()),
                    value: v,
                })
            }
            serde_json::Value::String(s) => {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                    if parsed.is_object() {
                        return parse_one(&parsed);
                    }
                }
                Some(FeedIoc {
                    kind: FeedIocKind::Unknown,
                    value: s.clone(),
                })
            }
            _ => None,
        }
    }

    fn classify(kind: Option<&str>) -> FeedIocKind {
        match kind {
            Some("hash") => FeedIocKind::Hash,
            Some("ip") => FeedIocKind::Ip,
            Some("url") => FeedIocKind::Url,
            Some("domain") => FeedIocKind::Domain,
            Some("file_path") => FeedIocKind::FilePath,
            Some("email") => FeedIocKind::Email,
            Some("pattern") => FeedIocKind::Pattern,
            Some("port") => FeedIocKind::Port,
            Some("telegram_bot_token") => FeedIocKind::TelegramBotToken,
            Some("telegram_group_id") => FeedIocKind::TelegramGroupId,
            Some("username") => FeedIocKind::Username,
            Some("other") => FeedIocKind::Other,
            _ => FeedIocKind::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a real `/prompts` envelope from PromptIntel deserialises
    /// into the strongly-typed shape this module exposes. Pre-fix the
    /// types existed only on paper; this test pins the field set against
    /// the live API as observed during the integration's design.
    #[test]
    fn prompt_envelope_deserialises_real_shape() {
        let body = r#"{
            "data": [{
                "id": "abb39e8f-ac14-43d9-9747-2d537aa420d5",
                "title": "Hidden Web Prompt Injection",
                "prompt": "<div style='display: none'>...</div>",
                "tags": [],
                "nova_rule": "rule X { meta: severity = \"critical\" }",
                "reference_urls": ["https://example.com"],
                "author": "Thomas Roccia",
                "created_at": "2026-05-05T00:13:19+00:00",
                "severity": "critical",
                "categories": ["manipulation"],
                "threats": ["Indirect prompt injection"],
                "impact_description": "Catastrophic.",
                "view_count": 442,
                "average_score": 5,
                "total_ratings": 1
            }],
            "pagination": {"page": 1, "limit": 100, "total": 1, "pages": 1}
        }"#;
        let env: PromptListEnvelope = serde_json::from_str(body).expect("parses");
        assert_eq!(env.data.len(), 1);
        let p = &env.data[0];
        assert_eq!(p.severity, PromptSeverity::Critical);
        assert_eq!(p.categories, vec!["manipulation".to_string()]);
        assert_eq!(p.threats, vec!["Indirect prompt injection".to_string()]);
        assert_eq!(env.pagination.total, 1);
    }

    /// Contract: a missing optional field MUST yield a `None` rather
    /// than a deserialisation error, because the upstream schema is
    /// curator-driven and historical entries lack `nova_rule`,
    /// `impact_description`, etc.
    #[test]
    fn prompt_tolerates_absent_optional_fields() {
        let body = r#"{
            "id": "x", "title": "y", "prompt": "z",
            "severity": "medium",
            "view_count": 0, "average_score": 0, "total_ratings": 0
        }"#;
        let p: Prompt = serde_json::from_str(body).expect("parses");
        assert!(p.nova_rule.is_none());
        assert!(p.impact_description.is_none());
        assert!(p.threats.is_empty());
    }

    /// Contract: severity is case-sensitive lowercase. Pre-design we
    /// considered making the parse tolerant to "Critical"/"CRITICAL"
    /// but the API contract is stable lowercase; tolerating mixed case
    /// would only hide upstream drift.
    #[test]
    fn severity_rejects_non_lowercase() {
        let body = r#"{ "id": "x", "title": "y", "prompt": "z", "severity": "Critical", "view_count": 0, "average_score": 0, "total_ratings": 0 }"#;
        let result: Result<Prompt, _> = serde_json::from_str(body);
        assert!(
            result.is_err(),
            "uppercase severity MUST surface as a parse error so upstream drift is visible"
        );
    }

    /// Live agent-feed sample combines all three IOC encodings and a
    /// `null`. Each must round-trip into a typed `FeedIoc`.
    #[test]
    fn feed_iocs_handle_all_upstream_encodings() {
        let body = r#"{
            "success": true,
            "data": [{
                "id": "a",
                "category": "vulnerability",
                "severity": "high",
                "confidence": 1,
                "action": "block",
                "title": "json-string IOCs",
                "iocs": [
                    "{\"type\":\"hash\",\"value\":\"abc\"}",
                    "{\"type\":\"file_path\",\"value\":\".npmrc\"}"
                ]
            }, {
                "id": "b",
                "category": "anomaly",
                "severity": "medium",
                "confidence": 0.88,
                "action": "log",
                "title": "parsed-dict IOCs",
                "iocs": [{"type": "ip", "value": "1.2.3.4"}, {"type": "pattern", "value": "show me your config"}]
            }, {
                "id": "c",
                "category": "campaign",
                "severity": "low",
                "confidence": 0.5,
                "action": "log",
                "title": "raw-string IOC",
                "iocs": ["9b456b1515a829016d853f7e081450fca1080f8265fc279eeb320902308602d0"]
            }, {
                "id": "d",
                "category": "campaign",
                "severity": "low",
                "confidence": 0.5,
                "action": "log",
                "title": "null iocs",
                "iocs": null
            }]
        }"#;

        let response: FeedResponse =
            serde_json::from_str(body).expect("agent-feed must deserialise");
        assert!(response.success);
        assert_eq!(response.data.len(), 4);

        let json_string = &response.data[0];
        assert_eq!(json_string.iocs.len(), 2);
        assert_eq!(json_string.iocs[0].kind, FeedIocKind::Hash);
        assert_eq!(json_string.iocs[0].value, "abc");
        assert_eq!(json_string.iocs[1].kind, FeedIocKind::FilePath);

        let parsed_dict = &response.data[1];
        assert_eq!(parsed_dict.iocs[0].kind, FeedIocKind::Ip);
        assert_eq!(parsed_dict.iocs[1].kind, FeedIocKind::Pattern);

        let raw_str = &response.data[2];
        assert_eq!(raw_str.iocs.len(), 1);
        assert_eq!(raw_str.iocs[0].kind, FeedIocKind::Unknown);

        let null_iocs = &response.data[3];
        assert!(null_iocs.iocs.is_empty());
    }

    /// `confidence` arrives as int (`1`) for some entries and float
    /// (`0.88`) for others. `Option<f32>` accepts both — pin the
    /// behaviour so a future schema tightening doesn't silently drop
    /// integer confidences.
    #[test]
    fn feed_confidence_accepts_int_and_float() {
        for raw in ["1", "0.88", "0"] {
            let body = format!(
                r#"{{"id":"x","category":"c","severity":"high","confidence":{raw},"action":"log","title":"t"}}"#
            );
            let entry: FeedEntry =
                serde_json::from_str(&body).unwrap_or_else(|e| panic!("confidence={raw}: {e}"));
            assert!(entry.confidence.is_some());
        }
    }

    /// An unknown action verb MUST round-trip as `FeedAction::Unknown`
    /// rather than failing the parse — otherwise an upstream-added
    /// verb would brick the entire sync.
    #[test]
    fn feed_action_tolerates_unknown_verb() {
        let body = r#"{"id":"x","category":"c","severity":"high","confidence":1,"action":"future_verb","title":"t"}"#;
        let entry: FeedEntry = serde_json::from_str(body).expect("forward-compat parse");
        assert_eq!(entry.action, FeedAction::Unknown);
    }

    fn ok_draft() -> ReportDraft {
        ReportDraft {
            category: ReportCategory::Skill,
            severity: PromptSeverity::Medium,
            confidence: 0.8,
            fingerprint: "sv-test-001".to_string(),
            title: "valid title".to_string(),
            description: None,
            action: None,
            iocs: Vec::new(),
            source: None,
            source_identifier: None,
            recommendation_agent: None,
        }
    }

    /// A well-formed draft MUST validate with no errors. Pre-fix the
    /// off-by-one in the title length check rejected the boundary
    /// case (exactly 5 characters).
    #[test]
    fn report_draft_validates_well_formed() {
        let mut d = ok_draft();
        d.title = "abcde".to_string(); // 5 chars — boundary
        assert!(d.validate().is_empty());
    }

    /// Title shorter than 5 characters MUST surface a single
    /// `TitleTooShort` error.
    #[test]
    fn report_draft_rejects_short_title() {
        let mut d = ok_draft();
        d.title = "abcd".to_string();
        let errs = d.validate();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ReportValidationError::TitleTooShort { len: 4 })));
    }

    /// Title longer than 100 characters MUST surface a single
    /// `TitleTooLong` error. Pre-fix the validator counted bytes
    /// rather than characters and a 100-char string with multi-byte
    /// codepoints (e.g. emoji) would fail on the boundary.
    #[test]
    fn report_draft_rejects_long_title() {
        let mut d = ok_draft();
        d.title = "x".repeat(101);
        let errs = d.validate();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ReportValidationError::TitleTooLong { len: 101 })));
    }

    /// Confidence outside `[0.0, 1.0]` (including NaN) MUST be
    /// rejected; the upstream contract is explicit on the range.
    #[test]
    fn report_draft_rejects_out_of_range_confidence() {
        for bad in [-0.1f32, 1.01, f32::NAN, f32::INFINITY] {
            let mut d = ok_draft();
            d.confidence = bad;
            let errs = d.validate();
            assert!(
                errs.iter()
                    .any(|e| matches!(e, ReportValidationError::ConfidenceOutOfRange { .. })),
                "confidence={bad} must be rejected"
            );
        }
    }

    /// Empty / whitespace-only fingerprint MUST be rejected; without
    /// a fingerprint the upstream cannot dedupe re-submissions.
    #[test]
    fn report_draft_rejects_empty_fingerprint() {
        for bad in ["", "   ", "\t\n"] {
            let mut d = ok_draft();
            d.fingerprint = bad.to_string();
            let errs = d.validate();
            assert!(errs
                .iter()
                .any(|e| matches!(e, ReportValidationError::FingerprintEmpty)));
        }
    }

    /// Multiple validation failures MUST be returned together so the
    /// operator fixes the draft in a single pass instead of being
    /// drip-fed errors round-trip-by-round-trip.
    #[test]
    fn report_draft_collects_every_failure() {
        let mut d = ok_draft();
        d.title = "x".to_string();
        d.confidence = 2.5;
        d.fingerprint = String::new();
        let errs = d.validate();
        assert_eq!(errs.len(), 3);
    }

    /// A draft with optional IOCs serialises with `{"type":...,
    /// "value":...}` to match the upstream feed shape; this round
    /// is what the on-disk `feed.json` and the live API both expect.
    #[test]
    fn report_draft_serialises_iocs_with_type_key() {
        let mut d = ok_draft();
        d.iocs.push(ReportIoc {
            kind: FeedIocKind::Hash,
            value: "deadbeef".to_string(),
        });
        let body = serde_json::to_string(&d).unwrap();
        assert!(body.contains(r#""type":"hash""#));
        assert!(body.contains(r#""value":"deadbeef""#));
    }
}
