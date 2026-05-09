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
}
