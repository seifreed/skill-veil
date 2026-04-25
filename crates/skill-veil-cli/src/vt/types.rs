//! Serde shapes for the VirusTotal v3 public API responses we consume.
//!
//! We deserialise *only* the fields skill-veil actually needs. Every field is
//! `#[serde(default)]` so an API schema drift (a new or missing subfield) does
//! not break parsing for the portions we care about.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Response envelope for `/api/v3/intelligence/search`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SearchResponse {
    #[serde(default)]
    pub(crate) data: Vec<FileRef>,
    #[serde(default)]
    pub(crate) meta: SearchMeta,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct SearchMeta {
    #[serde(default)]
    pub(crate) cursor: Option<String>,
    /// VT-reported total match count. Informational only, kept here so the
    /// field does not silently disappear from parsed responses.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) count: Option<u64>,
}

/// Reference to a single file returned by search or the `/files/{id}` endpoint.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FileRef {
    /// Typically "file"; retained so schema drift doesn't fail deserialization.
    #[serde(rename = "type", default)]
    #[allow(dead_code)]
    pub(crate) kind: String,
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) attributes: FileAttributes,
}

/// Full report envelope from `/files/{sha256}`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FileReportEnvelope {
    pub(crate) data: FileRef,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct FileAttributes {
    #[serde(default)]
    pub(crate) meaningful_name: Option<String>,
    #[serde(default)]
    pub(crate) type_description: Option<String>,
    #[serde(default)]
    pub(crate) size: Option<u64>,
    #[serde(default)]
    pub(crate) md5: Option<String>,
    #[serde(default)]
    pub(crate) sha1: Option<String>,
    #[serde(default)]
    pub(crate) sha256: Option<String>,
    #[serde(default)]
    pub(crate) last_analysis_stats: Option<LastAnalysisStats>,
    #[serde(default)]
    pub(crate) crowdsourced_ai_results: Vec<CrowdsourcedAiResult>,
    /// Catch-all for analyst tags, names, etc. — retained so we can surface
    /// them in cross-check reports without adding per-field structs.
    #[serde(flatten, default)]
    pub(crate) extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct LastAnalysisStats {
    #[serde(default)]
    pub(crate) malicious: u64,
    #[serde(default)]
    pub(crate) suspicious: u64,
    #[serde(default)]
    pub(crate) undetected: u64,
    #[serde(default)]
    pub(crate) harmless: u64,
    #[serde(default)]
    pub(crate) timeout: u64,
    #[serde(default)]
    pub(crate) failure: u64,
    #[serde(rename = "type-unsupported", default)]
    pub(crate) type_unsupported: u64,
}

/// A single crowdsourced AI verdict. VT currently exposes Google Code Insight
/// here; additional sources may appear over time.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct CrowdsourcedAiResult {
    #[serde(default)]
    pub(crate) source: String,
    #[serde(default)]
    pub(crate) category: String,
    #[serde(default)]
    pub(crate) verdict: String,
    #[serde(default)]
    pub(crate) analysis: String,
}

impl FileAttributes {
    /// Returns the first Code Insight result, if any. Falls back to the first
    /// crowdsourced AI result of any source.
    pub(crate) fn primary_ai_verdict(&self) -> Option<&CrowdsourcedAiResult> {
        self.crowdsourced_ai_results
            .iter()
            .find(|r| r.source.eq_ignore_ascii_case("Code Insight"))
            .or_else(|| self.crowdsourced_ai_results.first())
    }
}

/// Compact on-disk record we write per file. Mirrors `FileAttributes` plus the
/// SHA and a timestamp so the cache can be inspected independently of VT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CachedReport {
    pub(crate) sha256: String,
    pub(crate) fetched_at: String, // RFC3339
    pub(crate) attributes: FileAttributes,
}
