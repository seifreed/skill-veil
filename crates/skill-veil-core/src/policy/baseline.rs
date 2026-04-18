use super::default_policy_schema_version;
use crate::findings::OperationalContext;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    pub entries: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverFile {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    pub waivers: Vec<WaiverEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<OperationalContext>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}
