use super::default_policy_schema_version;
use crate::findings::OperationalContext;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineFile {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    /// `#[serde(default)]` keeps load-compat with files that omit the
    /// `entries:` key entirely (an empty baseline). Mirrors
    /// `PolicyFile.overrides` and the engineering standard in
    /// `CLAUDE.md` § "When a fix touches a public type, prefer adding
    /// optional fields with serde defaults rather than breaking on-disk
    /// caches."
    #[serde(default)]
    pub entries: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverFile {
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: String,
    /// `#[serde(default)]` keeps load-compat with files that omit the
    /// `waivers:` key entirely (an empty waiver file). Mirrors
    /// `PolicyFile.overrides`.
    #[serde(default)]
    pub waivers: Vec<WaiverEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[cfg(test)]
mod serde_default_tests {
    use super::*;
    use crate::policy::POLICY_SCHEMA_VERSION;

    /// # Contract
    ///
    /// `BaselineFile` MUST deserialize successfully from a YAML body
    /// that omits the `entries:` key, treating it as an empty baseline.
    /// Pre-fix `entries` was a `Vec<BaselineEntry>` without
    /// `#[serde(default)]`, so a baseline file written as just
    /// `schema_version: ...` (e.g. an emptied baseline kept for audit
    /// continuity) failed to load with a missing-field error. Mirrors
    /// the engineering standard in `CLAUDE.md` § "prefer optional fields
    /// with serde defaults rather than breaking on-disk caches".
    #[test]
    fn baseline_file_deserializes_without_entries_key() {
        let yaml = format!("schema_version: {POLICY_SCHEMA_VERSION}\n");
        let parsed: BaselineFile =
            serde_yaml::from_str(&yaml).expect("BaselineFile MUST load when `entries:` is omitted");
        assert!(
            parsed.entries.is_empty(),
            "missing `entries:` key MUST default to an empty Vec"
        );
        assert_eq!(parsed.schema_version, POLICY_SCHEMA_VERSION);
    }

    /// # Contract
    ///
    /// `WaiverFile` MUST deserialize successfully from a YAML body that
    /// omits the `waivers:` key. Same rationale as
    /// `baseline_file_deserializes_without_entries_key`. Pinned because
    /// `validate_waivers` runs after deserialization and would never see
    /// the file otherwise — so silent regression here would surface as
    /// a confusing parse error to users emptying their waivers list.
    #[test]
    fn waiver_file_deserializes_without_waivers_key() {
        let yaml = format!("schema_version: {POLICY_SCHEMA_VERSION}\n");
        let parsed: WaiverFile =
            serde_yaml::from_str(&yaml).expect("WaiverFile MUST load when `waivers:` is omitted");
        assert!(
            parsed.waivers.is_empty(),
            "missing `waivers:` key MUST default to an empty Vec"
        );
        assert_eq!(parsed.schema_version, POLICY_SCHEMA_VERSION);
    }

    /// # Contract (positive)
    ///
    /// A well-formed baseline file with explicit `entries:` still loads
    /// without regression. Guards against a future refactor that would
    /// mistakenly enable `#[serde(default)]` AND `#[serde(skip)]`
    /// together (which would silently drop user-authored entries).
    #[test]
    fn baseline_file_still_loads_explicit_entries() {
        let yaml = format!(
            "schema_version: {POLICY_SCHEMA_VERSION}\n\
             entries:\n  \
             - fingerprint: deadbeef\n    \
               rule_id: RULE_A\n    \
               reason: pre-existing\n"
        );
        let parsed: BaselineFile = serde_yaml::from_str(&yaml).expect("explicit entries must load");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].fingerprint, "deadbeef");
        assert_eq!(parsed.entries[0].rule_id, "RULE_A");
    }

    /// # Contract
    ///
    /// `BaselineEntry` MUST reject unknown fields so that typos like
    /// `fingerprintt` instead of `fingerprint` produce a clear error.
    /// Pre-fix, `#[serde(deny_unknown_fields)]` was absent, so a typo
    /// silently created a malformed entry with the wrong field missing.
    #[test]
    fn baseline_entry_rejects_unknown_fields() {
        let yaml = format!(
            "schema_version: {POLICY_SCHEMA_VERSION}\n\
             entries:\n  \
             - fingerprintt: deadbeef\n    \
               rule_id: RULE_A\n    \
               reason: pre-existing\n"
        );
        let result: Result<BaselineFile, _> = serde_yaml::from_str(&yaml);
        assert!(
            result.is_err(),
            "BaselineEntry MUST reject unknown field 'fingerprintt'; \
             pre-fix, this was silently accepted and fingerprint was missing"
        );
    }

    /// # Contract
    ///
    /// `WaiverEntry` MUST reject unknown fields so that typos like
    /// `rule_ld` instead of `rule_id` produce a clear error rather than
    /// silently defaulting `rule_id` to `None`, which could make a waiver
    /// match all rules (a policy bypass).
    #[test]
    fn waiver_entry_rejects_unknown_fields() {
        let yaml = format!(
            "schema_version: {POLICY_SCHEMA_VERSION}\n\
             waivers:\n  \
             - rule_ld: RULE_A\n    \
               reason: approved exception\n"
        );
        let result: Result<WaiverFile, _> = serde_yaml::from_str(&yaml);
        assert!(
            result.is_err(),
            "WaiverEntry MUST reject unknown field 'rule_ld'; \
             pre-fix, this was silently accepted and rule_id defaulted to None"
        );
    }

    /// # Contract
    ///
    /// `BaselineFile` MUST reject unknown top-level fields so that typos
    /// like `entires` instead of `entries` are caught at load time.
    #[test]
    fn baseline_file_rejects_unknown_top_level_fields() {
        let yaml = format!("schema_version: {POLICY_SCHEMA_VERSION}\nentires: []\n");
        let result: Result<BaselineFile, _> = serde_yaml::from_str(&yaml);
        assert!(
            result.is_err(),
            "BaselineFile MUST reject unknown field 'entires'; \
             pre-fix, this was silently accepted and entries defaulted to empty"
        );
    }

    /// # Contract
    ///
    /// `WaiverFile` MUST reject unknown top-level fields so that typos
    /// like `wavers` instead of `waivers` are caught at load time.
    #[test]
    fn waiver_file_rejects_unknown_top_level_fields() {
        let yaml = format!("schema_version: {POLICY_SCHEMA_VERSION}\nwavers: []\n");
        let result: Result<WaiverFile, _> = serde_yaml::from_str(&yaml);
        assert!(
            result.is_err(),
            "WaiverFile MUST reject unknown field 'wavers'; \
             pre-fix, this was silently accepted and waivers defaulted to empty"
        );
    }
}
