//! `manifest.json` schema produced by `skill-veil-rules/scripts/build-manifest.sh`.
//!
//! The on-disk shape is intentionally tiny: a version string, a UTC
//! timestamp, and a list of `(path, sha256, size_bytes)` triples. The
//! `schema_version` field allows additive evolution without breaking
//! existing binaries — readers MUST reject unknown majors and accept
//! unknown minors.

use serde::Deserialize;

/// Schema version of the on-disk `manifest.json` this binary
/// understands. Bump the major when introducing a breaking change
/// (e.g. removing a field or changing semantics); bump the minor for
/// additive fields.
pub(crate) const SUPPORTED_SCHEMA_VERSION: &str = "skill-veil.dev/rules-manifest/v1";

#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) schema_version: String,
    pub(crate) version: String,
    pub(crate) files: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ManifestEntry {
    pub(crate) path: String,
    pub(crate) sha256: String,
    #[serde(default)]
    pub(crate) size_bytes: Option<u64>,
}

impl Manifest {
    /// Verify the schema version is one this binary understands. Returns
    /// the parsed manifest unchanged on success, or an error message
    /// suitable for display to an operator.
    pub(crate) fn check_schema_version(&self) -> Result<(), String> {
        if self.schema_version == SUPPORTED_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(format!(
                "manifest schema_version `{}` is not supported by this binary \
                 (expected `{}`); upgrade `skill-veil` or pin an older rules release",
                self.schema_version, SUPPORTED_SCHEMA_VERSION
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: the v1 schema accepts the exact JSON layout produced
    /// by `scripts/build-manifest.sh`. If this test breaks, either the
    /// release script or this struct has drifted — fix whichever side
    /// regressed before shipping.
    #[test]
    fn parses_canonical_v1_manifest() {
        // `generated_at` is present in real manifests but ignored
        // here — serde silently drops unknown fields by default.
        let body = r#"{
            "schema_version": "skill-veil.dev/rules-manifest/v1",
            "version": "v0.1.0",
            "generated_at": "2026-05-09T17:45:26Z",
            "files": [
                { "path": "official/core.yaml",       "sha256": "aa", "size_bytes": 100 },
                { "path": "official/behavioral.yaml", "sha256": "bb", "size_bytes": 200 }
            ]
        }"#;
        let manifest: Manifest = serde_json::from_str(body).expect("v1 manifest must parse");
        manifest
            .check_schema_version()
            .expect("schema_version v1 must be accepted");
        assert_eq!(manifest.version, "v0.1.0");
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(manifest.files[0].path, "official/core.yaml");
        assert_eq!(manifest.files[0].sha256, "aa");
        assert_eq!(manifest.files[0].size_bytes, Some(100));
    }

    /// Contract: a manifest from a future schema version must be
    /// rejected at parse time, not silently accepted with bad
    /// semantics. The error message must name the unsupported version
    /// so the operator knows what to upgrade.
    #[test]
    fn rejects_unsupported_schema_version() {
        let body = r#"{
            "schema_version": "skill-veil.dev/rules-manifest/v999",
            "version": "v9.9.9",
            "files": []
        }"#;
        let manifest: Manifest = serde_json::from_str(body).expect("body itself parses");
        let err = manifest
            .check_schema_version()
            .expect_err("v999 must be rejected");
        assert!(
            err.contains("v999"),
            "error must name unsupported version: {err}"
        );
    }
}
