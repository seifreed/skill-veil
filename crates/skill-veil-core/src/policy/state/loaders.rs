//! On-disk policy/baseline/waiver loaders.
//!
//! Each loader reads through a `FileSystemProvider` so the domain layer
//! never reaches `std::fs` directly. The contract is documented in
//! `CLAUDE.md`: domain types depend ONLY on `ports.rs` traits.
//!
//! Errors surface as [`PolicyLoadError`] (a `thiserror`-typed domain
//! error) instead of `std::io::Error`. Routing schema-mismatch and
//! validation failures through a dedicated variant keeps the library
//! API free of infrastructure types — `std::io::Error` only appears
//! inside the `FileSystemError::IoError` payload, never in the loader's
//! return type.

use crate::policy::baseline::{BaselineFile, WaiverFile};
use crate::policy::disposition::DispositionOverlay;
use crate::policy::types::PolicyFile;
use crate::ports::{FileSystemError, FileSystemProvider};
use std::path::Path;

use super::validators::{
    validate_baseline, validate_disposition_overlay, validate_policy, validate_waivers,
};

/// Errors surfaced by the policy/baseline/waiver loaders.
///
/// Variants partition the failure modes the loaders can report so callers
/// can distinguish "file missing / IO failure" from "schema mismatch" from
/// "validation rule rejected the contents". Pre-fix the loaders returned
/// `std::io::Error` for all three, forcing callers to inspect
/// `ErrorKind` to discriminate.
#[derive(Debug, thiserror::Error)]
pub enum PolicyLoadError {
    /// Filesystem failure (path missing, permission denied, …).
    #[error("filesystem error: {0}")]
    Io(#[from] FileSystemError),
    /// File contents are not valid UTF-8.
    #[error("file is not valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
    /// Deserialisation (JSON or YAML) failed.
    #[error("malformed file: {0}")]
    Parse(String),
    /// File parsed but failed schema/semantic validation.
    #[error("validation failed: {0}")]
    Validation(String),
}

/// Read a file's contents through a `FileSystemProvider`, decoding strictly
/// as UTF-8. Errors surface as [`PolicyLoadError`] so loader signatures
/// stay free of `std::io::Error`.
fn read_text_through_port<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<String, PolicyLoadError> {
    let bytes = fs.read_file_bytes(path)?;
    String::from_utf8(bytes.as_bytes().to_vec()).map_err(|e| {
        PolicyLoadError::Parse(format!(
            "{}: file contains invalid UTF-8: {}",
            path.display(),
            e
        ))
    })
}

/// Determine which parser produced the more meaningful error for the given
/// content. Returns the JSON error when the content begins with a JSON
/// sentinel (`{` / `[`) — otherwise the YAML diagnostic dominates because
/// YAML accepts almost-anything-as-a-scalar and its error messages on broken
/// JSON are notoriously misleading ("mapping values are not allowed here"
/// for a missing comma). For genuine YAML the JSON parser fails fast, so we
/// pick the YAML error in every other case.
fn select_parser_error(
    content: &str,
    json_err: serde_json::Error,
    yaml_err: serde_yaml::Error,
) -> String {
    let trimmed = content.trim_start();
    let looks_like_json = trimmed.starts_with('{') || trimmed.starts_with('[');
    if looks_like_json {
        json_err.to_string()
    } else {
        yaml_err.to_string()
    }
}

fn parse_json_or_yaml<T>(content: &str) -> Result<T, PolicyLoadError>
where
    T: serde::de::DeserializeOwned,
{
    // Pre-fix: an empty (or whitespace-only) `.policy.json` file falls
    // through `serde_json` -> `serde_yaml`, where `serde_yaml` happily
    // returns the all-fields-defaulted struct (every collection becomes
    // `[]`). The truncation case ⇒ `Ok(PolicyFile { overrides: [] })` ⇒ the
    // caller silently loses every suppression instead of surfacing a clear
    // error. This guard refuses the empty document explicitly so a partial
    // write or `Ctrl-C` mid-edit cannot zero out the policy state.
    if content.trim().is_empty() {
        return Err(PolicyLoadError::Parse(
            "policy file is empty (whitespace only); refusing to silently apply defaulted fields"
                .to_string(),
        ));
    }
    match serde_json::from_str::<T>(content) {
        Ok(value) => Ok(value),
        Err(json_err) => match serde_yaml::from_str::<T>(content) {
            Ok(value) => Ok(value),
            Err(yaml_err) => Err(PolicyLoadError::Parse(select_parser_error(
                content, json_err, yaml_err,
            ))),
        },
    }
}

/// Read a file through `fs`, deserialise it as `T` (JSON or YAML), and run
/// `validate` against the parsed value. Centralises the read → parse →
/// validate pipeline that all three policy loaders share so a future fix
/// to the ordering or error mapping touches one place instead of three.
fn load_validated<F, T>(
    fs: &F,
    path: &Path,
    validate: fn(&T) -> Result<(), String>,
) -> Result<T, PolicyLoadError>
where
    F: FileSystemProvider,
    T: serde::de::DeserializeOwned,
{
    let content = read_text_through_port(fs, path)?;
    let value: T = parse_json_or_yaml(&content)?;
    validate(&value).map_err(PolicyLoadError::Validation)?;
    Ok(value)
}

/// Load a baseline file from disk and validate it against the current
/// baseline schema.
///
/// # Errors
///
/// - [`PolicyLoadError::Io`] if `path` is unreadable through `fs`.
/// - [`PolicyLoadError::InvalidUtf8`] if the bytes are not valid UTF-8.
/// - [`PolicyLoadError::Parse`] if the contents are not valid JSON or YAML.
/// - [`PolicyLoadError::Validation`] if the file parses but its
///   `schema_version` is unknown or any entry fails the baseline
///   semantic checks (empty fingerprint, empty reason, etc.).
pub fn load_baseline<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<BaselineFile, PolicyLoadError> {
    load_validated(fs, path, validate_baseline)
}

/// Load a waivers file from disk and validate it against the current
/// waivers schema.
///
/// # Errors
///
/// - [`PolicyLoadError::Io`] if `path` is unreadable through `fs`.
/// - [`PolicyLoadError::InvalidUtf8`] if the bytes are not valid UTF-8.
/// - [`PolicyLoadError::Parse`] if the contents are not valid JSON or YAML.
/// - [`PolicyLoadError::Validation`] if the file parses but its
///   `schema_version` is unknown or any waiver entry has no selectors
///   (`rule_id`, `artifact_path`, `context` are all absent).
pub fn load_waivers<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<WaiverFile, PolicyLoadError> {
    load_validated(fs, path, validate_waivers)
}

/// Load a policy file from disk and validate it against the current
/// policy schema.
///
/// # Errors
///
/// - [`PolicyLoadError::Io`] if `path` is unreadable through `fs`.
/// - [`PolicyLoadError::InvalidUtf8`] if the bytes are not valid UTF-8.
/// - [`PolicyLoadError::Parse`] if the contents are not valid JSON or YAML.
/// - [`PolicyLoadError::Validation`] if the file parses but fails the
///   policy semantic checks (unknown schema version, malformed
///   override, …).
pub fn load_policy<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<PolicyFile, PolicyLoadError> {
    load_validated(fs, path, validate_policy)
}

/// Load an analyst-feedback disposition overlay from disk.
///
/// # Errors
///
/// - [`PolicyLoadError::Io`] if `path` is unreadable through `fs`.
/// - [`PolicyLoadError::InvalidUtf8`] if the bytes are not valid UTF-8.
/// - [`PolicyLoadError::Parse`] if the contents are not valid JSON or
///   YAML (or carry unknown fields — the overlay is
///   `deny_unknown_fields`).
pub fn load_disposition_overlay<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<DispositionOverlay, PolicyLoadError> {
    load_validated(fs, path, validate_disposition_overlay)
}

#[cfg(test)]
mod load_waivers_tests {
    use super::*;
    use crate::adapters::StdFileSystemProvider;
    use crate::policy::POLICY_SCHEMA_VERSION;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_yaml(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create tempfile");
        file.write_all(content.as_bytes()).expect("write tempfile");
        file.flush().expect("flush tempfile");
        file
    }

    fn fs() -> StdFileSystemProvider {
        StdFileSystemProvider::new()
    }

    /// # Contract
    ///
    /// `load_waivers` MUST run `validate_waivers` after deserialising and
    /// surface a schema-mismatch as [`PolicyLoadError::Validation`]. Mirrors
    /// `load_policy` (which already validates) so callers cannot end up
    /// with a `WaiverFile` whose `schema_version` is unknown to the
    /// matching pipeline. Pre-fix: load_waivers silently accepted any
    /// schema version and the mismatch never surfaced at the boundary.
    #[test]
    fn load_waivers_rejects_invalid_schema_version() {
        let yaml = "schema_version: bogus/v0\nwaivers: []\n";
        let file = write_yaml(yaml);

        let err = load_waivers(&fs(), file.path()).expect_err(
            "waiver file with unknown schema_version MUST fail validation at load time",
        );
        assert!(
            matches!(err, PolicyLoadError::Validation(_)),
            "schema mismatch must surface as PolicyLoadError::Validation; got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("schema_version") || msg.contains("Unsupported"),
            "error must explain schema mismatch; got: {msg}"
        );
    }

    /// # Contract
    ///
    /// `load_waivers` MUST reject a file containing a waiver entry with no
    /// selectors (no `rule_id`, no `artifact_path`, no `context`) at load
    /// time. Such entries would suppress every finding indiscriminately
    /// once applied — the failure must surface immediately, not after
    /// the pipeline has already filtered real findings.
    #[test]
    fn load_waivers_rejects_waiver_without_selectors() {
        let yaml = format!(
            "schema_version: {POLICY_SCHEMA_VERSION}\nwaivers:\n  - reason: 'no selectors at all'\n",
        );
        let file = write_yaml(&yaml);

        let err = load_waivers(&fs(), file.path())
            .expect_err("waiver entry with no rule_id/artifact_path/context MUST fail validation");
        assert!(
            matches!(err, PolicyLoadError::Validation(_)),
            "missing-selector failure must surface as PolicyLoadError::Validation; got: {err:?}"
        );
        assert!(
            err.to_string().contains("selector"),
            "error must mention the missing selector requirement; got: {err}"
        );
    }

    /// # Contract (positive)
    ///
    /// A well-formed waiver file with the current schema version and at
    /// least one selector loads successfully. Guards against an
    /// over-strict validator regressing the happy path.
    #[test]
    fn load_waivers_accepts_well_formed_file() {
        let yaml = format!(
            "schema_version: {POLICY_SCHEMA_VERSION}\nwaivers:\n  - rule_id: RULE_A\n    reason: 'known false positive on this rule'\n",
        );
        let file = write_yaml(&yaml);

        let loaded = load_waivers(&fs(), file.path()).expect("well-formed waiver file must load");
        assert_eq!(loaded.waivers.len(), 1);
        assert_eq!(loaded.waivers[0].rule_id.as_deref(), Some("RULE_A"));
    }

    /// # Contract
    ///
    /// An empty (or whitespace-only) policy file MUST surface as
    /// `PolicyLoadError::Parse`, never silently parse to a defaulted
    /// `WaiverFile`. Pre-fix `serde_json` rejected the empty document but
    /// the loader fell through to `serde_yaml`, which returns the all-
    /// fields-defaulted struct (`waivers: []`). A `.policy.json` truncated
    /// by `Ctrl-C` mid-edit therefore looked like a deliberate "no
    /// suppressions" file, silently dropping every previously declared
    /// waiver.
    #[test]
    fn load_waivers_rejects_empty_or_whitespace_file() {
        for blank in ["", "   ", "\n\n\t\n  \n"] {
            let file = write_yaml(blank);
            let err = load_waivers(&fs(), file.path()).expect_err(
                "empty/whitespace policy file MUST fail at load time, not silently default",
            );
            assert!(
                matches!(err, PolicyLoadError::Parse(_)),
                "must surface as Parse error; got {err:?}"
            );
            assert!(
                err.to_string().contains("empty"),
                "error must mention emptiness; got {err}"
            );
        }
    }
}

#[cfg(test)]
mod load_baseline_tests {
    use super::*;
    use crate::adapters::StdFileSystemProvider;
    use crate::policy::POLICY_SCHEMA_VERSION;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_yaml(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create tempfile");
        file.write_all(content.as_bytes()).expect("write tempfile");
        file.flush().expect("flush tempfile");
        file
    }

    fn fs() -> StdFileSystemProvider {
        StdFileSystemProvider::new()
    }

    /// # Contract
    ///
    /// `load_baseline` MUST run `validate_baseline` after deserialising and
    /// surface a schema-mismatch as `io::ErrorKind::InvalidData`. Mirrors
    /// `load_policy` and `load_waivers`. Pre-fix: load_baseline silently
    /// accepted any schema version (BaselineFile::schema_version has a
    /// serde default), so a baseline produced under an obsolete schema
    /// could be applied unchanged against the current matching pipeline.
    #[test]
    fn load_baseline_rejects_invalid_schema_version() {
        let yaml = "schema_version: bogus/v0\nentries: []\n";
        let file = write_yaml(yaml);

        let err = load_baseline(&fs(), file.path()).expect_err(
            "baseline file with unknown schema_version MUST fail validation at load time",
        );
        assert!(
            matches!(err, PolicyLoadError::Validation(_)),
            "schema mismatch must surface as PolicyLoadError::Validation; got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("schema_version") || msg.contains("Unsupported"),
            "error must explain schema mismatch; got: {msg}"
        );
    }

    /// # Contract
    ///
    /// `load_baseline` MUST reject a baseline entry with an empty
    /// fingerprint. An empty fingerprint would match every finding's
    /// hash-prefix lookup, silently silencing the entire pipeline.
    #[test]
    fn load_baseline_rejects_entry_with_empty_fingerprint() {
        let yaml = format!(
            "schema_version: {POLICY_SCHEMA_VERSION}\nentries:\n  - fingerprint: ''\n    rule_id: RULE_A\n    reason: 'whatever'\n",
        );
        let file = write_yaml(&yaml);

        let err = load_baseline(&fs(), file.path())
            .expect_err("baseline entry with empty fingerprint MUST fail validation");
        assert!(
            matches!(err, PolicyLoadError::Validation(_)),
            "empty-fingerprint rejection must surface as PolicyLoadError::Validation; got: {err:?}"
        );
        assert!(
            err.to_string().contains("fingerprint"),
            "error must mention the empty fingerprint; got: {err}"
        );
    }

    /// # Contract
    ///
    /// `load_baseline` MUST reject entries whose `reason` is empty or
    /// whitespace-only. The reason field is a paper trail for the
    /// suppression — empty values defeat the audit purpose.
    #[test]
    fn load_baseline_rejects_entry_with_empty_reason() {
        let yaml = format!(
            "schema_version: {POLICY_SCHEMA_VERSION}\nentries:\n  - fingerprint: 'abc123'\n    rule_id: RULE_A\n    reason: '   '\n",
        );
        let file = write_yaml(&yaml);

        let err = load_baseline(&fs(), file.path())
            .expect_err("baseline entry with empty reason MUST fail validation");
        assert!(
            matches!(err, PolicyLoadError::Validation(_)),
            "empty-reason rejection must surface as PolicyLoadError::Validation; got: {err:?}"
        );
        assert!(
            err.to_string().contains("reason"),
            "error must mention the empty reason; got: {err}"
        );
    }

    /// # Contract (positive)
    ///
    /// A well-formed baseline file with the current schema version and at
    /// least one entry loads successfully.
    #[test]
    fn load_baseline_accepts_well_formed_file() {
        let yaml = format!(
            "schema_version: {POLICY_SCHEMA_VERSION}\nentries:\n  - fingerprint: 'sha256:abc'\n    rule_id: RULE_A\n    reason: 'documented exception'\n",
        );
        let file = write_yaml(&yaml);

        let loaded =
            load_baseline(&fs(), file.path()).expect("well-formed baseline file must load");
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].rule_id, "RULE_A");
        assert_eq!(loaded.entries[0].fingerprint, "sha256:abc");
    }
}

#[cfg(test)]
mod parser_error_selection_tests {
    use super::*;

    /// Contract: when content begins with a JSON sentinel (`{` / `[`), a
    /// parse failure surfaces the **JSON** parser's diagnostic — not the
    /// YAML parser's. Pre-fix `parse_json_or_yaml` discarded `json_err` and
    /// always reported `yaml_err` on failure, so an operator with a
    /// `policy.json` containing a trailing comma saw `mapping values are
    /// not allowed here` (a YAML grammar error against JSON content),
    /// which gave no actionable hint about the actual problem.
    #[test]
    fn parse_error_for_json_shaped_content_surfaces_json_diagnostic() {
        // Bracket mismatch — invalid both as JSON and as YAML. Fed through
        // serde_yaml the canonical message is "did not find expected ',' or
        // '}'", which does not match the JSON message and lets us assert
        // which parser produced the diagnostic.
        let bad_json = "{\"key\": \"value\" \"oops\"}";
        let err: PolicyLoadError = parse_json_or_yaml::<serde_json::Value>(bad_json)
            .expect_err("invalid JSON-shaped content must fail to parse");
        let msg = match err {
            PolicyLoadError::Parse(s) => s,
            other => panic!("expected Parse error, got {other:?}"),
        };
        // serde_json's error for this input: "expected `,` or `}`" — the
        // YAML parser's diagnostic for the same content reads "did not find
        // expected" or "mapping values are not allowed here". Assert the
        // operator-facing message has the JSON shape so a `.json` file with
        // a syntax bug doesn't surface a YAML-grammar complaint.
        assert!(
            msg.contains("expected `,` or `}`") || msg.contains("expected value"),
            "JSON-shaped content must surface JSON diagnostic, not YAML; got: {msg}"
        );
    }

    /// Contract: when content does not look like JSON, the YAML diagnostic
    /// dominates. This is the original behavior — pinned to ensure the new
    /// JSON-bias does not over-fire on genuine YAML input.
    #[test]
    fn parse_error_for_yaml_shaped_content_surfaces_yaml_diagnostic() {
        // Indentation-broken YAML; not even JSON-shaped (no leading `{`/`[`).
        let bad_yaml = "key: value\n  bad: : indent\n";
        let err: PolicyLoadError = parse_json_or_yaml::<serde_yaml::Value>(bad_yaml)
            .expect_err("invalid YAML-shaped content must fail to parse");
        assert!(
            matches!(err, PolicyLoadError::Parse(_)),
            "expected Parse error; got {err:?}"
        );
    }

    /// Contract: a leading-whitespace JSON document still triggers the
    /// JSON-bias. The selector trims start so a file produced by an editor
    /// with a BOM-less leading newline (or indented JSON) does not silently
    /// fall through to the YAML branch.
    #[test]
    fn parse_error_for_indented_json_still_reports_json() {
        let bad_json = "  \n{\"oops\": \"missing-close\"\n";
        let err: PolicyLoadError = parse_json_or_yaml::<serde_json::Value>(bad_json)
            .expect_err("invalid leading-whitespace JSON must fail");
        let msg = match err {
            PolicyLoadError::Parse(s) => s,
            other => panic!("expected Parse error, got {other:?}"),
        };
        assert!(
            !msg.contains("mapping values are not allowed"),
            "leading-whitespace JSON must NOT surface YAML's mapping error; got: {msg}"
        );
    }
}

#[cfg(test)]
mod load_disposition_tests {
    use super::*;
    use crate::adapters::StdFileSystemProvider;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Contract: a JSON disposition overlay round-trips through the
    /// `FileSystemProvider` port loader — this is the wiring that lets
    /// `--disposition` actually affect a scan.
    #[test]
    fn load_disposition_overlay_reads_json_through_port() {
        let mut file = NamedTempFile::new().expect("tempfile");
        file.write_all(
            br#"{"records":[{"finding_fingerprint":"fp1","rule_id":"R1","analyst_disposition":"false_positive","recorded_at":"2026-01-01T00:00:00Z"}]}"#,
        )
        .expect("write");
        file.flush().expect("flush");
        let fs = StdFileSystemProvider::new();
        let overlay = load_disposition_overlay(&fs, file.path()).expect("load");
        assert_eq!(overlay.records.len(), 1);
        assert_eq!(overlay.records[0].rule_id, "R1");
    }

    /// Contract (negative): unknown fields are rejected at the
    /// boundary (`deny_unknown_fields`), so a malformed overlay cannot
    /// silently reach the filter stage.
    #[test]
    fn load_disposition_overlay_rejects_unknown_fields() {
        let mut file = NamedTempFile::new().expect("tempfile");
        file.write_all(br#"{"records":[],"bogus":true}"#)
            .expect("write");
        file.flush().expect("flush");
        let fs = StdFileSystemProvider::new();
        assert!(load_disposition_overlay(&fs, file.path()).is_err());
    }
}
