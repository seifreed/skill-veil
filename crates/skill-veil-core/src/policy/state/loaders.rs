//! On-disk policy/baseline/waiver loaders.
//!
//! Each loader reads through a `FileSystemProvider` so the domain layer
//! never reaches `std::fs` directly. The contract is documented in
//! `CLAUDE.md`: domain types depend ONLY on `ports.rs` traits.

use crate::policy::baseline::{BaselineFile, WaiverFile};
use crate::policy::types::PolicyFile;
use crate::ports::{FileSystemError, FileSystemProvider};
use std::path::Path;

use super::validators::{validate_baseline, validate_policy, validate_waivers};

/// Read a file's contents through a `FileSystemProvider`, decoding strictly
/// as UTF-8. Mirrors the behaviour of `std::fs::read_to_string` while
/// keeping the dependency on the port. Returned as `std::io::Error` so
/// callers preserve the existing `Result<_, std::io::Error>` API.
fn read_text_through_port<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<String, std::io::Error> {
    let bytes = fs.read_file_bytes(path).map_err(|err| match err {
        FileSystemError::IoError(io) => io,
        FileSystemError::PathNotFound(missing) => std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("path not found: {}", missing.display()),
        ),
    })?;
    String::from_utf8(bytes.as_bytes().to_vec())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

pub fn load_baseline<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<BaselineFile, std::io::Error> {
    let content = read_text_through_port(fs, path)?;
    let baseline: BaselineFile = serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    validate_baseline(&baseline)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(baseline)
}

pub fn load_waivers<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<WaiverFile, std::io::Error> {
    let content = read_text_through_port(fs, path)?;
    let waivers: WaiverFile = serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    validate_waivers(&waivers)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(waivers)
}

pub fn load_policy<F: FileSystemProvider>(
    fs: &F,
    path: &Path,
) -> Result<PolicyFile, std::io::Error> {
    let content = read_text_through_port(fs, path)?;
    let policy = serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    validate_policy(&policy)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(policy)
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
    /// surface a schema-mismatch as `io::ErrorKind::InvalidData`. Mirrors
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
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
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
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
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
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
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
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
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
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
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
