//! On-disk format and reader for `~/.skill-veil.toml`.
//!
//! `FileFormat` and friends are the serde-deserialised shapes; nothing
//! outside `resolution/` should touch them. `read_file_if_exists` is the
//! shared loader used by `UnifiedConfig::load`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Read `path` if it exists, surfacing a `tracing::warn!` if the file is
/// group-/other-readable. Used for `~/.skill-veil.toml` and the legacy
/// `~/.vt.toml`, both of which hold API keys (VT, OpenAI, Anthropic,
/// xAI, Perplexity, Ollama Cloud).
///
/// # Contract
///
/// - `NotFound` ⇒ `None` (silent: file is truly absent).
/// - `EACCES`/other I/O ⇒ `None` PLUS a `tracing::warn!` so the operator
///   can distinguish "no config" from "config exists but is unreadable".
///
/// Pre-fix this function used `path.exists()` followed by `read_to_string`,
/// which both (a) introduced a TOCTOU race between the two syscalls, and
/// (b) silently masked `EACCES` (chmod 000) as `not found`, so an admin
/// who restricted the config without informing the user produced an
/// undebuggable "no API key configured" failure.
pub(super) fn read_file_if_exists(path: &std::path::Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            crate::util::secure_fs::warn_if_file_world_readable(path);
            Some(contents)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            tracing::warn!(
                "skipping config file {}: {err} (check file permissions)",
                path.display(),
            );
            None
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct FileFormat {
    #[serde(default)]
    pub(super) llm: Option<FileLlmSection>,
    /// Optional `[vt]` section so users can centralise both LLM and
    /// VirusTotal credentials in a single `~/.skill-veil.toml`. The
    /// legacy standalone `~/.vt.toml` keeps working — `vt::config`
    /// consults this section only as a fallback when the legacy file
    /// is absent.
    #[serde(default)]
    pub(super) vt: Option<FileVtSection>,
    /// Optional `[promptintel]` section for the PromptIntel
    /// (`api.promptintel.novahunting.ai`) corpus. Mirrors `[vt]`: the
    /// `PROMPTINTEL` environment variable wins, then this section, then
    /// "not configured". Same `apikey` shape so operators only have to
    /// learn one schema.
    #[serde(default)]
    pub(super) promptintel: Option<FilePromptIntelSection>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct FileVtSection {
    #[serde(default)]
    pub(super) apikey: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct FilePromptIntelSection {
    #[serde(default)]
    pub(super) apikey: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub(super) struct FileLlmSection {
    #[serde(default)]
    pub(super) provider: Option<String>,
    #[serde(flatten)]
    pub(super) providers: BTreeMap<String, FileProviderParams>,
    #[serde(default)]
    pub(super) limits: Option<FileLlmLimits>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct FileProviderParams {
    #[serde(default)]
    pub(super) model: Option<String>,
    #[serde(default)]
    pub(super) base_url: Option<String>,
    #[serde(default)]
    pub(super) api_key: Option<String>,
    #[serde(default)]
    pub(super) max_tokens: Option<u32>,
    #[serde(default)]
    pub(super) temperature: Option<f32>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct FileLlmLimits {
    #[serde(default)]
    pub(super) max_prompt_chars: Option<usize>,
    #[serde(default)]
    pub(super) request_timeout_secs: Option<u64>,
    /// Operator override for the consensus provider set, by wire name
    /// (e.g. `["openai", "grok", "ollama-cloud"]`). Omitted ⇒ the
    /// validated trio.
    #[serde(default)]
    pub(super) consensus_providers: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `~/.skill-veil.toml` accepts a `[vt]` section alongside
    /// `[llm]` so users can centralise both LLM and VirusTotal
    /// credentials in a single file. Pre-fix `FileFormat` only knew
    /// about `[llm]` and `#[serde(deny_unknown_fields)]` rejected
    /// `[vt]` with `unknown field 'vt', expected 'llm'`, masking VT
    /// integration as "LLM enrichment skipped" warnings on every scan.
    #[test]
    fn parses_unified_toml_with_vt_and_llm_sections() {
        let src = r#"
[vt]
apikey = "vt-test-key"

[llm]
provider = "lmstudio"

[llm.lmstudio]
model = "qwen/qwen3-coder-30b"
"#;
        let f: FileFormat = toml::from_str(src).expect("must accept [vt] alongside [llm]");
        let vt = f.vt.as_ref().expect("vt section must parse");
        assert_eq!(vt.apikey.as_deref(), Some("vt-test-key"));
        let llm = f.llm.as_ref().expect("llm section must still parse");
        assert_eq!(llm.provider.as_deref(), Some("lmstudio"));
    }

    /// Contract: `[vt]` sub-keys honour `deny_unknown_fields` so typos
    /// like `api_key` (underscore) or `apikey_value` surface as a clear
    /// parse error rather than silently producing `apikey: None` and
    /// then "VT not configured". Mirrors the same defensive contract on
    /// `[llm]` provider params and on the legacy `~/.vt.toml` schema.
    #[test]
    fn vt_section_rejects_unknown_subkeys() {
        let src = r#"
[vt]
api_key = "typo-with-underscore"
"#;
        let result: Result<FileFormat, _> = toml::from_str(src);
        assert!(
            result.is_err(),
            "FileVtSection MUST reject unknown field 'api_key'; \
             pre-fix typos would silently yield apikey=None"
        );
    }

    /// Contract: `~/.skill-veil.toml` parses every documented `[llm.*]`
    /// sub-table — the active provider, per-provider sections, and the
    /// shared `[llm.limits]` block — without flagging any of them as
    /// unknown sub-keys (the TOML loader uses `#[serde(flatten)]` for
    /// per-provider sections).
    #[test]
    fn parses_unified_toml_with_llm_sections() {
        let src = r#"
[llm]
provider = "anthropic"

[llm.anthropic]
model = "claude-sonnet-4-5"
max_tokens = 1024

[llm.openai]
model = "gpt-4o-mini"

[llm.limits]
max_prompt_chars = 80000
request_timeout_secs = 60
"#;
        let f: FileFormat = toml::from_str(src).unwrap();
        let llm = f.llm.as_ref().unwrap();
        assert_eq!(llm.provider.as_deref(), Some("anthropic"));
        assert_eq!(llm.providers.len(), 2);
        assert!(llm.providers.contains_key("anthropic"));
        assert!(llm.providers.contains_key("openai"));
    }

    /// # Contract
    ///
    /// `read_file_if_exists` MUST return `None` for a path that does
    /// not exist, without panicking. Safe to call speculatively on
    /// every config-search location, which is how `UnifiedConfig::load`
    /// uses it.
    #[test]
    fn read_file_if_exists_returns_none_for_missing_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("does-not-exist.toml");

        let result = read_file_if_exists(&missing);

        assert!(
            result.is_none(),
            "missing config files MUST yield None, not Some(empty)"
        );
    }

    /// # Contract
    ///
    /// `read_file_if_exists` MUST return the file body when the file
    /// exists, regardless of permissions. Pre-fix `~/.skill-veil.toml`
    /// got NO permission warning at all (only the standalone
    /// `~/.vt.toml` loader had one); post-fix the unified loader emits
    /// a tracing warning AND still returns the body so legitimate
    /// scans don't break. This test pins the load-success path so a
    /// future "fail-closed on world-readable config" refactor regresses
    /// here instead of silently disabling every shared-host install.
    #[cfg(unix)]
    #[test]
    fn read_file_if_exists_loads_world_readable_file_with_warning() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, "apikey = \"x\"").expect("seed config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("seed mode 0o644");

        let result = read_file_if_exists(&path);

        assert_eq!(
            result.as_deref(),
            Some("apikey = \"x\""),
            "world-readable config MUST still load — we warn, never block"
        );
    }

    /// # Contract
    ///
    /// A config file that exists on disk but is unreadable by the current
    /// process (e.g. `chmod 0o000` after admin lockdown) MUST NOT be
    /// silently treated as absent. Pre-fix the implementation used
    /// `path.exists() && read_to_string().ok()` so `EACCES` collapsed to
    /// `None` (`exists()` returns `false` on permission-denied stat in
    /// some cases, and `.ok()` discarded the error otherwise) — making
    /// "API key not configured" indistinguishable from "API key file is
    /// locked down". The new contract: still return `None` (callers
    /// remain branch-free), but the function MUST be reachable through
    /// the I/O error arm so callers can rely on the warn diagnostic.
    /// This test cannot capture the warn output portably; it asserts the
    /// reachability and `None` return without panicking.
    #[cfg(unix)]
    #[test]
    fn read_file_if_exists_returns_none_for_unreadable_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("locked.toml");
        std::fs::write(&path, "apikey = \"x\"").expect("seed config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("seed mode 0o000");

        // Skip when running as root — root bypasses DAC permission checks
        // and can read any file regardless of mode.
        if let Ok(uid_str) = std::env::var("UID") {
            if uid_str == "0" {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
                return;
            }
        }

        let result = read_file_if_exists(&path);

        // Restore so tempdir cleanup works even if the assertion fails.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));

        assert!(
            result.is_none(),
            "unreadable config MUST yield None (and produce a warn-level diagnostic, \
             not silently look identical to a missing file)"
        );
    }

    /// # Contract
    ///
    /// `FileProviderParams` MUST reject unknown fields so that config typos
    /// (e.g. `temperatur` instead of `temperature`, `apikey` instead of
    /// `api_key`) produce a clear error rather than silently falling back
    /// to defaults. Pre-fix, `#[serde(deny_unknown_fields)]` was absent,
    /// so a typo like `temperatur = 0.7` was silently ignored and the
    /// actual `temperature` defaulted to `None` (then 0.1 at the provider
    /// level), making it appear the config was accepted when it was not.
    #[test]
    fn file_provider_params_rejects_unknown_fields() {
        let src = r#"
model = "gpt-4o"
temperatur = 0.7
"#;
        let result: Result<FileProviderParams, _> = toml::from_str(src);
        assert!(
            result.is_err(),
            "FileProviderParams MUST reject unknown field 'temperatur'; \
             pre-fix, this was silently accepted and temperature defaulted to None"
        );
    }

    /// # Contract
    ///
    /// `FileLlmLimits` MUST reject unknown fields so that config typos
    /// (e.g. `max_prompt_charz` instead of `max_prompt_chars`,
    /// `request_timeout_sec` instead of `request_timeout_secs`) produce
    /// a clear error rather than silently falling back to defaults.
    /// Pre-fix, `#[serde(deny_unknown_fields)]` was absent, so a typo
    /// like `max_prompt_charz = 80000` was silently ignored and the
    /// actual `max_prompt_chars` defaulted to `None` (auto-detect).
    #[test]
    fn file_llm_limits_rejects_unknown_fields() {
        let src = r#"
max_prompt_charz = 80000
"#;
        let result: Result<FileLlmLimits, _> = toml::from_str(src);
        assert!(
            result.is_err(),
            "FileLlmLimits MUST reject unknown field 'max_prompt_charz'; \
             pre-fix, this was silently accepted and max_prompt_chars defaulted to None"
        );
    }

    /// # Contract
    ///
    /// `FileFormat` MUST reject unknown top-level fields so that config typos
    /// (e.g. `[lmm]` instead of `[llm]`) produce a clear error rather than
    /// silently discarding the entire LLM configuration. Pre-fix,
    /// `#[serde(deny_unknown_fields)]` was absent on `FileFormat`, so a typo
    /// like `[lmm]` was silently ignored and LLM enrichment defaulted to
    /// disabled with no error.
    #[test]
    fn file_format_rejects_unknown_top_level_fields() {
        let src = r#"
[lmm]
provider = "anthropic"
"#;
        let result: Result<FileFormat, _> = toml::from_str(src);
        assert!(
            result.is_err(),
            "FileFormat MUST reject unknown top-level field 'lmm'; \
             pre-fix, this was silently accepted and LLM config was lost"
        );
    }
}
