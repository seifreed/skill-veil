//! Script-level detectors decomposed by detection family.
//!
//! Each submodule owns a coherent slice of the detection surface so that
//! changes to (e.g.) the secret-exfiltration heuristic do not force the
//! reader through unrelated injection-pattern logic. The orchestrator in
//! `services::artifact_orchestration::scripts::mod` composes these detectors
//! through the `pub(crate)` re-exports below.
//!
//! - [`network`] — remote-binary fetches and secret-file → network taint.
//! - [`exec`] — process spawn, dynamic eval, language-specific
//!   command-injection regexes.
//! - [`secrets`] — Python / Node access to environment variables, home
//!   paths, and sensitive system files.
//! - [`persistence`] — deferred-execution, scheduled-task, and shell
//!   startup-file writes.
//! - [`install`] — supply-chain detectors (currently typosquatted global
//!   installs against a known-good asset list).
//! - [`match_helpers`] — `original_match_str` shared by detectors that
//!   pair regex matches against lowercased content with original-cased
//!   evidence.

mod dotenv;
mod exec;
mod install;
mod match_helpers;
mod network;
pub(crate) mod patterns;
mod persistence;
mod pipeline;
mod secrets;

pub(crate) use dotenv::references_dotenv_file;
pub(crate) use pipeline::detect_shell_pipeline_taint;

pub(crate) use exec::{
    detect_injection_patterns, detect_node_process_exec, detect_powershell_dynamic_exec,
    detect_python_exec_network, detect_shell_side_effects,
};
pub(crate) use install::detect_typosquatted_install;
pub(crate) use network::{detect_file_secret_to_network_flow, detect_remote_binary_downloads};
pub(crate) use persistence::{
    detect_deferred_execution, detect_powershell_persistence, detect_shell_persistence_write,
};
pub(crate) use secrets::{detect_node_secret_fs_access, detect_python_secret_system_access};

use std::path::Path;

/// True if `path` carries a script / executable-source extension (shell,
/// PowerShell, Python, JS/TS, Ruby, Perl, Go, Rust, PHP).
///
/// Shared by the artifact-orchestration dispatcher and the deceptive-docs
/// detector so the "is this artifact executable?" gate is defined in exactly
/// one place. The set MUST include the PowerShell module/data variants
/// (`.psm1`/`.psd1`) and all shell dialects (`.ksh`/`.fish`) — a missing
/// entry silently excludes that file from script analysis.
pub(crate) fn looks_like_script(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some(
            "sh" | "bash"
                | "zsh"
                | "ksh"
                | "fish"
                | "ps1"
                | "psm1"
                | "psd1"
                | "py"
                | "js"
                | "cjs"
                | "mjs"
                | "ts"
                | "mts"
                | "cts"
                | "rb"
                | "pl"
                | "go"
                | "rs"
                | "php"
                | "bat"
                | "cmd"
        )
    )
}

#[cfg(test)]
mod looks_like_script_tests {
    use super::looks_like_script;
    use std::path::PathBuf;

    /// Contract: every supported script/executable extension is recognised —
    /// including the PowerShell module (`.psm1`) and data (`.psd1`) variants
    /// and the KornShell (`.ksh`) / Fish (`.fish`) dialects.
    #[test]
    fn looks_like_script_covers_all_script_extensions() {
        for ext in [
            "sh", "bash", "zsh", "ksh", "fish", "ps1", "psm1", "psd1", "py", "js", "cjs", "mjs",
            "ts", "mts", "cts", "rb", "pl", "go", "rs", "php", "bat", "cmd",
        ] {
            let path = PathBuf::from(format!("/pkg/file.{ext}"));
            assert!(
                looks_like_script(&path),
                ".{ext} MUST be recognised as a script extension",
            );
        }
    }

    /// Contract: non-script extensions (docs, data, config) MUST NOT be
    /// classified as scripts.
    #[test]
    fn looks_like_script_rejects_non_script_extensions() {
        for ext in ["md", "txt", "json", "yaml", "toml", "xml", "csv"] {
            let path = PathBuf::from(format!("/pkg/file.{ext}"));
            assert!(
                !looks_like_script(&path),
                ".{ext} must NOT be classified as a script extension",
            );
        }
    }
}
