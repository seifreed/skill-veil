//! Script-level detectors decomposed by detection family.
//!
//! Each submodule owns a coherent slice of the detection surface so that
//! changes to (e.g.) the secret-exfiltration heuristic do not force the
//! reader through unrelated injection-pattern logic. The orchestrator in
//! `services::artifact_analysis::scripts::mod` composes these detectors
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

mod exec;
mod install;
mod match_helpers;
mod network;
pub(crate) mod patterns;
mod persistence;
mod secrets;

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
