//! PromptIntel integration for benchmark corpus management and
//! detection cross-check.
//!
//! PromptIntel (`api.promptintel.novahunting.ai`) is a curated database
//! of malicious prompts (Thomas Roccia / @fr0gger_) classified by the
//! "LLM Security Threats" taxonomy: prompt manipulation, abuse of
//! legitimate functions, suspicious patterns, abnormal outputs.
//!
//! This module is isolated from the core scanning pipeline — the
//! scanner must never depend on network access. PromptIntel is
//! development tooling: it downloads the prompt corpus, scans it with
//! the local skill-veil pipeline, and reports detection gaps so
//! curators can author new semantic / taint rules. The user explicitly
//! opted to use the upstream NOVA YARA-like rules ONLY as inspiration;
//! the project rule language stays YAML-based.

pub(crate) mod client;
pub(crate) mod config;
pub(crate) mod corpus;
pub(crate) mod coverage;
pub(crate) mod cross_check;
pub(crate) mod feed;
pub(crate) mod taxonomy;
pub(crate) mod types;
