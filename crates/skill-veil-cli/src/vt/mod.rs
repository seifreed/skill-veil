//! VirusTotal integration for corpus management and detection validation.
//!
//! This module is isolated from the core scanning pipeline: the scanner must
//! never depend on network access. `vt` is development tooling — it downloads
//! VT-flagged skill packages, fetches their `codeinsight` verdicts, and
//! cross-checks skill-veil's own verdict against VT's to surface detection
//! gaps.

pub(crate) mod client;
pub(crate) mod config;
pub(crate) mod cross_check;
pub(crate) mod download;
pub(crate) mod enrich;
pub(crate) mod types;

/// Minimum delay between consecutive VT requests. Both the enrich and
/// download flows honor this value; we keep it conservative because the
/// VT free tier allows roughly 4 req/min and bursts past that hit 429.
/// Combined with the retry/backoff in `client.rs`, 500 ms gives margin
/// without making large scans painful.
pub(crate) const REQUEST_DELAY_MS: u64 = 500;
