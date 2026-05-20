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

pub(crate) fn normalize_sha256_hex(value: &str) -> Option<String> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

/// Minimum delay between consecutive VT requests. Both the enrich and
/// download flows honor this value; we keep it conservative because the
/// VT free tier allows roughly 4 req/min and bursts past that hit 429.
/// Combined with the retry/backoff in `client.rs`, 500 ms gives margin
/// without making large scans painful.
pub(crate) const REQUEST_DELAY_MS: u64 = 500;

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    ///
    /// VT file identifiers are canonical lowercase SHA-256 values before
    /// they can be used in paths or URL segments.
    #[test]
    fn normalize_sha256_hex_accepts_and_lowercases_hex() {
        assert_eq!(normalize_sha256_hex(&"a".repeat(64)), Some("a".repeat(64)));
        assert_eq!(normalize_sha256_hex(&"A".repeat(64)), Some("a".repeat(64)));
    }

    /// # Contract
    ///
    /// Path syntax is never a valid VT file identifier.
    #[test]
    fn normalize_sha256_hex_rejects_path_syntax() {
        for bad in [
            String::new(),
            "abc".to_string(),
            "../escape".to_string(),
            "/tmp/escape".to_string(),
            "g".repeat(64),
        ] {
            assert!(normalize_sha256_hex(&bad).is_none(), "{bad:?} must reject");
        }
    }
}
