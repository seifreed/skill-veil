//! Shared helpers for the corpus/fixture integration test binaries.

use skill_veil_core::{ScanOptions, Scanner};

/// A scanner with the standard adapters and inline suppressions disabled —
/// the configuration every corpus/fixture integration test runs under.
pub fn corpus_scanner() -> Scanner {
    Scanner::with_std_adapters(ScanOptions {
        honor_inline_suppressions: false,
        ..Default::default()
    })
    .unwrap()
}
