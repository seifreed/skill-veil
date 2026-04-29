//! Shared test helpers for the `config` submodules.
//!
//! Tests across `providers.rs`, `limits.rs`, and `resolution.rs` mutate
//! process-global env vars (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.)
//! to exercise resolution paths. `cargo test` runs them in parallel by
//! default, so unsynchronised concurrent mutation would race. A single
//! `Mutex` shared via this module keeps them serialised without forcing
//! `--test-threads=1`.

use std::sync::Mutex;

pub(super) static ENV_LOCK: Mutex<()> = Mutex::new(());
