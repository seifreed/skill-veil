//! Display caps for the human-readable text output.
//!
//! Every textual list emitted by `format_text_output` is truncated to
//! one of these constants so the CLI output stays scannable on a
//! standard terminal. Centralising the values keeps the contract
//! explicit: changing how many verdict reasons or top factors are shown
//! is a single edit, not a hunt across the formatter for stray
//! `.take(3)` / `.take(5)` literals.

/// Top-N verdict reasons surfaced before "..." truncation.
pub(super) const MAX_DISPLAY_VERDICT_REASONS: usize = 3;

/// Top-N root-cause groups summarised under "Why".
pub(super) const MAX_DISPLAY_ROOT_CAUSE_GROUPS: usize = 3;

/// Top-N network targets listed inline under "Network targets".
pub(super) const MAX_DISPLAY_NETWORK_TARGETS: usize = 3;

/// Top-N score factors shown in the global summary.
pub(super) const MAX_DISPLAY_TOP_FACTORS: usize = 5;

/// Top-N policy escalation triggers shown in the global summary.
pub(super) const MAX_DISPLAY_POLICY_TRIGGERS: usize = 5;
