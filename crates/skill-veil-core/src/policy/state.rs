//! Policy / waiver / baseline runtime state.
//!
//! This module is split into thin, single-responsibility submodules:
//!
//! - `loaders` — file I/O for policy/baseline/waiver YAML/JSON, routed
//!   through the [`FileSystemProvider`](crate::ports::FileSystemProvider)
//!   port so the domain layer never reaches `std::fs` directly.
//! - `validators` — schema-version + invariant checks invoked at load
//!   time; matched-only-when-loaded so the matching pipeline never sees
//!   unsafe state.
//! - `apply` — runtime application of loaded state against
//!   `Vec<Finding>` (baseline removal, waiver removal, policy override
//!   action substitution + audit trail).
//! - `diff` — report-to-report comparison, classifying findings as new,
//!   resolved, waived, baselined, or unchanged.
//! - `matchers` — pure predicates shared by `apply` and `diff` for
//!   waiver / policy-override / context / specificity matching.

mod apply;
mod diff;
mod loaders;
mod matchers;
mod validators;

pub use apply::{
    apply_baseline, apply_policy_overrides, apply_policy_overrides_with_audit, apply_waivers,
    baseline_from_reports, count_baseline_matches,
};
pub use diff::{diff_reports, diff_reports_with_policy_state};
pub use loaders::{load_baseline, load_policy, load_waivers};
pub use validators::{validate_policy, validate_waivers};
