//! Local PromptIntel agent-feed cache + IOC matching against scan
//! results. Mirrors the architectural invariant established for VT
//! enrichment in `vt::enrich`: read-only enrichment that never
//! mutates the scanner's verdict, risk score, or finding set.

pub(crate) mod enrich;
pub(crate) mod store;
pub(crate) mod sync;
