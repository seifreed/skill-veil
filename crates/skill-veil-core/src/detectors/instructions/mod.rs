//! Document-level instruction detectors that need section/code-block
//! awareness.
//!
//! `intent_policy` hosts the cross-section "remote instruction download"
//! detector; `signals` exposes the lazy patterns used by
//! orchestration in `services::artifact_orchestration::instructions` for
//! persistence, network, secret, OAuth, browser, and privileged-role
//! prompts.

pub(crate) mod intent_policy;
pub(crate) mod signals;
