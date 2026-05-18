//! Document-level instruction detectors that need section/code-block
//! awareness.
//!
//! `intent_policy` hosts the cross-section "remote instruction download"
//! detector; `composite` is the k-of-n composite-family framework;
//! `dropper_delivery` hosts the fake-dependency / paste-site
//! social-engineering dropper family; `signals` exposes the lazy
//! patterns used by orchestration in
//! `services::artifact_orchestration::instructions` for persistence,
//! network, secret, OAuth, browser, and privileged-role prompts.

pub(crate) mod composite;
pub(crate) mod composite_families;
pub(crate) mod dropper_delivery;
pub(crate) mod intent_policy;
pub(crate) mod signals;
