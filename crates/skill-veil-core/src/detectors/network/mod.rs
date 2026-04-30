//! Network-target classification + webhook receiver detection.
//!
//! `targets` produces the [`targets::NetworkTarget`] enum and
//! per-line classifiers used by orchestration in
//! `services::artifact_orchestration::instructions`.
//!
//! `webhook` recognises inbound webhook receivers shipped without
//! authentication and returns a [`webhook::WebhookExposure`] enum
//! that carries its own rule id / reason / label.
//!
//! `findings` builds the actual `Finding` structs (severity, action,
//! threat category) for the three network-shaped signals so the
//! orchestration layer stays free of domain rules.

pub(crate) mod findings;
pub(crate) mod patterns;
pub(crate) mod targets;
pub(crate) mod webhook;
