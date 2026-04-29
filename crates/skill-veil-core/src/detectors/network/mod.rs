//! Network-target classification + webhook receiver detection.
//!
//! `targets` produces the [`targets::NetworkTarget`] enum and
//! per-line classifiers used by orchestration in
//! `services::artifact_analysis::instructions`.
//!
//! `webhook` recognises inbound webhook receivers shipped without
//! authentication and returns a [`webhook::WebhookExposure`] enum
//! that carries its own rule id / reason / label.

pub(crate) mod patterns;
pub(crate) mod targets;
pub(crate) mod webhook;
