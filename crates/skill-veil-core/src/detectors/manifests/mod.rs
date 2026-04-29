//! Manifest detectors: per-language and per-runtime analyses for
//! `package.json`, `pyproject.toml`, `Dockerfile`, `docker-compose.yml`,
//! `.npmrc`, `pip.conf`, `Makefile`, `Cargo.toml`, etc.
//!
//! Orchestration in `services::artifact_analysis::manifests` dispatches
//! against these detectors based on artifact name; each detector owns
//! the rule-id / severity / capability mapping for its manifest kind.

pub(crate) mod build;
pub(crate) mod container;
pub(crate) mod javascript;
pub(crate) mod python;
pub(crate) mod rust_cargo;
