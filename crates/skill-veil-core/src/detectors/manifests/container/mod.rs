//! Container manifest detectors split into single-responsibility submodules.
//!
//! - [`dockerfile`] — `Dockerfile` finding emission, capability inference,
//!   and artifact relations.
//! - [`compose`] — `docker-compose.yml` analyses (per-service findings,
//!   capabilities, relations).
//! - [`volumes`] — pure classifiers shared by `compose`: which volume
//!   shapes count as sensitive host mounts, which `env_file` shapes carry
//!   real paths, and how to render an `env_file` value for audit output.

pub(crate) mod compose;
pub(crate) mod dockerfile;
pub(crate) mod volumes;
