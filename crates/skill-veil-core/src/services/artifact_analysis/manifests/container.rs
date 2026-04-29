//! Container manifest analysis split into single-responsibility submodules:
//!
//! - [`dockerfile`] — `Dockerfile` finding emission, capability inference,
//!   and artifact relations (`Loads`, `Downloads`).
//! - [`compose`] — `docker-compose.yml` analyses (per-service findings,
//!   capabilities, relations).
//! - [`volumes`] — pure classifiers shared by `compose`: which volume
//!   shapes count as sensitive host mounts, which `env_file` shapes carry
//!   real paths, and how to render an `env_file` value for audit output.
//!
//! The crate-level entry points (`analyze_dockerfile`, `analyze_docker_compose`,
//! the capability/relations helpers) are re-exported below so existing
//! callers keep their import paths.

mod compose;
mod dockerfile;
mod volumes;

pub(crate) use compose::{
    analyze_docker_compose, docker_compose_capabilities, docker_compose_relations,
};
pub(crate) use dockerfile::{analyze_dockerfile, dockerfile_capabilities, dockerfile_relations};
