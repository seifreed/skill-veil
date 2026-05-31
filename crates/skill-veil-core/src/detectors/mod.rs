//! Domain-rule detectors moved out of `services/artifact_orchestration/`.
//!
//! The Clean-Architecture contract pinned in this crate's CLAUDE.md says
//! `services/` is the application layer (orchestration, dispatch,
//! aggregation) and must stay free of detection rules. Concrete
//! detectors — pattern lists, severity decisions, finding builders —
//! live here under `detectors/`. The orchestrator in
//! `services::artifact_orchestration::dispatch` composes these detectors
//! into the per-artifact pipeline.
//!
//! Each submodule owns a coherent slice of the detection surface so
//! changes to one detection family do not force readers through
//! unrelated logic.

pub(crate) mod instructions;
pub(crate) mod lockfiles;
pub(crate) mod manifests;
pub(crate) mod mcp;
pub mod native_ids;
pub(crate) mod network;
pub(crate) mod patterns;
pub(crate) mod permissions;
pub(crate) mod scripts;
pub(crate) mod typosquat;
