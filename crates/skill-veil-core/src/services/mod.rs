//! Service layer for skill-veil operations
//!
//! This module provides focused services that follow the Single Responsibility Principle:
//! - `ArtifactOrchestratorService`: Dispatches detectors over manifests and referenced artifacts
//! - `FileDiscoveryService`: Discovers skill files in directories
//! - `ScanFilterService`: Applies filters to scan findings

pub(crate) mod artifact_orchestration;
pub(crate) mod file_discovery;
mod scan_filter;

pub(crate) use artifact_orchestration::dispatch::{
    DOCKER_COMPOSE_NAMES, INSTRUCTION_NAMES, MCP_NAMES, TOML_ARTIFACT_NAMES,
};
pub use artifact_orchestration::ArtifactOrchestratorService;
pub use file_discovery::{is_explicit_skill_file, FileDiscoveryService};
pub use scan_filter::ScanFilterService;
