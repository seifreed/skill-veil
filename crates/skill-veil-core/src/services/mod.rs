//! Service layer for skill-veil operations
//!
//! This module provides focused services that follow the Single Responsibility Principle:
//! - `ArtifactAnalysisService`: Analyzes manifests and referenced artifacts
//! - `FileDiscoveryService`: Discovers skill files in directories
//! - `ScanFilterService`: Applies filters to scan findings

mod artifact_analysis;
pub(crate) mod file_discovery;
mod scan_filter;

pub(crate) use artifact_analysis::dispatch::{
    DOCKER_COMPOSE_NAMES, INSTRUCTION_NAMES, MCP_NAMES, TOML_ARTIFACT_NAMES,
};
pub use artifact_analysis::ArtifactAnalysisService;
pub use file_discovery::FileDiscoveryService;
pub use scan_filter::ScanFilterService;
