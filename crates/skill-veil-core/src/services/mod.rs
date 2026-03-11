//! Service layer for skill-veil operations
//!
//! This module provides focused services that follow the Single Responsibility Principle:
//! - `ArtifactAnalysisService`: Analyzes manifests and referenced artifacts
//! - `FileDiscoveryService`: Discovers skill files in directories
//! - `ScanFilterService`: Applies filters to scan findings

mod artifact_analysis;
mod file_discovery;
mod scan_filter;

pub use artifact_analysis::ArtifactAnalysisService;
pub use file_discovery::FileDiscoveryService;
pub use scan_filter::ScanFilterService;
