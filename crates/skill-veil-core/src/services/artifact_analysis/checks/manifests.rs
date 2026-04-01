use super::super::ArtifactAnalysisService;
use crate::analysis_model::ObservationBatch;
use std::path::{Path, PathBuf};

pub(crate) fn observe_package_json(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_package_json(path, content, sibling_files),
        "package_json",
    )
}

pub(crate) fn observe_requirements_txt(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_requirements_txt(path, content, &[]),
        "requirements_txt",
    )
}

pub(crate) fn observe_dockerfile(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_dockerfile(path, content),
        "dockerfile",
    )
}

pub(crate) fn observe_pyproject_toml(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_pyproject_toml(path, content, sibling_files),
        "pyproject_toml",
    )
}

pub(crate) fn observe_cargo_toml(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_cargo_toml(path, content, sibling_files),
        "cargo_toml",
    )
}

pub(crate) fn observe_gemfile(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_gemfile(path, content, sibling_files),
        "gemfile",
    )
}

pub(crate) fn observe_go_mod(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_go_mod(path, content, sibling_files),
        "go_mod",
    )
}

pub(crate) fn observe_composer_json(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_composer_json(path, content, sibling_files),
        "composer_json",
    )
}
