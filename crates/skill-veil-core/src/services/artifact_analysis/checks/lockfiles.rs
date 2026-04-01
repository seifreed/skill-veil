use super::super::ArtifactAnalysisService;
use crate::analysis_model::ObservationBatch;
use std::path::Path;

pub(crate) fn observe_package_lock(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_package_lock(path, content),
        "package_lock",
    )
}

pub(crate) fn observe_cargo_lock(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_cargo_lock(path, content),
        "cargo_lock",
    )
}

pub(crate) fn observe_poetry_lock(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(
        service.analyze_poetry_lock(path, content),
        "poetry_lock",
    )
}

pub(crate) fn observe_uv_lock(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(service.analyze_uv_lock(path, content), "uv_lock")
}

pub(crate) fn observe_yarn_lock(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(service.analyze_yarn_lock(path, content), "yarn_lock")
}

pub(crate) fn observe_pnpm_lock(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(service.analyze_pnpm_lock(path, content), "pnpm_lock")
}
