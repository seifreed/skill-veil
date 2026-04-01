use super::super::ArtifactAnalysisService;
use crate::analysis_model::ObservationBatch;
use std::path::Path;

pub(crate) fn observe_script(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> ObservationBatch {
    ObservationBatch::from_detector_findings(service.analyze_script(path, content), "script")
}
