use crate::analyzer::SkillDocument;
use crate::findings::{
    deduplicate_findings, derive_package_verdict, ArtifactKind, Finding, FindingSummary,
    MatchTarget,
};
use crate::policy::PolicyAudit;
use crate::ports::{FileSystemProvider, MarkdownParser};
use crate::scanner::{ScanError, ScanResult, Scanner};
use crate::scanner_support::{
    decode_warning_finding, parse_warning_finding, read_text_file_lossy, structured_parse_warning,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub(crate) fn scan_supporting_artifacts<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    doc: &SkillDocument,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for referenced_file in &doc.referenced_files {
        if !referenced_file.exists() || referenced_file.is_dir() {
            continue;
        }

        let Ok(artifact_doc) =
            SkillDocument::from_file_with_parser(referenced_file, &scanner.parser)
        else {
            continue;
        };

        let artifact_path = referenced_file.display().to_string();
        let artifact_kind = Scanner::<F, P>::artifact_kind_for_path(referenced_file);
        let artifact_content = read_text_file_lossy(referenced_file).ok();

        findings.extend(
            scanner
                .engine
                .evaluate(&artifact_doc)
                .into_iter()
                .map(|finding| {
                    finding
                        .with_match_target(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .with_artifact(artifact_kind, artifact_path.clone())
                }),
        );

        if let Some((content, decode_warning)) = artifact_content {
            if decode_warning {
                findings.push(decode_warning_finding(referenced_file, artifact_kind));
            }
            if let Some(parse_warning) =
                structured_parse_warning(referenced_file, &content, artifact_kind)
            {
                findings.push(parse_warning);
            }
            let sibling_files = Scanner::<F, P>::sibling_files(referenced_file);
            findings.extend(scanner.artifact_analysis.analyze(
                referenced_file,
                &content,
                &sibling_files,
            ));
        }
    }

    findings
}

pub(crate) fn scan_document_path<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    path: &Path,
) -> Result<ScanResult, ScanError> {
    let doc = SkillDocument::from_file_with_parser(path, &scanner.parser)?;
    let mut findings = scanner.engine.evaluate(&doc);
    if doc.decode_warning {
        findings.push(decode_warning_finding(
            path,
            Scanner::<F, P>::artifact_kind_for_path(path),
        ));
    }
    if doc.parse_warning {
        findings.push(parse_warning_finding(
            path,
            Scanner::<F, P>::artifact_kind_for_path(path),
            "Markdown sections could not be fully parsed; analysis continued with defensive fallback",
        ));
    }
    findings.extend(scan_supporting_artifacts(scanner, &doc));
    if let Ok((content, _decode_warning)) = read_text_file_lossy(path) {
        if let Some(parse_warning) = structured_parse_warning(
            path,
            &content,
            Scanner::<F, P>::artifact_kind_for_path(path),
        ) {
            findings.push(parse_warning);
        }
        let sibling_files = Scanner::<F, P>::sibling_files(path);
        findings.extend(
            scanner
                .artifact_analysis
                .analyze(path, &content, &sibling_files),
        );
    }
    let artifact_kind = Scanner::<F, P>::artifact_kind_for_path(path);
    let artifact_path = path.display().to_string();
    let artifact_graph = scanner.build_artifact_graph(&doc);
    let taint_findings = crate::artifact_taint::derive_taint_findings(&artifact_graph);
    let mut findings: Vec<_> = findings
        .into_iter()
        .map(|finding| match artifact_kind {
            ArtifactKind::SkillDocument => finding,
            _ => finding.with_artifact(artifact_kind, artifact_path.clone()),
        })
        .collect();
    findings.extend(taint_findings);
    let (findings, deduplication_summary) = deduplicate_findings(findings);
    let filter_outcome = scanner.filter_service.filter_with_summary(findings);
    let filtered_findings = filter_outcome.findings;
    let (primary_findings, supporting_findings) =
        ScanResult::split_findings_by_scope(path, artifact_kind, &filtered_findings);
    let summary = FindingSummary::from_findings_and_graph(&filtered_findings, &artifact_graph);
    let primary_summary = FindingSummary::from_findings(&primary_findings);
    let supporting_summary = FindingSummary::from_findings(&supporting_findings);
    let verdict_report = derive_package_verdict(
        &filtered_findings,
        &primary_summary,
        &supporting_summary,
        &summary,
    );
    let should_fail = scanner.filter_service.should_fail(&filtered_findings);

    Ok(ScanResult {
        path: path.to_path_buf(),
        name: doc.name,
        extension_kind: doc.extension_kind,
        classification: doc.classification,
        package_id: Scanner::<F, P>::derive_package_id(path),
        identity_source: doc.identity_source,
        structural_validity: doc.structural_validity,
        heuristic_score: doc.structural_signals.score,
        findings: filtered_findings,
        primary_findings,
        supporting_findings,
        summary,
        primary_summary,
        supporting_summary,
        verdict: verdict_report.verdict,
        verdict_report,
        deduplication_summary,
        artifact_graph,
        profile: scanner.filter_service.profile(),
        policy: scanner.filter_service.policy().cloned(),
        suppression_summary: filter_outcome.suppression_summary,
        policy_audit: PolicyAudit {
            effective_fail_on: scanner.filter_service.fail_on(),
            applied_overrides: filter_outcome.applied_overrides,
            ..PolicyAudit::default()
        },
        should_fail,
    })
}

pub(crate) fn discover_package_targets<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    path: &Path,
) -> Result<Vec<PathBuf>, ScanError> {
    let mut entrypoints = scanner.file_discovery.discover_skill_entrypoints(path);
    if entrypoints.is_empty() {
        entrypoints = scanner.file_discovery.discover_heuristic_candidates(path);
    }
    if entrypoints.is_empty() {
        return Err(ScanError::NoSkillEntrypoints(path.to_path_buf()));
    }

    let mut targets = BTreeSet::new();
    for entrypoint in entrypoints {
        targets.insert(entrypoint);
    }
    for manifest in discover_package_manifests(path) {
        targets.insert(manifest);
    }
    for lockfile in discover_lockfiles(path) {
        targets.insert(lockfile);
    }

    Ok(targets.into_iter().collect())
}

pub(crate) fn discover_package_manifests(path: &Path) -> Vec<PathBuf> {
    const MANIFEST_NAMES: &[&str] = &[
        "package.json",
        "mcp.json",
        "mcp.yaml",
        "mcp.yml",
        "package-lock.json",
        "requirements.txt",
        "pyproject.toml",
        "cargo.toml",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "makefile",
        ".npmrc",
        "pip.conf",
    ];

    WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let file_name = entry.file_name().to_str()?.to_ascii_lowercase();
            MANIFEST_NAMES
                .contains(&file_name.as_str())
                .then(|| entry.into_path())
        })
        .collect()
}

pub(crate) fn discover_lockfiles(path: &Path) -> Vec<PathBuf> {
    const LOCKFILE_NAMES: &[&str] = &[
        "package-lock.json",
        "cargo.lock",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
    ];

    WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let file_name = entry.file_name().to_str()?.to_ascii_lowercase();
            LOCKFILE_NAMES
                .contains(&file_name.as_str())
                .then(|| entry.into_path())
        })
        .collect()
}
