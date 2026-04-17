use crate::analyzer::SkillDocument;
use crate::findings::{
    deduplicate_findings, derive_package_verdict, Finding, FindingSummary, MatchTarget,
};
use crate::policy::PolicyAudit;
use crate::ports::{FileSystemProvider, MarkdownParser};
use crate::scanner::{ScanError, ScanResult, Scanner};
use crate::scanner_support::{
    artifact_parse_error_finding, decode_warning_finding, parse_warning_finding,
    read_text_file_lossy, structured_parse_warning,
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

        let artifact_kind = crate::scanner_graph::artifact_kind_for_path::<F>(referenced_file);
        let artifact_path = referenced_file.display().to_string();

        let artifact_doc =
            match SkillDocument::from_file_with_parser(referenced_file, scanner.parser()) {
                Ok(doc) => doc,
                Err(err) => {
                    findings.push(artifact_parse_error_finding(
                        referenced_file,
                        artifact_kind,
                        &err.to_string(),
                    ));
                    continue;
                }
            };
        findings.extend(
            scanner
                .engine()
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

        {
            let content = artifact_doc.raw_content;
            let decode_warning = artifact_doc.decode_warning;
            if decode_warning {
                findings.push(decode_warning_finding(referenced_file, artifact_kind));
            }
            if let Some(parse_warning) =
                structured_parse_warning(referenced_file, &content, artifact_kind)
            {
                findings.push(parse_warning);
            }
            let sibling_files = crate::scanner_graph::sibling_files(
                scanner.file_discovery().fs_provider(),
                referenced_file,
            );
            findings.extend(
                scanner
                    .artifact_analysis()
                    .analyze(referenced_file, &content, &sibling_files)
                    .into_iter()
                    .map(|f| {
                        if f.artifact_path.is_some() {
                            f
                        } else {
                            f.with_artifact(artifact_kind, artifact_path.clone())
                        }
                    }),
            );
        }
    }

    findings
}

pub(crate) fn scan_document_path<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    path: &Path,
) -> Result<ScanResult, ScanError> {
    let doc = SkillDocument::from_file_with_parser(path, scanner.parser())?;
    let artifact_kind = crate::scanner_graph::artifact_kind_for_path::<F>(path);
    let artifact_path = path.display().to_string();
    let primary_content = doc.raw_content.clone();

    let mut findings = scanner.engine().evaluate(&doc);
    findings.extend(collect_primary_doc_warnings::<F>(&doc, path));
    findings.extend(scan_supporting_artifacts(scanner, &doc));
    if let Some(w) = structured_parse_warning(path, &primary_content, artifact_kind) {
        findings.push(w);
    }
    let sibling_files =
        crate::scanner_graph::sibling_files(scanner.file_discovery().fs_provider(), path);
    findings.extend(
        scanner
            .artifact_analysis()
            .analyze(path, &primary_content, &sibling_files),
    );

    let artifact_graph = scanner.build_artifact_graph(&doc);
    let taint_findings = crate::artifact_taint::derive_taint_findings(&artifact_graph);
    // Preserve findings that already have artifact context (e.g., from supporting artifact
    // analysis). Only tag uncontextualized findings with the primary artifact.
    let mut findings = contextualize_findings(findings, artifact_kind, &artifact_path);
    findings.extend(taint_findings);
    let (findings, deduplication_summary) = deduplicate_findings(findings);

    let (findings, inline_suppressed) =
        collect_and_apply_suppressions(findings, path, &doc, &primary_content);

    let filter_outcome = scanner.filter_service().filter_with_summary(findings);
    let filtered_findings = filter_outcome.findings;
    let (primary_findings, supporting_findings) =
        ScanResult::split_findings_by_scope(path, artifact_kind, &filtered_findings);
    let summary = FindingSummary::from_findings_and_graph(&filtered_findings, &artifact_graph);
    // Scope-specific summaries use finding-only scoring (no graph capabilities)
    // so that primary_summary.risk_score reflects only primary-artifact risk,
    // not capabilities from supporting artifacts (and vice versa).
    let primary_summary = FindingSummary::from_findings(&primary_findings);
    let supporting_summary = FindingSummary::from_findings(&supporting_findings);
    let verdict_report = derive_package_verdict(
        &filtered_findings,
        &primary_summary,
        &supporting_summary,
        &summary,
    );
    let should_fail = scanner.filter_service().should_fail(&filtered_findings);

    Ok(ScanResult {
        path: path.to_path_buf(),
        name: doc.name,
        extension_kind: doc.extension_kind,
        classification: doc.classification,
        package_id: crate::scanner_graph::derive_package_id(path),
        identity_source: doc.identity_source,
        structural_validity: doc.structural_validity,
        heuristic_score: doc.structural_signals.score,
        primary_artifact_kind: artifact_kind,
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
        profile: scanner.filter_service().profile(),
        policy: scanner.filter_service().policy().cloned(),
        suppression_summary: crate::policy::SuppressionSummary {
            inline_suppressed,
            ..filter_outcome.suppression_summary
        },
        policy_audit: PolicyAudit {
            precedence_order: vec![
                "inline_suppressions".to_string(),
                "waivers".to_string(),
                "baseline".to_string(),
                "policy_overrides".to_string(),
            ],
            effective_fail_on: scanner.filter_service().fail_on(),
            applied_overrides: filter_outcome.applied_overrides,
        },
        should_fail,
    })
}

fn collect_primary_doc_warnings<F: FileSystemProvider>(
    doc: &SkillDocument,
    path: &Path,
) -> Vec<Finding> {
    let artifact_kind = crate::scanner_graph::artifact_kind_for_path::<F>(path);
    let mut warnings = Vec::new();
    if doc.decode_warning {
        warnings.push(decode_warning_finding(path, artifact_kind));
    }
    if doc.parse_warning {
        warnings.push(parse_warning_finding(
            path,
            artifact_kind,
            "Markdown sections could not be fully parsed; analysis continued with defensive fallback",
        ));
    }
    warnings
}

fn contextualize_findings(
    findings: Vec<Finding>,
    artifact_kind: crate::ArtifactKind,
    artifact_path: &str,
) -> Vec<Finding> {
    findings
        .into_iter()
        .map(|f| {
            if f.artifact_path.is_some() {
                f
            } else {
                f.with_artifact(artifact_kind, artifact_path.to_string())
            }
        })
        .collect()
}

/// Collect inline suppression sources from the primary document and its referenced
/// files, then apply suppressions to the deduplicated findings.
fn collect_and_apply_suppressions(
    findings: Vec<Finding>,
    path: &Path,
    doc: &SkillDocument,
    primary_content: &str,
) -> (Vec<Finding>, usize) {
    let mut ref_contents: Vec<(PathBuf, String)> = Vec::new();
    for referenced_file in &doc.referenced_files {
        if let Ok((ref_content, _)) = read_text_file_lossy(referenced_file) {
            ref_contents.push((referenced_file.clone(), ref_content));
        }
    }
    let mut suppression_sources: Vec<(&Path, &str)> = Vec::with_capacity(1 + ref_contents.len());
    suppression_sources.push((path, primary_content));
    for (ref_path, ref_content) in &ref_contents {
        suppression_sources.push((ref_path.as_path(), ref_content.as_str()));
    }
    let inline_suppressions =
        crate::inline_suppressions::collect_inline_suppressions(&suppression_sources);
    let primary_path_str = path.display().to_string();
    crate::inline_suppressions::apply_inline_suppressions(
        findings,
        &inline_suppressions,
        Some(&primary_path_str),
    )
}

pub(crate) fn discover_package_targets<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    path: &Path,
) -> Result<Vec<PathBuf>, ScanError> {
    let mut entrypoints = scanner.file_discovery().discover_skill_entrypoints(path);
    if entrypoints.is_empty() {
        entrypoints = scanner.file_discovery().discover_heuristic_candidates(path);
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

/// Walk `root` and collect files whose lowercased name matches any entry in `names`.
fn discover_files_by_name(root: &Path, names: &[&str]) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| !should_skip_discovery_dir(root, entry))
        .filter_map(|e| match e {
            Ok(entry) => Some(entry),
            Err(err) => {
                tracing::warn!(
                    "Skipping entry during package discovery in {}: {err}",
                    root.display()
                );
                None
            }
        })
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let file_name = entry.file_name().to_str()?.to_ascii_lowercase();
            names
                .contains(&file_name.as_str())
                .then(|| entry.into_path())
        })
        .collect()
}

pub(crate) fn discover_package_manifests(path: &Path) -> Vec<PathBuf> {
    const MANIFEST_NAMES: &[&str] = &[
        "package.json",
        "mcp.json",
        "mcp.yaml",
        "mcp.yml",
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
    discover_files_by_name(path, MANIFEST_NAMES)
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
    discover_files_by_name(path, LOCKFILE_NAMES)
}

fn should_skip_discovery_dir(_root: &Path, entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    entry.file_name().to_str().is_some_and(|name| {
        matches!(
            name,
            "node_modules"
                | "vendor"
                | ".git"
                | "dist"
                | "build"
                | "target"
                | ".venv"
                | "venv"
                | "__pycache__"
                | ".yarn"
                | ".pnpm-store"
                | ".next"
                | ".turbo"
                | "coverage"
        )
    })
}
