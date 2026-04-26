use crate::analyzer::SkillDocument;
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{
    deduplicate_findings, derive_package_verdict, ArtifactKind, Finding, FindingSummary,
    MatchTarget,
};
use crate::policy::{
    AppliedPolicyOverride, PolicyAudit, SuppressionSummary, POLICY_AUDIT_PRECEDENCE,
};
use crate::ports::{FileSystemProvider, MarkdownParser};
use crate::scanner::{ScanError, ScanResult, Scanner};
use crate::scanner_support::{
    artifact_parse_error_finding, decode_warning_finding, parse_warning_finding,
    read_text_file_lossy, structured_parse_warning,
};
use crate::services::file_discovery::{
    discover_lockfiles, discover_package_manifests, FileDiscoveryService,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(crate) fn scan_supporting_artifacts<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    doc: &SkillDocument,
) -> Vec<Finding> {
    let fs = scanner.file_discovery().fs_provider();
    let mut findings = Vec::new();

    let supporting_artifacts = collect_supporting_artifact_paths(scanner, doc);

    for referenced_file in &supporting_artifacts {
        // Existence is checked through the same `FileSystemProvider` that
        // performs the subsequent `from_file_with_provider` read. Using
        // `PathBuf::exists` here would consult `std::fs` directly, opening
        // a TOCTOU window between the check and the read AND letting test
        // doubles disagree with production behaviour (a `MockFileSystemProvider`
        // can report a path as missing while `std::fs::exists` says yes,
        // or vice versa). The `is_dir` check stays on `std::fs` because
        // the port intentionally exposes only file-bytes / metadata; a
        // directory passed here would surface as a read error from the
        // provider and become an `artifact_parse_error_finding`, but
        // skipping it explicitly keeps the noise floor low.
        if !fs.exists(referenced_file) || referenced_file.is_dir() {
            continue;
        }

        let artifact_kind = crate::scanner_graph::artifact_kind_for_path::<F>(referenced_file);
        let artifact_path = referenced_file.display().to_string();

        let artifact_doc =
            match SkillDocument::from_file_with_provider(referenced_file, scanner.parser(), fs) {
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
                        .with_artifact(artifact_kind, artifact_path.as_str())
                }),
        );

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
        let sibling_files = crate::scanner_graph::sibling_files(fs, referenced_file);
        findings.extend(
            scanner
                .artifact_analysis()
                .analyze(referenced_file, &content, &sibling_files)
                .into_iter()
                .map(|f| {
                    if f.artifact_path.is_some() {
                        f
                    } else {
                        f.with_artifact(artifact_kind, artifact_path.as_str())
                    }
                }),
        );
    }

    findings
}

/// Build the list of supporting-artifact paths to evaluate for a skill document.
///
/// Includes every path extracted from the markdown (`doc.referenced_files`) plus,
/// when the document is an explicit skill entrypoint, any co-located scripts
/// and data-bearing files under the package root. The latter catches payloads
/// that malicious skills reference via absolute-looking paths (e.g.
/// `~/.openclaw/skills/.../x.sh`) or hide inside config / `.txt` blobs that
/// the markdown never mentions at all.
fn collect_supporting_artifact_paths<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    doc: &SkillDocument,
) -> Vec<PathBuf> {
    let mut artifacts = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    for referenced in &doc.referenced_files {
        if seen.insert(referenced.clone()) {
            artifacts.push(referenced.clone());
        }
    }

    if !FileDiscoveryService::<F>::is_explicit_skill_file(&doc.path) {
        return artifacts;
    }
    let Some(package_root) = doc.path.parent() else {
        return artifacts;
    };
    let discovery = scanner.file_discovery();
    for discovered in discovery.discover_package_scripts(package_root) {
        if discovered == doc.path {
            continue;
        }
        if seen.insert(discovered.clone()) {
            artifacts.push(discovered);
        }
    }
    for discovered in discovery.discover_package_data_files(package_root) {
        if discovered == doc.path {
            continue;
        }
        if seen.insert(discovered.clone()) {
            artifacts.push(discovered);
        }
    }
    artifacts
}

pub(crate) fn scan_document_path<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    path: &Path,
) -> Result<ScanResult, ScanError> {
    let doc = SkillDocument::from_file_with_provider(
        path,
        scanner.parser(),
        scanner.file_discovery().fs_provider(),
    )?;
    let artifact_kind = crate::scanner_graph::artifact_kind_for_path::<F>(path);
    let artifact_path = path.display().to_string();
    let primary_content = doc.raw_content.clone();

    let (raw_findings, artifact_graph) = collect_raw_findings(
        scanner,
        &doc,
        path,
        artifact_kind,
        &artifact_path,
        &primary_content,
    );
    // Apply inline suppressions BEFORE deduplication. The dedup pass merges
    // findings on `(rule_id, category, matched_on, match_value, kind, scope,
    // path)` and only preserves the first non-`None` `line_number` it sees.
    // If two emissions of the same rule reach scan_document_path with
    // different line numbers (one carrying a `// skill-veil:disable` comment
    // line, another path-less from artifact-graph taint), running suppressions
    // afterwards would let the merged finding survive when its representative
    // line happens to be the non-suppressed copy. Suppressing first ensures
    // each emission is matched against its own original line number.
    let (raw_findings, suppressed_findings) =
        collect_and_apply_suppressions(scanner, raw_findings, path, &doc, &primary_content);
    let (findings, deduplication_summary) = deduplicate_findings(raw_findings);
    let inline_suppressed = suppressed_findings.len();

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
    let extracted_iocs = collect_extracted_iocs(scanner, &doc, path, &primary_content);

    Ok(ScanResult {
        metadata: crate::scanner_types::ArtifactMetadata {
            path: path.to_path_buf(),
            name: doc.name,
            extension_kind: doc.extension_kind,
            classification: doc.classification,
            package_id: crate::scanner_graph::derive_package_id(path),
            identity_source: doc.identity_source,
            structural_validity: doc.structural_validity,
            heuristic_score: doc.structural_signals.score,
            primary_artifact_kind: artifact_kind,
        },
        findings: filtered_findings,
        suppressed_findings,
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
        suppression_summary: build_suppression_summary(
            inline_suppressed,
            filter_outcome.suppression_summary,
        ),
        policy_audit: build_policy_audit(scanner, filter_outcome.applied_overrides),
        should_fail,
        extracted_iocs,
    })
}

/// Collect IOCs from the primary document and every supporting artifact. Runs
/// offline (no network) and feeds downstream enrichment tooling.
fn collect_extracted_iocs<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    doc: &SkillDocument,
    primary_path: &Path,
    primary_content: &str,
) -> crate::ioc_extraction::ExtractedIocs {
    let mut iocs =
        crate::ioc_extraction::extract_from_artifact(primary_path, primary_content.as_bytes());

    let supporting = collect_supporting_artifact_paths(scanner, doc);
    let fs = scanner.file_discovery().fs_provider();
    for path in supporting {
        if let Ok(file) = fs.read_file_bytes(&path) {
            let bytes = file.as_bytes();
            iocs.merge(crate::ioc_extraction::extract_from_artifact(&path, bytes));
        }
    }
    iocs
}

fn collect_raw_findings<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    doc: &SkillDocument,
    path: &Path,
    artifact_kind: ArtifactKind,
    artifact_path: &str,
    primary_content: &str,
) -> (Vec<Finding>, ArtifactGraph) {
    let mut findings = scanner.engine().evaluate(doc);
    findings.extend(collect_primary_doc_warnings::<F>(doc, path));
    findings.extend(scan_supporting_artifacts(scanner, doc));
    findings.extend(deceptive_docs_findings(scanner, doc));
    if let Some(w) = structured_parse_warning(path, primary_content, artifact_kind) {
        findings.push(w);
    }
    let sibling_files =
        crate::scanner_graph::sibling_files(scanner.file_discovery().fs_provider(), path);
    findings.extend(
        scanner
            .artifact_analysis()
            .analyze(path, primary_content, &sibling_files),
    );
    let artifact_graph = scanner.build_artifact_graph(doc);
    let taint_findings = crate::artifact_taint::derive_taint_findings(&artifact_graph);
    // Preserve findings that already have artifact context (e.g., from supporting artifact
    // analysis). Only tag uncontextualized findings with the primary artifact.
    findings = contextualize_findings(findings, artifact_kind, artifact_path);
    findings.extend(taint_findings);
    (findings, artifact_graph)
}

/// Run the claim-vs-behavior detector. Reads each supporting artifact via the
/// scanner's filesystem provider; failures are silently dropped (the artifact
/// is just not contributing to deceptive-docs evaluation).
fn deceptive_docs_findings<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    doc: &SkillDocument,
) -> Vec<Finding> {
    let supporting = collect_supporting_artifact_paths(scanner, doc);
    if supporting.is_empty() {
        return Vec::new();
    }
    let fs = scanner.file_discovery().fs_provider();
    let materialised: Vec<(PathBuf, String)> = supporting
        .into_iter()
        .filter_map(|p| read_text_file_lossy(&p, fs).ok().map(|(c, _)| (p, c)))
        .collect();
    crate::deceptive_docs::detect_deceptive_documentation(doc, &materialised)
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

fn build_suppression_summary(
    inline_suppressed: usize,
    base: SuppressionSummary,
) -> SuppressionSummary {
    SuppressionSummary {
        inline_suppressed,
        ..base
    }
}

fn build_policy_audit<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    applied_overrides: Vec<AppliedPolicyOverride>,
) -> PolicyAudit {
    PolicyAudit {
        precedence_order: POLICY_AUDIT_PRECEDENCE
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        effective_fail_on: scanner.filter_service().fail_on(),
        applied_overrides,
    }
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
fn collect_and_apply_suppressions<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    findings: Vec<Finding>,
    path: &Path,
    doc: &SkillDocument,
    primary_content: &str,
) -> (Vec<Finding>, Vec<Finding>) {
    let fs = scanner.file_discovery().fs_provider();
    let supporting_artifacts = collect_supporting_artifact_paths(scanner, doc);
    let mut ref_contents: Vec<(PathBuf, String)> = Vec::new();
    for referenced_file in &supporting_artifacts {
        if let Ok((ref_content, _)) = read_text_file_lossy(referenced_file, fs) {
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

#[cfg(test)]
mod scan_supporting_artifacts_tests {
    /// Architectural contract: `scan_supporting_artifacts` MUST consult
    /// the `FileSystemProvider` port for existence, not `Path::exists`
    /// directly. Mixing the two backends opens a TOCTOU window between
    /// the existence check and the subsequent `from_file_with_provider`
    /// read, AND lets test doubles disagree with production behaviour
    /// (a `MockFileSystemProvider` can report a path as missing while
    /// `std::fs::exists` says yes, or vice versa).
    ///
    /// Mirrors the sibling contract test
    /// `file_discovery_does_not_call_std_fs_metadata_directly` in
    /// `services::file_discovery`. The `is_dir` check on `std::fs` is
    /// intentionally allowed: the port exposes only file-bytes / metadata,
    /// and a directory passed to `from_file_with_provider` already surfaces
    /// as a read error — the explicit skip just keeps the noise floor low.
    #[test]
    fn scan_supporting_artifacts_uses_fs_provider_for_existence_check() {
        let body = include_str!("scanner_execution.rs");
        let production = body.split("#[cfg(test)]").next().unwrap_or(body);
        let in_function = production
            .split("fn scan_supporting_artifacts<")
            .nth(1)
            .and_then(|after_sig| after_sig.split("\nfn ").next())
            .expect("scan_supporting_artifacts must be present in production code");
        assert!(
            !in_function.contains("referenced_file.exists()"),
            "scan_supporting_artifacts must not call Path::exists directly; \
             route existence checks through the FileSystemProvider port to \
             keep test doubles consistent with production behaviour"
        );
        assert!(
            in_function.contains("fs.exists(referenced_file)"),
            "scan_supporting_artifacts must use fs.exists(referenced_file) so \
             that mock providers and production share the same code path"
        );
    }
}
