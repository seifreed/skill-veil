//! Canonical scanner pipeline. Per-document orchestration that other
//! modules rely on to preserve their guarantees.
//!
//! # Pipeline ordering (load-bearing)
//!
//! `scan_document_path` and the package-level entrypoints execute these
//! stages in this exact order:
//!
//! 1. Parse markdown → evaluate rules → scan supporting artifacts.
//! 2. Run artifact analysis on every artifact reachable from the entry.
//! 3. Derive taint findings from the artifact graph.
//! 4. **Apply inline suppressions** (`# skill-veil:ignore` markers).
//! 5. **Deduplicate** findings (`findings::deduplicate_findings`).
//! 6. **Apply policy filters** (baseline, waivers, overrides).
//! 7. Build the verdict (`PackageAssessmentPipeline`).
//! 8. Compute the CI gating signal (`should_fail`).
//!
//! # Ordering guarantees
//!
//! Each ordered pair below is load-bearing: reordering changes a guarantee
//! that other modules pin via regression tests. When you touch this file,
//! update the table and re-run
//! `cargo test -p skill-veil-core labeled_corpus_meets_phase1_baseline`
//! to confirm the corpus precision/recall stays within bounds.
//!
//! | Pair                  | Order                       | Why                                                                                                                                                                                                                                                                                                                                              | Pinned by                                                       |
//! |-----------------------|-----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
//! | suppressions ↔ dedup  | suppressions BEFORE dedup   | Dedup merges on `(rule_id, category, matched_on, match_value, kind, scope, path)` and keeps the first non-`None` `line_number` it sees. If two emissions of the same rule arrive with different lines (one carrying a `// skill-veil:disable` source line, another path-less from artifact-graph taint), suppressing AFTER dedup would let the merged finding survive when its representative line is the non-suppressed copy. Suppressing first matches each emission against its own original line. | inline rationale at `scan_document_path` (see body of this file) |
//! | dedup ↔ policy        | dedup BEFORE policy         | Baselines and waivers fingerprint findings on the canonical (post-dedup) view. Filtering against the un-deduplicated stream lets repeated emissions bypass a single baseline entry.                                                                                                                                                              | `baseline_matches_finding_does_not_apply_paths_match_suffix`    |
//! | policy ↔ verdict      | policy BEFORE verdict       | Calibration must see exactly the findings the user will see, so waived / overridden findings do not escalate severity in the verdict.                                                                                                                                                                                                            | `labeled_corpus_meets_phase1_baseline`                          |

use crate::analyzer::SkillDocument;
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{
    deduplicate_findings, ArtifactKind, Finding, FindingSummary, MatchTarget, PackageVerdictReport,
};
use crate::policy::{
    AppliedPolicyOverride, PolicyAudit, SuppressionSummary, POLICY_AUDIT_PRECEDENCE,
};
use crate::ports::{FileSystemProvider, MarkdownParser};
use crate::scanner::{ScanError, ScanResult, Scanner};
use crate::scanner_support::{
    artifact_parse_error_finding, binary_disguise_finding, decode_warning_finding,
    parse_warning_finding, read_text_file_lossy, structured_parse_warning,
};
use crate::services::file_discovery::FileDiscoveryService;
use crate::verdict::derive_package_verdict;
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
        findings.extend(analyze_referenced_artifact(scanner, referenced_file));
    }

    findings
}

/// Per-artifact analysis: parse the file, then run binary-disguise checks,
/// engine rule evaluation, decode/parse warnings, and artifact-orchestration
/// detectors. Each finding is contextualised with the artifact's kind and
/// path. A parse failure surfaces as a single `artifact_parse_error_finding`.
fn analyze_referenced_artifact<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    referenced_file: &Path,
) -> Vec<Finding> {
    let fs = scanner.file_discovery().fs_provider();
    let artifact_kind = crate::scanner_graph::artifact_kind_for_path::<F>(referenced_file);
    let artifact_path = referenced_file.display().to_string();

    let artifact_doc =
        match SkillDocument::from_file_with_provider(referenced_file, scanner.parser(), fs) {
            Ok(doc) => doc,
            Err(err) => {
                return vec![artifact_parse_error_finding(
                    referenced_file,
                    artifact_kind,
                    &err.to_string(),
                )];
            }
        };

    let mut findings = Vec::new();
    if let Some(kind) = artifact_doc.binary_disguise_kind.as_deref() {
        findings.push(binary_disguise_finding(
            referenced_file,
            kind,
            artifact_kind,
            MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            },
        ));
    }
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
    if artifact_doc.decode_warning {
        findings.push(decode_warning_finding(referenced_file, artifact_kind));
    }
    if let Some(parse_warning) =
        structured_parse_warning(referenced_file, &artifact_doc.raw_content, artifact_kind)
    {
        findings.push(parse_warning);
    }
    let sibling_files = crate::scanner_graph::sibling_files(fs, referenced_file);
    let orchestrator_findings = scanner.artifact_orchestration().analyze(
        referenced_file,
        &artifact_doc.raw_content,
        &sibling_files,
        Some(&artifact_doc),
    );
    findings.extend(contextualize_findings(
        orchestrator_findings,
        artifact_kind,
        artifact_path.as_str(),
    ));
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
    let (raw_findings, suppressed_findings) =
        collect_and_apply_suppressions(scanner, raw_findings, path, &doc, &primary_content);
    let (findings, deduplication_summary) = deduplicate_findings(raw_findings);
    let inline_suppressed = suppressed_findings.len();

    let filter_outcome = scanner.filter_service().filter_with_summary(findings);
    let filtered_findings = filter_outcome.findings;
    let (
        primary_findings,
        supporting_findings,
        summary,
        primary_summary,
        supporting_summary,
        verdict_report,
    ) = build_verdict_and_summaries(&filtered_findings, &artifact_graph, path, artifact_kind);
    let should_fail = scanner.filter_service().should_fail(&filtered_findings);
    let extracted_iocs = collect_extracted_iocs(scanner, &doc, path, &primary_content);

    let metadata = build_artifact_metadata(path, &doc, artifact_kind);
    Ok(ScanResult {
        metadata,
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

/// Snapshot the document-level metadata that the `ScanResult` carries
/// alongside findings. Pure data marshaling; clones owned strings so the
/// caller can keep using `doc` for downstream IOC extraction.
fn build_artifact_metadata(
    path: &Path,
    doc: &SkillDocument,
    artifact_kind: ArtifactKind,
) -> crate::scanner_types::ArtifactMetadata {
    crate::scanner_types::ArtifactMetadata {
        path: path.to_path_buf(),
        name: doc.name.clone(),
        extension_kind: doc.extension_kind,
        classification: doc.classification,
        package_id: crate::scanner_graph::derive_package_id(path),
        identity_source: doc.identity_source,
        structural_validity: doc.structural_validity,
        heuristic_score: doc.structural_signals.score,
        primary_artifact_kind: artifact_kind,
    }
}

/// Compute the package-wide finding summary, the per-scope summaries, and the
/// verdict report from the post-policy findings + artifact graph.
///
/// Scope-specific summaries use finding-only scoring (no graph capabilities)
/// so that `primary_summary.risk_score` reflects only primary-artifact risk,
/// not capabilities from supporting artifacts (and vice versa).
fn build_verdict_and_summaries(
    filtered_findings: &[Finding],
    artifact_graph: &ArtifactGraph,
    path: &Path,
    artifact_kind: ArtifactKind,
) -> (
    Vec<Finding>,
    Vec<Finding>,
    FindingSummary,
    FindingSummary,
    FindingSummary,
    PackageVerdictReport,
) {
    let (primary_findings, supporting_findings) =
        ScanResult::split_findings_by_scope(path, artifact_kind, filtered_findings);
    let summary = FindingSummary::from_findings_and_graph(filtered_findings, artifact_graph);
    let primary_summary = FindingSummary::from_findings(&primary_findings);
    let supporting_summary = FindingSummary::from_findings(&supporting_findings);
    let verdict_report = derive_package_verdict(
        filtered_findings,
        &primary_summary,
        &supporting_summary,
        &summary,
    );
    (
        primary_findings,
        supporting_findings,
        summary,
        primary_summary,
        supporting_summary,
        verdict_report,
    )
}

/// Collect IOCs from the primary document and every supporting artifact. Runs
/// offline (no network) and feeds downstream enrichment tooling.
///
/// # Hash-fidelity contract
///
/// The primary artifact MUST be hashed over its raw on-disk bytes, NOT
/// over the lossy-decoded UTF-8 string in `doc.raw_content`. The lossy
/// decode replaces every invalid byte with U+FFFD (`0xEF 0xBF 0xBD` in
/// UTF-8), so a binary-disguised skill (ZIP/PE/ELF embedded in `.md`)
/// would otherwise hash to a digest that disagrees with `sha256sum` on
/// disk and breaks VT cross-check exactly when it matters most. The
/// fix re-reads the raw bytes through the `FileSystemProvider` port so
/// the SHA-256 in `ExtractedIocs.file_hashes` round-trips with stock
/// hashing tools.
fn collect_extracted_iocs<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    doc: &SkillDocument,
    primary_path: &Path,
    primary_content: &str,
) -> crate::ioc_extraction::ExtractedIocs {
    let fs = scanner.file_discovery().fs_provider();
    // IOC extraction has two output groups:
    //  - URL/IP/domain tokens, which can come from the lossy-decoded
    //    string without changing the result (they're ASCII-only).
    //  - File hashes, which MUST be computed over the on-disk bytes.
    // We re-read the primary file once: the cost is one extra
    // `read_file_bytes` per scan and the digest is correct.
    let primary_bytes = match fs.read_file_bytes(primary_path) {
        Ok(file) => file.as_bytes().to_vec(),
        Err(err) => {
            tracing::warn!(
                path = %primary_path.display(),
                error = %err,
                "IOC extraction: failed to re-read primary artifact for SHA-256; \
                 falling back to lossy-decoded content (digest may not match sha256sum)"
            );
            primary_content.as_bytes().to_vec()
        }
    };
    let mut iocs = crate::ioc_extraction::extract_from_artifact(primary_path, &primary_bytes);

    let supporting = collect_supporting_artifact_paths(scanner, doc);
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
    findings.extend(scanner.artifact_orchestration().analyze(
        path,
        primary_content,
        &sibling_files,
        Some(doc),
    ));
    let artifact_graph = scanner.build_artifact_graph(doc);
    let taint_findings = crate::artifact_taint::derive_taint_findings(&artifact_graph);
    // Preserve findings that already have artifact context (e.g., from supporting artifact
    // analysis). Only tag uncontextualized findings with the primary artifact.
    findings = contextualize_findings(findings, artifact_kind, artifact_path);
    findings.extend(taint_findings);
    (findings, artifact_graph)
}

/// Run the claim-vs-behavior detector. Reads each supporting artifact via the
/// scanner's filesystem provider; I/O errors are logged and the artifact is
/// excluded from deceptive-docs evaluation (but not silently swallowed).
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
        .filter_map(|p| match read_text_file_lossy(&p, fs) {
            Ok((c, _)) => Some((p, c)),
            Err(e) => {
                tracing::warn!("deceptive-docs: skipping {}: {e}", p.display());
                None
            }
        })
        .collect();
    crate::deceptive_docs::detect_deceptive_documentation(doc, &materialised)
}

fn collect_primary_doc_warnings<F: FileSystemProvider>(
    doc: &SkillDocument,
    path: &Path,
) -> Vec<Finding> {
    let artifact_kind = crate::scanner_graph::artifact_kind_for_path::<F>(path);
    let mut warnings = Vec::new();
    if let Some(kind) = doc.binary_disguise_kind.as_deref() {
        warnings.push(binary_disguise_finding(
            path,
            kind,
            artifact_kind,
            MatchTarget::Document,
        ));
    }
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

/// Collect inline suppression sources from the primary document and its
/// referenced files, then apply per-finding suppressions.
///
/// # Why this runs BEFORE deduplication
///
/// `deduplicate_findings` merges findings on
/// `(rule_id, category, matched_on, match_value, kind, scope, path)` and only
/// preserves the first non-`None` `line_number` it sees. If two emissions of
/// the same rule reach `scan_document_path` with different line numbers (one
/// carrying a `// skill-veil:disable` comment line, another path-less from
/// artifact-graph taint), running suppressions afterwards would let the merged
/// finding survive when its representative line happens to be the
/// non-suppressed copy. Suppressing first ensures each emission is matched
/// against its own original line number.
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
    for manifest in scanner.file_discovery().discover_package_manifests(path) {
        targets.insert(manifest);
    }
    for lockfile in scanner.file_discovery().discover_lockfiles(path) {
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
        let Some(after_sig) = production.split("fn scan_supporting_artifacts<").nth(1) else {
            // The signature renamed; surface a single, actionable failure
            // message rather than a generic .expect panic stack.
            panic!(
                "scanner_execution.rs no longer contains a `fn scan_supporting_artifacts<...>` \
                 production definition. If you renamed it, update this contract test to track \
                 the new name."
            );
        };
        let in_function = after_sig.split("\nfn ").next().unwrap_or(after_sig);
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
