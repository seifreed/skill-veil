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
use crate::path_safety::path_resolves_within_base;
use crate::policy::{
    AppliedPolicyOverride, PolicyAudit, SuppressionSummary, POLICY_AUDIT_PRECEDENCE,
};
use crate::ports::{FileSystemProvider, MarkdownParser};
use crate::scanner::{ScanError, ScanResult, Scanner};
use crate::scanner_support::{
    artifact_parse_error_finding, binary_disguise_finding, decode_warning_finding,
    parse_warning_finding, read_text_file_lossy, structured_parse_warning,
};
use crate::services::is_explicit_skill_file;
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
        // Existence and file-type checks both go through the
        // `FileSystemProvider` port. Using `PathBuf::is_dir()` would consult
        // `std::fs::metadata` directly (following symlinks — the port's
        // `is_dir` uses `symlink_metadata` and rejects symlinks), opening
        // both a TOCTOU window and a symlink-evasion path where a malicious
        // package shipping `evil_dir -> /etc` would be silently skipped
        // instead of surfacing as a read error. It also lets test doubles
        // disagree with production behaviour.
        //
        // The `!fs.is_file()` guard rejects symlinks (including
        // symlinks-to-directories), FIFOs, and device files — all of which
        // would cause `read_file_bytes` to hang (FIFO), produce unbounded
        // reads (devices), or spurious parse errors (symlink-to-directory).
        if !fs.exists(referenced_file) || !fs.is_file(referenced_file) {
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
    let artifact_kind = crate::scanner_graph::artifact_kind_for_path(referenced_file);
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

    if crate::detectors::bytecode::is_python_bytecode(referenced_file) {
        if let Ok(content) = fs.read_file_bytes(referenced_file) {
            let has_source = pyc_sibling_source_exists(fs, referenced_file);
            findings.extend(crate::detectors::bytecode::analyze_pyc(
                content.as_bytes(),
                has_source,
                referenced_file,
            ));
        }
    }
    findings
}

/// `true` when a `.py` source file with the same stem sits next to a
/// `.pyc`. Sourceless bytecode is a documented way to hide logic from
/// review, so its absence is a signal the bytecode detector consumes.
fn pyc_sibling_source_exists<F: FileSystemProvider>(fs: &F, pyc: &Path) -> bool {
    pyc.file_stem()
        .map(|stem| {
            let mut source = stem.to_os_string();
            source.push(".py");
            pyc.with_file_name(source)
        })
        .is_some_and(|source| fs.exists(&source) && fs.is_file(&source))
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
    let fs = scanner.file_discovery().fs_provider();
    let base_dir = doc.path.parent().unwrap_or_else(|| Path::new("."));

    for referenced in &doc.referenced_files {
        if !path_resolves_within_base(fs, referenced, base_dir) {
            tracing::warn!(
                "skipping referenced artifact outside package root after symlink resolution: {}",
                referenced.display()
            );
            continue;
        }
        if seen.insert(referenced.clone()) {
            artifacts.push(referenced.clone());
        }
    }

    if !is_explicit_skill_file(&doc.path) {
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
    let artifact_kind = crate::scanner_graph::artifact_kind_for_path(path);
    let artifact_path = path.display().to_string();
    let primary_content = doc.raw_content.clone();

    let dependencies = collect_dependency_inventory(scanner, &doc, path, &primary_content);

    let (raw_findings, artifact_graph) = collect_raw_findings(
        scanner,
        &doc,
        path,
        artifact_kind,
        &artifact_path,
        &primary_content,
        &dependencies,
    );
    let (raw_findings, suppressed_findings) = if scanner.honor_inline_suppressions() {
        collect_and_apply_suppressions(scanner, raw_findings, path, &doc, &primary_content)
    } else {
        (raw_findings, Vec::new())
    };
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
        dependencies,
    })
}

/// Collect the package's declared dependencies from the primary artifact (when
/// it is itself a manifest) and every supporting manifest. Pure and offline;
/// the network-enabled OSV lookup that consumes this lives in the CLI crate.
fn collect_dependency_inventory<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    doc: &SkillDocument,
    primary_path: &Path,
    primary_content: &str,
) -> Vec<crate::dependency_inventory::ParsedDependency> {
    let mut deps = Vec::new();
    let mut collect = |path: &Path, content: &str| {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            deps.extend(crate::dependency_inventory::collect_for_manifest(
                name,
                content,
                &path.display().to_string(),
            ));
        }
    };
    collect(primary_path, primary_content);

    let fs = scanner.file_discovery().fs_provider();
    for path in collect_supporting_artifact_paths(scanner, doc) {
        if !(fs.exists(&path) && fs.is_file(&path)) {
            continue;
        }
        match read_text_file_lossy(&path, fs) {
            Ok((content, _)) => collect(&path, &content),
            Err(e) => tracing::warn!("dependency-inventory: skipping {}: {e}", path.display()),
        }
    }
    deps
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
    // When re-reading the file fails, we use `extract_from_text` (which omits
    // the file hash) rather than hashing the lossy-decoded content. The
    // lossy-decoded string replaces invalid UTF-8 bytes with U+FFFD, so a
    // SHA-256 computed over it would disagree with `sha256sum` on the raw
    // file — exactly when an accurate hash is most needed (binary-disguised
    // malware payloads). Skipping the hash is safer than producing a wrong one.
    let mut iocs = match fs.read_file_bytes(primary_path) {
        Ok(file) => crate::ioc_extraction::extract_from_artifact(primary_path, file.as_bytes()),
        Err(err) => {
            tracing::warn!(
                path = %primary_path.display(),
                error = %err,
                "IOC extraction: failed to re-read primary artifact for SHA-256; \
                 skipping file hash (URL/IP/domain extraction continues)"
            );
            crate::ioc_extraction::extract_from_text(primary_content)
        }
    };

    let supporting = collect_supporting_artifact_paths(scanner, doc);
    for path in supporting {
        // Reject symlinks, FIFOs, and device files before reading — mirrors
        // the guard in scan_supporting_artifacts. Without this, a malicious
        // skill referencing /dev/urandom or a symlink → /etc/shadow would
        // leak sensitive content into IOC extraction.
        if !fs.exists(&path) || !fs.is_file(&path) {
            continue;
        }
        match fs.read_file_bytes(&path) {
            Ok(file) => {
                let bytes = file.as_bytes();
                iocs.merge(crate::ioc_extraction::extract_from_artifact(&path, bytes));
            }
            Err(e) => tracing::warn!(
                "ioc-extraction: skipping supporting artifact {}: {e}",
                path.display()
            ),
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
    dependencies: &[crate::dependency_inventory::ParsedDependency],
) -> (Vec<Finding>, ArtifactGraph) {
    let mut findings = scanner.engine().evaluate(doc);
    findings.extend(collect_primary_doc_warnings(doc, path));
    findings.extend(scan_supporting_artifacts(scanner, doc));
    findings.extend(deceptive_docs_findings(scanner, doc));
    findings.extend(unicode_deception_findings(
        scanner,
        doc,
        artifact_kind,
        artifact_path,
    ));
    findings.extend(crate::detectors::typosquat::scan_typosquat(dependencies));
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
    let taint_findings = crate::artifact_taint::derive_taint_findings(&artifact_graph, &findings);
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
        .filter(|p| fs.exists(p) && fs.is_file(p))
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

/// Scan the primary document and every supporting artifact for Unicode-based
/// deception (invisible characters, bidi overrides, tag-block smuggling,
/// homoglyph tokens). Supporting-artifact I/O errors are logged and skipped,
/// mirroring `deceptive_docs_findings`.
fn unicode_deception_findings<F: FileSystemProvider, P: MarkdownParser>(
    scanner: &Scanner<F, P>,
    doc: &SkillDocument,
    artifact_kind: ArtifactKind,
    artifact_path: &str,
) -> Vec<Finding> {
    let mut findings = crate::unicode_deception::scan_unicode_deception(
        &doc.raw_content,
        artifact_kind,
        artifact_path,
    );
    let fs = scanner.file_discovery().fs_provider();
    for p in collect_supporting_artifact_paths(scanner, doc) {
        if !(fs.exists(&p) && fs.is_file(&p)) {
            continue;
        }
        match read_text_file_lossy(&p, fs) {
            Ok((content, _)) => findings.extend(crate::unicode_deception::scan_unicode_deception(
                &content,
                ArtifactKind::ReferencedArtifact,
                &p.display().to_string(),
            )),
            Err(e) => tracing::warn!("unicode-deception: skipping {}: {e}", p.display()),
        }
    }
    findings
}

fn collect_primary_doc_warnings(doc: &SkillDocument, path: &Path) -> Vec<Finding> {
    let artifact_kind = crate::scanner_graph::artifact_kind_for_path(path);
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
    let mut seen_paths: BTreeSet<PathBuf> = supporting_artifacts.iter().cloned().collect();
    let mut ref_contents: Vec<(PathBuf, String)> = Vec::new();
    for referenced_file in &supporting_artifacts {
        // Reject symlinks, FIFOs, and device files before reading inline
        // suppressions — mirrors the guard in scan_supporting_artifacts.
        if !fs.exists(referenced_file) || !fs.is_file(referenced_file) {
            continue;
        }
        match read_text_file_lossy(referenced_file, fs) {
            Ok((ref_content, _)) => {
                ref_contents.push((referenced_file.clone(), ref_content));
            }
            Err(e) => tracing::warn!(
                "suppression: cannot read referenced file {}: {e}",
                referenced_file.display()
            ),
        }
    }
    // Taint findings reference source/sink files that may not appear in
    // `doc.referenced_files`. Without their content, `# skill-veil:ignore`
    // comments in those files have no effect on taint findings.
    for finding in &findings {
        if let Some(ref artifact_path) = finding.artifact_path {
            let artifact_pb = PathBuf::from(artifact_path.as_str());
            if seen_paths.insert(artifact_pb.clone())
                && fs.exists(&artifact_pb)
                && fs.is_file(&artifact_pb)
            {
                match read_text_file_lossy(&artifact_pb, fs) {
                    Ok((content, _)) => {
                        ref_contents.push((artifact_pb, content));
                    }
                    Err(e) => tracing::warn!(
                        "suppression: cannot read taint artifact {}: {e}",
                        artifact_path
                    ),
                }
            }
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
    /// the `FileSystemProvider` port for BOTH existence and directory
    /// checks, not `Path::exists` / `Path::is_dir` directly. Mixing the
    /// two backends opens a TOCTOU window and lets test doubles disagree
    /// with production behaviour. Pre-fix the is_dir check bypassed the
    /// port by calling Path::is_dir directly (follows symlinks), while
    /// rejects symlinks — a malicious package shipping `evil_dir -> /etc`
    /// would be silently skipped instead of surfaced as a read error.
    ///
    /// The `!fs.is_file()` guard also rejects symlinks-to-directories,
    /// FIFOs, and device files — all of which would cause `read_file_bytes`
    /// to hang (FIFO), produce unbounded reads (devices), or spurious
    /// parse errors (symlink-to-directory).
    #[test]
    fn scan_supporting_artifacts_uses_fs_provider_for_existence_and_is_file() {
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
            !in_function.contains(".is_dir()"),
            "scan_supporting_artifacts must not call Path::is_dir directly; \
             Path::is_dir follows symlinks and bypasses the FileSystemProvider port, \
             which uses symlink_metadata and rejects symlinks."
        );
        assert!(
            in_function.contains("fs.exists(referenced_file)"),
            "scan_supporting_artifacts must use fs.exists(referenced_file) so \
             that mock providers and production share the same code path"
        );
        assert!(
            in_function.contains("fs.is_file(referenced_file)"),
            "scan_supporting_artifacts must use fs.is_file(referenced_file) so \
             that symlinks, FIFOs, and device files are rejected via the \
             FileSystemProvider port's symlink_metadata check instead of \
             causing hangs or unbounded reads"
        );
    }
}
