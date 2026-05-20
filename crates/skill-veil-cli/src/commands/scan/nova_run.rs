//! NOVA rule execution against the scanned target.
//!
//! Two consumer surfaces share a single evaluation pass:
//!
//! - [`evaluate_against_target`] returns a structured
//!   [`NovaScanReport`] the scan command uses to inject NOVA hits
//!   into the canonical `Finding` stream so they appear in JSON /
//!   SARIF output alongside skill-veil-rules findings.
//! - [`render_text_block`] returns the legacy post-scan text block
//!   that summarises matches + lists capabilities the rule wanted
//!   that we could not service (semantics / LLM stubs).
//!
//! Running NOVA twice in the same scan would double the work and
//! drift the two outputs apart, so the caller should evaluate once
//! and reuse the report for both.

use crate::init::{current_install, NovaInstallSnapshot};
use crate::util::terminal_safe::sanitise_for_terminal;
use anyhow::Result;
use skill_veil_core::nova::{
    evaluate_rule, mapping::nova_match_to_findings, parse_rules, LlmEvaluator,
    NativeKeywordEvaluator, NotYetWiredLlm, NotYetWiredSemantic, NovaMatch, NovaRule,
    SemanticEvaluator, SkippedCapability,
};
use skill_veil_core::{ArtifactKind, ArtifactScope, Finding};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAX_NOVA_RULE_BYTES: u64 = 1024 * 1024;
const MAX_NOVA_SCAN_BODY_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct NovaScanReport {
    pub(crate) install: NovaInstallSnapshot,
    pub(crate) hits: Vec<NovaScanHit>,
    pub(crate) skipped_capabilities: Vec<SkippedCapability>,
    pub(crate) rule_count: usize,
    pub(crate) body_count: usize,
}

#[derive(Debug)]
pub(crate) struct NovaScanHit {
    pub(crate) source_path: PathBuf,
    pub(crate) rule: NovaRule,
    pub(crate) m: NovaMatch,
}

impl NovaScanHit {
    fn to_findings(&self) -> Vec<Finding> {
        nova_match_to_findings(
            &self.rule,
            &self.m,
            Some(&self.source_path),
            ArtifactKind::SkillDocument,
            ArtifactScope::AgentEntrypoint,
        )
    }
}

impl NovaScanReport {
    /// Convert every NOVA hit in this report into the canonical
    /// `Finding` shape, indexed by source artifact path. The scan
    /// command consumes this map to merge NOVA findings into the
    /// matching `ScanResult` in `PackageScanResult.results`.
    pub(crate) fn findings_by_path(&self) -> std::collections::HashMap<PathBuf, Vec<Finding>> {
        let mut out: std::collections::HashMap<PathBuf, Vec<Finding>> =
            std::collections::HashMap::new();
        for hit in &self.hits {
            let findings = hit.to_findings();
            if findings.is_empty() {
                continue;
            }
            out.entry(hit.source_path.clone())
                .or_default()
                .extend(findings);
        }
        out
    }
}

pub(crate) fn evaluate_against_target(
    target: &Path,
    cache_dir_override: Option<&Path>,
    llm_eval: Option<&dyn LlmEvaluator>,
    semantic_eval: Option<&dyn SemanticEvaluator>,
) -> Result<Option<NovaScanReport>> {
    let install = current_install(cache_dir_override.map(Path::to_path_buf))?;
    let Some(nova) = install.nova else {
        return Ok(None);
    };

    let rules = load_all_rules(&nova.install_dir);
    if rules.is_empty() {
        return Ok(None);
    }

    let bodies = collect_scan_bodies(target);
    if bodies.is_empty() {
        return Ok(None);
    }

    let kw = NativeKeywordEvaluator::new();
    let stub_sem = NotYetWiredSemantic;
    let stub_llm = NotYetWiredLlm;
    // Trait-object dispatch lets callers inject `--nova-llm` and
    // `--nova-semantics` evaluators without monomorphising the engine
    // for every combination. `engine::evaluate_rule` is `?Sized`-bound
    // on every evaluator generic specifically to make this zero-cost
    // ergonomic.
    let llm_dispatch: &dyn LlmEvaluator = llm_eval.unwrap_or(&stub_llm);
    let sem_dispatch: &dyn SemanticEvaluator = semantic_eval.unwrap_or(&stub_sem);

    let mut hits: Vec<NovaScanHit> = Vec::new();
    let mut skipped_caps: Vec<SkippedCapability> = Vec::new();
    for (path, body) in &bodies {
        for rule in &rules {
            match evaluate_rule(rule, body, &kw, sem_dispatch, llm_dispatch) {
                Ok(m) => {
                    if m.matched {
                        hits.push(NovaScanHit {
                            source_path: path.clone(),
                            rule: rule.clone(),
                            m,
                        });
                    } else {
                        for cap in &m.skipped_capabilities {
                            if !skipped_caps.contains(cap) {
                                skipped_caps.push(*cap);
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        rule = %rule.name,
                        path = %path.display(),
                        "NOVA rule evaluation failed: {err}"
                    );
                }
            }
        }
    }

    if hits.is_empty() && skipped_caps.is_empty() {
        return Ok(None);
    }
    Ok(Some(NovaScanReport {
        install: nova,
        hits,
        skipped_capabilities: skipped_caps,
        rule_count: rules.len(),
        body_count: bodies.len(),
    }))
}

/// Render the operator-facing text block summarising the report.
/// Kept as the final output of the scan command (after JSON/SARIF
/// rendering) so quiet/JSON/SARIF runs that suppress the text block
/// still get the structured NOVA findings via the report itself.
pub(crate) fn render_text_block(report: &NovaScanReport) -> String {
    let mut out = String::new();
    out.push_str("\n--- NOVA rule matches ---\n");
    out.push_str(&format!(
        "  pack:    nova-rules @ {}  ({} rules, {} files scanned)\n",
        short(&report.install.commit_sha),
        report.rule_count,
        report.body_count,
    ));
    if report.hits.is_empty() {
        out.push_str("  result:  no rules matched\n");
    } else {
        out.push_str(&format!("  matches: {}\n", report.hits.len()));
        for hit in &report.hits {
            out.push_str(&format!(
                "    - {} :: {}\n",
                sanitise_for_terminal(&hit.source_path.display().to_string()),
                sanitise_for_terminal(&hit.m.rule_name)
            ));
            let kw_hits: Vec<String> = hit
                .m
                .keyword_hits
                .iter()
                .filter_map(|(k, v)| {
                    if *v {
                        Some(sanitise_for_terminal(k))
                    } else {
                        None
                    }
                })
                .collect();
            if !kw_hits.is_empty() {
                out.push_str(&format!("        keywords:  ${}\n", kw_hits.join(" $")));
            }
        }
    }
    if !report.skipped_capabilities.is_empty() {
        out.push_str("  note:    rules requiring these capabilities were skipped:\n");
        for cap in &report.skipped_capabilities {
            let label = match cap {
                SkippedCapability::Semantics => {
                    "semantics (sentence embeddings unavailable: build with --features nova-semantics, or this run passed --no-nova-semantics)"
                }
                SkippedCapability::Llm => {
                    "llm (opt-in with --nova-llm; otherwise patterns are skipped, see tracing warn for runtime errors)"
                }
            };
            out.push_str(&format!("    - {label}\n"));
        }
    }
    out
}

fn load_all_rules(install_dir: &Path) -> Vec<NovaRule> {
    let mut rules = Vec::new();
    for entry in walkdir::WalkDir::new(install_dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("nov") {
            continue;
        }
        let body = match read_to_string_with_cap(path, MAX_NOVA_RULE_BYTES) {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    "skipping NOVA rule file (read error): {err}"
                );
                continue;
            }
        };
        match parse_rules(&body) {
            Ok(parsed) => rules.extend(parsed),
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    "skipping NOVA rule file (parse error): {err}"
                );
            }
        }
    }
    rules
}

fn collect_scan_bodies(target: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    if target.is_file() {
        if let Ok(body) = read_to_string_with_cap(target, MAX_NOVA_SCAN_BODY_BYTES) {
            out.push((target.to_path_buf(), body));
        }
        return out;
    }
    for entry in walkdir::WalkDir::new(target)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|s| s.to_str());
        if !matches!(
            ext,
            Some("md") | Some("markdown") | Some("txt") | Some("yaml") | Some("yml")
        ) {
            continue;
        }
        if let Ok(body) = read_to_string_with_cap(path, MAX_NOVA_SCAN_BODY_BYTES) {
            out.push((path.to_path_buf(), body));
        }
    }
    out
}

fn read_to_string_with_cap(path: &Path, max_bytes: u64) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if meta.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size {} exceeds limit {max_bytes}",
                path.display(),
                meta.len()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(meta.len().try_into().unwrap_or(0));
    let mut limited = file.take(max_bytes + 1);
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size exceeds limit {max_bytes}",
                path.display()
            ),
        ));
    }
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn short(sha: &str) -> &str {
    if sha.len() >= 7 {
        &sha[..7]
    } else {
        sha
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    ///
    /// Normal-sized scan targets are read into the NOVA body set.
    #[test]
    fn collect_scan_bodies_accepts_small_target_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("SKILL.md");
        std::fs::write(&file, "# Skill\nkeyword").unwrap();

        let bodies = collect_scan_bodies(&file);

        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].1, "# Skill\nkeyword");
    }

    /// # Contract
    ///
    /// Files above the NOVA per-body cap are skipped instead of read
    /// into memory.
    #[test]
    fn collect_scan_bodies_rejects_oversized_target_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("oversized.md");
        let handle = std::fs::File::create(&file).unwrap();
        handle.set_len(MAX_NOVA_SCAN_BODY_BYTES + 1).unwrap();

        let bodies = collect_scan_bodies(&file);

        assert!(bodies.is_empty());
    }

    /// # Contract
    ///
    /// NOVA's human text block must not emit terminal control bytes
    /// from package paths or external rule metadata.
    #[test]
    fn render_text_block_sanitises_nova_control_sequences() {
        let mut keyword_hits = std::collections::BTreeMap::new();
        keyword_hits.insert("kw\x1b[2J".to_string(), true);
        let report = NovaScanReport {
            install: NovaInstallSnapshot {
                commit_sha: "0123456789abcdef".to_string(),
                tarball_sha256: "a".repeat(64),
                install_dir: PathBuf::from("/tmp/nova"),
                file_count: 1,
            },
            hits: vec![NovaScanHit {
                source_path: PathBuf::from("prompt\x1b]8;;https://evil.invalid\x07.md"),
                rule: NovaRule {
                    name: "rule".to_string(),
                    meta: std::collections::BTreeMap::new(),
                    keywords: std::collections::BTreeMap::new(),
                    semantics: std::collections::BTreeMap::new(),
                    llm: std::collections::BTreeMap::new(),
                    condition: skill_veil_core::nova::condition::ConditionExpr::Literal(true),
                },
                m: NovaMatch {
                    rule_name: "rule\x1b[2J".to_string(),
                    matched: true,
                    keyword_hits,
                    semantic_hits: std::collections::BTreeMap::new(),
                    llm_hits: std::collections::BTreeMap::new(),
                    skipped_capabilities: Vec::new(),
                },
            }],
            skipped_capabilities: Vec::new(),
            rule_count: 1,
            body_count: 1,
        };

        let rendered = render_text_block(&report);

        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\x07'));
    }
}
