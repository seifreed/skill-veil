//! NOVA rule execution against the scanned target.
//!
//! Loads every `.nov` file installed under
//! `<cache>/rules/nova-<sha>/`, walks the scan target's markdown
//! bodies, and emits a one-shot text block summarising which NOVA
//! rules matched. Intentionally text-only for this first pass —
//! integrating NOVA matches into the JSON / SARIF reports is a
//! follow-up that will need a `RuleSource::Nova` finding kind on
//! the core side.

use crate::init::{current_install, NovaInstallSnapshot};
use anyhow::Result;
use skill_veil_core::nova::{
    evaluate_rule, parse_rules, NativeKeywordEvaluator, NotYetWiredLlm, NotYetWiredSemantic,
    NovaMatch, NovaRule, SkippedCapability,
};
use std::path::{Path, PathBuf};

/// Run NOVA rules against the scan target. Returns the rendered text
/// block to print after the existing enrichment output, or `None` if
/// NOVA is not installed / nothing matched / quiet mode is on.
pub(crate) fn try_scan_with_nova(
    target: &Path,
    cache_dir_override: Option<&Path>,
    quiet: bool,
) -> Result<Option<String>> {
    if quiet {
        return Ok(None);
    }
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
    let sem = NotYetWiredSemantic;
    let llm = NotYetWiredLlm;

    let mut hits: Vec<(String, NovaMatch)> = Vec::new();
    let mut skipped_caps: Vec<SkippedCapability> = Vec::new();
    for (path, body) in &bodies {
        for rule in &rules {
            match evaluate_rule(rule, body, &kw, &sem, &llm) {
                Ok(m) => {
                    if m.matched {
                        hits.push((path.display().to_string(), m));
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
    Ok(Some(render(
        &nova,
        &hits,
        &skipped_caps,
        rules.len(),
        bodies.len(),
    )))
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
        let body = match std::fs::read_to_string(path) {
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
        if let Ok(body) = std::fs::read_to_string(target) {
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
        if let Ok(body) = std::fs::read_to_string(path) {
            out.push((path.to_path_buf(), body));
        }
    }
    out
}

fn render(
    install: &NovaInstallSnapshot,
    hits: &[(String, NovaMatch)],
    skipped: &[SkippedCapability],
    rule_count: usize,
    body_count: usize,
) -> String {
    let mut out = String::new();
    out.push_str("\n--- NOVA rule matches ---\n");
    out.push_str(&format!(
        "  pack:    nova-rules @ {}  ({rule_count} rules, {body_count} files scanned)\n",
        short(&install.commit_sha),
    ));
    if hits.is_empty() {
        out.push_str("  result:  no rules matched\n");
    } else {
        out.push_str(&format!("  matches: {}\n", hits.len()));
        for (path, m) in hits {
            out.push_str(&format!("    - {} :: {}\n", path, m.rule_name));
            let kw_hits: Vec<&str> = m
                .keyword_hits
                .iter()
                .filter_map(|(k, v)| if *v { Some(k.as_str()) } else { None })
                .collect();
            if !kw_hits.is_empty() {
                out.push_str(&format!("        keywords:  ${}\n", kw_hits.join(" $")));
            }
        }
    }
    if !skipped.is_empty() {
        out.push_str("  note:    rules requiring these capabilities were skipped:\n");
        for cap in skipped {
            let label = match cap {
                SkippedCapability::Semantics => {
                    "semantics (sentence embeddings — pending native runtime)"
                }
                SkippedCapability::Llm => {
                    "llm (provider routing — pending wiring to the existing skill-veil LLM chain)"
                }
            };
            out.push_str(&format!("    - {label}\n"));
        }
    }
    out
}

fn short(sha: &str) -> &str {
    if sha.len() >= 7 {
        &sha[..7]
    } else {
        sha
    }
}
