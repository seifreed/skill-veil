//! Orchestrates LLM-based enrichment for a scan result, following the same
//! strict contract as the VT enrichment:
//!
//! # Architectural invariant — DO NOT BREAK
//!
//! **LLM enrichment is strictly additive and never modifies skill-veil's own
//! verdict, risk score, finding set, or any other field of `ScanResult`.**
//!
//! [`enrich_scan_result`] takes `&PackageScanResult` (read-only) and returns
//! a fresh [`LlmEnrichment`]. Callers render both sides separately; there is
//! no mutation pathway. If you ever find yourself wanting to tip the verdict
//! from LLM output, build it as a *separate* consumer that reads both and
//! composes its own combined decision — do not thread LLM values back into
//! `ScanResult`.
//!
//! # Safety contract (same as VT)
//!
//! 1. Enrichment is off unless `~/.skill-veil.toml` (or env vars) provide an
//!    LLM section AND the caller hasn't passed `--no-llm-enrich`.
//! 2. Cloud providers (OpenAI / Anthropic / Ollama Cloud) require an
//!    explicit API key from config or env. Local providers (Ollama local /
//!    LMStudio) default to localhost.
//! 3. Cache keys are content-addressed (SHA-256 of the prompt); re-scanning
//!    the same skill hits the cache instead of re-sending.

use super::cache::{
    compute_cache_key, compute_cache_key_with_followup, load_fresh, persist, CACHE_TTL_DAYS,
};
use super::client::LlmProvider;
use super::prompt::{
    build_followup_prompt, build_manifest_prompt, parse_verdict_json, ManifestEntry,
    SkillBundleInput,
};
use super::providers::build_provider;
use super::types::{LlmError, LlmPrompt, LlmVerdict};
use crate::config::{LlmConfigSection, LlmProviderKind};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use skill_veil_core::{PackageScanResult, ScanResult};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct LlmEnrichment {
    pub provider: String,
    pub model: String,
    pub packages: Vec<LlmPackageResult>,
    pub prompt_chars_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LlmPackageResult {
    pub package_id: Option<String>,
    pub primary_path: PathBuf,
    pub verdict: Option<LlmVerdict>,
    pub status: LlmStatus,
    pub cached: bool,
    pub prompt_chars: usize,
    pub raw_response_excerpt: Option<String>,
    pub fetched_at: DateTime<Utc>,
    /// 1 if the manifest prompt sufficed; 2 if the LLM requested a follow-up
    /// with full contents. Capped at 2 — no turn-3 loop. 0 for cache entries
    /// predating this field (treated as "legacy/unknown" by display code).
    #[serde(default)]
    pub turns_used: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum LlmStatus {
    Ok,
    ParseError {
        message: String,
    },
    ProviderError {
        message: String,
    },
    /// Bundle still exceeds the char budget after manifest truncation + caps.
    /// We skip the provider call to avoid HTTP 400 context overflow. The
    /// local scanner verdict remains authoritative.
    BundleTooLarge {
        user_json_chars: usize,
        budget: usize,
    },
}

pub(crate) struct LlmEnrichOptions {
    pub cache_root: PathBuf,
    pub max_prompt_chars: usize,
    pub provider_override: Option<LlmProviderKind>,
}

/// Build a bundle for a single `ScanResult`. The caller supplies the primary
/// content + supporting-artifact contents it already read during the scan.
pub(crate) struct PreparedBundle<'a> {
    pub primary_content: &'a str,
    pub supporting: Vec<(PathBuf, String)>,
}

pub(crate) fn enrich_scan_result(
    config: &LlmConfigSection,
    opts: &LlmEnrichOptions,
    scan_result: &PackageScanResult,
    bundles: Vec<PreparedBundle<'_>>,
) -> Result<LlmEnrichment> {
    let mut effective_config = config.clone();
    if let Some(override_kind) = opts.provider_override {
        effective_config.provider = override_kind;
    }
    let provider = build_provider(&effective_config)
        .map_err(|e| anyhow::anyhow!("failed to initialise LLM provider: {e}"))?;
    let provider_name = provider.name().to_string();
    let model_name = provider.model().to_string();

    // Probe the real context window of the loaded model (Ollama / LMStudio
    // let users configure ctx at load-time, so the static model table is
    // often wrong for local providers). The probe is best-effort; the
    // config layer honors an explicit user override above the probe.
    let probed_tokens = provider.probe_context_length();
    let resolved_max_chars = effective_config.effective_max_prompt_chars_with_probe(probed_tokens);
    if let Some(tokens) = probed_tokens {
        if resolved_max_chars != opts.max_prompt_chars {
            tracing::debug!(
                "LLM probe updated max_prompt_chars: config={} → probed={resolved_max_chars} (tokens={tokens})",
                opts.max_prompt_chars,
            );
        }
    }
    let resolved_opts = LlmEnrichOptions {
        cache_root: opts.cache_root.clone(),
        max_prompt_chars: resolved_max_chars,
        provider_override: opts.provider_override,
    };

    crate::util::secure_fs::create_dir_secure(&resolved_opts.cache_root)
        .with_context(|| format!("creating {}", resolved_opts.cache_root.display()))?;

    let mut enrichment = LlmEnrichment {
        provider: provider_name.clone(),
        model: model_name.clone(),
        packages: Vec::new(),
        prompt_chars_total: 0,
    };

    if scan_result.results.len() != bundles.len() {
        tracing::error!(
            "enrich_scan_result: results ({}) and bundles ({}) length mismatch — \
             excess items will be silently skipped",
            scan_result.results.len(),
            bundles.len()
        );
    }
    for (scan_res, bundle) in scan_result.results.iter().zip(bundles) {
        match enrich_one(
            provider.as_ref(),
            &provider_name,
            &model_name,
            &resolved_opts,
            scan_res,
            &bundle,
        ) {
            Ok(pkg) => {
                enrichment.prompt_chars_total += pkg.prompt_chars;
                enrichment.packages.push(pkg);
            }
            Err(err) => {
                tracing::warn!("LLM enrichment error for result: {err:#}");
                enrichment.packages.push(LlmPackageResult {
                    package_id: scan_res.metadata.package_id.clone(),
                    primary_path: scan_res.metadata.path.clone(),
                    verdict: None,
                    status: LlmStatus::ProviderError {
                        message: err.to_string(),
                    },
                    cached: false,
                    prompt_chars: 0,
                    raw_response_excerpt: None,
                    fetched_at: Utc::now(),
                    turns_used: 0,
                });
            }
        }
    }

    Ok(enrichment)
}

const MAX_REQUESTED_PATHS: usize = 10;

/// Build a provider response → (status, verdict, excerpt). Shared across
/// both turns.
fn call_provider(
    provider: &dyn LlmProvider,
    prompt: &super::types::LlmPrompt,
) -> (LlmStatus, Option<LlmVerdict>, Option<String>) {
    match provider.analyze(prompt) {
        Ok(raw) => match parse_verdict_json(&raw.content) {
            Ok(v) => (LlmStatus::Ok, Some(v), Some(trim_excerpt(&raw.content))),
            Err(msg) => (
                LlmStatus::ParseError { message: msg },
                None,
                Some(trim_excerpt(&raw.content)),
            ),
        },
        Err(LlmError::Unauthorized) => (
            LlmStatus::ProviderError {
                message: "unauthorized".into(),
            },
            None,
            None,
        ),
        Err(err) => (
            LlmStatus::ProviderError {
                message: err.to_string(),
            },
            None,
            None,
        ),
    }
}

struct TurnOutcome {
    status: LlmStatus,
    verdict: Option<LlmVerdict>,
    excerpt: Option<String>,
}

struct FollowupOutcome {
    turn: TurnOutcome,
    files: Vec<(PathBuf, String)>,
    prompt_chars_added: usize,
}

/// Run the LLM enrichment pipeline for a single scan result.
///
/// # Contract
///
/// - **Budget guard:** the SYSTEM + USER prompt of the manifest turn MUST fit
///   within `opts.max_prompt_chars`. If the combined length exceeds the
///   budget, the function returns a `BundleTooLarge` status WITHOUT calling
///   the provider — server-side concatenation of system + user is what the
///   model tokenises, so user-only counting underestimates by ~1650 chars on
///   every call, enough to overflow tight local-provider budgets. The same
///   exact guard applies to the follow-up turn after full-file context is
///   serialised.
/// - **Two-turn invariant:** at most one follow-up turn is executed. Turn 2
///   is gated on (a) Turn 1 returning `Ok`, (b) the LLM listing
///   `insufficient_context` paths, and (c) those paths intersecting the
///   manifest. The follow-up fileset is capped at `MAX_REQUESTED_PATHS` to
///   prevent an LLM-driven DoS.
/// - **Cache key derivation:** Turn-1-only results are stored under
///   `cache_key_t1` so a future scan with the same manifest reuses them
///   directly. Turn-2 results derive a key that incorporates digests of the
///   fetched files, so a different fileset (e.g. an edited script) does not
///   get served the stale verdict for the full `CACHE_TTL_DAYS`.
fn enrich_one(
    provider: &dyn LlmProvider,
    provider_name: &str,
    model_name: &str,
    opts: &LlmEnrichOptions,
    scan_res: &ScanResult,
    bundle: &PreparedBundle<'_>,
) -> Result<LlmPackageResult> {
    let bundle_input = SkillBundleInput {
        primary_path: &scan_res.metadata.path,
        primary_content: bundle.primary_content,
        supporting: bundle.supporting.clone(),
        our_verdict: scan_res.verdict,
        our_risk_score: scan_res.summary.risk_score,
        our_findings: &scan_res.findings,
        extracted_iocs: &scan_res.extracted_iocs,
    };
    let (manifest_prompt, manifest) = build_manifest_prompt(bundle_input, opts.max_prompt_chars);
    let combined_chars = manifest_prompt.user_json.len() + manifest_prompt.system.len();
    if combined_chars > opts.max_prompt_chars {
        return Ok(make_too_large_result(
            scan_res,
            combined_chars,
            opts.max_prompt_chars,
        ));
    }

    let sampling_fp = provider.sampling_fingerprint();
    let cache_key_t1 = compute_cache_key(provider_name, model_name, &sampling_fp, &manifest_prompt);
    let cache_path_t1 = opts.cache_root.join(format!("{cache_key_t1}.json"));
    if let Some(fresh) = load_fresh(&cache_path_t1, Duration::days(CACHE_TTL_DAYS))? {
        return Ok(LlmPackageResult {
            cached: true,
            ..fresh
        });
    }

    let mut prompt_chars = combined_chars;
    let TurnOutcome {
        mut status,
        mut verdict,
        mut excerpt,
    } = execute_manifest_turn(provider, &manifest_prompt);
    let mut turns_used: u8 = 1;
    let mut followup_files: Vec<(PathBuf, String)> = Vec::new();

    if let Some(v1) = verdict.as_ref().filter(|_| matches!(status, LlmStatus::Ok)) {
        if !v1.insufficient_context.is_empty() {
            // Check turn-2 cache before calling the provider again.
            // Pre-fix the turn-2 cache key was computed only *after* the
            // follow-up turn executed, so re-scans always re-prompted.
            let manifest_paths: std::collections::BTreeSet<&str> =
                manifest.iter().map(|m| m.path.as_str()).collect();
            let requested: Vec<String> = v1
                .insufficient_context
                .iter()
                .filter(|p| manifest_paths.contains(p.as_str()))
                .take(MAX_REQUESTED_PATHS)
                .cloned()
                .collect();
            if !requested.is_empty() {
                let lookup: std::collections::BTreeMap<String, String> = bundle
                    .supporting
                    .iter()
                    .map(|(p, c)| (p.display().to_string(), c.clone()))
                    .collect();
                let followup_files: Vec<(PathBuf, String)> = requested
                    .into_iter()
                    .filter_map(|p| lookup.get(&p).map(|c| (PathBuf::from(&p), c.clone())))
                    .collect();
                if !followup_files.is_empty() {
                    let t2_key = compute_cache_key_with_followup(
                        provider_name,
                        model_name,
                        &sampling_fp,
                        &manifest_prompt,
                        &followup_files,
                    );
                    let t2_path = opts.cache_root.join(format!("{t2_key}.json"));
                    if let Some(fresh) = load_fresh(&t2_path, Duration::days(CACHE_TTL_DAYS))? {
                        return Ok(LlmPackageResult {
                            cached: true,
                            ..fresh
                        });
                    }
                }
            }
        }
        if let Some(outcome) = execute_followup_turn(
            provider,
            scan_res,
            bundle,
            &manifest,
            v1,
            opts.max_prompt_chars,
        ) {
            status = outcome.turn.status;
            verdict = outcome.turn.verdict;
            excerpt = outcome.turn.excerpt;
            turns_used = 2;
            followup_files = outcome.files;
            prompt_chars += outcome.prompt_chars_added;
        }
    }

    let result = LlmPackageResult {
        package_id: scan_res.metadata.package_id.clone(),
        primary_path: scan_res.metadata.path.clone(),
        verdict,
        status,
        cached: false,
        prompt_chars,
        raw_response_excerpt: excerpt,
        fetched_at: Utc::now(),
        turns_used,
    };

    let cache_path = if turns_used == 2 {
        let key = compute_cache_key_with_followup(
            provider_name,
            model_name,
            &sampling_fp,
            &manifest_prompt,
            &followup_files,
        );
        opts.cache_root.join(format!("{key}.json"))
    } else {
        cache_path_t1
    };
    persist(&cache_path, &result)?;
    Ok(result)
}

/// Build the early-return record emitted when the manifest prompt cannot fit
/// the configured budget. Centralised so the caller's happy path stays free
/// of inline `LlmPackageResult` boilerplate.
fn make_too_large_result(
    scan_res: &ScanResult,
    combined_chars: usize,
    budget: usize,
) -> LlmPackageResult {
    LlmPackageResult {
        package_id: scan_res.metadata.package_id.clone(),
        primary_path: scan_res.metadata.path.clone(),
        verdict: None,
        status: LlmStatus::BundleTooLarge {
            user_json_chars: combined_chars,
            budget,
        },
        cached: false,
        prompt_chars: combined_chars,
        raw_response_excerpt: None,
        fetched_at: Utc::now(),
        turns_used: 0,
    }
}

/// Run turn 1 of the manifest protocol: the LLM sees paths + size +
/// 15-line previews of every supporting artifact, plus our findings and
/// IOCs. The provider response is parsed into a structured outcome that
/// the orchestrator either persists directly or feeds into turn 2.
fn execute_manifest_turn(provider: &dyn LlmProvider, prompt: &LlmPrompt) -> TurnOutcome {
    let (status, verdict, excerpt) = call_provider(provider, prompt);
    TurnOutcome {
        status,
        verdict,
        excerpt,
    }
}

/// Conditionally run turn 2 when the LLM listed `insufficient_context`
/// paths. Returns `None` when no follow-up is warranted (verdict listed
/// no paths, none intersected the manifest, or no requested path content is
/// available), letting the orchestrator skip without re-implementing the
/// gating logic.
///
/// The fetched fileset is capped at `MAX_REQUESTED_PATHS` to bound the
/// turn-2 prompt and prevent an LLM-driven DoS. The exact serialised prompt
/// size is checked before the provider call because the estimator cannot
/// account perfectly for TOON/JSON escaping and fixed system-prompt overhead.
fn execute_followup_turn(
    provider: &dyn LlmProvider,
    scan_res: &ScanResult,
    bundle: &PreparedBundle<'_>,
    manifest: &[ManifestEntry],
    turn1_verdict: &LlmVerdict,
    max_prompt_chars: usize,
) -> Option<FollowupOutcome> {
    if turn1_verdict.insufficient_context.is_empty() {
        return None;
    }
    let manifest_paths: std::collections::BTreeSet<&str> =
        manifest.iter().map(|m| m.path.as_str()).collect();
    let requested: Vec<String> = turn1_verdict
        .insufficient_context
        .iter()
        .filter(|p| manifest_paths.contains(p.as_str()))
        .take(MAX_REQUESTED_PATHS)
        .cloned()
        .collect();
    if requested.is_empty() {
        return None;
    }
    let lookup: std::collections::BTreeMap<String, String> = bundle
        .supporting
        .iter()
        .map(|(p, c)| (p.display().to_string(), c.clone()))
        .collect();
    // A path can be in `manifest_paths` (so it survived the first filter)
    // yet absent from `lookup` if the bundle builder dropped it under the
    // prompt-budget cap. The `filter_map` below would silently skip such
    // requests; emit a debug trace so "turn-2 ignored my
    // insufficient_context entry" is debuggable without re-running the
    // whole pipeline.
    let requested_with_contents: Vec<(PathBuf, String)> = requested
        .into_iter()
        .filter_map(|p| match lookup.get(&p) {
            Some(c) => Some((PathBuf::from(&p), c.clone())),
            None => {
                tracing::debug!(
                    "LLM-requested path {p:?} is in manifest but \
                     was dropped from bundle (likely budget truncation); \
                     skipping for turn-2"
                );
                None
            }
        })
        .collect();
    if requested_with_contents.is_empty() {
        return None;
    }
    let followup_input = SkillBundleInput {
        primary_path: &scan_res.metadata.path,
        primary_content: bundle.primary_content,
        supporting: Vec::new(),
        our_verdict: scan_res.verdict,
        our_risk_score: scan_res.summary.risk_score,
        our_findings: &scan_res.findings,
        extracted_iocs: &scan_res.extracted_iocs,
    };
    let followup_prompt =
        build_followup_prompt(&followup_input, &requested_with_contents, max_prompt_chars);
    let prompt_chars_added = followup_prompt.user_json.len() + followup_prompt.system.len();
    if prompt_chars_added > max_prompt_chars {
        return Some(FollowupOutcome {
            turn: TurnOutcome {
                status: LlmStatus::BundleTooLarge {
                    user_json_chars: prompt_chars_added,
                    budget: max_prompt_chars,
                },
                verdict: None,
                excerpt: None,
            },
            files: requested_with_contents,
            prompt_chars_added,
        });
    }
    let (status, verdict, excerpt) = call_provider(provider, &followup_prompt);
    Some(FollowupOutcome {
        turn: TurnOutcome {
            status,
            verdict,
            excerpt,
        },
        files: requested_with_contents,
        prompt_chars_added,
    })
}

/// Maximum characters retained from an LLM provider response when storing
/// it in the enrichment record. Keeps cache files bounded while preserving
/// enough text for analysts to triage by eye.
const LLM_EXCERPT_MAX_CHARS: usize = 500;

fn trim_excerpt(s: &str) -> String {
    s.chars().take(LLM_EXCERPT_MAX_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use skill_veil_core::{
        AgentExtensionKind, ArtifactClassification, ArtifactGraph, ArtifactIdentitySource,
        ArtifactKind, ArtifactMetadata, BlastRadiusSummary, DeduplicationSummary, ExtractedIocs,
        FindingSummary, HygieneSummary, PackageHealth, PackageVerdictReport, PolicyAudit,
        ScanResult, StructuralValidity, SuppressionSummary, Verdict,
    };

    use super::super::types::LlmRawResponse;
    use super::*;

    struct RecordingProvider {
        calls: AtomicUsize,
        response: &'static str,
    }

    impl RecordingProvider {
        fn new(response: &'static str) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                response,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl LlmProvider for RecordingProvider {
        fn analyze(&self, _prompt: &LlmPrompt) -> Result<LlmRawResponse, LlmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(LlmRawResponse {
                content: self.response.to_string(),
            })
        }

        fn name(&self) -> &'static str {
            "test"
        }

        fn model(&self) -> &str {
            "test-model"
        }

        fn sampling_fingerprint(&self) -> String {
            "test-sampling".to_string()
        }
    }

    fn minimal_scan_result() -> ScanResult {
        let summary = FindingSummary::from_findings(&[]);
        ScanResult {
            metadata: ArtifactMetadata {
                path: PathBuf::from("SKILL.md"),
                name: "SKILL.md".to_string(),
                extension_kind: AgentExtensionKind::Skill,
                classification: ArtifactClassification::ConfirmedSkill,
                package_id: None,
                identity_source: ArtifactIdentitySource::ExplicitName,
                structural_validity: StructuralValidity::Confirmed,
                heuristic_score: 0,
                primary_artifact_kind: ArtifactKind::SkillDocument,
            },
            findings: Vec::new(),
            suppressed_findings: Vec::new(),
            primary_findings: Vec::new(),
            supporting_findings: Vec::new(),
            summary: summary.clone(),
            primary_summary: summary.clone(),
            supporting_summary: summary,
            verdict: Verdict::Benign,
            verdict_report: PackageVerdictReport {
                verdict: Verdict::Benign,
                package_health: PackageHealth::Healthy,
                hygiene_summary: HygieneSummary::default(),
                declared_permissions: Vec::new(),
                effective_capabilities: Vec::new(),
                blast_radius_summary: BlastRadiusSummary::default(),
                verdict_reasons: Vec::new(),
                root_cause_groups: Vec::new(),
                top_risk_drivers: Vec::new(),
                calibration_notes: Vec::new(),
                calibration_risk_adjustment: 0,
            },
            deduplication_summary: DeduplicationSummary::default(),
            artifact_graph: ArtifactGraph::new(),
            profile: None,
            policy: None,
            suppression_summary: SuppressionSummary::default(),
            policy_audit: PolicyAudit::default(),
            should_fail: false,
            extracted_iocs: ExtractedIocs::default(),
        }
    }

    fn manifest_entry(path: &str, content: &str) -> ManifestEntry {
        ManifestEntry {
            path: path.to_string(),
            size_bytes: content.len(),
            preview: content.to_string(),
        }
    }

    fn requesting_verdict(path: &str) -> LlmVerdict {
        LlmVerdict {
            verdict: "suspicious".to_string(),
            confidence: 0.5,
            analysis: "needs context".to_string(),
            key_signals: Vec::new(),
            agreement_with_scanner: Some("partial".to_string()),
            insufficient_context: vec![path.to_string()],
        }
    }

    const VALID_VERDICT_JSON: &str = r#"{
        "verdict":"benign",
        "confidence":0.8,
        "analysis":"full context is safe",
        "key_signals":[],
        "agreement_with_scanner":"agree",
        "insufficient_context":[]
    }"#;

    /// Compile-time witness: `enrich_scan_result` takes `&PackageScanResult`
    /// (shared reference), matching the VT contract. If someone changes it to
    /// `&mut` or consume-by-value, this test stops compiling.
    #[test]
    fn enrich_signature_is_read_only_on_scan_result() {
        fn assert_signature(
            _f: fn(
                &LlmConfigSection,
                &LlmEnrichOptions,
                &PackageScanResult,
                Vec<PreparedBundle<'_>>,
            ) -> Result<LlmEnrichment>,
        ) {
        }
        assert_signature(enrich_scan_result);
    }

    /// Contract: `LlmEnrichment` is a pure value type — `Default`,
    /// `Clone`, and `Serialize` round-trip without surprises so the
    /// enrichment pipeline can pass it across module boundaries and the
    /// CLI can render it without bespoke construction logic.
    #[test]
    fn llm_enrichment_is_pure_value_type() {
        let e = LlmEnrichment::default();
        let _copy = e.clone();
        let _json = serde_json::to_string(&e).unwrap();
    }

    /// Contract: turn 2 rejects prompts whose exact SYSTEM + USER size exceeds
    /// the configured budget and does not call the provider.
    #[test]
    fn followup_turn_rejects_prompt_over_budget_without_provider_call() {
        let provider = RecordingProvider::new(VALID_VERDICT_JSON);
        let scan_res = minimal_scan_result();
        let script_path = "scripts/context.py";
        let script = "print('context')";
        let bundle = PreparedBundle {
            primary_content: "# Skill\n",
            supporting: vec![(PathBuf::from(script_path), script.to_string())],
        };
        let manifest = vec![manifest_entry(script_path, script)];
        let verdict = requesting_verdict(script_path);

        let outcome =
            execute_followup_turn(&provider, &scan_res, &bundle, &manifest, &verdict, 1).unwrap();

        assert_eq!(provider.calls(), 0);
        assert!(matches!(
            outcome.turn.status,
            LlmStatus::BundleTooLarge { budget: 1, .. }
        ));
        assert!(outcome.prompt_chars_added > 1);
    }

    /// Contract: turn 2 calls the provider once when the exact prompt size
    /// fits the configured budget.
    #[test]
    fn followup_turn_calls_provider_when_prompt_fits_budget() {
        let provider = RecordingProvider::new(VALID_VERDICT_JSON);
        let scan_res = minimal_scan_result();
        let script_path = "scripts/context.py";
        let script = "print('context')";
        let bundle = PreparedBundle {
            primary_content: "# Skill\n",
            supporting: vec![(PathBuf::from(script_path), script.to_string())],
        };
        let manifest = vec![manifest_entry(script_path, script)];
        let verdict = requesting_verdict(script_path);

        let outcome =
            execute_followup_turn(&provider, &scan_res, &bundle, &manifest, &verdict, 50_000)
                .unwrap();

        assert_eq!(provider.calls(), 1);
        assert!(matches!(outcome.turn.status, LlmStatus::Ok));
        assert!(outcome.turn.verdict.is_some());
        assert!(outcome.prompt_chars_added <= 50_000);
    }
}
