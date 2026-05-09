use clap::{Args, Parser, Subcommand, ValueEnum};
use std::num::NonZeroUsize;
use std::path::PathBuf;

/// Default soft cap for `vt download --limit`. Encoded as `NonZeroUsize`
/// so the type system rejects `--limit 0` at clap parse time instead of
/// silently allowing a zero-file download.
const DEFAULT_VT_DOWNLOAD_LIMIT: NonZeroUsize = match NonZeroUsize::new(500) {
    Some(n) => n,
    None => unreachable!(),
};

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum ColorChoiceArg {
    Auto,
    Always,
    Never,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum PolicyProfileArg {
    Personal,
    Team,
    Enterprise,
    Research,
}

#[derive(Parser)]
#[command(name = "skill-veil")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Increase log verbosity. Mutually exclusive with `--quiet` —
    /// passing both used to resolve silently to "quiet wins", which
    /// hid an unintended user input. Round-5 audit Bug 3.19.
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,
    /// Suppress non-error output. Mutually exclusive with `--verbose`
    /// (clap rejects the combination at parse time).
    #[arg(short, long, global = true)]
    pub quiet: bool,
    #[arg(long, global = true, value_enum, default_value = "auto")]
    pub color: ColorChoiceArg,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Scan(ScanArgs),
    ScanFile(ScanArgs),
    ScanPackage(ScanArgs),
    ScanDataset(ScanArgs),
    Benchmark(BenchmarkArgs),
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    Diff(DiffArgs),
    Waivers {
        #[command(subcommand)]
        action: WaiversAction,
    },
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// VirusTotal corpus management and detection cross-check tooling.
    Vt {
        #[command(subcommand)]
        action: VtAction,
    },
    /// PromptIntel corpus management and benchmark cross-check tooling.
    #[command(name = "promptintel", alias = "prompt-intel")]
    PromptIntel {
        #[command(subcommand)]
        action: PromptIntelAction,
    },
    /// Download and verify the latest signed `skill-veil-rules`
    /// release into the user cache. After init, `skill-veil scan` uses
    /// the downloaded packs automatically — no `--rules-dir` needed.
    Init(InitArgs),
}

#[derive(Args, Clone)]
pub struct InitArgs {
    /// Pin to a specific release tag (e.g. `v0.1.0`). Default: resolve
    /// the latest stable release via the GitHub `releases/latest`
    /// redirect.
    #[arg(long)]
    pub version: Option<String>,
    /// Override the install root. Default: `dirs::cache_dir()/skill-veil/`.
    /// The downloaded rules end up at
    /// `<cache_dir>/rules/<version>/official/`.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct RulesUpdateArgs {
    /// Pin to a specific release tag instead of the latest.
    #[arg(long)]
    pub version: Option<String>,
    /// Override the install root.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct RulesStatusArgs {
    /// Override the install root used for the lookup.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
    /// Output format.
    #[arg(short, long, value_enum, default_value = "text")]
    pub format: OutputFormat,
}

#[derive(Subcommand, Clone)]
pub enum PromptIntelAction {
    /// Download the PromptIntel corpus into a scannable directory.
    Download(PromptIntelDownloadArgs),
    /// Scan the downloaded corpus and report detection gaps.
    CrossCheck(PromptIntelCrossCheckArgs),
    /// Manage the local PromptIntel agent-feed cache used to enrich
    /// scans with community-curated IOCs.
    #[command(subcommand)]
    Feed(PromptIntelFeedAction),
    /// Submit threat-intel reports to PromptIntel and inspect prior
    /// submissions. Rate-limited (5/h, 20/d for submission; 60/h for
    /// listing).
    #[command(subcommand)]
    Report(PromptIntelReportAction),
    /// Audit which PromptIntel taxonomy threats are covered by at
    /// least one rule in the loaded packs. Pure-offline analysis;
    /// does not contact the API.
    Coverage(PromptIntelCoverageArgs),
}

#[derive(Args, Clone)]
pub struct PromptIntelCoverageArgs {
    /// Optional override for the rule pack directory. Defaults to
    /// the scanner's discovery order (`$SKILL_VEIL_RULES_DIR` →
    /// `~/.cache/skill-veil/rules/<current>/official/` → legacy
    /// `./rules/official/`). See `default_external_rule_dirs` for the
    /// full contract.
    #[arg(long)]
    pub rules_dir: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: PromptIntelCrossCheckFormat,
}

#[derive(Subcommand, Clone)]
pub enum PromptIntelFeedAction {
    /// Pull the PromptIntel agent-feed into the local cache. Default
    /// is incremental (`?since=<last_sync>`); `--full` forces a
    /// complete re-pull so revocations propagate.
    Sync(PromptIntelFeedSyncArgs),
    /// List cached entries.
    List(PromptIntelFeedListArgs),
    /// Show the persisted client-side rate-limit budget.
    Budget(PromptIntelFeedBudgetArgs),
}

#[derive(Args, Clone)]
pub struct PromptIntelFeedSyncArgs {
    /// Cache root override. Defaults to `dirs::cache_dir()/skill-veil/`.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
    /// Force a full re-pull instead of an incremental delta. Required
    /// to propagate revocations because the upstream `?since=` filter
    /// does not return entries that were revoked since `last_sync`.
    #[arg(long, default_value_t = false)]
    pub full: bool,
}

#[derive(Args, Clone)]
pub struct PromptIntelFeedListArgs {
    /// Cache root override. Defaults to `dirs::cache_dir()/skill-veil/`.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: PromptIntelCrossCheckFormat,
}

#[derive(Args, Clone)]
pub struct PromptIntelFeedBudgetArgs {
    /// Cache root override. Defaults to `dirs::cache_dir()/skill-veil/`.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
}

/// Subcommand family for `POST /agents/reports` (5/h, 20/d) and
/// `GET /agents/reports/mine` (60/h).
#[derive(Subcommand, Clone)]
pub enum PromptIntelReportAction {
    /// Submit a draft report to PromptIntel. The body MUST be a JSON
    /// file conforming to the [`ReportDraft`] schema; validate locally
    /// with `--dry-run` before spending hourly quota.
    Submit(PromptIntelReportSubmitArgs),
    /// List reports the authenticated agent has previously submitted.
    List(PromptIntelReportListArgs),
}

#[derive(Args, Clone)]
pub struct PromptIntelReportSubmitArgs {
    /// JSON file holding the report draft. See `ReportDraft` for the
    /// expected shape; required fields are `category`, `severity`,
    /// `confidence`, `fingerprint`, `title` (5–100 chars).
    #[arg(long)]
    pub file: PathBuf,
    /// Cache root override (used by the rate-limit tracker).
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
    /// Validate the draft and print the JSON that would be submitted
    /// without contacting the API. Recommended before every real
    /// submission since the hourly cap is just 5/h.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

#[derive(Args, Clone)]
pub struct PromptIntelReportListArgs {
    /// Cache root override (used by the rate-limit tracker).
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
    /// Page size; clamped client-side to ≥1.
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
    /// Page offset.
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: PromptIntelCrossCheckFormat,
}

#[derive(Args, Clone)]
pub struct PromptIntelDownloadArgs {
    /// Destination directory for the downloaded corpus. Reports are
    /// written to `<dest>/prompts/` plus an `_index.json` and `_meta.json`.
    #[arg(long, default_value = "data/promptintel")]
    pub dest: PathBuf,
    /// Per-page size requested from the API (max 100).
    #[arg(long, default_value_t = 100)]
    pub page_size: u32,
    /// Per-request delay in milliseconds between paginated requests.
    /// Default 200ms is a polite client; the API does not publish a hard
    /// rate limit.
    #[arg(long, default_value_t = 200)]
    pub rate_limit_ms: u64,
    /// Optional cap on total prompts written. Useful when iterating on
    /// rules locally without re-downloading the entire corpus each time.
    /// Must be ≥ 1 when supplied; clap rejects `--limit 0` at parse time.
    #[arg(long)]
    pub limit: Option<NonZeroUsize>,
}

#[derive(Args, Clone)]
pub struct PromptIntelCrossCheckArgs {
    /// Corpus directory previously populated via
    /// `skill-veil promptintel download`.
    #[arg(long, default_value = "data/promptintel")]
    pub dir: PathBuf,
    /// Output format for the cross-check report.
    #[arg(long, value_enum, default_value = "text")]
    pub format: PromptIntelCrossCheckFormat,
    /// Optional output file. Defaults to stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Only list prompts skill-veil failed to flag. Detection rate
    /// summary is unaffected.
    #[arg(long, default_value_t = false)]
    pub only_misses: bool,
    /// Exit 1 when overall detection rate < this fraction (0.0–1.0).
    /// Errored prompts are excluded from both numerator and
    /// denominator. Boundary is strict-less-than: `rate == threshold`
    /// passes (matches `scan-package --fail-on`).
    #[arg(long, value_parser = parse_fail_below)]
    pub fail_below: Option<f64>,
    /// Promote PromptIntel taxonomy drift to a CI gate failure (exit 1).
    /// Drift means the corpus carries a threat name that isn't in
    /// `taxonomy::TAXONOMY`; the renderer surfaces such names in a
    /// `[Drift]` section regardless of this flag.
    #[arg(long, default_value_t = false)]
    pub strict_taxonomy: bool,
}

/// Without this guard `--fail-below 1.5` would always trip and
/// `--fail-below -0.1` would never trip — both silent footguns.
fn parse_fail_below(raw: &str) -> Result<f64, String> {
    let value: f64 = raw
        .parse()
        .map_err(|err| format!("`--fail-below` must be a number ({err})"))?;
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(format!(
            "`--fail-below` must be in the inclusive range [0.0, 1.0]; got {value}"
        ));
    }
    Ok(value)
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum PromptIntelCrossCheckFormat {
    Text,
    Json,
}

#[derive(Subcommand, Clone)]
pub enum VtAction {
    /// Run a VT Intelligence search and download matching files + reports.
    Download(VtDownloadArgs),
    /// Fetch a single file's VT report (codeinsight + analysis stats).
    Report(VtReportArgs),
    /// Scan a corpus directory and compare per-package verdicts against VT.
    CrossCheck(VtCrossCheckArgs),
}

#[derive(Args, Clone)]
pub struct VtDownloadArgs {
    /// VT Intelligence query string. Defaults to the OpenClaw skill malicious
    /// corpus query.
    #[arg(long)]
    pub query: Option<String>,
    /// Destination directory for the downloaded corpus. Reports are written
    /// to `<dest>/.vt-reports/`.
    #[arg(long, default_value = "data")]
    pub dest: PathBuf,
    /// Maximum number of files to download (soft cap; VT may return fewer).
    /// Must be ≥ 1; clap rejects `--limit 0` at parse time.
    #[arg(long, default_value_t = DEFAULT_VT_DOWNLOAD_LIMIT)]
    pub limit: NonZeroUsize,
    /// Only fetch report JSONs, skip binary downloads (useful without a
    /// premium VT apikey).
    #[arg(long, default_value_t = false)]
    pub report_only: bool,
    /// Per-request delay in milliseconds. Default 500ms is safe for the VT
    /// free tier (4 lookups/min, 500/day). Premium accounts can lower this
    /// (e.g. 60ms ≈ 16 req/s) for substantially faster bulk downloads. The
    /// value applies to both the search-pagination loop and the per-sample
    /// download loop.
    #[arg(long, default_value_t = 500)]
    pub rate_limit_ms: u64,
}

#[derive(Args, Clone)]
pub struct VtReportArgs {
    pub sha256: String,
    /// Write the JSON report to this path instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct VtCrossCheckArgs {
    /// Corpus directory previously populated via `skill-veil vt download`.
    #[arg(long, default_value = "data")]
    pub dir: PathBuf,
    /// Output format for the cross-check report.
    #[arg(long, value_enum, default_value = "text")]
    pub format: VtCrossCheckFormat,
    /// Optional output file. Defaults to stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Only list packages where skill-veil disagreed with VT.
    #[arg(long, default_value_t = false)]
    pub only_mismatches: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum VtCrossCheckFormat {
    Text,
    Json,
    Markdown,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum DatasetViewArg {
    Full,
    Entrypoints,
    PackageRisk,
    Verdicts,
}

#[derive(Args, Clone)]
pub struct ScanArgs {
    pub path: PathBuf,
    #[arg(short, long, value_enum, default_value = "text")]
    pub format: OutputFormat,
    #[arg(long, value_enum)]
    pub fail_on: Option<SeverityArg>,
    #[arg(long, value_enum)]
    pub min_severity: Option<SeverityArg>,
    #[arg(long)]
    pub rules_dir: Option<PathBuf>,
    #[arg(long, value_enum)]
    pub profile: Option<PolicyProfileArg>,
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    #[arg(long)]
    pub waivers: Option<PathBuf>,
    #[arg(long)]
    pub policy: Option<PathBuf>,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub no_recursive: bool,
    #[arg(long, default_value_t = false)]
    pub quiet_summary: bool,
    #[arg(long, default_value_t = false)]
    pub explain_policy: bool,
    /// Cap how many findings appear in text output. Must be ≥ 1; clap
    /// rejects `--finding-limit 0` at parse time.
    #[arg(long)]
    pub finding_limit: Option<NonZeroUsize>,
    #[arg(long, value_enum)]
    pub preset: Option<ScanPresetArg>,
    #[arg(long, value_enum, default_value = "full")]
    pub dataset_view: DatasetViewArg,
    #[arg(long, default_value_t = false)]
    pub analyst_summary: bool,
    /// Disable VT enrichment even when ~/.vt.toml is present. Enrichment
    /// is otherwise auto-activated when the config file exists.
    #[arg(long, default_value_t = false)]
    pub no_vt_enrich: bool,
    /// When an extracted URL or file hash is not yet indexed by VT, submit
    /// it for scanning instead of skipping. Default is lookup-only.
    #[arg(long, default_value_t = false)]
    pub vt_submit_unknown: bool,
    /// Disable LLM enrichment even when `~/.skill-veil.toml` has an `[llm]`
    /// section. Enrichment is otherwise auto-activated when config exists.
    #[arg(long, default_value_t = false)]
    pub no_llm_enrich: bool,
    /// Disable PromptIntel feed enrichment. The lookup is offline and
    /// only adds hits from the cache populated by
    /// `skill-veil promptintel feed sync`; this flag exists for CI
    /// where deterministic output is required regardless of which
    /// machine has a populated cache.
    #[arg(long, default_value_t = false)]
    pub no_promptintel_enrich: bool,
    /// Skip the once-per-day GitHub query that notifies you when a
    /// newer skill-veil-rules release or NOVA commit is available.
    /// The notifier is best-effort and never blocks; this flag (or
    /// the env var `SKILL_VEIL_NO_UPDATE_CHECK=1`) is for air-gapped
    /// environments and CI runs where you do not want any outbound
    /// connection beyond what the scan itself requires.
    #[arg(long, default_value_t = false)]
    pub no_update_check: bool,
    /// Skip running NOVA rules even if a NOVA pack is installed in
    /// the cache. Useful for benchmarks that pin the skill-veil-rules
    /// signal in isolation, or for runs against prompt content
    /// already pre-screened by NOVA upstream.
    #[arg(long, default_value_t = false)]
    pub no_nova: bool,
    /// Override the active LLM provider for this scan without touching the
    /// config file. Valid: openai, anthropic, ollama, ollama-cloud, lmstudio.
    #[arg(long)]
    pub llm_provider: Option<String>,
    /// Fail the scan when any external rule pack declares a rule id that
    /// collides with an already-loaded rule. Default is to warn and keep
    /// the first-loaded version (preserves backwards-compat).
    #[arg(long, default_value_t = false)]
    pub strict_rules: bool,
    /// Override the base directory for VT and LLM enrichment caches.
    /// Default: `dirs::cache_dir()/skill-veil/<scan-path-key>/`. Caches
    /// are NEVER placed inside the scanned package — a malicious skill
    /// could otherwise ship a forged cache entry to suppress real VT
    /// or LLM lookups for the cache TTL window. Use this flag in CI or
    /// sandboxed runs where the default user cache directory is not
    /// suitable.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct BenchmarkArgs {
    pub corpus: PathBuf,
    #[arg(short, long, value_enum, default_value = "json")]
    pub format: OutputFormat,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub history_file: Option<PathBuf>,
    #[arg(long)]
    pub release_id: Option<String>,
    #[arg(long)]
    pub dashboard_output: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct BaselineCreateArgs {
    pub report: PathBuf,
    #[arg(short, long)]
    pub output: PathBuf,
}

#[derive(Args, Clone)]
pub struct BaselineUpdateArgs {
    pub report: PathBuf,
    #[arg(long)]
    pub baseline: PathBuf,
    #[arg(short, long)]
    pub output: PathBuf,
    #[arg(long, default_value_t = false)]
    pub allow_new_findings: bool,
}

#[derive(Args, Clone)]
pub struct DiffArgs {
    pub previous: PathBuf,
    pub current: PathBuf,
    #[arg(short, long, value_enum, default_value = "text")]
    pub format: OutputFormat,
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    #[arg(long)]
    pub waivers: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub ci_summary: bool,
    #[arg(long, value_enum)]
    pub fail_on: Option<DiffFailPolicyArg>,
}

#[derive(Subcommand, Clone)]
pub enum BaselineAction {
    Create(BaselineCreateArgs),
    Update(BaselineUpdateArgs),
}

#[derive(Subcommand, Clone)]
pub enum WaiversAction {
    Validate(WaiversValidateArgs),
}

#[derive(Subcommand, Clone)]
pub enum PolicyAction {
    Validate(PolicyValidateArgs),
}

#[derive(Args, Clone)]
pub struct WaiversValidateArgs {
    pub path: PathBuf,
}

#[derive(Args, Clone)]
pub struct PolicyValidateArgs {
    pub path: PathBuf,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum DiffFailPolicyArg {
    NewActive,
    NewBlocking,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum ScanPresetArg {
    Local,
    Ci,
    Strict,
    Enterprise,
}

#[derive(Subcommand)]
pub enum RulesAction {
    List {
        #[arg(long)]
        category: Option<String>,
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    Test {
        rule_id: String,
        #[arg(short, long)]
        file: Option<PathBuf>,
        #[arg(short, long)]
        content: Option<String>,
        #[arg(long, default_value = "../skill-veil-rules/official")]
        rules_dir: PathBuf,
        #[arg(long)]
        expect_match: Option<bool>,
        #[arg(long)]
        expected_count: Option<usize>,
        #[arg(long, value_enum)]
        expected_severity: Option<SeverityArg>,
        #[arg(long, value_enum)]
        expected_action: Option<RecommendedActionArg>,
        #[arg(long)]
        expected_category: Option<String>,
    },
    TestPack {
        #[arg(long, default_value = "../skill-veil-rules/official")]
        rules_dir: PathBuf,
        #[arg(long, default_value = "../skill-veil-rules/fixtures/behavioral.yaml")]
        fixtures: PathBuf,
    },
    Validate {
        #[arg(long, default_value = "../skill-veil-rules/official")]
        rules_dir: PathBuf,
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    PackInfo {
        #[arg(long, default_value = "../skill-veil-rules/official")]
        rules_dir: PathBuf,
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    /// Re-run `skill-veil init` to refresh the locally installed
    /// rules pack. Equivalent to `skill-veil init` but lives under
    /// `rules` for discoverability.
    Update(RulesUpdateArgs),
    /// Show which signed rules-pack release is currently installed in
    /// the user cache (path, version, trusted key id).
    Status(RulesStatusArgs),
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Shield,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum RecommendedActionArg {
    Log,
    RequireApproval,
    Block,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// # Contract
    ///
    /// `vt download --limit 0` and `scan --finding-limit 0` MUST be rejected
    /// at clap parse time. Pre-fix both fields were `usize` / `Option<usize>`
    /// with no value-parser bound, so `--limit 0` was accepted and the VT
    /// download path silently fetched zero files (similarly the text output
    /// emitted zero findings). Switching to `NonZeroUsize` lets the type
    /// system carry the invariant — clap's built-in `FromStr` rejects `0`.
    #[test]
    fn vt_download_limit_zero_is_rejected() {
        let err = match Cli::try_parse_from(["skill-veil", "vt", "download", "--limit", "0"]) {
            Ok(_) => panic!("--limit 0 must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().to_lowercase().contains("limit"),
            "error must mention --limit: {err}"
        );

        // Sanity: a positive value parses cleanly.
        Cli::try_parse_from(["skill-veil", "vt", "download", "--limit", "1"])
            .expect("--limit 1 must be accepted");
    }

    #[test]
    fn scan_finding_limit_zero_is_rejected() {
        let err = match Cli::try_parse_from(["skill-veil", "scan", "./pkg", "--finding-limit", "0"])
        {
            Ok(_) => panic!("--finding-limit 0 must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().to_lowercase().contains("finding-limit"),
            "error must mention --finding-limit: {err}"
        );

        Cli::try_parse_from(["skill-veil", "scan", "./pkg", "--finding-limit", "5"])
            .expect("--finding-limit 5 must be accepted");
    }

    /// Pin the default at 500 — both as documentation and to catch
    /// accidental edits to `DEFAULT_VT_DOWNLOAD_LIMIT`.
    #[test]
    fn vt_download_limit_default_is_500() {
        let cli = Cli::try_parse_from(["skill-veil", "vt", "download"]).unwrap();
        let Commands::Vt {
            action: VtAction::Download(args),
        } = cli.command
        else {
            panic!("expected vt download subcommand");
        };
        assert_eq!(args.limit.get(), 500);
    }

    /// Contract: out-of-range `--fail-below` is rejected at parse
    /// time. Without this guard a negative threshold would never
    /// trip the gate (rate >= 0) and a `> 1.0` threshold would
    /// always trip it — both silent footguns.
    #[test]
    fn fail_below_rejects_out_of_range() {
        for bad in ["-0.1", "1.01", "2", "nan", "inf"] {
            let res = Cli::try_parse_from([
                "skill-veil",
                "promptintel",
                "cross-check",
                "--fail-below",
                bad,
            ]);
            assert!(
                res.is_err(),
                "--fail-below {bad} must be rejected at parse time"
            );
        }
    }

    /// Contract: 0.0 and 1.0 are both accepted. 0.0 is the
    /// "always pass" sentinel; 1.0 enforces 100% detection.
    #[test]
    fn fail_below_accepts_boundary_values() {
        for ok in ["0.0", "0.5", "0.95", "1.0"] {
            Cli::try_parse_from([
                "skill-veil",
                "promptintel",
                "cross-check",
                "--fail-below",
                ok,
            ])
            .unwrap_or_else(|e| panic!("--fail-below {ok} must parse: {e}"));
        }
    }
}
