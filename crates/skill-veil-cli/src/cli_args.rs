use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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
    #[arg(short, long, global = true)]
    pub verbose: bool,
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
    #[arg(long)]
    pub finding_limit: Option<usize>,
    #[arg(long, value_enum)]
    pub preset: Option<ScanPresetArg>,
    #[arg(long, value_enum, default_value = "full")]
    pub dataset_view: DatasetViewArg,
    #[arg(long, default_value_t = false)]
    pub analyst_summary: bool,
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
        #[arg(long, default_value = "rules/official")]
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
        #[arg(long, default_value = "rules/official")]
        rules_dir: PathBuf,
        #[arg(long, default_value = "rules/fixtures/behavioral.yaml")]
        fixtures: PathBuf,
    },
    Validate {
        #[arg(long, default_value = "rules/official")]
        rules_dir: PathBuf,
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    PackInfo {
        #[arg(long, default_value = "rules/official")]
        rules_dir: PathBuf,
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
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
